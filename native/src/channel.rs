//! Agent Fabric — agent-side channel-join client (#72 AF4, ADR-0020): the **policy** half.
//!
//! **The wire protocol itself no longer lives here.** Phase 2 of the CADS-Tunnel/ct-agent
//! consolidation (ADR-0020 amendment) made CADS-Tunnel's `ct_common` the NORMATIVE home of
//! the channel join protocol's client half: [`ct_common::channel_wire`] (outcome type, ack
//! parser and its `OK`-line grammar, refusal-category decoding, park-expiry classification —
//! and the normative ack contract in that module's doc), [`ct_common::channel_wire::io`]
//! (the stream-generic admission exchange for the rendezvous and relay legs) and
//! [`ct_common::channel_quic`] (the accept-any-cert channel dialer, the QUIC join wrappers,
//! the bounded post-admission stream setup). Those are a VERBATIM port of the bodies that
//! used to be in this file and in `transport.rs`/`channel_run/session.rs` (v0.7.23), with
//! their whole fix history — ct-agent#21 #23 #28 #36 #129 #140 #148, CADS-Tunnel#494 #495
//! #500 #506 #524 #557 — and the duplex guard tests, which moved with them. A byte-for-byte
//! parity proof between the old bodies and the port ran in this crate between the pin bump
//! and this change (PR4's `channel/parity_tests.rs`, 120 script × parameter pairs).
//!
//! This module now **re-exports** every moved name under its old path, so no call site in
//! this crate changed, and keeps only what is ct-agent POLICY rather than wire protocol:
//! the `CT_CHANNEL_PHASE_MARKER` operator switch ([`phase_marker_enabled`]), the `:443`
//! marker gate that also needs the negotiated ALPN ([`phase_marker_for`]), and the
//! switch-gated QUIC join ([`present_channel_join_marked`]). A wire-behaviour question is
//! answered by ct-common's source; a wire change lands there first and reaches this crate
//! through the pinned CADS-Tunnel tag (all five pins move together — see the lockfile guard
//! in CI). The `ct_edge`-driven integration tests below keep running against the re-exports.

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::SigningKey;
use quinn::Connection;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// ---------------------------------------------------------------------------------------
// The wire protocol, re-exported from its normative home (Phase-2 PR5). Same names, same
// paths as before; `pub` now where some were `pub(crate)`/private, which only widens.
// ---------------------------------------------------------------------------------------
pub use ct_common::channel_wire::{
    decode_hex_32, decode_hex_64, decode_refusal_category, error_names_park_expiry, is_refusal_token_shape,
    parse_channel_ack, quic_park_expired_marker, ChannelJoinOutcome, DroppedLegBeforeAck, CHANNEL_ACK_MAX_BYTES,
    PHASE_MARKER_RELAY, PHASE_MARKER_RENDEZVOUS, PHASE_PREAMBLE_MAGIC, POSSESSION_CHALLENGE_LEN,
    REFUSAL_CATEGORY_MAX_LEN,
};
pub use ct_common::channel_wire::io::{
    present_channel_join_on_stream, present_channel_relay_join_on_stream, read_refusal_tail_token,
    ADMISSION_EXCHANGE_TIMEOUT, KA_PARK_INACTIVITY_BOUND, REFUSAL_TAIL_BOUND,
};
pub use ct_common::channel_quic::{present_channel_join, present_channel_join_quic};

/// #495 slice 2a (v0.4.14): the optional phase preamble a KA-generation client sends
/// before its length-framed join -- [0xFF, phase]. On a `:443` TLS-TCP leg, only ever
/// sent when the TLS negotiation selected a KA id (see `transport::ka_negotiated`): an
/// old edge selected a legacy id and receives byte-identical legacy traffic. On QUIC
/// (CADS-Tunnel#495 U2 (a'), [`present_channel_join_marked`]) there is no ALPN to gate
/// on at all -- safety instead rests entirely on the length-prefix property below,
/// which holds on every transport equally. The magic 0xFF is unambiguous against the
/// length prefix (it would mean a >=65280-byte join, refused as len-oob by every edge
/// since the field existed).
/// #495 measurement isolation (requested by the tester after the 2a series proved
/// unrunnable with published binaries): `CT_CHANNEL_PHASE_MARKER=off` (or `0`)
/// suppresses the phase preamble on EVERY transport while keeping everything else
/// identical — the only way to vary the marker as a SINGLE variable, since every marked
/// release also carries the #494 ack-reader fix. Default: markers on.
pub(crate) fn phase_marker_enabled() -> bool {
    phase_marker_enabled_from(std::env::var("CT_CHANNEL_PHASE_MARKER").ok().as_deref())
}

/// Pure core of [`phase_marker_enabled`]: only the explicit strings `off`/`0`
/// disable the marker — unset, empty, or anything else keeps the default (on),
/// so a typo can never silently drop the marker generation.
pub(crate) fn phase_marker_enabled_from(v: Option<&str>) -> bool {
    !matches!(v.map(str::trim), Some("off") | Some("0"))
}

/// #495 2a: the ONE gate for sending a `[0xFF, phase]` preamble on a `:443` TLS
/// channel leg — the operator switch (v0.4.17, [`phase_marker_enabled`]) AND the
/// edge having negotiated a KA-generation ALPN ([`crate::transport::ka_negotiated`]).
/// A legacy edge selected a legacy id and must receive byte-identical legacy
/// traffic, so this returns `None` there regardless of the switch. Shared by the
/// rendezvous- and relay-leg dial sites so the two cannot drift (#25).
pub(crate) fn phase_marker_for(
    tls: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    phase: u8,
) -> Option<u8> {
    (phase_marker_enabled() && crate::transport::ka_negotiated(tls)).then_some(phase)
}

/// CADS-Tunnel#495 U2 (a'): the QUIC analog of [`present_channel_join`] that also sends the
/// `[0xFF, phase]` phase preamble -- previously every QUIC join hardcoded `None` here
/// regardless of the operator switch, which is exactly the gap #495's own status table
/// tracked as "(a') ct-agent sendet den Marker -- offen, braucht ein Release": the edge's
/// QUIC-side tolerance for the marker ((b'), CADS-Tunnel#495 slice U2) has been live and
/// field-verified since 2026-08-19, but was inert because no released ct-agent ever sent
/// one on this transport.
///
/// Gated ONLY on [`phase_marker_enabled`] -- unlike [`phase_marker_for`]'s `:443` twin,
/// this is deliberately NOT also gated on a negotiated-ALPN check: QUIC has no ALPN
/// concept at all, and the edge's own wire-safety argument for tolerating an unexpected
/// marker rests entirely on the length-prefix property (`[0xFF, phase]` reads as a
/// declared length of >= 65280 bytes to any edge without the #495(b') peek -- a clean
/// len-oob refusal, never a hang), not on ALPN-negotiated detection.
///
/// `phase` should be [`PHASE_MARKER_RENDEZVOUS`] for a pure admission connection (the
/// peer is learned here but the actual session runs elsewhere -- e.g. a `broker_conn`)
/// and [`PHASE_MARKER_RELAY`] for a connection the spliced/relayed session itself runs
/// over afterward (e.g. a `relay_conn`) -- mirroring the `:443` front-door callers'
/// existing [`phase_marker_for`] convention so the two transports cannot drift apart.
pub(crate) async fn present_channel_join_marked(
    conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    phase: u8,
) -> Result<ChannelJoinOutcome, BoxError> {
    present_channel_join_quic(conn, request, holder, phase_marker_enabled().then_some(phase)).await
}

#[cfg(test)]
mod tests {
    // Phase-2 PR5: the duplex-only guard tests (ct-agent#21 #23 #36 #129 #148 #494 #495a #500
    // #506 #524 #557 …) moved verbatim to ct_common::channel_wire with the bodies they guard.
    // What stays here drives a REAL ct_edge broker/rendezvous/front door over QUIC and TLS-TCP
    // against the re-exported client half.
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ed25519_dalek::Signer;
    use tokio::io::AsyncWriteExt;
    use ct_edge::channel_broker::{broker_channel_rendezvous, resolve_channel_join};
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};

    const OP_SEED: [u8; 32] = [7u8; 32];

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&OP_SEED)
    }

    #[test]
    fn phase_marker_switch_disables_only_on_explicit_off_or_zero() {
        // #495 measurement isolation: only the explicit opt-outs disable the marker —
        // unset/empty/typos keep the default ON, so the marker generation can never be
        // dropped by accident.
        assert!(phase_marker_enabled_from(None), "unset -> on");
        assert!(phase_marker_enabled_from(Some("")), "empty -> on");
        assert!(phase_marker_enabled_from(Some("on")), "explicit on -> on");
        assert!(phase_marker_enabled_from(Some("false")), "unknown word -> on (no silent opt-out)");
        assert!(!phase_marker_enabled_from(Some("off")), "off -> disabled");
        assert!(!phase_marker_enabled_from(Some("0")), "0 -> disabled");
        assert!(!phase_marker_enabled_from(Some(" off ")), "trimmed -> disabled");
    }

    fn signed_grant(channel: [u8; 32], holder: &SigningKey, dir: Direction) -> SignedChannelGrant {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let signature = operator().sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// CADS-Tunnel#495 U2 (a'): `present_channel_join_marked` actually puts the `[0xFF,
    /// phase]` preamble on the QUIC wire -- the exact gap #495's own status table named
    /// ("(a') ct-agent sendet den Marker -- offen"). Drives a REAL quinn connection (not
    /// a bare duplex, unlike the relay-leg twin above) so the assertion covers the whole
    /// `present_channel_join_marked` -> `open_bi` -> `present_channel_join_on_stream`
    /// path, not just the wire-writing core.
    #[tokio::test]
    async fn present_channel_join_marked_prefixes_the_quic_join_495_u2() {
        let channel = [0x15u8; 32];
        let holder = SigningKey::from_bytes(&[0x42u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.15:1515".to_string(),
        };
        let expected_len = request.encode().len() as u16;

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (_s, mut r) = conn.accept_bi().await.expect("accept_bi");
            let mut head = [0u8; 4];
            r.read_exact(&mut head).await.expect("wire head");
            head
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let req = request.clone();
        let hk = SigningKey::from_bytes(&[0x42u8; 32]);
        let presenter = tokio::spawn(async move {
            let _ = present_channel_join_marked(&conn, &req, &hk, PHASE_MARKER_RENDEZVOUS).await;
        });

        let head = srv.await.expect("server task");
        assert_eq!(head[0], PHASE_PREAMBLE_MAGIC, "preamble magic first on the real QUIC wire");
        assert_eq!(head[1], PHASE_MARKER_RENDEZVOUS, "phase byte second");
        assert_eq!(u16::from_be_bytes([head[2], head[3]]), expected_len, "then the length, unmoved");
        let _ = presenter.await;
    }

    #[tokio::test]
    async fn present_channel_join_completes_the_possession_handshake() {
        // AF4: the agent-side client drives the full broker handshake end-to-end
        // against the real edge broker. A genuine holder is admitted; a holder that
        // signs the possession challenge with the wrong key is refused.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xA0u8; 32];
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.7:9000".to_string(),
        };

        // (1) genuine holder -> Admitted.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        assert_eq!(
            outcome,
            ChannelJoinOutcome::Admitted { peer_endpoint: String::new(), peer_noise_pubkey: None, peer_holder: None, peer_attestation: None, observed_reflexive: None },
            "the genuine holder proves possession and is admitted"
        );
        conn.close(0u32.into(), b"done");
        let _ = srv.await;

        // (2) wrong possession key -> Refused (the grant is valid, possession is not).
        let thief = SigningKey::from_bytes(&[0x99u8; 32]);
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let srv2 = tokio::spawn(async move {
            resolve_channel_join(&server2, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let outcome2 = present_channel_join(&conn2, &request, &thief).await.expect("join drives");
        // #524: the dev-dependency edge is pinned to CADS-Tunnel v0.4.15, the first
        // tag that FRAMES the refusal category — so this is now the real-edge proof
        // that the token the agent parses is the one the edge actually writes, not a
        // fixture agreeing with itself. The old-edge interop (a bare `NO` staying
        // category-less) keeps its own wire-level tests above.
        assert_eq!(
            outcome2,
            ChannelJoinOutcome::Refused { category: Some("possession".to_string()) },
            "a wrong possession key is refused, with the edge's own category",
        );
        let _ = srv2.await;
    }

    #[tokio::test]
    async fn two_agent_clients_learn_each_others_endpoint() {
        // AF4 end-to-end: two agent clients present joins for the same channel; the
        // broker pairs them and each client parses the PEER's advertised endpoint out
        // of its Admitted outcome.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xB0u8; 32];
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let req_a = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_a, Direction::Initiate),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_b, Direction::Accept),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_a, &holder_a).await.expect("a joins");
            conn.close(0u32.into(), b"done");
            out
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_b, &holder_b).await.expect("b joins");
            conn.close(0u32.into(), b"done");
            out
        });

        let out_a = a.await.expect("a");
        let out_b = b.await.expect("b");
        let _ = srv.await;
        // Each side learns the PEER's endpoint AND (#121 B1-follow) its OWN edge-observed
        // reflexive from the live rendezvous finisher — previously `None`, now the loopback
        // source it connected from.
        for (out, peer_ep, who) in [(out_a, "203.0.113.2:7002", "A"), (out_b, "203.0.113.1:7001", "B")] {
            match out {
                ChannelJoinOutcome::Admitted {
                    peer_endpoint,
                    peer_noise_pubkey,
                    peer_holder,
                    peer_attestation,
                    observed_reflexive,
                } => {
                    assert_eq!(peer_endpoint, peer_ep, "agent {who} learns the peer endpoint");
                    assert_eq!((peer_noise_pubkey, peer_holder, peer_attestation), (None, None, None));
                    let r = observed_reflexive.expect("learns its reflexive via the live rendezvous finisher");
                    assert!(r.ip().is_loopback(), "agent {who} reflexive is the loopback source it dialed from");
                }
                other => panic!("expected Admitted, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn rendezvous_relays_each_peers_attested_noise_key() {
        // #72 AF4 / #100 (hands-off): when the registry has each member's Noise key,
        // the broker relays the PEER's key in the ack, so each agent learns the peer's
        // Noise pubkey to pin — no operator-conveyed value. The authorize closure
        // returns (operator, this-holder's-noise), keyed on the holder.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xC0u8; 32];
        let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let hkey_a = holder_a.verifying_key().to_bytes();
        let hkey_b = holder_b.verifying_key().to_bytes();
        let noise_a = [0xAAu8; 32];
        let noise_b = [0xBBu8; 32];
        // Each member attests its own Noise key with its holder key (#101).
        let attest_a = holder_a
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hkey_a, &noise_a))
            .to_bytes();
        let attest_b = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hkey_b, &noise_b))
            .to_bytes();
        let req_a = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_a, Direction::Initiate),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_b, Direction::Accept),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, h| async move {
                // Each member resolves to (operator, its Noise key, its attestation).
                let (noise, attest) = if h == hkey_a { (noise_a, attest_a) } else { (noise_b, attest_b) };
                (c.0 == channel).then_some((op_pub, Some(noise), Some(attest)))
            })
            .await
            .map(|_| ())
        });
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_a, &holder_a).await.expect("a joins");
            conn.close(0u32.into(), b"done");
            out
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_b, &holder_b).await.expect("b joins");
            conn.close(0u32.into(), b"done");
            out
        });

        let out_a = a.await.expect("a");
        let out_b = b.await.expect("b");
        let _ = srv.await;
        // A learns B's endpoint + attested Noise key/holder/attestation, plus its OWN
        // reflexive from the live finisher (#121 B1-follow — loopback source here).
        for (out, peer_ep, pn, ph, pa, who) in [
            (out_a, "203.0.113.2:7002", noise_b, hkey_b, attest_b, "A"),
            (out_b, "203.0.113.1:7001", noise_a, hkey_a, attest_a, "B"),
        ] {
            match out {
                ChannelJoinOutcome::Admitted {
                    peer_endpoint,
                    peer_noise_pubkey,
                    peer_holder,
                    peer_attestation,
                    observed_reflexive,
                } => {
                    assert_eq!(peer_endpoint, peer_ep, "agent {who} learns the peer endpoint");
                    assert_eq!(peer_noise_pubkey, Some(pn), "agent {who} learns the peer Noise key");
                    assert_eq!(peer_holder, Some(ph), "agent {who} learns the peer holder");
                    assert_eq!(peer_attestation, Some(pa), "agent {who} learns the peer attestation");
                    let r = observed_reflexive.expect("learns its reflexive via the live rendezvous finisher");
                    assert!(r.ip().is_loopback(), "agent {who} reflexive is the loopback source");
                }
                other => panic!("expected Admitted, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn two_agents_carry_data_over_a_channel_session() {
        // #72 AF4-session end-to-end over a REAL QUIC connection: this is the payoff
        // of the rendezvous above. Once each agent has learned its peer's endpoint,
        // the initiator dials the responder and they run a Noise_IK A2A session keyed
        // on their member Noise static keys, then exchange application data BOTH ways
        // — the live, encrypted, mutually-authenticated tunnel-to-tunnel data path.
        use ct_common::a2a::{a2a_initiate, a2a_recv, a2a_respond, a2a_send};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;

        // The responder listens on its advertised endpoint; the initiator dials it.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut s, mut r) = conn.accept_bi().await.expect("accept_bi");
            let mut sess = a2a_respond(&mut s, &mut r, &resp_priv).await.expect("responder handshake");
            let got = a2a_recv(&mut r, &mut sess).await.expect("recv");
            assert_eq!(got, b"hello from agent A", "responder decrypts A's application data");
            a2a_send(&mut s, &mut sess, b"ack from agent B").await.expect("send ack");
            // Keep the connection (and endpoint) alive until the initiator is done so
            // the ack is delivered before teardown.
            conn.closed().await;
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (mut s, mut r) = conn.open_bi().await.expect("open_bi");
        let mut sess = a2a_initiate(&mut s, &mut r, &initiator.private, &responder.public)
            .await
            .expect("initiator handshake");
        a2a_send(&mut s, &mut sess, b"hello from agent A").await.expect("send");
        let ack = a2a_recv(&mut r, &mut sess).await.expect("recv");
        assert_eq!(ack, b"ack from agent B", "agent A decrypts agent B's encrypted reply");
        conn.close(0u32.into(), b"done");
        srv.await.expect("responder task");
    }

    #[tokio::test]
    async fn member_learns_its_edge_observed_reflexive_over_quic() {
        // #121 Phase B1 (frozen): the AutoNAT round-trip over REAL QUIC. A member joins over the
        // authenticated channel connection; the edge observes its reflexive (post-NAT) source
        // via `read_join_on_connection` (`conn.remote_address()`) and reports it back in the OK
        // ack as the `r=<addr>` token; the joining member parses it into
        // `Admitted { observed_reflexive: Some(..) }`. The learned address MUST equal both what
        // the edge observed AND the loopback source the client actually connected from.
        use ct_edge::channel_broker::read_join_on_connection;

        let pk = operator().verifying_key().to_bytes();
        let channel = [0x5Bu8; 32];
        let holder = SigningKey::from_bytes(&[0x0au8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6011".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        // The edge task: admit the join, then ack `OK r=<observed reflexive>` — the exact
        // primitive the B2 hole-punch and Phase C superpeer election consume.
        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut send, _req, _op, _noise, _attest, observed) =
                read_join_on_connection(&conn, 500, std::time::Duration::from_secs(5), &move |c, _h| async move {
                    (c.0 == channel).then_some((pk, None, None))
                })
                .await
                .expect("admitted");
            send.write_all(format!("OK r={observed}").as_bytes()).await.expect("ack");
            send.finish().expect("finish");
            conn.closed().await; // hold the connection so the member reads the ack to EOF
            observed
        });

        let client = build_client_endpoint(cert).expect("client");
        let client_source = client.local_addr().expect("client local addr");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        conn.close(0u32.into(), b"done");
        let observed = srv.await.expect("edge task");

        match outcome {
            ChannelJoinOutcome::Admitted { observed_reflexive, .. } => {
                assert_eq!(
                    observed_reflexive,
                    Some(observed),
                    "the member learns exactly the reflexive address the edge observed",
                );
                assert_eq!(
                    observed_reflexive,
                    Some(client_source),
                    "the observed reflexive equals the loopback source the client connected from",
                );
                assert!(observed.ip().is_loopback(), "the test's source is loopback");
            }
            other => panic!("a valid join must be Admitted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn member_learns_its_edge_observed_reflexive_over_tls_tcp_443() {
        // #121 Phase B1 (frozen): the same AutoNAT round-trip over a REAL TLS-over-TCP `:443`
        // front-door stream — the fallback path for a member whose network blocks the channel
        // ports. The edge takes the reflexive from the accepted `TcpStream`'s `peer_addr()`,
        // threads it through `admit_channel_join_on_duplex`, and reports it in the `r=<addr>`
        // token; the member parses it into `Admitted { observed_reflexive: Some(..) }` via the
        // transport-agnostic `present_channel_join_on_stream`. Proves BOTH transports carry it.
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::io::split;

        let pk = operator().verifying_key().to_bytes();
        let channel = [0xF4u8; 32];
        let holder = SigningKey::from_bytes(&[0x0au8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6041".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let listen_addr: SocketAddr = listener.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("tcp accept");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a real TLS-TCP stream");
            stream.write_all(format!("OK r={observed}").as_bytes()).await.expect("ack");
            stream.shutdown().await.expect("shutdown");
            observed
        });

        let client_tls = tcp_tls_connect(listen_addr, cert).await.expect("tls-tcp connect");
        let (cli_r, cli_w) = split(client_tls);
        let outcome = present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false)
            .await
            .expect("join drives over the :443 duplex");
        let observed = srv.await.expect("edge task");

        match outcome {
            ChannelJoinOutcome::Admitted { observed_reflexive, .. } => {
                assert_eq!(
                    observed_reflexive,
                    Some(observed),
                    "the :443 member learns exactly the reflexive the edge observed on the TCP peer",
                );
                assert!(observed.ip().is_loopback(), "the test's TCP source is loopback");
            }
            other => panic!("a valid :443 join must be Admitted, got {other:?}"),
        }
    }
}
