//! Verbindungsaufbau fuer den Kanal-Beitritt: Reflexiv-Erkennung, DCUtR-Aufwertung,
//! Relay-Fallback/-Leiter, und die Rueckversuchs-Politik der Beitrittsschleife.
//!
//! Herausgeloest aus `channel_run/mod.rs` (Konsolidierungsprogramm, Modulsplit Schnitt 4):
//! die groesste noch verbliebene erkennbare Naht -- wie ein Mitglied ueberhaupt eine
//! Verbindung zum Partner herstellt (DCUtR/Direktwahl/Relay-Leiter) und wie diese Versuche
//! bei einem Fehlschlag oder einer Foerderung erneut angestossen werden, getrennt von der
//! CLI-Konfiguration (`cli_config`), der reinen Kandidatenwahl (`dialing`) und der
//! Sitzungszulassung/-bedienung, die in `mod.rs` bleibt (haengt eng mit `ServeSessionCtx`
//! zusammen -- keine der hier verschobenen Funktionen beruehrt sie).
//!
//! Reiner Verschiebeschnitt: kein Verhalten geaendert. `mod.rs` 2509 -> 1357 Zeilen; das
//! sind, mit den ersten drei Schnitten zusammen, 1856 Zeilen aus der urspruenglich
//! 3213-zeiligen Datei herausgeloest. Zehn Bezeichner wurden von privat auf `pub(crate)`
//! geoeffnet -- zwei davon erst im zweiten Anlauf gefunden, als ein Nicht-Test-Bau
//! (`CHANNEL_ACCEPT_TIMEOUT`) bzw. der Testbau selbst (`ChannelJoinCliConfig::ladder`,
//! bislang nur ueber die parent-privilegierte Sichtbarkeit innerhalb von `mod.rs` erreichbar)
//! die Luecke meldete; nachgewiesen per Zeilenvergleich gegen den Originalblock -- sonst
//! nichts unterscheidet die beiden Fassungen -- damit `mod.rs` und die Testdatei dieselben
//! Namen wie zuvor erreichen.

use super::*;

/// #248/#238: the edge's QUIC "whoami" query address (its 'W' reflexive-address echo, on
/// the SAME QUIC listener Browser-Plane agents register on) -- same host as the `:443`
/// relay-gate, this deployment's stable QUIC port (4433) unless an operator overrides it
/// via `CT_CHANNEL_REFLEXIVE_EDGE` (host:port; e.g. if the edge's QUIC listener is
/// NAT/port-mapped differently from its `:443` front door).
pub fn reflexive_query_addr(relay_gate_addr: SocketAddr, override_raw: Option<&str>) -> Result<SocketAddr, String> {
    match override_raw {
        Some(s) if !s.trim().is_empty() => resolve_socket_addr(s.trim()),
        _ => Ok(SocketAddr::new(relay_gate_addr.ip(), 4433)),
    }
}

/// #248/#238: query the edge's 'W' reflexive-address echo to learn this member's GENUINE
/// UDP-observed reflexive address -- the piece missing from #248's original candidate-pool
/// fix, which only ever had a TCP-observed address (from the `:443` relay-gate's own
/// admission handshake) to seed. A NAT maps a TCP flow and a UDP flow from the same host to
/// DIFFERENT external ports, so DCUtR's QUIC direct-dial attempt (its preferred one) was
/// consistently seeded with the wrong transport's address and timed out even against
/// cone-type (punchable) NATs.
///
/// Best-effort by construction: any failure (edge unreachable on that port, timeout,
/// malformed reply) returns `None`, exactly like an edge that never observed a reflexive
/// address at all — this is a pure enhancement layered on top of the existing TCP-derived
/// candidate, never a hard requirement for the relay-gate join to proceed. Uses
/// [`crate::transport::build_channel_dialer`] (accepts any server cert): the reply isn't
/// sensitive and needs no authentication — a MITM lying about the observed address can only
/// make the punch fail, never weaken the channel's real security, which rests entirely on the
/// Noise_IK/grant/possession layers elsewhere.
///
/// Deliberately does NOT apply the `#137`/`is_global_unicast` safety filter itself — the
/// caller does, exactly like `own_observed_reflexive` above, so this function stays testable
/// against a real (loopback, in tests) server without the filter masking a wiring bug.
pub async fn discover_udp_reflexive(edge_quic_addr: SocketAddr, timeout: std::time::Duration) -> Option<SocketAddr> {
    let attempt = async {
        let endpoint = crate::transport::build_channel_dialer().ok()?;
        let conn = endpoint.connect(edge_quic_addr, "localhost").ok()?.await.ok()?;
        let (mut send, mut recv) = conn.open_bi().await.ok()?;
        send.write_all(b"W").await.ok()?;
        send.finish().ok()?;
        let mut len = [0u8; 1];
        recv.read_exact(&mut len).await.ok()?;
        let mut buf = vec![0u8; len[0] as usize];
        recv.read_exact(&mut buf).await.ok()?;
        std::str::from_utf8(&buf).ok()?.parse::<SocketAddr>().ok()
    };
    tokio::time::timeout(timeout, attempt).await.ok().flatten()
}

/// **#136 N-wire — DCUtR-upgradable relay join over the `:443` relay-gate.** Like
/// [`join_via_relay_dcutr`], but reaches the Circuit-Relay v2 relay through
/// [`dial_relay_gate_over_443`] instead of a directly-dialable `CT_CHANNEL_CIRCUIT_RELAY`
/// multiaddr — the deployment this session actually ships: no new public port, the relay-node
/// gated by grant + possession before a single byte reaches it. `own_grant` is this member's
/// own signed grant (presented to the relay-gate, distinct from the channel-join grant already
/// consumed by `present_channel_join`, though today they are the same value).
#[allow(clippy::too_many_arguments)]
pub async fn join_via_relay_gate_dcutr<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    local: P,
    relay_gate_addr: SocketAddr,
    relay_gate_cert: CertificateDer<'static>,
    own_grant: &ct_common::channel::SignedChannelGrant,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    use tokio_util::compat::TokioAsyncReadCompatExt;

    // CADS-Tunnel#495 U2 (a'): relay_conn's actual (post-admission) bi-stream carries the
    // relay-gate leg's data below -- PHASE_MARKER_RELAY, mirroring the :443 relay ladder's
    // own phase_marker_for(&stream, PHASE_MARKER_RELAY) call.
    let (peer_noise, own_observed_reflexive) =
        match present_channel_join_marked(relay_conn, request, holder, PHASE_MARKER_RELAY).await? {
        ChannelJoinOutcome::Admitted {
            peer_noise_pubkey: Some(noise),
            peer_holder,
            peer_attestation,
            observed_reflexive,
            ..
        } => {
            // ct-agent#41 (#35 "Path A"): see verify_relayed_dcutr_peer's own doc comment.
            let noise = verify_relayed_dcutr_peer(request, noise, peer_holder, peer_attestation)?;
            (noise, observed_reflexive)
        }
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("DCUtR relay-gate join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused { category } => {
            // #524: base string frozen, category appended when present.
            return Err(AdmissionRefused::boxed_with_category(
                "edge relay refused the channel join",
                category.as_deref(),
            ));
        }
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    };
    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::other(e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    let (gate_stream, relay_peer) =
        dial_relay_gate_over_443(relay_gate_addr, relay_gate_cert, own_grant, holder).await?;
    // #248: seed the DCUtR swarm with this member's OWN reflexive address, when the edge
    // observed one and it's actually safe to advertise (same #137 global-unicast filter
    // every other candidate-address path in this file already applies). Without this,
    // DCUtR has no real external address to offer the peer at all -- it can only ever
    // advertise the relay-node's own address (learned via identify over the circuit,
    // which is the EDGE's address, not this member's own, since the edge proxies every
    // relay-gate connection) or nothing, so the hole-punch had no real candidate to try.
    // Live-reproduced: dozens of real relay-gate sessions with admission + circuit
    // genuinely established, never once a completed hole-punch -- this is why.
    // #248/#238-follow, CORRECTING an earlier (wrong) belief about this value: `own_observed_reflexive`
    // is NOT observed over any TCP connection -- `relay_conn` (this fn's `present_channel_join` call
    // just above) is unconditionally a QUIC connection (`dial_relay_preferring_direct` ->
    // `build_channel_dialer` -> `quinn::Endpoint::connect`), to the relay/broker port, not the
    // `:443` relay-gate leg at all. It's a real, genuinely-observed external port -- just for an
    // unrelated ephemeral QUIC socket, not any TCP one and not the swarm's own QUIC punch listener
    // either. There is currently no TCP-reflexive-discovery mechanism anywhere in this codebase (that
    // would need the edge to report back the observed remote address for the actual `dial_relay_gate_over_443`
    // TCP+TLS connection specifically -- a new edge-side wire-protocol addition, mirroring the 'W'
    // echo op below, not yet built). So `own_observed_reflexive` is diagnostic-only now (logged
    // below), never used to seed a dial candidate -- see `p2p::build_relay_gate_client`'s doc
    // comment for why constructing one from it was actively wrong, not just suboptimal.
    //
    // Query the edge's 'W' echo (its normal QUIC :4433 listener) for a genuine UDP-observed
    // reflexive address, so DCUtR's preferred QUIC direct-dial attempt gets seeded with a real
    // address. Best-effort, bounded, never blocks the join on failure.
    let reflexive_edge_addr = reflexive_query_addr(
        relay_gate_addr,
        std::env::var("CT_CHANNEL_REFLEXIVE_EDGE").ok().as_deref(),
    )
    .ok();
    let own_reflexive_udp = match reflexive_edge_addr {
        Some(addr) => discover_udp_reflexive(addr, std::time::Duration::from_secs(5)).await,
        None => None,
    }
    .filter(|a| ct_common::channel::is_global_unicast(*a));
    if debug_timing_enabled() {
        eprintln!(
            "ct-agent channel: debug relay-gate DCUtR own reflexive: relay/broker-observed (QUIC, NOT a TCP candidate) {:?}; own reflexive (udp, queried at {:?}) = {:?}",
            own_observed_reflexive,
            reflexive_edge_addr,
            own_reflexive_udp
        );
    }
    let (client, circuit_relay) =
        crate::p2p::build_relay_gate_client(gate_stream.compat(), relay_peer, own_reflexive_udp)?;
    crate::p2p::run_channel_session_upgradable_dcutr(
        relay_send,
        relay_recv,
        local,
        role,
        own_noise_private,
        &peer_noise,
        client,
        circuit_relay,
    )
    .await
}

/// **#104 direct-P2P wire-in.** Run one side of an A2A channel session over `relay_conn` as an
/// **upgradable** session: it starts on the relay and, in the background, opportunistically dials a
/// direct link and cuts the byte stream over to it (offloading the edge) — transparently to the
/// app, no byte lost at the seam. Composes
/// [`ct_common::upgrade::run_upgradable_session_initiator`]/`_responder` with the real quinn
/// dial/accept: the channel **initiator** advertises `own_direct_endpoint` (its `direct_listener`'s
/// address) in-band and, on the peer's `Ready`, accepts the incoming direct dial; the channel
/// **responder**, on the `Offer`, dials that endpoint ([`dial_peer_direct`]) and handshakes the
/// direct Noise session. The direct-Noise role is tied to who-dials (the dialer is the Noise
/// initiator) so `a2a_initiate`/`a2a_respond` never block each other. If the hole-punch fails, the
/// session stays on the relay. An initiator with no listener to offer (a relay-only member) runs a
/// plain [`run_channel_session_on_stream`]. The relay leg stays end-to-end either way; this test
/// runs over loopback.
///
/// **The live cross-NAT hole-punch is NOT proven** — this said "proven on the deploy (#104 H4)".
/// See the note on [`crate::p2p::run_upgradable_dcutr_session`] for the two records that say
/// otherwise (ct-agent#6, open, measures every real cross-NAT direct dial failing; and
/// CADS-Tunnel's `docs/product/comparison.md`). The relay fallback is what carries traffic
/// between two NAT'd agents today.
///
/// Noted here as well as there because the claim existed in BOTH places under different issue
/// tags (#104 H4 here, #136 N136.4 there), and correcting only the one that turned up first
/// would have left the other reading as a live proof.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_session_upgradable<P>(
    relay_conn: &Connection,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    direct_listener: Option<Endpoint>,
    own_direct_endpoint: Option<String>,
    dial_timeout: std::time::Duration,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    use ct_common::a2a::establish_direct_session;
    use ct_common::upgrade::{
        run_upgradable_session_initiator, run_upgradable_session_responder_verified, Role, UpgradeCoordinator,
    };

    let map_err = |e: Box<dyn std::error::Error + Send + Sync>| io::Error::other(e.to_string());
    let (relay_send, relay_recv) = match role {
        ChannelRole::Initiate => relay_conn.open_bi().await.map_err(|e| map_err(Box::new(e)))?,
        ChannelRole::Accept => relay_conn.accept_bi().await.map_err(|e| map_err(Box::new(e)))?,
    };
    // The relay handshake borrows these; the direct-establishment closures need owned copies.
    let (relay_priv, relay_peer) = (*own_noise_private, *peer_noise_public);
    let (direct_priv, direct_peer) = (*own_noise_private, *peer_noise_public);

    match role {
        ChannelRole::Initiate => {
            let (listener, endpoint) = match (direct_listener, own_direct_endpoint) {
                (Some(l), Some(e)) => (l, e),
                // Relay-only initiator (no dialable direct address): run the plain relay session.
                _ => {
                    return run_channel_session_on_stream(
                        relay_send, relay_recv, ChannelRole::Initiate, &relay_priv, &relay_peer, local,
                    )
                    .await
                    .map_err(Into::into)
                }
            };
            let coord = UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100);
            eprintln!("ct-agent channel: #104 upgrade — offering direct candidate {endpoint} in-band");
            run_upgradable_session_initiator(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                &relay_peer,
                coord,
                1,
                || async move { Some(endpoint) },
                move || async move {
                    // Accept the incoming direct dial (the responder dials us), then handshake as the
                    // direct-Noise RESPONDER (the dialer is the Noise initiator).
                    let incoming = match tokio::time::timeout(dial_timeout, listener.accept()).await {
                        Ok(Some(i)) => i,
                        Ok(None) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct listener closed with no incoming — staying on relay");
                            return None;
                        }
                        Err(_) => {
                            eprintln!(
                                "ct-agent channel: #104 upgrade — no incoming direct dial within {dial_timeout:?} — staying on relay"
                            );
                            return None;
                        }
                    };
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — incoming direct connection failed ({e}) — staying on relay");
                            return None;
                        }
                    };
                    let (s, r) = match conn.accept_bi().await {
                        Ok(sr) => sr,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct bi-stream accept failed ({e}) — staying on relay");
                            return None;
                        }
                    };
                    match establish_direct_session(s, r, false, &direct_priv, &direct_peer).await {
                        Ok(session) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise session established, cutting over from relay");
                            Some(session)
                        }
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise handshake failed ({e}) — staying on relay");
                            None
                        }
                    }
                },
            )
            .await
            .map_err(Into::into)
        }
        ChannelRole::Accept => {
            let coord = UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100);
            run_upgradable_session_responder_verified(
                relay_send,
                relay_recv,
                local,
                &relay_priv,
                &relay_peer,
                coord,
                1,
                // #137 SSRF guard (reflexive candidate) / #276 same-subnet guard (local
                // candidate): the offered endpoint is peer-conveyed and never passed the edge
                // broker's `safe_endpoint` gate, so `select_upgrade_candidate` applies the
                // appropriate filter to whichever half it ends up choosing — refuse to even
                // signal Ready when neither candidate is dialable.
                |ep: String| async move {
                    let chosen = select_upgrade_candidate(&ep);
                    eprintln!(
                        "ct-agent channel: #104 upgrade — peer offered direct candidate {ep}{}",
                        match chosen {
                            Some(a) => format!(" -> selected {a}"),
                            None => " (rejected: no dialable candidate — neither a same-subnet local nor a global-unicast reflexive address, #137/#276)".to_string(),
                        }
                    );
                    chosen.is_some()
                },
                // ct-agent#35: was the plain (non-`_verified`) responder, so this closure never
                // saw an attested key at all -- `establish_direct_session` pinned whatever
                // `peer_noise_public` this function was called with, unchecked against the live
                // peer. `_verified` hands the ATTESTED key down as `expected_peer` (same pattern
                // ct-agent#11 already established for the DCUtR path, p2p.rs): using it here
                // instead of the captured `direct_peer` keeps one source of truth.
                move |ep: String, expected_peer: [u8; 32]| async move {
                    // Dial the selected candidate (SSRF/same-subnet-guarded, #137/#276) and
                    // handshake as the direct-Noise INITIATOR. No dialable candidate → stay on relay.
                    let addr = match select_upgrade_candidate(&ep) {
                        Some(a) => a,
                        None => return None, // already logged as rejected above
                    };
                    let conn = match dial_peer_direct(addr, dial_timeout).await {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct dial to {addr} failed ({e:?}) — staying on relay");
                            return None;
                        }
                    };
                    let (s, r) = match conn.open_bi().await {
                        Ok(sr) => sr,
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct bi-stream open to {addr} failed ({e}) — staying on relay");
                            return None;
                        }
                    };
                    match establish_direct_session(s, r, true, &direct_priv, &expected_peer).await {
                        Ok(session) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise session established with {addr}, cutting over from relay");
                            Some(session)
                        }
                        Err(e) => {
                            eprintln!("ct-agent channel: #104 upgrade — direct Noise handshake with {addr} failed ({e}) — staying on relay");
                            None
                        }
                    }
                },
            )
            .await
            .map_err(Into::into)
        }
    }
}

/// Which relay-leg transport [`run_channel_join_with_admission`] falls back to when the
/// direct dial fails (#106 relay-leg-443). The direct-QUIC relay works for a member that
/// can still reach the relay port; a member on a truly `:443`-only network (relay port
/// FILTERED too) needs the relay itself walked over the fallback ladder — direct QUIC,
/// then the unified `:443` TLS-TCP front door — so it can relay at all. Selecting on this
/// keeps every existing QUIC caller unchanged while adding the ladder-capable relay leg.
pub enum RelayFallback<'a> {
    /// A pre-dialed QUIC relay connection (the original relay leg): present the join over
    /// it and run the session over a fresh bi-stream ([`join_via_relay`]).
    Quic(&'a Connection),
    /// A relay endpoint to dial **lazily** — only if the direct path fails and the relay
    /// fallback actually fires (#103 fix). The eager variant held an idle QUIC connection
    /// open through admission + the whole direct-dial/accept wait; the edge's accept loop
    /// reaped that idle connection as a spurious `closed by peer: 0` (a `[quic-bistream]`
    /// drop) before any join, masking the real outcome. Dialing on demand removes it.
    QuicLazy(std::net::SocketAddr),
    /// Walk the relay ladder (direct QUIC → the `:443` front door) via
    /// [`join_via_relay_ladder`]. `rungs` is [`ChannelJoinCliConfig::relay_ladder`];
    /// `edge_cert` is the trust anchor the front-door TLS dial needs; `direct_timeout`
    /// bounds each direct QUIC relay dial before it falls through to `:443`.
    Ladder {
        rungs: &'a [ChannelDialRung],
        edge_cert: CertificateDer<'static>,
        direct_timeout: std::time::Duration,
    },
}

/// Dispatch the relay fallback to the selected transport (#106 relay-leg-443): a
/// [`RelayFallback::Quic`] connection reuses the original [`join_via_relay`]; a
/// [`RelayFallback::Ladder`] walks the relay ladder via [`join_via_relay_ladder`]. This
/// is the single seam both fallback arms of [`run_channel_join_with_admission`] call, so
/// the outcome-driven data path stays identical regardless of the relay transport.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn join_via_relay_fallback<P>(
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    upgrade: Option<(Endpoint, String)>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    match relay {
        RelayFallback::Quic(conn) => {
            join_via_relay(conn, request, holder, role, own_noise_private, peer_noise_public, local, upgrade).await
        }
        RelayFallback::QuicLazy(addr) => {
            // #103 fix: dial the relay only now, when the fallback has actually fired —
            // no idle connection is held during admission/direct-dial for the edge to reap.
            let conn = crate::transport::build_channel_dialer()?
                .connect(addr, "localhost")?
                .await?;
            join_via_relay(&conn, request, holder, role, own_noise_private, peer_noise_public, local, upgrade).await
        }
        RelayFallback::Ladder { rungs, edge_cert, direct_timeout } => {
            join_via_relay_ladder(
                rungs,
                edge_cert,
                direct_timeout,
                request,
                holder,
                role,
                own_noise_private,
                peer_noise_public,
                local,
                upgrade,
            )
            .await
        }
    }
}

/// The relay-leg analog of [`present_channel_join_via_ladder`] (#106 relay-leg-443): walk
/// the relay `rungs`, and on the first rung whose **transport connects**, present the join
/// and run the Noise session over that rung — committing `local` to it. A rung whose
/// transport can't connect (a blocked direct relay port → [`ChannelDialError::Unreachable`],
/// or a `Failed` TLS/connect) falls through to the next; once a rung connects, the session
/// is the terminal action, so we never retry after it starts (`local` is single-move). A
/// **direct** rung dials QUIC to the relay port and delegates to [`join_via_relay`] (join +
/// session on a fresh bi-stream of the same connection). A **front-door** rung opens the
/// `:443` TLS-TCP route ([`crate::transport::tcp_tls_connect_channel`], ALPN
/// `ct-edge-channel`), presents the join *without* consuming the stream
/// ([`present_channel_relay_join_on_stream`]), and — on `Admitted` — runs the session over
/// that **same** relay-spliced stream ([`run_channel_session_on_stream`]); a `Refused` is a
/// finished handshake, not a transport failure, so it errors rather than falling through.
/// This is what lets a fully `:443`-only member (relay port also blocked) relay at all —
/// closing the exact gap the #103 sink reported. Errors only when every rung is blocked.
///
/// #25: this walks the same rung sequence as [`dial_ladder`] but cannot be composed over
/// it — `local` is single-move (committed to exactly one rung's session), while
/// `dial_ladder`'s per-rung closure must be re-callable for every rung. The hand-rolled
/// `last: Option<BoxError>` accumulator here is that constraint, not an oversight.
#[allow(clippy::too_many_arguments)]
pub async fn join_via_relay_ladder<P>(
    rungs: &[ChannelDialRung],
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    // #104: only the direct-QUIC rung can carry the in-band upgrade (it hands off a real
    // `&Connection` to `join_via_relay`); the `:443` front-door rung is a plain TLS-TCP
    // byte stream with no independent QUIC connection to open a second stream on, so it
    // stays a plain relay session regardless of this option.
    upgrade: Option<(Endpoint, String)>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // `local` is single-move: hold it in an Option and commit it to the first rung whose
    // transport connects. Fall through ONLY on a transport error, tracked in `last`.
    let mut local = Some(local);
    let mut last: Option<BoxError> = None;
    for rung in rungs {
        if rung.kind.is_front_door() {
            // The `:443` front door over TLS-TCP. The SAME stream carries the join AND the
            // spliced session, so present without consuming it. The boring rung differs
            // only in its ClientHello (ALPN h2 / SNI edge-cdn.invalid); the edge
            // routes both to the same handler, so the leg below is identical.
            let connect = match rung.kind {
                ChannelDialKind::FrontDoorBoring => {
                    crate::transport::tcp_tls_connect_channel_boring(rung.endpoint, edge_cert.clone()).await
                }
                _ => crate::transport::tcp_tls_connect_channel(rung.endpoint, edge_cert.clone()).await,
            };
            match connect {
                Ok(stream) => {
                    eprintln!(
                        "ct-agent channel: relay leg via the {} rung ({}) (#106)",
                        rung.kind.label(),
                        rung.endpoint
                    );
                    // #495 slice 2a (v0.4.14): mark this leg's PHASE when the edge speaks
                    // the KA generation -- phase-compatible pairing removes the mixed-phase
                    // early-eof class. An old edge negotiated a legacy id: no marker sent.
                    let phase_marker = crate::channel::phase_marker_for(&stream, crate::channel::PHASE_MARKER_RELAY);
                    let (mut recv, mut send) = tokio::io::split(stream);
                    let local = local.take().expect("local is committed to exactly one rung");
                    match present_channel_relay_join_on_stream(&mut send, &mut recv, request, holder, phase_marker).await? {
                        ChannelJoinOutcome::Admitted { .. } => {}
                        ChannelJoinOutcome::Refused { category } => {
                            // #524: base string frozen, category appended when present.
                            return Err(AdmissionRefused::boxed_with_category(
                                "edge relay refused the channel join over the :443 front door",
                                category.as_deref(),
                            ));
                        }
                        // #21: the relay park was reaped before a partner arrived -- return the
                        // typed error immediately (no further rungs: the rung WORKED, there was
                        // just nobody to pair with yet; re-dialing this same leg is the recovery).
                        ChannelJoinOutcome::ParkExpired => {
                            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"));
                        }
                    }
                    return run_channel_session_on_stream(
                        send,
                        recv,
                        role,
                        own_noise_private,
                        peer_noise_public,
                        local,
                    )
                    .await
                    .map_err(Into::into);
                }
                Err(e) => last = Some(e),
            }
        } else {
            // Direct: QUIC to the relay port. Unreachable/Failed falls through to :443.
            match dial_peer_direct(rung.endpoint, direct_timeout).await {
                Ok(conn) => {
                    eprintln!("ct-agent channel: relay leg via QUIC ({}) (#106)", rung.endpoint);
                    let local = local.take().expect("local is committed to exactly one rung");
                    return join_via_relay(
                        &conn, request, holder, role, own_noise_private, peer_noise_public, local, upgrade,
                    )
                    .await;
                }
                Err(ChannelDialError::Unreachable) => last = Some(ChannelDialError::Unreachable.into()),
                Err(ChannelDialError::Failed(e) | ChannelDialError::ConnectFailed(e)) => last = Some(e),
            }
        }
    }
    Err(last.unwrap_or_else(|| "relay ladder had no rungs to dial".into()))
}

/// How long the acceptor waits for a direct connection before falling back to the
/// edge relay in the plane-brokered CLI flow (#72 / #98 / #103).
pub(crate) const CHANNEL_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Config for the **plane-brokered** `ct-agent channel` flow (#98 / #103): present a
/// grant to the edge rendezvous, learn the peer via the broker (keys relayed — no
/// out-of-band `CT_CHANNEL_*` exchange), and connect direct-then-relay. Read from
/// `CT_CHANNEL_*` so it fits the `/channel.sh` one-liner. This is the cross-host path
/// (NAT traversal via the broker), distinct from the direct-address [`ChannelRunConfig`].
pub struct ChannelJoinCliConfig {
    pub role: ChannelRole,
    /// Edge rendezvous endpoint (`CT_CHANNEL_BROKER`, `CT_EDGE_CHANNEL_LISTEN` on the plane).
    pub broker_addr: SocketAddr,
    /// Edge relay endpoint used on direct-dial failure (`CT_CHANNEL_RELAY`).
    pub relay_addr: SocketAddr,
    /// The operator-signed channel grant this member holds (`CT_CHANNEL_GRANT`, hex).
    pub grant: ct_common::channel::SignedChannelGrant,
    /// The holder ed25519 private key that proves possession (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    pub holder: SigningKey,
    /// This member's Noise (X25519) private key (`CT_CHANNEL_NOISE_KEY`, hex). SECRET.
    pub own_noise_private: [u8; 32],
    /// The host:port this member **binds** its direct-path QUIC listener to
    /// (`CT_CHANNEL_LISTEN`). Inside a NAT/container this is typically `0.0.0.0:<port>`
    /// or a private bridge address — see `advertise_addr` for what a peer actually dials.
    pub listen_addr: SocketAddr,
    /// The host:port this member **advertises** to a peer for the direct path
    /// (`CT_CHANNEL_ADVERTISE`, optional — defaults to `listen_addr` when unset). Exists
    /// because a containerized/NAT'd accept-side member cannot bind the address the
    /// outside world reaches it on (e.g. a Docker port-published `<public-ip>:<port>`
    /// while the process itself binds `0.0.0.0:<port>`) — mirrors the same split
    /// `CT_AGENT_DIRECT_ADVERTISE` already provides for the Browser-Plane tunnel path.
    /// Relay-only auto-detection and the peer-facing admission `endpoint` both use THIS
    /// address, not `listen_addr` — what matters for dialability is what's advertised.
    pub advertise_addr: SocketAddr,
    /// Whether this member joins in **relay-only** mode (#121): forced by
    /// `CT_CHANNEL_RELAY_ONLY`, or auto-detected when `listen_addr` is not globally routable
    /// (a NAT-only host). A relay-only member skips binding the direct listener and advertises
    /// the relay-only sentinel, participating purely via the edge relay + the `:443` fallback.
    pub relay_only: bool,
    /// Optional unified `:443` front door (`CT_CHANNEL_FRONT_DOOR`, host:port) — the #106
    /// fallback for restrictive networks that block the channel broker/relay ports. When
    /// set, the dial ladder tries the direct broker/relay first, then this front door over
    /// TLS-TCP with the `ct-edge-channel` ALPN.
    pub front_door: Option<SocketAddr>,
    /// The edge's TLS certificate (DER) the `:443` front-door dial trusts
    /// (`CT_CHANNEL_FRONT_DOOR_CERT`, hex) — the trust anchor a front-door TLS-TCP dial
    /// needs (#106). Present ⇒ `run_channel_join_command` admits over the broker *ladder*
    /// (direct QUIC → the `:443` front door). Absent ⇒ direct-QUIC-only broker admission,
    /// even if `front_door` is set (a front door you have no root for is unusable).
    pub front_door_cert: Option<CertificateDer<'static>>,
    /// Optional libp2p **Circuit-Relay v2** multiaddr (`CT_CHANNEL_CIRCUIT_RELAY`, #136 N-wire).
    /// When set for a **relay-only** member, the join starts on the edge relay and then
    /// opportunistically hole-punches to a **direct** NAT-to-NAT link via DCUtR through this
    /// circuit relay ([`join_via_relay_dcutr`]). Absent ⇒ the plain edge-relay session (no punch).
    pub circuit_relay: Option<libp2p::Multiaddr>,
    /// The edge's `:443` **relay-gate** leg (`CT_CHANNEL_RELAY_GATE`, host:port) — the real
    /// gated Circuit-Relay v2 hole-punch this project ships (no new public port; grant +
    /// possession pre-auth before a byte reaches the relay-node, see `crates/edge/src/relay_gate.rs`
    /// on the edge side). When set for a **relay-only** member, takes priority over
    /// `circuit_relay` (a directly-dialable relay multiaddr, kept for the nat-lab test rig) —
    /// [`join_via_relay_gate_dcutr`] is used instead of [`join_via_relay_dcutr`].
    pub relay_gate_addr: Option<SocketAddr>,
    /// The trust anchor (DER) for the `:443` relay-gate TLS-TCP dial (`CT_CHANNEL_RELAY_GATE_CERT`,
    /// hex) — required alongside `relay_gate_addr`, same treatment as `front_door_cert`.
    pub relay_gate_cert: Option<CertificateDer<'static>>,
    /// **#104 in-band relay→direct upgrade**, opt-in (`CT_CHANNEL_DIRECT_UPGRADE=1`, default
    /// off — unset, nothing changes). When true and a relay-leg session forms (this member's
    /// own [`ChannelJoinOutcome::Admitted::observed_reflexive`] was learned during THIS
    /// admission), the session negotiates a direct-dial candidate **in-band, over the
    /// already-Noise_IK-authenticated relay stream itself** — never a new advertised/open
    /// port, never anything the broker relays — and opportunistically upgrades to it,
    /// falling back to the relay transparently on failure. This is the real payoff for two
    /// members on genuinely separate networks; on a single co-located host (e.g. this
    /// project's own demos) the observed-reflexive address is a private bridge IP, so the
    /// SSRF guard (`upgrade_safe_endpoint`) correctly refuses it and the session simply
    /// stays on the relay, exactly as it did before this option existed.
    pub direct_upgrade: bool,
    /// #276: this member's OWN genuinely direct edge relay address (`CT_CHANNEL_RELAY_DIRECT`,
    /// host:port), tried BEFORE `relay_addr` on the relay-gate DCUtR path — "always look for
    /// direct communication; relay is only the last line of defense," specifically for a
    /// member whose configured `CT_CHANNEL_RELAY` points at a same-network super-peer relay
    /// (`#276` piece 2) rather than the real edge. Absent (the common case) ⇒ unchanged
    /// behavior, dial `relay_addr` directly with no extra latency. Present ⇒ try this address
    /// first (bounded timeout), falling through to `relay_addr` only on failure — see
    /// [`dial_relay_preferring_direct`].
    pub relay_addr_direct: Option<SocketAddr>,
    /// #16 escape hatch, channel-path counterpart of `CT_AGENT_REGISTER_TCP_ONLY`:
    /// when true (`CT_CHANNEL_FRONT_DOOR_ONLY`), the broker/relay dial ladders skip
    /// the direct QUIC rung entirely and dial the `:443` front door exclusively —
    /// for deployments whose UDP path to the edge is known-flaky ("UDP flapping"),
    /// where a session admitted over QUIC dies with the next flap while the TLS-TCP
    /// front door stays up. Requires `front_door` + `front_door_cert` (refused at
    /// parse time otherwise — a front-door-only ladder with no front door would have
    /// zero rungs). Default `false`: ladder order unchanged.
    pub front_door_only: bool,
}

/// Parse the optional `CT_CHANNEL_CIRCUIT_RELAY` libp2p circuit-relay multiaddr (#136 N-wire):
/// absent/empty ⇒ `None` (no DCUtR upgrade — plain relay session); set-but-malformed ⇒ an error
/// (a typo shouldn't silently disable the hole-punch, mirroring the `:443` front-door handling).
/// Pure — the multiaddr is validated here so a bad value fails config load, not mid-session.
pub fn parse_circuit_relay(value: Option<String>) -> Result<Option<libp2p::Multiaddr>, String> {
    match value {
        Some(s) if !s.trim().is_empty() => s
            .trim()
            .parse::<libp2p::Multiaddr>()
            .map(Some)
            .map_err(|e| format!("CT_CHANNEL_CIRCUIT_RELAY invalid multiaddr: {e}")),
        _ => Ok(None),
    }
}

/// How one rung of the channel dial ladder reaches the edge (#106). Ordered from the most
/// direct transport to the least conspicuous one; see [`ChannelJoinCliConfig::ladder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDialKind {
    /// A direct QUIC dial to the channel port.
    Direct,
    /// The unified `:443` front door (TLS-TCP) advertising the `ct-edge-channel` ALPN, so a
    /// network that blocks the channel ports can still reach the broker/relay (the #31/#46
    /// pattern). Presents SNI `localhost`.
    FrontDoor,
    /// The same `:443` front door, dialed so that the ClientHello looks like ordinary
    /// HTTPS: ALPN `h2` under SNI `edge-cdn.invalid`
    /// ([`crate::transport::tcp_tls_connect_channel_boring`]). For networks whose DPI
    /// fingerprints the distinctive `ct-edge-channel` ALPN or the obviously-wrong
    /// `localhost` SNI and drops the connection before the join bytes reach the broker.
    FrontDoorBoring,
}

impl ChannelDialKind {
    /// Whether this rung goes over the `:443` front door (either ClientHello flavour)
    /// rather than a direct QUIC dial.
    pub fn is_front_door(self) -> bool {
        matches!(self, Self::FrontDoor | Self::FrontDoorBoring)
    }

    /// The operator-facing rung name used in the dial diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::FrontDoor => "front-door(:443)",
            Self::FrontDoorBoring => "front-door-boring-alpn(:443)",
        }
    }
}

/// One rung of the channel dial **fallback ladder** (#106): where + how to reach the edge
/// channel broker or relay. Tried in order; the first rung that connects wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelDialRung {
    /// The endpoint to dial.
    pub endpoint: SocketAddr,
    /// Which transport/ClientHello flavour to reach [`Self::endpoint`] with.
    pub kind: ChannelDialKind,
}

/// Decide whether this member joins in **relay-only** mode (#121): `explicit` (the
/// `CT_CHANNEL_RELAY_ONLY` flag) always forces it on; otherwise it auto-detects relay-only
/// when `listen_addr` is not a globally-routable (global-unicast) address — a NAT-only /
/// private-address-only host that the edge would refuse to advertise (#94) and that no peer
/// could dial. A relay-only member skips binding the direct listener and advertises the
/// [`ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY`] sentinel, participating purely via the
/// edge relay + the #106 `:443` fallback (outbound-only). Pure — it decides from the address
/// alone, so it is unit-testable without touching real network interfaces.
/// ct-agent#22: can this member plausibly be reached inbound on what it advertised?
///
/// The measured symptom was a **constant** ~11 s first contact (11017/10865/11177 ms across
/// three samples — a spread under 320 ms means a timer, not luck). The acceptor waits
/// `CHANNEL_ACCEPT_TIMEOUT` (8 s) for a direct connection that can never arrive, while the
/// initiator burns `DIRECT_DIAL_TIMEOUT` (5 s) dialing the same unreachable address; the two
/// run in parallel and the relay leg follows.
///
/// The existing auto-detection (`relay_only_mode`) catches an address that is *structurally*
/// undialable — private, loopback, CGNAT. It cannot catch a **public but firewalled** one,
/// which is exactly the reported shape: the advertised endpoint passes the edge's
/// global-unicast filter and still nothing can connect to it.
///
/// The missing fact is already in hand by then: the edge echoes each member's own observed
/// source address in the ack (`r=`). If the edge sees this member on a *different* global
/// address of the same family than it advertises, it is behind a NAT that is not
/// port-forwarding the advertised address, and waiting the full window buys nothing.
///
/// Deliberately silent (returns `true`, "keep waiting") in every case where the observation
/// says nothing:
/// * no `r=` in the ack (older edge) — no information;
/// * observed address not global (edge co-located / behind the same NAT) — meaningless to
///   compare, the same reasoning as CADS-Tunnel#546's `Unobservable`;
/// * different address family — ordinary dual-stack, not evidence of unreachability;
/// * advertised value unparseable or the relay-only sentinel — not this check's business.
///
/// Same IP with a different port is **corroborated**: that is what a port-forward looks like.
pub(crate) fn own_endpoint_looks_reachable(
    advertised: &str,
    observed: Option<std::net::SocketAddr>,
) -> bool {
    let Some(obs) = observed else { return true };
    if !ct_common::channel::is_global_unicast(obs) {
        return true;
    }
    let Ok(adv) = advertised.parse::<std::net::SocketAddr>() else {
        return true;
    };
    if adv.ip().is_ipv4() != obs.ip().is_ipv4() {
        return true;
    }
    adv.ip() == obs.ip()
}

pub fn relay_only_mode(explicit: bool, listen_addr: SocketAddr) -> bool {
    explicit || !is_globally_routable(listen_addr.ip())
}

/// Whether `ip` is a globally-routable (global-unicast) address — the mirror of the edge's
/// `safe_endpoint` range check (#94): loopback / unspecified / multicast, RFC1918 private,
/// link-local (`169.254/16`, `fe80::/10`), CGNAT (`100.64/10`) and IPv6 unique-local
/// (`fc00::/7`) are all NOT routable. A member with only such an address can't be dialed, so
/// it defaults to relay-only.
fn is_globally_routable(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                return false;
            }
            let o = v4.octets();
            !(o[0] == 100 && (64..=127).contains(&o[1])) // reject CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            (s0 & 0xfe00) != 0xfc00 && (s0 & 0xffc0) != 0xfe80 // reject fc00::/7 + fe80::/10
        }
    }
}

/// #137 SSRF guard for the #104 in-band relay→direct upgrade. The responder dials a
/// **peer-conveyed** `Offer.direct_endpoint`; because the upgrade is negotiated peer-to-peer over
/// the relay pump, that endpoint **never passed the edge broker's `safe_endpoint` admission gate**
/// (#94). Apply the IDENTICAL range filter here — the shared [`ct_common::channel::is_global_unicast`],
/// the exact primitive the edge's `safe_endpoint` is built on — so a malicious/compromised initiator
/// cannot make the responder dial an internal address: loopback, RFC1918/LAN, cloud metadata
/// `169.254.169.254`, link-local, CGNAT, IPv6 ULA, unspecified. Returns the parsed address ONLY if
/// it is safe to dial; `None` (unparseable **or** non-global-unicast) refuses the upgrade and the
/// session stays on the relay. This is an unconditional security guard — no test bypass.
pub(crate) fn upgrade_safe_endpoint(ep: &str) -> Option<SocketAddr> {
    ep.parse::<SocketAddr>()
        .ok()
        .filter(|addr| ct_common::channel::is_global_unicast(*addr))
}

/// Resolve an edge endpoint (`CT_CHANNEL_BROKER` / `CT_CHANNEL_RELAY`) that may be given as either a
/// literal `IP:port` **or** a `host:port` hostname (#214: the plane's rendezvous/relay is often handed
/// out as e.g. `bunsenbrenner.org:4433`). A literal address is taken as-is (no name lookup, so the
/// common case and the tests stay resolver-free); otherwise it is resolved via DNS and the first
/// address is used. A string with no port, or a name that resolves to nothing, is a clear error rather
/// than the previous opaque "invalid socket address syntax".
pub(crate) fn resolve_socket_addr(raw: &str) -> Result<SocketAddr, String> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Ok(sa);
    }
    use std::net::ToSocketAddrs;
    raw.to_socket_addrs()
        .map_err(|e| format!("{raw:?} is not an IP:port and did not resolve as host:port: {e}"))?
        .next()
        .ok_or_else(|| format!("{raw:?} resolved to no addresses"))
}

impl ChannelJoinCliConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// The ordered dial plan for the **rendezvous broker**: the direct port first, then
    /// (if `CT_CHANNEL_FRONT_DOOR` is configured) the `:443` front door — or the front
    /// door alone under `CT_CHANNEL_FRONT_DOOR_ONLY` (#16). Pure.
    pub fn broker_ladder(&self) -> Vec<ChannelDialRung> {
        Self::ladder(self.broker_addr, self.front_door, self.front_door_only)
    }

    /// The ordered dial plan for the **relay** (used on direct-dial failure): the direct
    /// port first, then (if configured) the `:443` front door — or the front door alone
    /// under `CT_CHANNEL_FRONT_DOOR_ONLY` (#16). Pure.
    pub fn relay_ladder(&self) -> Vec<ChannelDialRung> {
        Self::ladder(self.relay_addr, self.front_door, self.front_door_only)
    }

    /// Direct QUIC first, then — if a front door is configured — the two `:443` rungs, the
    /// established `ct-edge-channel` one before the DPI-resistant boring-ALPN one. That
    /// order is deliberate: the boring rung is strictly a last resort for networks that
    /// fingerprint the ClientHello (#106 boring-alpn, from a real 2026-08-12 support case),
    /// so on every network where the existing rungs work, nothing about the dial changes.
    /// Pure.
    pub(crate) fn ladder(
        direct: SocketAddr,
        front_door: Option<SocketAddr>,
        front_door_only: bool,
    ) -> Vec<ChannelDialRung> {
        // #16: `front_door_only` drops the direct QUIC rung — an operator pinning a
        // known-flaky-UDP deployment to the TLS-TCP front door outright. Guarded at
        // parse time to require a configured front door, so this can never yield an
        // empty ladder.
        let mut rungs = Vec::with_capacity(3);
        if !(front_door_only && front_door.is_some()) {
            rungs.push(ChannelDialRung { endpoint: direct, kind: ChannelDialKind::Direct });
        }
        if let Some(fd) = front_door {
            rungs.push(ChannelDialRung { endpoint: fd, kind: ChannelDialKind::FrontDoor });
            rungs.push(ChannelDialRung { endpoint: fd, kind: ChannelDialKind::FrontDoorBoring });
        }
        rungs
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = |k: &str, what: &str| -> Result<SocketAddr, String> {
            let raw = f(k).ok_or_else(|| format!("{k} required ({what})"))?;
            resolve_socket_addr(raw.trim()).map_err(|e| format!("{k} invalid ({what}): {e}"))
        };
        let broker_addr = addr("CT_CHANNEL_BROKER", "edge rendezvous host:port")?;
        let relay_addr = addr("CT_CHANNEL_RELAY", "edge relay host:port")?;
        // #121/#173: relay-only mode. `CT_CHANNEL_RELAY_ONLY` forces it on; otherwise it is
        // auto-detected below from the advertised listen address. Parsed BEFORE CT_CHANNEL_LISTEN
        // because a relay-only member has no dialable address, so CT_CHANNEL_LISTEN is OPTIONAL in
        // that mode — it's never bound or advertised (the relay-only sentinel stands in). #173: both
        // source-2 and sink independently hit the old unconditional hard-error and had to invent a
        // dummy value; a relay-only operator no longer has to.
        let relay_only_explicit = f("CT_CHANNEL_RELAY_ONLY")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        let listen_addr = match f("CT_CHANNEL_LISTEN") {
            Some(s) if !s.trim().is_empty() => s.trim().parse().map_err(|e| format!("CT_CHANNEL_LISTEN invalid: {e}"))?,
            // Relay-only has no dialable address → an unbound placeholder is never used.
            _ if relay_only_explicit => SocketAddr::from(([0, 0, 0, 0], 0)),
            _ => return Err("CT_CHANNEL_LISTEN required (advertised host:port) — or set CT_CHANNEL_RELAY_ONLY=1 for a relay-only member with no dialable address".to_string()),
        };
        // Optional: the address a peer actually dials, when it differs from what this
        // process binds (`listen_addr`) — e.g. a Docker port-published `<public-ip>:<port>`
        // while the container itself binds `0.0.0.0:<port>`. Absent ⇒ advertise_addr ==
        // listen_addr, unchanged from before this field existed. A set-but-malformed value
        // is an error, same treatment as every other CT_CHANNEL_* address.
        let advertise_addr = match f("CT_CHANNEL_ADVERTISE") {
            Some(s) if !s.trim().is_empty() => {
                resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_ADVERTISE invalid: {e}"))?
            }
            _ => listen_addr,
        };
        let grant_bytes = f("CT_CHANNEL_GRANT")
            .as_deref()
            .and_then(hex_bytes)
            .ok_or("CT_CHANNEL_GRANT required (hex signed grant)")?;
        let grant = ct_common::channel::SignedChannelGrant::decode(&grant_bytes)
            .map_err(|e| format!("CT_CHANNEL_GRANT malformed: {e}"))?;
        let holder = req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex")?;
        let own_noise_private = req_hex32(&f, "CT_CHANNEL_NOISE_KEY", "64 hex")?;
        // #106: optional :443 front-door fallback. Absent -> direct-only ladder; a set but
        // malformed value is an error (a typo shouldn't silently drop the fallback).
        let front_door = match f("CT_CHANNEL_FRONT_DOOR") {
            Some(s) if !s.trim().is_empty() => {
                Some(resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_FRONT_DOOR invalid: {e}"))?)
            }
            _ => None,
        };
        // #106: the trust anchor for the `:443` front-door TLS-TCP dial. Optional and
        // independent of `front_door` (a set-but-malformed value is an error — a typo
        // shouldn't silently drop the fallback); absent ⇒ direct-QUIC-only admission.
        let front_door_cert = match f("CT_CHANNEL_FRONT_DOOR_CERT") {
            Some(s) if !s.trim().is_empty() => {
                let raw = s.trim();
                let der = hex_bytes(raw).ok_or_else(|| {
                    format!(
                        "CT_CHANNEL_FRONT_DOOR_CERT must be hex DER -- got {} character(s), \
                         {}",
                        raw.len(),
                        if raw.len() % 2 != 0 { "an odd count (one nibble lost?)" } else { "with a non-hex character in it" }
                    )
                })?;
                // ct-agent#26: fail HERE, naming the damage, instead of letting a truncated
                // value become a generic TLS error minutes later on a different machine.
                der_certificate_shape(&der)
                    .map_err(|why| format!("invalid CT_CHANNEL_FRONT_DOOR_CERT: {why}"))?;
                Some(CertificateDer::from(der))
            }
            _ => None,
        };
        // Auto-detect relay-only when not forced: a non-globally-routable ADVERTISED address
        // (a NAT-only host the edge would refuse to advertise, #94) is treated as relay-only.
        // Uses advertise_addr, not listen_addr — a container legitimately binds a private/
        // unspecified address while advertising a real public one; what matters for
        // dialability is what's advertised, not what's bound.
        let relay_only = relay_only_mode(relay_only_explicit, advertise_addr);
        // #136 N-wire: optional libp2p circuit-relay multiaddr for the DCUtR NAT-to-NAT punch.
        let circuit_relay = parse_circuit_relay(f("CT_CHANNEL_CIRCUIT_RELAY"))?;
        // The real gated relay-gate leg: same optional/malformed-is-an-error treatment as
        // CT_CHANNEL_FRONT_DOOR/_CERT above.
        let relay_gate_addr = match f("CT_CHANNEL_RELAY_GATE") {
            Some(s) if !s.trim().is_empty() => {
                Some(resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_RELAY_GATE invalid: {e}"))?)
            }
            _ => None,
        };
        let relay_gate_cert = match f("CT_CHANNEL_RELAY_GATE_CERT") {
            Some(s) if !s.trim().is_empty() => Some(CertificateDer::from(
                hex_bytes(s.trim()).ok_or("CT_CHANNEL_RELAY_GATE_CERT must be hex DER")?,
            )),
            _ => None,
        };
        // #104 in-band relay->direct upgrade: opt-in, off by default (unset -> false,
        // identical truthy-string handling as CT_CHANNEL_RELAY_ONLY above).
        let direct_upgrade = f("CT_CHANNEL_DIRECT_UPGRADE")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        // #276: optional, same treatment as CT_CHANNEL_FRONT_DOOR above (a set-but-malformed
        // value is an error, not a silently-dropped preference).
        let relay_addr_direct = match f("CT_CHANNEL_RELAY_DIRECT") {
            Some(s) if !s.trim().is_empty() => {
                Some(resolve_socket_addr(s.trim()).map_err(|e| format!("CT_CHANNEL_RELAY_DIRECT invalid: {e}"))?)
            }
            _ => None,
        };
        // #16: front-door-only dialing (same truthy handling as CT_CHANNEL_RELAY_ONLY).
        // Requires a usable front door — refusing at parse time beats a zero-rung ladder
        // that would fail every join with an unhelpful "no rungs to dial".
        let front_door_only = f("CT_CHANNEL_FRONT_DOOR_ONLY")
            .map(|s| {
                let t = s.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        if front_door_only && (front_door.is_none() || front_door_cert.is_none()) {
            return Err(
                "CT_CHANNEL_FRONT_DOOR_ONLY requires CT_CHANNEL_FRONT_DOOR and CT_CHANNEL_FRONT_DOOR_CERT"
                    .to_string(),
            );
        }
        Ok(Self {
            role,
            broker_addr,
            relay_addr,
            grant,
            holder,
            own_noise_private,
            listen_addr,
            advertise_addr,
            relay_only,
            front_door,
            front_door_cert,
            circuit_relay,
            relay_gate_addr,
            relay_gate_cert,
            direct_upgrade,
            relay_addr_direct,
            front_door_only,
        })
    }
}

/// #276: dial the edge relay leg, preferring a genuinely direct connection over a configured
/// fallback (e.g. a same-network super-peer relay) whenever one is available and reachable —
/// "always look for direct communication; relay is only the last line of defense," per
/// explicit design guidance for the super-peer mechanism. Tries `direct` first, bounded by
/// `timeout` so an unreachable direct address can't stall the whole join indefinitely; on any
/// failure (connect error or timeout) falls through to `fallback`. When `direct` is `None` —
/// the common case, a member with no direct edge reachability of its own, which is PRECISELY
/// why it configured a super-peer fallback in the first place — dials `fallback` immediately
/// with no extra latency, unaffected by this preference.
pub(crate) async fn dial_relay_preferring_direct(
    direct: Option<SocketAddr>,
    fallback: SocketAddr,
    timeout: std::time::Duration,
) -> Result<Connection, BoxError> {
    if let Some(direct_addr) = direct {
        let attempt = async {
            crate::transport::build_channel_dialer()?.connect(direct_addr, "localhost")?.await.map_err(BoxError::from)
        };
        match tokio::time::timeout(timeout, attempt).await {
            Ok(Ok(conn)) => {
                eprintln!("ct-agent channel: dialed direct edge {direct_addr} (#276, preferred over the configured relay fallback)");
                return Ok(conn);
            }
            Ok(Err(e)) => {
                eprintln!("ct-agent channel: direct edge dial to {direct_addr} failed ({e}), falling back to {fallback} (#276)")
            }
            Err(_) => eprintln!(
                "ct-agent channel: direct edge dial to {direct_addr} timed out after {timeout:?}, falling back to {fallback} (#276)"
            ),
        }
    }
    crate::transport::build_channel_dialer()?.connect(fallback, "localhost")?.await.map_err(BoxError::from)
}

/// #248: what a relay-gate/circuit-relay DCUtR join loop should do after one attempt,
/// given whether it succeeded, whether this member is a persistent `--serve`, and the
/// one-shot retry budget already spent. Pure decision core, extracted from the two live
/// loops (relay-gate, circuit-relay) below so it's unit-testable without a real network.
///
/// Found live via bob-2's own crash-log capture: a persistent `--serve` member that
/// COMPLETES a session -- even one whose DCUtR upgrade attempt failed with
/// `AttemptsExceeded` and fell back to relay, which is still `Ok(())` ("hole-punch failure
/// stays on the relay" is this whole mechanism's own design) -- must loop back to admit the
/// NEXT peer, not stop. Before this fix both live loops only special-cased `Err` for
/// `serve_loop`; `Ok(())` fell through to an unconditional `return`, silently ending the
/// whole process after exactly one session. Reproduced 2/2 by bob-2's supervisor: always
/// exactly 3 DCUtR `OutgoingConnectionError`s (a genuine, correctly-handled hole-punch
/// failure), then a clean `exit(0)` with no error logged anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DcutrLoopAction {
    /// This peer's session is over (successfully or not) and this is a persistent serve
    /// member: sleep `delay`, reset the one-shot retry counter to 0, carry
    /// `consecutive_refusals` forward, and admit the next peer.
    RetryReset { delay: std::time::Duration, consecutive_refusals: u32 },
    /// An error, and a one-shot caller's own bounded retry budget still has room: sleep
    /// `delay`, bump the counter to `next_attempt`, and try again.
    RetryBounded { next_attempt: u32, delay: std::time::Duration },
    /// Stop the loop; return the original result to the caller (a one-shot caller out of
    /// retries or definitively refused, or a non-`serve_loop` result of either kind).
    Stop,
}

/// The fast inter-session cadence of the DCUtR loops (#248) — the delay after a
/// SUCCESSFUL session or a transient error; refusals and park expiries get the
/// policy delays from [`errors`] instead (#24).
pub(crate) const DCUTR_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);

/// #248: a one-shot Initiate (or non-serve Accept) on the relay-gate/circuit-relay
/// DCUtR path shouldn't fail on the very first #140 stall either -- live-reproduced
/// on the a2a-demo's plain "bob" scenario: the persistent --serve side eventually
/// gets past a stall by retrying forever, while the one-shot side had zero tolerance
/// and failed the whole call on one hiccup. Bounded (unlike `serve_loop`'s retry)
/// because a one-shot CLI/demo call must still terminate in reasonable time.
const ONE_SHOT_DCUTR_ADMISSION_RETRIES: u32 = 2;

/// #24: the DCUtR loops used to route on `result.is_ok()` alone, which threw the
/// error CLASS away — a serve member with a definitively refused grant hot-looped
/// at ~5 attempts/s against the edge forever, the exact flood #231 was filed
/// about. This now applies the same policy [`errors`] documents and
/// `serve_loop_concurrent` already follows: definitive refusals back off
/// exponentially (capped, [`admission_retry_backoff`]), park expiries re-park
/// immediately, transients and completed sessions keep the fast cadence. A
/// one-shot caller stops right away on a definitive refusal — its bounded
/// retries cannot succeed without operator action. Pure.
pub(crate) fn dcutr_loop_action<T>(
    result: &Result<T, BoxError>,
    serve_loop: bool,
    attempt: u32,
    max_one_shot_retries: u32,
    consecutive_refusals: u32,
) -> DcutrLoopAction {
    let (errored, refused, expired) = match result {
        Ok(_) => (false, false, false),
        Err(e) => (true, is_definitive_admission_refusal(e), is_park_expired(e)),
    };
    if serve_loop {
        let (delay, refusals) = if expired {
            (std::time::Duration::ZERO, 0) // #21: re-park immediately
        } else if refused {
            (admission_retry_backoff(DCUTR_RETRY_BACKOFF, true, consecutive_refusals), consecutive_refusals + 1)
        } else {
            // A completed session or a transient error: fast cadence, streak broken.
            let _ = errored;
            (DCUTR_RETRY_BACKOFF, 0)
        };
        return DcutrLoopAction::RetryReset { delay, consecutive_refusals: refusals };
    }
    if refused {
        return DcutrLoopAction::Stop; // definitive: retrying cannot succeed
    }
    if errored && attempt < max_one_shot_retries {
        let delay = if expired { std::time::Duration::ZERO } else { DCUTR_RETRY_BACKOFF };
        return DcutrLoopAction::RetryBounded { next_attempt: attempt + 1, delay };
    }
    DcutrLoopAction::Stop
}

/// #24: the shared DCUtR join loop both relay-only variants run — deduplicated
/// from two near-verbatim ~45-line copies whose diverged `label` printed
/// "relay-gate" in the circuit-relay branch. `join` performs ONE dial+admission
/// attempt; its **outer** `Err` is a dial/setup failure and stays terminal
/// (exactly the old `?`-propagation), while the **inner** `Result` is the
/// admission outcome and is routed through [`dcutr_loop_action`]'s policy.
pub(crate) async fn run_dcutr_join_loop<T, F, Fut>(label: &str, serve_loop: bool, join: F) -> Result<T, BoxError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Result<T, BoxError>, BoxError>>,
{
    let mut attempt: u32 = 0;
    let mut consecutive_refusals: u32 = 0;
    loop {
        let result = join().await?;
        match dcutr_loop_action(&result, serve_loop, attempt, ONE_SHOT_DCUTR_ADMISSION_RETRIES, consecutive_refusals) {
            DcutrLoopAction::RetryReset { delay, consecutive_refusals: refusals } => {
                if let Err(e) = &result {
                    eprintln!("ct-agent channel: {label} admission error, re-admitting in {delay:?} (#248/#24): {e}");
                }
                attempt = 0;
                consecutive_refusals = refusals;
                tokio::time::sleep(delay).await;
            }
            DcutrLoopAction::RetryBounded { next_attempt, delay } => {
                attempt = next_attempt;
                if let Err(e) = &result {
                    eprintln!(
                        "ct-agent channel: {label} admission error, retrying ({attempt}/{ONE_SHOT_DCUTR_ADMISSION_RETRIES}) (#248): {e}"
                    );
                }
                tokio::time::sleep(delay).await;
            }
            DcutrLoopAction::Stop => return result,
        }
    }
}

