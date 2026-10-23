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
//!
//! Schnitt 7 (Konsolidierungsprogramm, spaeter): `ChannelJoinCliConfig` selbst -- die
//! CLI-Konfigurationsstruktur samt Parsing/Dial-Leiter-Aufbau -- nach `join_config.rs`
//! herausgeloest, als eigene, von der eigentlichen Verbindungsaufbaulogik trennbare Naht.
//! `CHANNEL_ACCEPT_TIMEOUT` bleibt hier (auch von `serving.rs` genutzt, keine
//! Konfigurations-Angelegenheit im engeren Sinn).

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
    let (peer_noise, own_observed_reflexive, peer_holder) =
        match present_channel_join_marked(relay_conn, request, holder, PHASE_MARKER_RELAY).await? {
        ChannelJoinOutcome::Admitted {
            peer_noise_pubkey: Some(noise),
            peer_holder,
            peer_attestation,
            observed_reflexive,
            ..
        } => {
            // ct-agent#41 (#35 "Path A"): see verify_relayed_dcutr_peer's own doc comment.
            let (noise, peer_holder) = verify_relayed_dcutr_peer(request, noise, peer_holder, peer_attestation)?;
            (noise, observed_reflexive, peer_holder)
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
    let local = gate_local(local, request, role, peer_holder, holder)?;
    let (relay_send, relay_recv) = open_relay_channel_streams(relay_conn, role).await?;
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

    let (relay_send, relay_recv) = open_relay_channel_streams(relay_conn, role).await?;
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
/// `Clone` (ct-agent#295): the accept race keeps a copy for its one serial re-dial.
#[derive(Clone)]
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

impl RelayFallback<'_> {
    /// ct-agent#295: whether every leg this relay can produce goes over the `:443` front door
    /// (`CT_CHANNEL_FRONT_DOOR_ONLY`) -- the only transport on which the edge can see an
    /// abandoned park (when the leg negotiates keepalive), and the same rungs the serial order
    /// would walk, so racing it never moves the member into another pairer.
    pub(crate) fn is_front_door_only(&self) -> bool {
        match self {
            Self::Ladder { rungs, .. } => !rungs.is_empty() && rungs.iter().all(|r| r.kind.is_front_door()),
            Self::Quic(_) | Self::QuicLazy(_) => false,
        }
    }
}

/// Dispatch the relay fallback to the selected transport (#106 relay-leg-443). This is the
/// single seam every relay-leg caller goes through -- both fallback arms of
/// [`run_channel_join_with_admission`], and the public [`join_via_relay`] /
/// [`join_via_relay_ladder`] entry points, which are thin wrappers over it -- so the
/// outcome-driven data path stays identical regardless of the relay transport.
///
/// ct-agent#22 (b): the leg is two-phase underneath -- [`park_relay_leg`] (connect, present
/// the join, wait to be paired + spliced) then [`ParkedRelayLeg::run_session`] (the Noise
/// session) -- so the acceptor's accept-vs-relay race can decide on an *admitted* leg. This
/// serial wrapper is byte-for-byte the pre-split behaviour for every non-race caller.
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
    park_relay_leg(relay, request, holder)
        .await?
        .run_session(role, own_noise_private, peer_noise_public, local, upgrade)
        .await
}

/// ct-agent#22 (b) / #295: whether an acceptor with a bound direct listener RACES its accept
/// window against the relay leg instead of serialising them (`CT_CHANNEL_ACCEPT_RACE`).
///
/// The race is only safe where the edge can see an abandoned park: when the direct path wins,
/// the parked relay leg is closed, and only a keepalive-negotiated `:443` leg turns that close
/// into an immediate "dead" mark on the edge (`spawn_park_keepalive_pump`: KA EOF = death). A
/// non-KA `:443` EOF is a tolerated legacy half-close and a QUIC park is not monitored at all
/// -- such a leg stays pairable as a corpse until its TTL (#22 Nachtrag and Befund 2). The
/// `cl=1` ack tag the #22 plan waited for was never built on the edge, so the leg's own
/// negotiated ALPN is the signal instead (#22 option A).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptRaceMode {
    /// `0`/`false`/`no`/`off`: the serial accept-then-relay order, byte-for-byte.
    Off,
    /// Unset (the default since #295): race only where it is safe -- a relay ladder of `:443`
    /// rungs only, whose leg is presented at once only when it negotiated keepalive (a legacy
    /// leg is held unpresented until the accept window is decided, see [`RaceParkPolicy`]). A
    /// relay that starts on QUIC keeps the serial order: holding an idle QUIC relay connection
    /// is what #103 removed, and racing it would park where the edge cannot see abandonment. At
    /// most [`RACE_PARK_BUDGET`] sessions of a member race at once; the others stay serial.
    Auto,
    /// `1`/`true`/`yes`/`on`: the #22 opt-in as before -- race and park on every relay leg,
    /// QUIC and legacy `:443` included. Whenever a race runs (here, or [`Self::Auto`] where it
    /// races) its direct arm wins only on a verified peer ([`accept_verified_direct`]); the serial
    /// order still takes the first direct connection as it always did.
    On,
}

/// ct-agent#295 (review): what this switch was until #295 -- `false` the serial order, `true`
/// the #22 opt-in -- so a library caller of [`run_channel_join_with_admission`] that passes a
/// `bool` keeps compiling and keeps its behaviour.
impl From<bool> for AcceptRaceMode {
    fn from(race: bool) -> Self {
        if race {
            Self::On
        } else {
            Self::Off
        }
    }
}

impl AcceptRaceMode {
    /// The race this mode runs before falling back to `relay`, or `None` for the serial order.
    pub(crate) fn race_policy_for(self, relay: &RelayFallback<'_>) -> Option<RaceParkPolicy> {
        match self {
            Self::Off => None,
            Self::On => Some(RaceParkPolicy::AnyLeg),
            Self::Auto => relay.is_front_door_only().then_some(RaceParkPolicy::MonitoredOnly),
        }
    }

    /// What an acceptor with a bound listener does with `relay`, for its start-up log line.
    pub(crate) fn startup_note(self, relay: &RelayFallback<'_>) -> &'static str {
        match (self, self.race_policy_for(relay)) {
            (Self::Off, _) => "off (CT_CHANNEL_ACCEPT_RACE=0) -- the relay leg is dialed after the accept window",
            (_, Some(RaceParkPolicy::AnyLeg)) => {
                "on (CT_CHANNEL_ACCEPT_RACE=1) -- every relay leg parks during the accept window"
            }
            (_, Some(RaceParkPolicy::MonitoredOnly)) => {
                "adaptive -- a keepalive-monitored :443 relay leg parks during the accept window \
                 (CT_CHANNEL_ACCEPT_RACE=0 turns it off)"
            }
            // #295 (review): never suggest the switch for this member alone -- it also moves the
            // member's admission to the `:443` pairer, where a peer still on QUIC never meets it.
            (_, None) => {
                "adaptive, serial here -- the relay leg starts on QUIC, which the edge does not \
                 monitor (CT_CHANNEL_FRONT_DOOR_ONLY=1 on BOTH members of the channel makes it \
                 race; see \"Pairing reality\" in docs/channel.md)"
            }
        }
    }
}

/// `CT_CHANNEL_ACCEPT_RACE` (ct-agent#295): an on spelling selects [`AcceptRaceMode::On`], an
/// off spelling [`AcceptRaceMode::Off`], and unset, empty or unrecognised the adaptive
/// [`AcceptRaceMode::Auto`] -- a typo can therefore never race a leg the edge cannot police
/// (it is also reported once at start, see [`crate::envflag`]).
pub(crate) fn accept_race_mode_from(v: Option<&str>) -> AcceptRaceMode {
    match crate::envflag::tristate_named("CT_CHANNEL_ACCEPT_RACE", v, "adaptive") {
        Some(true) => AcceptRaceMode::On,
        Some(false) => AcceptRaceMode::Off,
        None => AcceptRaceMode::Auto,
    }
}

/// ct-agent#295: how many sessions of ONE member (channel + holder) may race at once in this
/// process under the adaptive default. A racing session keeps a relay park of that member
/// queued while it waits for its partner, and the edge supersedes a member's OLDEST park once
/// more than four are queued (`PARKS_PER_MEMBER`, CADS-Tunnel `channel_broker.rs`) -- the serve
/// loop's own rendezvous park counts too. Under a burst of first contacts (#200: five Builds at
/// once) unbounded racing would supersede the rendezvous park and the parks of other sessions,
/// whose partners would then be spliced FIFO to the wrong session. Two racing parks plus the
/// rendezvous park stay below the cap with room to spare; a session beyond the budget keeps
/// the serial order -- exactly the behaviour before #295.
pub(crate) const RACE_PARK_BUDGET: usize = 2;

/// A member as the edge's park cap counts it: (channel, holder).
type ParkMember = ([u8; 32], [u8; 32]);

/// The racing parks currently claimed per member in this process ([`RacingParkClaim`]).
static RACING_PARKS: std::sync::Mutex<Vec<(ParkMember, usize)>> = std::sync::Mutex::new(Vec::new());

/// ct-agent#295: one of a member's [`RACE_PARK_BUDGET`] racing parks, released on drop -- when
/// the race is decided and its park was consumed by the pairing or closed.
pub(crate) struct RacingParkClaim {
    member: ParkMember,
}

impl RacingParkClaim {
    /// A claim for the member `request` joins as, or `None` while its budget is in use.
    fn try_claim(request: &ChannelJoinRequest) -> Option<Self> {
        use ct_common::sync::MutexExt;
        let member = (request.grant.grant.channel.0, request.grant.grant.holder);
        let mut racing = RACING_PARKS.lock_safe();
        match racing.iter_mut().find(|(m, _)| *m == member) {
            Some((_, n)) if *n >= RACE_PARK_BUDGET => return None,
            Some((_, n)) => *n += 1,
            None => racing.push((member, 1)),
        }
        Some(Self { member })
    }
}

impl Drop for RacingParkClaim {
    fn drop(&mut self) {
        use ct_common::sync::MutexExt;
        let mut racing = RACING_PARKS.lock_safe();
        if let Some(i) = racing.iter().position(|(m, _)| *m == self.member) {
            racing[i].1 = racing[i].1.saturating_sub(1);
            if racing[i].1 == 0 {
                racing.swap_remove(i);
            }
        }
    }
}

/// ct-agent#295: the race one join runs, or `None` for the serial order --
/// [`AcceptRaceMode::race_policy_for`], and under the adaptive default only while the member's
/// [`RACE_PARK_BUDGET`] has room. `=1` stays unbudgeted, as the #22 opt-in always was.
pub(crate) fn accept_race_for(
    mode: AcceptRaceMode,
    relay: &RelayFallback<'_>,
    request: &ChannelJoinRequest,
) -> Option<(RaceParkPolicy, Option<RacingParkClaim>)> {
    let park = mode.race_policy_for(relay)?;
    if park == RaceParkPolicy::AnyLeg {
        return Some((park, None));
    }
    match RacingParkClaim::try_claim(request) {
        Some(claim) => Some((park, Some(claim))),
        None => {
            eprintln!(
                "ct-agent channel: accept-vs-relay race: {RACE_PARK_BUDGET} sessions of this member are already \
                 racing -- this one keeps the serial order (the edge queues at most 4 parks per member) (#295)"
            );
            None
        }
    }
}

/// ct-agent#295: when the race may PRESENT its relay leg, i.e. create a park on the edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RaceParkPolicy {
    /// [`AcceptRaceMode::On`]: present every leg at once (the #22 opt-in semantics).
    AnyLeg,
    /// [`AcceptRaceMode::Auto`]: present at once only a leg whose abandonment the edge sees (a
    /// keepalive-negotiated `:443` leg); hold any other leg connected but unpresented until the
    /// direct arm has given up -- the park itself then keeps the serial order, only the
    /// transport connect is saved -- and close it unpresented if the direct arm wins.
    MonitoredOnly,
}

/// ct-agent#22 (b): a relay leg that is **parked and admitted** -- the edge has paired this
/// member with its partner and spliced the leg -- on which the Noise session has NOT
/// started yet. [`park_relay_leg`] produces it, [`ParkedRelayLeg::run_session`] consumes it.
/// The split is what lets the acceptor race the park against its direct accept window: the
/// race decides on an admitted leg, never on a half-presented one, and the loser is closed
/// explicitly rather than merely dropped (the edge only detects an abandoned `:443` park
/// promptly on a clean close -- issue Nachtrag, `spawn_park_keepalive_pump`).
pub(crate) enum ParkedRelayLeg {
    /// A QUIC relay connection ([`RelayFallback::Quic`], [`RelayFallback::QuicLazy`], or the
    /// ladder's direct rung): the session runs over a fresh bi-stream of this connection.
    Quic(Connection),
    /// The `:443` front-door rung: the SAME TLS-TCP stream that carried the join carries the
    /// spliced session next, so its split halves travel with the leg.
    Stream {
        send: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
        recv: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    },
}

impl ParkedRelayLeg {
    /// Phase 2 of the relay leg: run the Noise session over the admitted, spliced transport.
    /// `upgrade` (#104) only applies to a QUIC leg -- the `:443` front-door rung is a plain
    /// byte stream with no independent QUIC connection to open a second stream on, so it
    /// stays a plain relay session regardless of the option (unchanged from #104).
    pub(crate) async fn run_session<P>(
        self,
        role: ChannelRole,
        own_noise_private: &[u8; 32],
        peer_noise_public: &[u8; 32],
        local: P,
        upgrade: Option<(Endpoint, String)>,
    ) -> Result<(), BoxError>
    where
        P: AsyncRead + AsyncWrite + Unpin,
    {
        match self {
            Self::Quic(conn) => match upgrade {
                Some((listener, own_direct_endpoint)) => {
                    run_channel_session_upgradable(
                        &conn,
                        role,
                        own_noise_private,
                        peer_noise_public,
                        local,
                        Some(listener),
                        Some(own_direct_endpoint),
                        DIRECT_DIAL_TIMEOUT,
                    )
                    .await
                }
                None => run_channel_session(&conn, role, own_noise_private, peer_noise_public, local)
                    .await
                    .map_err(Into::into),
            },
            Self::Stream { send, recv } => {
                run_channel_session_on_stream(send, recv, role, own_noise_private, peer_noise_public, local)
                    .await
                    .map_err(Into::into)
            }
        }
    }

    /// The race loser's EXPLICIT close (#22) for a leg that was already admitted when the
    /// direct path won (the same-instant tie): tell the edge now, not at the park TTL.
    pub(crate) async fn close(self) {
        match self {
            Self::Quic(conn) => close_quic_relay_leg(&conn),
            Self::Stream { mut send, .. } => close_stream_relay_leg(&mut send).await,
        }
    }
}

/// ct-agent#22 (b): the close reason the race loser sends on its QUIC relay leg -- visible in
/// the edge's connection-close log line, so a park that vanished can be told from a crash.
const RELAY_LEG_CLOSE_REASON: &[u8] = b"direct won (#22)";

/// ct-agent#22 (b): how long the race loser waits for its `:443` write half to shut down
/// (TLS close_notify + FIN) before giving up on the courtesy. Bounded so a stalled edge can
/// never delay the direct session that just won.
const RELAY_LEG_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Explicit QUIC close of an abandoned relay leg (#22): a CONNECTION_CLOSE the edge sees
/// immediately, instead of the idle-timeout it would otherwise wait out on a dropped handle.
fn close_quic_relay_leg(conn: &Connection) {
    conn.close(0u32.into(), RELAY_LEG_CLOSE_REASON);
}

/// Explicit `:443` close of an abandoned relay leg (#22): `shutdown()` sends the TLS
/// close_notify, which the edge's park pump reads as a clean `Ok(0)` -- on a KA-negotiated
/// leg that marks the park dead at once (issue Nachtrag). A bare drop would only FIN the
/// socket, which the pump cannot tell from a legacy half-close until its next 10 s tick.
async fn close_stream_relay_leg<W: AsyncWrite + Unpin>(send: &mut W) {
    use tokio::io::AsyncWriteExt;
    let _ = tokio::time::timeout(RELAY_LEG_CLOSE_TIMEOUT, send.shutdown()).await;
}

/// ct-agent#295 (review): how long a race loser whose abandon landed INSIDE its `:443` relay
/// leg's admission exchange keeps that exchange going to finish its possession proof
/// ([`finish_possession_proof`]) -- normally one edge round trip plus the edge's live membership
/// check. Bounded like [`RELAY_LEG_CLOSE_TIMEOUT`], so a stalled edge delays the direct session
/// that just won by at most this much on top of the close.
const RELAY_LEG_PROOF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// ct-agent#295 (review): the write half of a `:443` relay leg during its admission exchange,
/// counting the bytes the exchange has handed to it -- [`finish_possession_proof`] reads the
/// count to tell where an abandon landed.
pub(crate) struct ProofProgress<'a, W> {
    pub(crate) inner: &'a mut W,
    pub(crate) written: &'a std::sync::atomic::AtomicUsize,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ProofProgress<'_, W> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = std::pin::Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = polled {
            this.written.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }
        polled
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// ct-agent#295 (review): how many bytes a `:443` relay leg writes up to and including its
/// possession signature in `present_channel_relay_join_on_stream` -- the optional `[0xFF, phase]`
/// preamble, the 2-byte length, the join itself, the ed25519 signature over the edge's challenge.
pub(crate) fn possession_proof_len(request: &ChannelJoinRequest, phase_marker: Option<u8>) -> usize {
    phase_marker.map_or(0, |_| 2) + 2 + request.encode().len() + ed25519_dalek::SIGNATURE_LENGTH
}

/// ct-agent#295 (review): an abandon can land while the race's `:443` relay leg is INSIDE its
/// admission exchange -- join written, possession signature not yet. Closing there is what the
/// edge reads as a failed possession proof (`read_exact` of the signature hits EOF): it logs
/// `channel-join NO [possession]` for a legitimate member and returns a DEFINITIVE refusal, which
/// its `:443` listener charges to the member's address -- past `JOIN_REFUSALS_PER_MINUTE` it sheds
/// every join from that address (the member's own rendezvous re-admissions, every member behind
/// the same NAT) for the rest of the minute. The adaptive default makes a direct win in that
/// window ordinary: the keepalive leg presents at once, and the window is one edge round trip
/// plus the edge's live membership check. So the exchange is driven on until the signature is
/// written, bounded by [`RELAY_LEG_PROOF_TIMEOUT`]: the edge then holds a valid park, which the
/// caller's explicit close turns into a corpse at once on a keepalive leg (KA EOF = death),
/// never a refusal. An abandon before the first byte or after the signature needs nothing -- the
/// edge sees a plain I/O drop, or a parked leg closing.
async fn finish_possession_proof<F>(
    mut presenting: std::pin::Pin<&mut F>,
    written: &std::sync::atomic::AtomicUsize,
    proof_end: usize,
) where
    F: std::future::Future<Output = Result<ChannelJoinOutcome, BoxError>>,
{
    use std::sync::atomic::Ordering::Relaxed;
    let at = written.load(Relaxed);
    if at == 0 || at >= proof_end {
        return;
    }
    let mut admitted = false;
    let finished = std::future::poll_fn(|cx| match std::future::Future::poll(presenting.as_mut(), cx) {
        std::task::Poll::Ready(outcome) => {
            admitted = matches!(outcome, Ok(ChannelJoinOutcome::Admitted { .. }));
            std::task::Poll::Ready(())
        }
        std::task::Poll::Pending if written.load(Relaxed) >= proof_end => std::task::Poll::Ready(()),
        std::task::Poll::Pending => std::task::Poll::Pending,
    });
    match tokio::time::timeout(RELAY_LEG_PROOF_TIMEOUT, finished).await {
        Ok(()) if admitted => eprintln!(
            "ct-agent channel: accept-vs-relay race: relay leg was admitted while finishing its possession \
             proof -- closing it (#295)"
        ),
        Ok(()) => {}
        Err(_) => eprintln!(
            "ct-agent channel: accept-vs-relay race: relay leg could not finish its possession proof within \
             {RELAY_LEG_PROOF_TIMEOUT:?} -- closing it mid-admission (#295)"
        ),
    }
}

/// What [`park_relay_leg_until`] resolved to.
pub(crate) enum RelayLegPark {
    /// The edge paired and spliced this leg; the Noise session may start on it.
    Admitted(ParkedRelayLeg),
    /// The `abandon` future resolved first: the transport was closed explicitly (see
    /// [`close_quic_relay_leg`] / [`close_stream_relay_leg`]) and nothing further happens on it.
    Abandoned,
}

/// Phase 1 of the relay leg (ct-agent#22 (b)): connect the relay transport selected by
/// `relay`, present the join, and return only once the edge has paired this member and
/// spliced the leg (`Admitted`). A `Refused` / `ParkExpired` ack surfaces as the same typed
/// errors ([`AdmissionRefused`] / [`ParkExpired`]) the serial join always produced -- the
/// serve loops' backoff / re-park policy keys on them. The ladder rungs are walked exactly as
/// before (a rung whose transport cannot connect falls through; a finished handshake does not).
pub(crate) async fn park_relay_leg(
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
) -> Result<ParkedRelayLeg, BoxError> {
    match park_relay_leg_until(relay, request, holder, std::future::pending::<()>(), None::<std::future::Pending<()>>)
        .await?
    {
        RelayLegPark::Admitted(leg) => Ok(leg),
        // `pending()` never resolves, so this arm cannot be reached; typed rather than a
        // panic so a future caller passing a real signal here still gets an error, not a crash.
        RelayLegPark::Abandoned => Err("relay leg reported abandoned without an abandon signal (#22)".into()),
    }
}

/// [`park_relay_leg`] with an `abandon` future the race owner resolves when the direct path
/// won (ct-agent#22 (b)). The leg checks it at every await point: while its transport is
/// still connecting the dial is simply dropped; once the join is presented and the leg is
/// waiting for the edge's ack, the transport is closed EXPLICITLY before returning
/// [`RelayLegPark::Abandoned`]. Ownership of the transport never leaves this future, which is
/// why the close can be explicit at all -- a `select!` that merely dropped the future would
/// only ever get the implicit close (QUIC) or a bare FIN (`:443`), the exact thing the
/// issue's Nachtrag rules out.
///
/// `hold_unmonitored` (ct-agent#295, [`RaceParkPolicy::MonitoredOnly`]): when set, a leg whose
/// abandonment the edge cannot see -- QUIC, or a `:443` leg that negotiated no keepalive -- is
/// connected but NOT presented until that future resolves (the direct arm gave up); if
/// `abandon` comes first it is closed unpresented, so no park ever existed. A keepalive leg is
/// presented at once either way.
pub(crate) async fn park_relay_leg_until<A, H>(
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    abandon: A,
    hold_unmonitored: Option<H>,
) -> Result<RelayLegPark, BoxError>
where
    A: std::future::Future<Output = ()>,
    H: std::future::Future<Output = ()>,
{
    tokio::pin!(abandon);
    let mut hold = hold_unmonitored.map(Box::pin);
    match relay {
        RelayFallback::Quic(conn) => {
            park_relay_leg_on_quic(conn.clone(), request, holder, &mut abandon, &mut hold).await
        }
        RelayFallback::QuicLazy(addr) => {
            // #103 fix: dial the relay only now, when the fallback has actually fired —
            // no idle connection is held during admission/direct-dial for the edge to reap.
            let dial = async {
                crate::transport::build_channel_dialer()?.connect(addr, "localhost")?.await.map_err(BoxError::from)
            };
            let conn = tokio::select! {
                biased;
                _ = &mut abandon => return Ok(RelayLegPark::Abandoned),
                dialed = dial => dialed?,
            };
            park_relay_leg_on_quic(conn, request, holder, &mut abandon, &mut hold).await
        }
        RelayFallback::Ladder { rungs, edge_cert, direct_timeout } => {
            park_relay_leg_via_ladder(rungs, edge_cert, direct_timeout, request, holder, &mut abandon, &mut hold).await
        }
    }
}

/// ct-agent#295: whether a connected relay leg may be presented now. With no hold (or a leg the
/// edge monitors) at once; otherwise once the hold resolves (`true`), unless the race abandons
/// the leg first (`false` -- the caller closes it unpresented). Consumes the hold, so a later
/// rung or call never polls a finished future.
async fn released_for_presenting<A, H>(
    abandon: &mut A,
    hold: &mut Option<std::pin::Pin<Box<H>>>,
    monitored: bool,
    leg: &str,
) -> bool
where
    A: std::future::Future<Output = ()> + Unpin,
    H: std::future::Future<Output = ()>,
{
    if monitored {
        return true;
    }
    let Some(mut held) = hold.take() else { return true };
    eprintln!(
        "ct-agent channel: accept-vs-relay race: the {leg} relay leg is not keepalive-monitored by \
         the edge -- holding it unpresented until the direct accept window is decided (#295)"
    );
    tokio::select! {
        biased;
        _ = &mut *abandon => false,
        _ = held.as_mut() => true,
    }
}

/// Present the join over an already-connected QUIC relay connection and park until paired
/// (the QUIC half of [`park_relay_leg_until`]). The refusal / park-expiry wording is the
/// frozen pre-split text of [`join_via_relay`].
async fn park_relay_leg_on_quic<A, H>(
    conn: Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    abandon: &mut A,
    hold: &mut Option<std::pin::Pin<Box<H>>>,
) -> Result<RelayLegPark, BoxError>
where
    A: std::future::Future<Output = ()> + Unpin,
    H: std::future::Future<Output = ()>,
{
    // ct-agent#295: the edge does not monitor a QUIC park, so under a hold it is not presented
    // before the race allows it.
    if !released_for_presenting(abandon, hold, false, "QUIC").await {
        close_quic_relay_leg(&conn);
        return Ok(RelayLegPark::Abandoned);
    }
    // CADS-Tunnel#495 U2 (a'): relay_conn's own bi-stream carries the session below --
    // PHASE_MARKER_RELAY, mirroring the :443 relay ladder's phase_marker_for(&stream,
    // PHASE_MARKER_RELAY) call.
    // #295 (review): unlike the `:443` leg (`finish_possession_proof`), an abandon here can still
    // cut the possession proof -- the join stream lives inside ct-common's QUIC presenter, and a
    // CONNECTION_CLOSE discards stream data the edge has not read yet. Only `=1` races a QUIC leg.
    let outcome = tokio::select! {
        biased;
        _ = &mut *abandon => None,
        presented = present_channel_join_marked(&conn, request, holder, PHASE_MARKER_RELAY) => Some(presented),
    };
    let Some(outcome) = outcome else {
        close_quic_relay_leg(&conn);
        return Ok(RelayLegPark::Abandoned);
    };
    match outcome? {
        ChannelJoinOutcome::Admitted { .. } => Ok(RelayLegPark::Admitted(ParkedRelayLeg::Quic(conn))),
        ChannelJoinOutcome::Refused { category } => {
            // #524: base string frozen, category appended when present.
            Err(AdmissionRefused::boxed_with_category(
                "edge relay refused the channel join",
                category.as_deref(),
            ))
        }
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    }
}

/// Walk the relay `rungs` and park on the first whose transport connects (the ladder half of
/// [`park_relay_leg_until`]; the walk order, fall-through rule, log lines and frozen error
/// wording are those of the pre-split [`join_via_relay_ladder`], whose doc comment explains
/// them). Only the *transport* connect of a rung may fall through to the next; once a rung
/// connects, its admission outcome is terminal.
async fn park_relay_leg_via_ladder<A, H>(
    rungs: &[ChannelDialRung],
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    abandon: &mut A,
    hold: &mut Option<std::pin::Pin<Box<H>>>,
) -> Result<RelayLegPark, BoxError>
where
    A: std::future::Future<Output = ()> + Unpin,
    H: std::future::Future<Output = ()>,
{
    let mut last: Option<BoxError> = None;
    for rung in rungs {
        if rung.kind.is_front_door() {
            // The `:443` front door over TLS-TCP. The SAME stream carries the join AND the
            // spliced session, so present without consuming it. The boring rung differs
            // only in its ClientHello (ALPN h2 / SNI edge-cdn.invalid); the edge
            // routes both to the same handler, so the leg below is identical.
            let connect = async {
                match rung.kind {
                    ChannelDialKind::FrontDoorBoring => {
                        crate::transport::tcp_tls_connect_channel_boring(rung.endpoint, edge_cert.clone()).await
                    }
                    _ => crate::transport::tcp_tls_connect_channel(rung.endpoint, edge_cert.clone()).await,
                }
            };
            let connected = tokio::select! {
                biased;
                _ = &mut *abandon => return Ok(RelayLegPark::Abandoned),
                connected = connect => connected,
            };
            match connected {
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
                    // ct-agent#295: the same negotiation tells whether the edge would see this
                    // leg abandoned (KA: EOF = death); only such a leg may park during the race.
                    let monitored = crate::transport::ka_negotiated(&stream);
                    let (mut recv, mut send) = tokio::io::split(stream);
                    if !released_for_presenting(abandon, hold, monitored, "legacy :443").await {
                        close_stream_relay_leg(&mut send).await;
                        return Ok(RelayLegPark::Abandoned);
                    }
                    // #295 (review): counted, so an abandon that lands inside the admission
                    // exchange finishes the possession proof before the close below.
                    let written = std::sync::atomic::AtomicUsize::new(0);
                    let outcome = {
                        let mut counted = ProofProgress { inner: &mut send, written: &written };
                        let presenting =
                            present_channel_relay_join_on_stream(&mut counted, &mut recv, request, holder, phase_marker);
                        tokio::pin!(presenting);
                        let outcome = tokio::select! {
                            biased;
                            _ = &mut *abandon => None,
                            presented = &mut presenting => Some(presented),
                        };
                        if outcome.is_none() {
                            finish_possession_proof(presenting, &written, possession_proof_len(request, phase_marker))
                                .await;
                        }
                        outcome
                    };
                    let Some(outcome) = outcome else {
                        close_stream_relay_leg(&mut send).await;
                        return Ok(RelayLegPark::Abandoned);
                    };
                    return match outcome? {
                        ChannelJoinOutcome::Admitted { .. } => {
                            Ok(RelayLegPark::Admitted(ParkedRelayLeg::Stream { send, recv }))
                        }
                        ChannelJoinOutcome::Refused { category } => {
                            // #524: base string frozen, category appended when present.
                            Err(AdmissionRefused::boxed_with_category(
                                "edge relay refused the channel join over the :443 front door",
                                category.as_deref(),
                            ))
                        }
                        // #21: the relay park was reaped before a partner arrived -- return the
                        // typed error immediately (no further rungs: the rung WORKED, there was
                        // just nobody to pair with yet; re-dialing this same leg is the recovery).
                        ChannelJoinOutcome::ParkExpired => Err(ParkExpired::boxed(
                            "edge relay park expired with no partner within the park window (#21) -- re-park the relay leg",
                        )),
                    };
                }
                Err(e) => last = Some(e),
            }
        } else {
            // Direct: QUIC to the relay port. Unreachable/Failed falls through to :443.
            let dialed = tokio::select! {
                biased;
                _ = &mut *abandon => return Ok(RelayLegPark::Abandoned),
                dialed = dial_peer_direct(rung.endpoint, direct_timeout) => dialed,
            };
            match dialed {
                Ok(conn) => {
                    eprintln!("ct-agent channel: relay leg via QUIC ({}) (#106)", rung.endpoint);
                    return park_relay_leg_on_quic(conn, request, holder, abandon, hold).await;
                }
                Err(ChannelDialError::Unreachable) => last = Some(ChannelDialError::Unreachable.into()),
                Err(ChannelDialError::Failed(e) | ChannelDialError::ConnectFailed(e)) => last = Some(e),
            }
        }
    }
    Err(last.unwrap_or_else(|| "relay ladder had no rungs to dial".into()))
}

/// ct-agent#295: a direct connection whose Noise_IK handshake has completed AND verified the
/// attested peer key -- the only kind of direct connection that may win the accept race.
pub(crate) struct VerifiedDirect {
    /// Held for the session's lifetime, like the borrowed `conn` of [`run_channel_session`].
    conn: Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    session: snow::TransportState,
}

impl VerifiedDirect {
    /// The session on the verified connection: the pump and the #134 drain, no second handshake.
    async fn run_session<P>(self, peer_noise_public: &[u8; 32], local: P) -> Result<(), BoxError>
    where
        P: AsyncRead + AsyncWrite + Unpin,
    {
        let Self { conn, send, recv, session } = self;
        let ran = run_handshaken_quic_session(session, send, recv, peer_noise_public, local).await;
        drop(conn);
        ran.map_err(Into::into)
    }
}

/// ct-agent#295: the close reason a direct connection gets when it fails the race's peer check
/// -- visible to that dialer at once instead of after its idle timeout.
const DIRECT_PEER_CHECK_FAILED: &[u8] = b"peer check failed (#295)";

/// ct-agent#295: the race's direct arm. Accepts on the (possibly shared, #200) direct listener
/// until a connection VERIFIES as this session's attested peer: the QUIC handshake (bounded by
/// [`DIRECT_DIAL_TIMEOUT`], the dialer's own patience), the #139-bounded channel stream and the
/// #126-bounded Noise_IK handshake with `a2a_respond_verified`. A connection that fails any of
/// it -- another session's initiator, anyone else who reaches the listener over QUIC (it checks
/// no ALPN and no grant), a stalled handshake -- is closed and the arm accepts the next one, so it
/// can no longer make the race give up this session's relay leg.
/// `window` bounds when a connection may be ACCEPTED: none is taken after it, not even one that
/// queued while an earlier one was being verified. A connection accepted inside the window keeps
/// its own bounds (5 s QUIC, 15 s stream, 10 s Noise), so a partner is not cut off mid-handshake
/// and the arm ends at most one such verification after the window.
pub(crate) async fn accept_verified_direct(
    ep: &Endpoint,
    window: std::time::Duration,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
) -> Result<VerifiedDirect, BoxError> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        // #295 (review): the deadline is checked FIRST. `timeout_at(deadline, ep.accept())` polls
        // the accept before its timer and quinn hands out a queued `Incoming` at once, so after a
        // slow verification it kept accepting past the window -- a trickle of stalling strangers
        // kept the arm alive without bound, and a held relay leg aging behind it.
        let incoming = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                return Err(format!("no verified direct connection within {window:?}").into())
            }
            accepted = ep.accept() => match accepted {
                Some(incoming) => incoming,
                None => return Err("channel listener closed with no incoming".into()),
            },
        };
        let remote = incoming.remote_address();
        let conn = match tokio::time::timeout(DIRECT_DIAL_TIMEOUT, incoming).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                eprintln!(
                    "ct-agent channel: accept-vs-relay race: direct handshake from {remote} failed ({e}) \
                     -- still accepting (#295)"
                );
                continue;
            }
            Err(_) => {
                eprintln!(
                    "ct-agent channel: accept-vs-relay race: direct handshake from {remote} did not \
                     complete within {DIRECT_DIAL_TIMEOUT:?} -- still accepting (#295)"
                );
                continue;
            }
        };
        let verified = async {
            let (mut send, mut recv) = open_channel_streams(
                &conn,
                ChannelRole::Accept,
                ct_common::channel_quic::DIRECT_STREAM_SETUP_TIMEOUT,
            )
            .await?;
            let session =
                handshake_channel_session(&mut send, &mut recv, ChannelRole::Accept, own_noise_private, peer_noise_public)
                    .await?;
            Ok::<_, std::io::Error>((send, recv, session))
        };
        match verified.await {
            Ok((send, recv, session)) => return Ok(VerifiedDirect { conn, send, recv, session }),
            Err(e) => {
                eprintln!(
                    "ct-agent channel: accept-vs-relay race: direct connection from {remote} failed the \
                     attested-peer check ({e}) -- closed; the relay leg stays parked, still accepting (#295)"
                );
                conn.close(0u32.into(), DIRECT_PEER_CHECK_FAILED);
            }
        }
    }
}

#[cfg(test)]
tokio::task_local! {
    /// ct-agent#295 (measurement harness): where [`race_accept_against_relay`] reports its
    /// decision -- the winner and the `won after N ms` its log line prints -- inside a test's
    /// scope, so the harness tabulates the numbers instead of parsing stderr. Outside such a
    /// scope nothing is reported.
    pub(crate) static RACE_DECISIONS: std::sync::Arc<std::sync::Mutex<Vec<(&'static str, u128)>>>;
}

#[cfg(test)]
fn note_race_decision(winner: &'static str, ms: u128) {
    let _ = RACE_DECISIONS.try_with(|sink| {
        if let Ok(mut decisions) = sink.lock() {
            decisions.push((winner, ms));
        }
    });
}

/// ct-agent#22 (b) / #295: the acceptor's **accept-vs-relay** race, replacing the serial
/// accept-then-relay wait of the `ChannelRole::Accept` arm in
/// [`run_channel_join_with_admission`], which runs it as [`AcceptRaceMode`] says. Two futures
/// run side by side:
///
/// * **direct** = [`accept_verified_direct`]: accept, QUIC handshake, channel stream and the
///   Noise_IK handshake against the ATTESTED peer key, all before the arm may win. Until #295
///   the QUIC handshake alone decided, so on the shared `--serve` listener another session's
///   initiator (or anyone who reaches the listener over QUIC) won the race, made this session
///   give up its parked relay leg, and only then failed the Noise check (#22 Befund 3) -- while
///   this session's real partner waited on the relay for a leg that had just been closed. A
///   handshake that stalls or fails still never ends the session (#22 Befund 1); the arm keeps
///   accepting within the window.
/// * **relay** = [`park_relay_leg_until`]: connect, present, park until paired + spliced. Under
///   [`RaceParkPolicy::MonitoredOnly`] a leg the edge would not see abandoned is held
///   connected but unpresented until the direct arm has given up.
///
/// Whichever completes first wins. Direct won -> the relay leg is told to abandon and closes
/// its transport EXPLICITLY (QUIC CONNECTION_CLOSE / TLS close_notify) before the direct
/// session starts -- a `:443` leg caught inside its admission exchange first finishes its
/// possession proof (bounded, `finish_possession_proof`), which the edge would otherwise count
/// as a refusal; relay won -> the accept future is dropped and the session runs on the leg. Either path failing
/// keeps the other one awaited. A relay leg that fails without a typed refusal or park expiry
/// is dialed once more, at the earliest when the direct arm has given up -- the moment the
/// serial order dials it first (#295): a connect failure at the start of the window, or a held
/// leg the edge dropped while it waited, costs no more than it does serially. A definitive
/// refusal or a park expiry is returned as it is (the serve loops' backoff / re-park policy keys
/// on those typed errors).
///
/// Split-brain is impossible on this side alone (Befund 1): the initiator is serial -- it
/// parks on the relay only after its direct dial came back `Unreachable`, dropping the
/// `connecting` future -- so the peer we are paired with can never be on both transports.
/// When both futures are ready in the same poll, the VERIFIED direct connection is preferred
/// (`biased`, #295 review): it is proven to be this session's attested peer, whereas an
/// admitted relay leg is only the edge's first-in-first-out pick among the channel's waiting
/// initiators -- with concurrent serve sessions possibly another session's. Taking the relay
/// would close a verified peer and run Noise against a maybe-wrong one; taking the direct
/// closes the admitted leg like any other loser.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn race_accept_against_relay<P>(
    ep: Endpoint,
    accept_timeout: std::time::Duration,
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    upgrade: Option<(Endpoint, String)>,
    park: RaceParkPolicy,
    // #295: this race's share of the member's racing-park budget, released once decided.
    claim: Option<RacingParkClaim>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    enum Won {
        /// `relay_live`: whether the relay leg is still parked (to be told to close) or already
        /// failed on its own (a finished future must not be polled again).
        Direct { verified: VerifiedDirect, relay_live: bool },
        Relay(ParkedRelayLeg),
    }
    let started = std::time::Instant::now();
    let elapsed_ms = || started.elapsed().as_millis();
    // #295: kept for the one serial re-dial of a relay leg that failed early.
    let serial_relay = relay.clone();
    // Boxed (not `tokio::pin!`) so each loser can be dropped explicitly BEFORE the winner's
    // session starts -- a half-done `Incoming` held for a session's lifetime would stall
    // that dialer's handshake; a `pin!`ed future only drops at the end of this scope.
    let mut direct = Box::pin(accept_verified_direct(&ep, accept_timeout, own_noise_private, peer_noise_public));
    let (abandon_tx, abandon_rx) = tokio::sync::oneshot::channel::<()>();
    // #295: releases a held (unmonitored) leg for presenting. Only an explicit send releases it,
    // and the sender lives until the end of this function: a dropped sender must never present
    // a leg the race is about to abandon.
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let mut release_tx = Some(release_tx);
    let hold = match park {
        RaceParkPolicy::AnyLeg => None,
        RaceParkPolicy::MonitoredOnly => Some(async move {
            if release_rx.await.is_err() {
                std::future::pending::<()>().await;
            }
        }),
    };
    let mut relay_leg = Box::pin(park_relay_leg_until(
        relay,
        request,
        holder,
        async move {
            let _ = abandon_rx.await;
        },
        hold,
    ));
    let won = tokio::select! {
        biased;
        verified = &mut direct => match verified {
            Ok(verified) => Won::Direct { verified, relay_live: true },
            Err(direct_err) => {
                eprintln!(
                    "ct-agent channel: accept-vs-relay race: direct path gave up after {}ms ({direct_err}) -- \
                     the relay leg stays parked, awaiting it (#22)",
                    elapsed_ms()
                );
                // #295: a held leg presents now -- the park keeps the serial order, only its
                // transport connect was saved.
                if let Some(release) = release_tx.take() {
                    let _ = release.send(());
                }
                match relay_leg.as_mut().await {
                    Ok(RelayLegPark::Admitted(leg)) => Won::Relay(leg),
                    Ok(RelayLegPark::Abandoned) => {
                        return Err("relay leg abandoned before the race was decided (#22)".into())
                    }
                    // #295 (review): an untyped failure from here on -- above all a HELD leg the
                    // edge dropped while it sat connected but unpresented past the edge's join
                    // deadline -- would end the session where the serial order dials the relay
                    // only now. So dial it once more, as for an early failure below.
                    Err(relay_err) if !is_definitive_admission_refusal(&relay_err) && !is_park_expired(&relay_err) => {
                        eprintln!(
                            "ct-agent channel: accept-vs-relay race: relay leg failed after {}ms ({relay_err}) -- \
                             dialing it once more, as the serial order dials the relay only now (#295)",
                            elapsed_ms()
                        );
                        Won::Relay(park_relay_leg(serial_relay, request, holder).await?)
                    }
                    Err(relay_err) => return Err(relay_err),
                }
            }
        },
        parked = &mut relay_leg => match parked {
            Ok(RelayLegPark::Admitted(leg)) => Won::Relay(leg),
            Ok(RelayLegPark::Abandoned) => {
                return Err("relay leg abandoned before the race was decided (#22)".into())
            }
            Err(relay_err) => {
                eprintln!(
                    "ct-agent channel: accept-vs-relay race: relay leg failed after {}ms ({relay_err}) -- \
                     still waiting for a direct connection within the accept window (#22)",
                    elapsed_ms()
                );
                match direct.as_mut().await {
                    Ok(verified) => Won::Direct { verified, relay_live: false },
                    Err(direct_err) => {
                        if is_definitive_admission_refusal(&relay_err) || is_park_expired(&relay_err) {
                            eprintln!(
                                "ct-agent channel: accept-vs-relay race: direct path also gave up after {}ms \
                                 ({direct_err}) -- reporting the relay error (#22)",
                                elapsed_ms()
                            );
                            return Err(relay_err);
                        }
                        eprintln!(
                            "ct-agent channel: accept-vs-relay race: direct path also gave up after {}ms \
                             ({direct_err}) -- dialing the relay leg once more, where the serial order would \
                             have dialed it first (#295)",
                            elapsed_ms()
                        );
                        Won::Relay(park_relay_leg(serial_relay, request, holder).await?)
                    }
                }
            }
        },
    };
    match won {
        Won::Direct { verified, relay_live } => {
            // #295 (review): the moment the race was decided, before the loser's close -- which
            // may now include finishing a possession proof and must not inflate "won after".
            let ms = elapsed_ms();
            // Tell the parked leg to close itself explicitly and wait (bounded) for it to do so:
            // the transport lives inside that future, so this is the only place it can be
            // closed rather than dropped. A leg that was admitted in the same instant (the
            // same-instant tie, impossible for the partner we are paired with -- see above)
            // is closed the same way so the edge learns now, not at the park TTL. A held leg
            // was never presented: it closes without ever having been a park (#295). A leg the
            // abandon caught inside its admission exchange first finishes its possession proof
            // (`finish_possession_proof`, #295 review) -- hence the proof bound in this wait.
            if relay_live {
                let _ = abandon_tx.send(());
                let closing = RELAY_LEG_PROOF_TIMEOUT + RELAY_LEG_CLOSE_TIMEOUT * 2;
                match tokio::time::timeout(closing, relay_leg.as_mut()).await {
                    Ok(Ok(RelayLegPark::Admitted(leg))) => {
                        eprintln!("ct-agent channel: accept-vs-relay race: relay leg was admitted in the same instant -- closing it (#22)");
                        leg.close().await;
                    }
                    Ok(Ok(RelayLegPark::Abandoned)) | Ok(Err(_)) | Err(_) => {}
                }
            }
            drop(relay_leg);
            drop(release_tx);
            drop(claim); // the park is closed: it no longer counts against the member's cap
            #[cfg(test)]
            note_race_decision("direct", ms);
            eprintln!("ct-agent channel: accept-vs-relay race: direct won after {ms}ms -- relay leg closed (#22)");
            verified.run_session(peer_noise_public, local).await
        }
        Won::Relay(leg) => {
            // Drop the accept future now (not at scope end): an in-flight `Incoming` it may
            // hold would otherwise stall that dialer for this whole session.
            drop(direct);
            drop(claim); // the park was consumed by the pairing
            let ms = elapsed_ms();
            #[cfg(test)]
            note_race_decision("relay", ms);
            eprintln!("ct-agent channel: accept-vs-relay race: relay won after {ms}ms -- direct accept abandoned (#22)");
            leg.run_session(ChannelRole::Accept, own_noise_private, peer_noise_public, local, upgrade).await
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
/// `last: Option<BoxError>` accumulator (now in `park_relay_leg_via_ladder`, ct-agent#22 (b))
/// is that constraint, not an oversight.
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
    // ct-agent#22 (b): the walk itself lives in `park_relay_leg_via_ladder` (phase 1, shared
    // with the acceptor's accept-vs-relay race); `local` is committed only once a rung has
    // been admitted, which is the same single rung the pre-split walk committed it to.
    join_via_relay_fallback(
        RelayFallback::Ladder { rungs, edge_cert, direct_timeout },
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

/// How long the acceptor waits for a direct connection before falling back to the
/// edge relay in the plane-brokered CLI flow (#72 / #98 / #103).
pub(crate) const CHANNEL_ACCEPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

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

/// How many dial/setup failures in a row a persistent DCUtR serve member tolerates before it
/// ends with the error. With [`dial_failure_action`]'s backoff that is several minutes of an
/// unreachable edge -- far longer than an edge restart -- while a permanent misconfiguration
/// still surfaces instead of retrying silently forever.
pub(crate) const MAX_CONSECUTIVE_DCUTR_DIAL_FAILURES: u32 = 20;

/// The delay before the next dial after `consecutive` dial/setup failures in a row
/// (`consecutive >= 1`), or `None` once [`MAX_CONSECUTIVE_DCUTR_DIAL_FAILURES`] is reached.
/// Exponential from [`DCUTR_RETRY_BACKOFF`], capped like a definitive refusal: a failure that
/// happens at once must not dial at the fast inter-session cadence. Pure.
pub(crate) fn dial_failure_action(consecutive: u32) -> Option<std::time::Duration> {
    if consecutive >= MAX_CONSECUTIVE_DCUTR_DIAL_FAILURES {
        return None;
    }
    Some(admission_retry_backoff(DCUTR_RETRY_BACKOFF, true, consecutive.saturating_sub(1)))
}

/// #24: the shared DCUtR join loop both relay-only variants run — deduplicated
/// from two near-verbatim ~45-line copies whose diverged `label` printed
/// "relay-gate" in the circuit-relay branch. `join` performs ONE dial+admission
/// attempt; its **outer** `Err` is a dial/setup failure, terminal for a one-shot
/// join and retried with [`dial_failure_action`]'s bounded backoff in serve mode, while the
/// **inner** `Result` is the admission outcome, routed through [`dcutr_loop_action`].
pub(crate) async fn run_dcutr_join_loop<T, F, Fut>(label: &str, serve_loop: bool, join: F) -> Result<T, BoxError>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<Result<T, BoxError>, BoxError>>,
{
    let mut attempt: u32 = 0;
    let mut consecutive_refusals: u32 = 0;
    let mut consecutive_dial_failures: u32 = 0;
    loop {
        // In serve mode a dial/setup failure (an edge restart, a network blip) is retried with
        // its own exponential backoff instead of ending the persistent serve process -- but not
        // forever: a failure that never clears (a misconfigured relay address fails at once,
        // every time) ends the loop after MAX_CONSECUTIVE_DCUTR_DIAL_FAILURES so the operator
        // or a supervisor sees it. One-shot callers keep the old `?`.
        let result = match join().await {
            Ok(result) => {
                consecutive_dial_failures = 0;
                result
            }
            Err(e) if serve_loop => {
                consecutive_dial_failures = consecutive_dial_failures.saturating_add(1);
                match dial_failure_action(consecutive_dial_failures) {
                    Some(delay) => {
                        eprintln!(
                            "ct-agent channel: {label} dial failed ({consecutive_dial_failures}/\
                             {MAX_CONSECUTIVE_DCUTR_DIAL_FAILURES}), retrying in {delay:?}: {e}"
                        );
                        tokio::time::sleep(equal_jitter(delay, rand::random::<f64>())).await;
                        continue;
                    }
                    None => {
                        return Err(format!(
                            "{label}: giving up after {consecutive_dial_failures} consecutive dial failures: {e}"
                        )
                        .into())
                    }
                }
            }
            Err(e) => return Err(e),
        };
        match dcutr_loop_action(&result, serve_loop, attempt, ONE_SHOT_DCUTR_ADMISSION_RETRIES, consecutive_refusals) {
            DcutrLoopAction::RetryReset { delay, consecutive_refusals: refusals } => {
                if let Err(e) = &result {
                    eprintln!("ct-agent channel: {label} admission error, re-admitting in {delay:?} (#248/#24): {e}");
                }
                attempt = 0;
                consecutive_refusals = refusals;
                // #114-style jitter (see errors::equal_jitter): dcutr_loop_action stays pure/
                // deterministic for testability, so jitter is applied here at the sleep site
                // instead, same as the other four admission-layer backoff call sites.
                tokio::time::sleep(equal_jitter(delay, rand::random::<f64>())).await;
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

