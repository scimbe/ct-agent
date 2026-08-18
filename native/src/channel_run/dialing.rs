//! Direktwahl und Sprossen-Leiter fuer den Kanal-Beitritt.
//!
//! Herausgeloest aus `channel_run/mod.rs` (Konsolidierungsprogramm, Modulsplit Schnitt 3):
//! wie ein Mitglied einen Direktpfad-Kandidaten bildet, ihn auf Tauglichkeit prueft und die
//! Transport-Sprossen der Reihe nach durchgeht, bis eine traegt. Eine geschlossene
//! Zustaendigkeit -- Wahl und Waehlen eines Pfades -- ohne Sitzungs- oder Protokolllogik
//! darueber.
//!
//! Reiner Verschiebeschnitt: kein Verhalten geaendert. Sichtbarkeiten wurden nur so weit
//! geoeffnet, wie der Umzug es verlangt.

use super::*;

/// Bound on a direct A2A dial before giving up (#72 AF4-session-resilience). Kept
/// short so a peer that's unreachable on the direct path (NAT / firewall / down) fails
/// fast — the signal to fall back to the edge relay — instead of hanging on the QUIC
/// handshake's retransmits.
pub const DIRECT_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// #104: build this member's in-band relay->direct upgrade candidate from its own
/// edge-observed reflexive address (learned during THIS admission — the edge tells a
/// member its own address as part of `ChannelJoinOutcome::Admitted`, over the same
/// already-authenticated broker/relay connection, never a new open port). Binds a fresh
/// ephemeral direct listener (`0.0.0.0:0`) purely for this upgrade attempt — a listener
/// distinct from `CT_CHANNEL_LISTEN`'s, never advertised to the broker or to anyone but
/// this one already-Noise-verified peer. `None` when the edge reported no reflexive
/// address for this admission (e.g. the `:443` front-door leg doesn't observe one), the
/// reflexive address isn't global-unicast, or the listener fails to bind — the session
/// then simply stays on the relay, unaffected.
///
/// Found live (#248, 2026-08-01): a member co-located with the edge on the same Docker
/// host (e.g. a demo bridge container) has an edge-observed reflexive address on the
/// **Docker bridge network** (RFC1918, e.g. `172.18.0.19`) — real from the edge's point
/// of view, but meaningless to any genuinely external peer, who can never route to it.
/// Offering it anyway isn't just wasted effort: the peer's own SSRF guard
/// (`upgrade_safe_endpoint`, #137) correctly refuses to dial it, but in production this
/// consistently left the *initiator* blocked for the full outer session timeout rather
/// than falling back to the relay promptly (`drive_initiator_upgrade`'s reply wait is
/// documented as "the caller's concern" to bound and isn't bounded here) — turning an
/// always-doomed direct attempt into a full session failure instead of a same-second
/// relay fallback. The responder already validates the *peer's* offered endpoint this
/// way (#137); this applies the identical filter symmetrically to our OWN candidate
/// before ever offering it, so an unreachable candidate is never offered in the first
/// place and the initiator's own coordinator degrades to relay-only immediately (the
/// `_ => run_channel_session_on_stream(...)` arm in
/// [`run_channel_session_upgradable`](crate::channel_run::run_channel_session_upgradable))
/// — same as if the edge had reported no reflexive address at all. A same-Docker-network
/// peer (this demo's own baseline scenario, both sides on the same host) is unaffected
/// only in the sense that its reflexive address is *also* RFC1918 and would now also
/// skip the direct attempt — a strictly safe trade: that pairing was never a
/// representative test of real cross-network direct-P2P reachability anyway, and it
/// still relays correctly.
pub(crate) async fn build_upgrade_candidate(observed_reflexive: Option<SocketAddr>) -> Option<(Endpoint, String)> {
    let addr = observed_reflexive?;
    if !ct_common::channel::is_global_unicast(addr) {
        eprintln!(
            "ct-agent channel: #104 upgrade — our own edge-observed reflexive address {addr} is not \
             global-unicast (RFC1918/link-local/etc, #248) — skipping the direct-upgrade attempt, staying on relay"
        );
        return None;
    }
    let (listener, _cert) = crate::transport::build_direct_listener().ok()?;
    // #276 piece 1: also offer a LAN-local candidate, when this host has one -- the same
    // ephemeral port `listener` bound on 0.0.0.0 accepts on every interface, including the
    // local one, so pairing the offered local IP with that port is a real, dialable target.
    // Encoded as `reflexive\0local` (see `split_offered_candidates`) so `ct_common::upgrade`'s
    // wire format and generic signatures stay completely untouched -- this is purely how
    // ct-agent packs/unpacks the one `String` field `UpgradeMsg::Offer` already carries. The
    // offering side announces its own real local address truthfully, same as it already does
    // for its reflexive address; the RESPONDER is the one that must not trust it outright
    // (`select_upgrade_candidate`'s `same_local_subnet` gate).
    let endpoint = match (local_egress_ip(), listener.local_addr().ok()) {
        (Some(local_ip), Some(bound)) if is_lan_candidate(local_ip) => {
            format!("{addr}\0{}", SocketAddr::new(local_ip, bound.port()))
        }
        _ => addr.to_string(),
    };
    Some((listener, endpoint))
}

/// #276: whether `ip` is the kind of address worth offering as a LAN-local direct-upgrade
/// candidate at all (private RFC1918 or IPv6 ULA) -- loopback/link-local/multicast/global
/// addresses are never useful here (a global address already goes through the reflexive
/// candidate; loopback/link-local/multicast can never be a peer's real LAN address).
pub(crate) fn is_lan_candidate(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00, // unique-local fc00::/7
    }
}

/// Best-effort local (LAN-facing) IP: "connect" a UDP socket to an unrouted public address
/// (no packet is sent -- it only makes the OS pick the default-route source interface) and
/// read the socket's local address. `None` when there is no route. Mirrors the same trick
/// `CADS-Tunnel`'s `ct-client` crate already uses for its own local-egress classifier
/// (`ladder.rs::local_egress_ip`) -- deliberately no new dependency for interface
/// enumeration.
pub(crate) fn local_egress_ip() -> Option<std::net::IpAddr> {
    let sock = std::net::UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): never a real host, so nothing is contacted --
    // connect() only fixes the source interface via the routing table.
    sock.connect(("192.0.2.1", 9)).ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// #276: split a peer-offered direct-upgrade endpoint into its required reflexive
/// candidate and an optional LAN-local one, the counterpart to `build_upgrade_candidate`'s
/// `reflexive\0local` encoding. An empty or malformed local segment degrades to "no local
/// candidate" rather than a parse error -- the reflexive candidate alone is always a
/// complete, valid offer on its own (unchanged pre-#276 behavior).
pub(crate) fn split_offered_candidates(ep: &str) -> (&str, Option<&str>) {
    match ep.split_once('\0') {
        Some((reflexive, local)) if !local.is_empty() => (reflexive, Some(local)),
        Some((reflexive, _)) => (reflexive, None),
        None => (ep, None),
    }
}

/// #276: choose which of a peer-offered candidate pair to actually dial. Prefers the
/// LAN-local candidate — cheap, low-latency, and if it connects it's almost certainly the
/// same network — but ONLY after `same_local_subnet` confirms it against THIS host's own
/// local address; a malformed local candidate, a family mismatch, or a candidate outside
/// our own subnet all fall through to the existing `#137`-guarded reflexive candidate,
/// never to an ungated dial. This is the one seam both `dial_probe` and
/// `dial_and_establish` call, so "is this safe" and "what do we actually dial" can never
/// disagree.
pub(crate) fn select_upgrade_candidate(ep: &str) -> Option<SocketAddr> {
    let (reflexive, local) = split_offered_candidates(ep);
    if let Some(local) = local {
        if let Ok(candidate) = local.parse::<SocketAddr>() {
            if let Some(my_local) = local_egress_ip() {
                if ct_common::channel::same_local_subnet(my_local, candidate.ip()) {
                    return Some(candidate);
                }
            }
        }
    }
    upgrade_safe_endpoint(reflexive)
}

/// Why a direct dial to a paired peer did not connect (#72 AF4-session-resilience).
#[derive(Debug)]
pub enum ChannelDialError {
    /// The dial did not complete within the timeout — the peer is unreachable on the
    /// **direct** path. This is the signal to fall back to the edge relay, not an error
    /// to surface to the user.
    Unreachable,
    /// The dial failed for another reason (bad address, endpoint setup, connect error).
    Failed(BoxError),
}

impl std::fmt::Display for ChannelDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelDialError::Unreachable => write!(f, "peer unreachable on the direct path"),
            ChannelDialError::Failed(e) => write!(f, "direct dial failed: {e}"),
        }
    }
}

impl std::error::Error for ChannelDialError {}

/// Dial a paired peer's advertised endpoint directly over QUIC (accept-any transport —
/// Noise_IK is the real auth), bounded by `timeout`. A timeout is classified as
/// [`ChannelDialError::Unreachable`] rather than a generic error, so the caller can
/// distinguish "the direct path is blocked, fall back to the relay" from "the dial
/// itself is malformed" — the crux of the connection-difficulty handling.
pub async fn dial_peer_direct(
    addr: std::net::SocketAddr,
    timeout: std::time::Duration,
) -> Result<Connection, ChannelDialError> {
    let dialer = crate::transport::build_channel_dialer().map_err(ChannelDialError::Failed)?;
    let connecting = dialer
        .connect(addr, "localhost")
        .map_err(|e| ChannelDialError::Failed(Box::new(e)))?;
    match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(ChannelDialError::Failed(Box::new(e))),
        Err(_elapsed) => Err(ChannelDialError::Unreachable),
    }
}

/// Walk a channel dial **fallback ladder** (#106): try each rung in order and return
/// the first that connects. A rung that fails — `Unreachable` (a restrictive network
/// blocked the direct channel port) or `Failed` — falls through to the next, so a
/// blocked *direct* rung falls back to the `:443` front-door rung. Errors only when
/// **every** rung is blocked (all paths down). The per-rung transport connect is
/// injected as `dial`, so the ladder-walk is pure and unit-testable without sockets;
/// the caller supplies the real QUIC-direct / TLS-TCP-`:443` dials (the latter carries
/// the `ct-edge-channel` ALPN so the `:443` front door routes it to the broker).
pub async fn dial_ladder<C, D, Fut>(rungs: &[ChannelDialRung], dial: D) -> Result<C, ChannelDialError>
where
    D: Fn(&ChannelDialRung) -> Fut,
    Fut: std::future::Future<Output = Result<C, ChannelDialError>>,
{
    let mut last: Option<ChannelDialError> = None;
    for rung in rungs {
        match dial(rung).await {
            Ok(conn) => return Ok(conn),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or(ChannelDialError::Unreachable))
}

/// Present a channel join by walking the fallback `rungs` (#106 client-dial-443): for a
/// **direct** rung, dial the channel port over QUIC ([`dial_peer_direct`]) and run the
/// join on a fresh bi-stream ([`present_channel_join`]); for a **front-door** rung, open
/// the unified `:443` route over TLS-TCP ([`crate::transport::tcp_tls_connect_channel`],
/// ALPN `ct-edge-channel`) and run the identical join over the split TLS stream
/// ([`present_channel_join_on_stream`]). Composed over [`dial_ladder`], so the first rung
/// that is genuinely **`Admitted`** wins. A rung whose transport can't connect
/// (`Unreachable` on a blocked direct port, or a `Failed` TLS/connect) falls through to
/// the next, letting a network that blocks the direct channel port recover over `:443` —
/// and so does a rung whose join comes back **`Refused`** ([`reject_refused_outcome`]):
/// a network that corrupts or fingerprints the request differently per rung (exactly what
/// this ladder's `:443` legs exist to route around) can turn a garbled request into a
/// spurious `NO` on one rung while a cleaner rung would have been legitimately admitted,
/// so a single refusal must not end the walk (live-reported gap, ct-agent#15). Errors only
/// when every rung is blocked or refused — that final error still reports a genuine
/// refusal as one, just after every rung has actually been tried. `edge_cert` is the root
/// the front-door TLS dial trusts; `direct_timeout` bounds each direct QUIC dial (the
/// [`DIRECT_DIAL_TIMEOUT`] signal).
pub async fn present_channel_join_via_ladder(
    rungs: &[ChannelDialRung],
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    edge_cert: CertificateDer<'static>,
    direct_timeout: std::time::Duration,
) -> Result<ChannelJoinOutcome, BoxError> {
    dial_ladder(rungs, |rung: &ChannelDialRung| {
        let endpoint = rung.endpoint;
        let kind = rung.kind;
        let edge_cert = edge_cert.clone();
        async move {
            // Diagnosability (real support case, 2026-08-12): dial_ladder only keeps the
            // LAST rung's error, and ChannelDialError::Failed's Display hardcodes "direct
            // dial failed" regardless of which rung actually produced it -- an operator
            // debugging a blocked-direct-port case sees an identically-worded failure for
            // both the direct attempt AND a subsequent :443 front-door attempt, with no way
            // to tell from the log alone whether the fallback even ran. Name the rung being
            // tried and its outcome explicitly, independent of the generic error text.
            let rung_label = kind.label();
            eprintln!("ct-agent channel: dialing {rung_label} rung {endpoint}");
            let result = if kind.is_front_door() {
                // #106 fallback: the :443 front door over TLS-TCP. Both flavours run the
                // identical join on the resulting stream -- the edge dispatches the boring
                // ClientHello (ALPN h2 / SNI edge-cdn.invalid) to the same channel
                // broker as the ct-edge-channel ALPN, so only the dialer differs.
                async {
                    let stream = match kind {
                        ChannelDialKind::FrontDoorBoring => {
                            crate::transport::tcp_tls_connect_channel_boring(endpoint, edge_cert).await
                        }
                        _ => crate::transport::tcp_tls_connect_channel(endpoint, edge_cert).await,
                    }
                    .map_err(ChannelDialError::Failed)?;
                    // #495 slice 2a (v0.4.14): mark the RENDEZVOUS phase on KA-generation
                    // edges (see the relay ladder's twin comment for the why).
                    let phase_marker = crate::channel::phase_marker_for(&stream, crate::channel::PHASE_MARKER_RENDEZVOUS);
                    // #506: a KA-negotiated leg waits for its pairing on the TICK contract
                    // (the edge's 10 s NUL keepalives prove the park alive), so the park may
                    // outlive the fixed 45 s exchange bound once the edge runs a long TTL.
                    // Deliberately gated on the ALPN alone — the v0.4.17 marker switch must
                    // not disable liveness-based waiting.
                    let ka_tick_wait = crate::transport::ka_negotiated(&stream);
                    let (recv, send) = tokio::io::split(stream);
                    // finish_send_after_sig = false (#21 follow-up): on this TCP/TLS leg the
                    // old post-signature shutdown was a close_notify+FIN that half-closed the
                    // whole connection -- the parked member then waited out its park as a
                    // closing flow, and the edge's reap teardown RST'd the in-flight EX away
                    // (packet-capture-proven). The edge needs no EOF; keep the leg fully open.
                    present_channel_join_on_stream(send, recv, request, holder, ADMISSION_EXCHANGE_TIMEOUT, false, phase_marker, ka_tick_wait)
                        .await
                        .map_err(ChannelDialError::Failed)
                }
                .await
            } else {
                // Direct: QUIC to the channel port. Unreachable falls through to :443.
                async {
                    let conn = dial_peer_direct(endpoint, direct_timeout).await?;
                    present_channel_join(&conn, request, holder)
                        .await
                        .map_err(ChannelDialError::Failed)
                }
                .await
            };
            // #248-class gap (live-reported, 2026-08-13, ct-agent#15): `reject_refused_outcome`
            // already exists to turn a `Refused` outcome into an `Err` so it isn't mistaken for a
            // finished/successful step -- it's used in `admit_one_peer`, but wasn't wired into
            // THIS closure, so `dial_ladder` saw `Ok(ChannelJoinOutcome::Refused)` as "this rung
            // is done, stop" instead of "this rung's join was refused, try the next one." A
            // network that corrupts/truncates the request bytes differently per rung (the exact
            // DPI interference this ladder exists to route around) can turn a garbled request
            // into a spurious `NO` on one rung while a cleaner rung would have been legitimately
            // admitted -- so a `Refused` must fall through like any other per-rung failure, not
            // end the walk. If every rung is genuinely refused (e.g. a real not-member grant),
            // the ladder still reports that refusal -- just after actually trying every rung.
            let result = result.and_then(|outcome| match outcome {
                // #21: a park expiry is NOT a rung failure -- this rung worked end to end (the
                // join was admitted into a park; the edge answered), there was simply no partner
                // within the park TTL. It must STOP the walk as a successful outcome (the caller
                // converts it to the typed [`ParkExpired`] and re-parks on the same transport),
                // never fall through like `Refused` does -- the fall-through is exactly the
                // ladder-advance misclassification #21 was filed about.
                ChannelJoinOutcome::ParkExpired => Ok(ChannelJoinOutcome::ParkExpired),
                other => reject_refused_outcome(other).map_err(ChannelDialError::Failed),
            });
            match &result {
                Ok(_) => eprintln!("ct-agent channel: {rung_label} rung {endpoint} succeeded"),
                Err(e) => eprintln!("ct-agent channel: {rung_label} rung {endpoint} failed: {e}"),
            }
            result
        }
    })
    .await
    .map_err(Into::into)
}
