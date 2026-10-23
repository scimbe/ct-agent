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

/// #104/#296: what one relay-leg session needs for the in-band relay->direct upgrade: ONE
/// endpoint ([`crate::transport::build_channel_endpoint`]) that is the direct listener AND the
/// socket the offered address is learned through, plus where to ask (`CT_CHANNEL_REFLEXIVE_EDGE`,
/// else the relay leg's host on the edge's `'W'` port, see [`reflexive_query_addr`]).
///
/// #296: before, the offer was this admission's edge-observed `r=` and the listener a second,
/// fresh `0.0.0.0:0` socket. `r=` belongs to the admission dialer (closed by then, or a TCP
/// source port when admission ran over `:443`), so the offered port never matched the
/// listener -- not even for a host with a public address and no NAT.
pub struct DirectUpgrade {
    endpoint: Endpoint,
    /// `CT_CHANNEL_REFLEXIVE_EDGE` as read when the session started (unset/empty = the relay
    /// leg's host on port 4433, the same rule the relay-gate path uses).
    reflexive_edge: Option<String>,
}

/// #296: bound on the `'W'` query right before the Offer. The relay session runs meanwhile;
/// no answer only means there is nothing to offer.
pub(crate) const UPGRADE_REFLEXIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

impl DirectUpgrade {
    /// The direct listener: a cheap handle onto the shared socket.
    pub(crate) fn listener(&self) -> Endpoint {
        self.endpoint.clone()
    }

    /// #296: this endpoint's own reflexive address, asked THROUGH it at the edge's `'W'` echo
    /// next to `relay` (the relay leg's remote address). Unfiltered, so a loopback test can see
    /// it; [`Self::offer`] applies the global-unicast filter. `timeout` bounds the whole answer,
    /// the name lookup of a `host:port` override included.
    pub(crate) async fn own_reflexive(&self, relay: SocketAddr, timeout: std::time::Duration) -> Option<SocketAddr> {
        let started = tokio::time::Instant::now();
        let edge_w = match tokio::time::timeout(timeout, self.query_target(relay)).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                eprintln!("ct-agent channel: #104 upgrade — CT_CHANNEL_REFLEXIVE_EDGE unusable ({e}) — nothing to offer, staying on relay (#296)");
                return None;
            }
            Err(_) => {
                eprintln!(
                    "ct-agent channel: #104 upgrade — CT_CHANNEL_REFLEXIVE_EDGE did not resolve within {timeout:?} — nothing to offer, staying on relay (#296)"
                );
                return None;
            }
        };
        let found = whoami_via(&self.endpoint, edge_w, timeout.saturating_sub(started.elapsed())).await;
        if found.is_none() {
            eprintln!(
                "ct-agent channel: #104 upgrade — no 'W' answer from {edge_w} within {timeout:?} — nothing to offer, staying on relay (#296)"
            );
        }
        found
    }

    /// #296: where to ask. `CT_CHANNEL_REFLEXIVE_EDGE` as an `ip:port` is taken as it is; a
    /// `host:port` is looked up on tokio's blocking pool, not with std's lookup: this runs while
    /// the relay session pumps, in the same task, and a slow resolver would otherwise hold this
    /// worker thread and that pump for as long as it takes. Of the answers it takes one of the
    /// endpoint's own family -- the shared endpoint is bound on `0.0.0.0` and cannot send to an
    /// IPv6 address, and resolvers commonly list `::1`/AAAA first. Unset: the relay leg's host on
    /// the `'W'` port ([`reflexive_query_addr`], no lookup).
    async fn query_target(&self, relay: SocketAddr) -> Result<SocketAddr, String> {
        let raw = match self.reflexive_edge.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s,
            _ => return reflexive_query_addr(relay, None),
        };
        if let Ok(literal) = raw.parse::<SocketAddr>() {
            return Ok(literal);
        }
        let v4 = self.endpoint.local_addr().map(|a| a.is_ipv4()).unwrap_or(true);
        let found: Vec<SocketAddr> = tokio::net::lookup_host(raw)
            .await
            .map_err(|e| format!("{raw:?} is not an IP:port and did not resolve as host:port: {e}"))?
            .collect();
        found
            .iter()
            .find(|a| a.is_ipv4() == v4)
            .or_else(|| found.first())
            .copied()
            .ok_or_else(|| format!("{raw:?} resolved to no addresses"))
    }

    /// #296: the Offer: [`Self::own_reflexive`] as ONE `ip:port`, only when global-unicast
    /// (#248). One address, never the former `reflexive\0local` pair: the pinned ct-common
    /// responder (CADS-Tunnel#480) refuses an offer that does not parse as one global-unicast
    /// address, so any appended LAN half made the WHOLE offer fail for every initiator whose
    /// own egress address is private (that is, every NAT'd one).
    pub(crate) async fn offer(&self, relay: SocketAddr) -> Option<String> {
        let reflexive = self.own_reflexive(relay, UPGRADE_REFLEXIVE_TIMEOUT).await?;
        if !ct_common::channel::is_global_unicast(reflexive) {
            eprintln!(
                "ct-agent channel: #104 upgrade — own reflexive address {reflexive} is not global-unicast (#248) — nothing to offer, staying on relay"
            );
            return None;
        }
        Some(reflexive.to_string())
    }
}

/// #104: decide whether this member runs the in-band upgradable relay session at all, and if
/// so bind its shared direct endpoint (#296, [`DirectUpgrade`]). The decision is unchanged:
/// only a member the edge observed on a global-unicast address (this admission's `r=`) takes
/// part. That keeps both members of a pair on the same framing when one of them is an older
/// release -- the upgradable session's pump tags every frame, a plain session does not -- so
/// `r=` stays the gate, but it is no longer what gets offered: the offer is learned through
/// the endpoint itself right before it is sent ([`DirectUpgrade::offer`]). `None` when the
/// edge reported no reflexive address, it is not global-unicast, or the endpoint fails to
/// bind -- the session then simply stays on the relay, unaffected.
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
pub(crate) fn build_upgrade_candidate(
    observed_reflexive: Option<SocketAddr>,
    reflexive_edge: Option<String>,
) -> Option<DirectUpgrade> {
    let addr = observed_reflexive?;
    if !ct_common::channel::is_global_unicast(addr) {
        eprintln!(
            "ct-agent channel: #104 upgrade — our own edge-observed reflexive address {addr} is not \
             global-unicast (RFC1918/link-local/etc, #248) — skipping the direct-upgrade attempt, staying on relay"
        );
        return None;
    }
    let (endpoint, _cert) = crate::transport::build_channel_endpoint().ok()?;
    Some(DirectUpgrade { endpoint, reflexive_edge })
}

/// #276: whether `ip` is the kind of address worth offering as a LAN-local direct-upgrade
/// candidate at all (private RFC1918 or IPv6 ULA) -- loopback/link-local/multicast/global
/// addresses are never useful here (a global address already goes through the reflexive
/// candidate; loopback/link-local/multicast can never be a peer's real LAN address).
/// #296: no longer offered (see [`DirectUpgrade::offer`]); kept for the #276 selection tests.
#[cfg(test)]
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
/// #296: this release offers one address only, and the pinned ct-common responder refuses an
/// offer carrying a `\0` half before this ever runs (CADS-Tunnel#480), so in practice only
/// the plain, single-address form reaches here.
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
    /// The **front-door TLS-TCP `:443` connect step itself** failed (consolidation program,
    /// typed-errors-first pass, split out of the former single `Failed` variant): TCP
    /// connect, or the TLS handshake up to `connector.connect()` returning. Kept distinct
    /// from [`Self::Failed`] so [`crate::channel_run::errors::is_transport_handshake_eof`]
    /// can downcast to the boxed `std::io::Error` and check `kind()` structurally — a
    /// post-handshake admission-exchange EOF (a totally different failure with a totally
    /// different meaning) can surface with the SAME `io::ErrorKind::UnexpectedEof`, so the
    /// two phases must stay in different variants or that classifier could not tell them
    /// apart without also risking misreading a normal exchange failure as the CADS-Tunnel#335
    /// connection-cap-saturation signal.
    ConnectFailed(BoxError),
    /// The dial failed for another reason (bad address, endpoint setup, connect error, or
    /// the admission exchange itself after a successful connect).
    Failed(BoxError),
}

impl std::fmt::Display for ChannelDialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelDialError::Unreachable => write!(f, "peer unreachable on the direct path"),
            ChannelDialError::ConnectFailed(e) => write!(f, "front-door TLS connect failed: {e}"),
            ChannelDialError::Failed(e) => write!(f, "direct dial failed: {e}"),
        }
    }
}

impl std::error::Error for ChannelDialError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChannelDialError::Unreachable => None,
            ChannelDialError::ConnectFailed(e) | ChannelDialError::Failed(e) => Some(e.as_ref()),
        }
    }
}

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
                    .map_err(ChannelDialError::ConnectFailed)?;
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
                    // CADS-Tunnel#495 U2 (a'): this rung's twin :443 leg above marks
                    // PHASE_MARKER_RENDEZVOUS (admission-only, same as this direct-QUIC rung).
                    present_channel_join_marked(&conn, request, holder, PHASE_MARKER_RENDEZVOUS)
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
