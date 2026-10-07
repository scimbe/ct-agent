//! `ChannelJoinCliConfig`: die CLI-Konfiguration des plane-brokered `ct-agent channel`-Beitritts
//! (Umgebungsvariablen-Parsing, Dial-Leiter-Aufbau, verwandte reine Hilfsfunktionen).
//!
//! Herausgeloest aus `channel_run/connectivity.rs` (Konsolidierungsprogramm, Modulsplit
//! Schnitt 7): reiner Verschiebeschnitt, kein Verhalten geaendert -- trennt die
//! Konfigurations-Struktur (Parsen, Dial-Leiter, Erreichbarkeits-Heuristiken) von der
//! eigentlichen Verbindungsaufbau-/Rueckversuchslogik, die in `connectivity.rs` bleibt.
//! `CHANNEL_ACCEPT_TIMEOUT` bleibt bewusst in `connectivity.rs` (dort auch von `serving.rs`
//! ueber den `pub(crate) use`-Re-Export erreicht, keine Konfigurations-Angelegenheit).

use super::*;

/// Config for the **plane-brokered** `ct-agent channel` flow (#98 / #103): present a
/// grant to the edge rendezvous, learn the peer via the broker (keys relayed — no
/// out-of-band `CT_CHANNEL_*` exchange), and connect direct-then-relay. Read from
/// `CT_CHANNEL_*` so it fits the `/channel.sh` one-liner. This is the cross-host path
/// (NAT traversal via the broker), distinct from the direct-address [`ChannelRunConfig`].
pub struct ChannelJoinCliConfig {
    pub role: ChannelRole,
    /// Edge rendezvous endpoint (`CT_CHANNEL_BROKER`, `CT_EDGE_CHANNEL_LISTEN` on the plane).
    pub broker_addr: SocketAddr,
    /// The raw, trimmed `CT_CHANNEL_BROKER` value `broker_addr` was resolved from (a host:port
    /// name or an IP:port literal) -- kept alongside the resolved address so a later join
    /// attempt can re-resolve a hostname instead of being stuck with the address learned at
    /// startup. Not yet read outside `from_lookup` and the tests (AUF-20261006-061).
    pub broker_raw: String,
    /// Edge relay endpoint used on direct-dial failure (`CT_CHANNEL_RELAY`).
    pub relay_addr: SocketAddr,
    /// The raw, trimmed `CT_CHANNEL_RELAY` value `relay_addr` was resolved from -- same
    /// purpose as `broker_raw`.
    pub relay_raw: String,
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
    /// AUF-20261006-069: the raw (trimmed) `CT_CHANNEL_FRONT_DOOR` value, `None` when
    /// unset/empty -- what the background refresher re-resolves (see [`JoinRefresher`]).
    pub front_door_raw: Option<String>,
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
    /// ct-agent#22 (b), `CT_CHANNEL_ACCEPT_RACE` (opt-in, default off): an `Accept` member
    /// with a bound listener races its accept window against the relay leg instead of
    /// waiting the full `CHANNEL_ACCEPT_TIMEOUT` before it even dials the relay -- see
    /// `channel_run::race_accept_against_relay`. Off ⇒ today's serial order.
    pub accept_race: bool,
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
    /// ct-agent#47: whether a persistent `--call-service` session (`CT_CHANNEL_CALL_PERSISTENT`,
    /// on by default) reconnects internally when the underlying network session dies, instead of
    /// exiting non-zero and leaving the calling application to detect the dead process and
    /// respawn it externally (`CT_CHANNEL_CALL_RECONNECT`). Default **on** — only an explicit
    /// `0`/`false`/`no` restores the pre-#47 exit(1) contract — same "the safer behavior is the
    /// default, a typo can't silently disable it" convention as
    /// [`crate::channel_run::service_calls::call_persistent_enabled_from`]. Has no effect outside
    /// persistent CALL_SERVICE mode.
    pub call_reconnect: bool,
    /// The resolver `join_addr_for_attempt`/`join_addr_now` use to re-resolve `broker_raw`/
    /// `relay_raw` on a later join attempt -- `resolve_socket_addr` in `from_lookup`, a plain
    /// fn pointer (not a closure) so the field stays `Copy`-free but trivially constructible in
    /// tests. Not yet read outside the tests (AUF-20261006-061).
    pub join_resolve: fn(&str) -> Result<SocketAddr, String>,
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

// trace: REQ-0006, AUF-20261006-060 (DEC-0061)
/// How long [`join_addr_now`] waits for `resolve` on its blocking thread before falling back
/// to `last` -- same value as `RESOLVE_TIMEOUT` in `config.rs`.
const JOIN_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The address to dial on THIS join attempt (REQ-0006): a moved broker/relay is followed
/// without a restart, because `raw` (`broker_raw`/`relay_raw`) is re-resolved every time this
/// is called instead of once at startup. An IP:port literal is returned as-is -- `resolve` is
/// not called at all, so the common case and the tests stay resolver-free. Otherwise
/// `resolve(raw)` is tried: `Ok` wins; `Err` returns `last`, the caller's own last-good
/// address, so a resolver outage never takes a working broker/relay away. Pure: no state, no
/// process-wide memory (unlike `AgentConfig::resolve_edge_or` in `config.rs`, there is no
/// multi-caller "newest known address" to share here -- each ladder has exactly one caller).
#[allow(dead_code)] // bis AUF-20261006-061 (Teil B) ohne Aufrufer
pub(crate) fn join_addr_for_attempt(
    raw: &str,
    last: SocketAddr,
    resolve: impl Fn(&str) -> Result<SocketAddr, String>,
) -> SocketAddr {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return sa;
    }
    resolve(raw).unwrap_or(last)
}

/// Async wrapper around [`join_addr_for_attempt`] for a `fn`-pointer resolver such as
/// [`resolve_socket_addr`] (`ChannelJoinCliConfig::join_resolve`): an IP:port literal returns
/// immediately, no `spawn_blocking`. A hostname is resolved on a blocking thread --
/// `resolve_socket_addr` calls the blocking `ToSocketAddrs::to_socket_addrs`, and running that
/// on the async reactor would stall every other task on this runtime for the lookup's duration
/// -- under `JOIN_RESOLVE_TIMEOUT`. A timeout, a `JoinError` (the blocking task panicked) or an
/// `Err` from `resolve` all fall back to `last`, same as the sync version.
pub(crate) async fn join_addr_now(
    raw: &str,
    last: SocketAddr,
    resolve: impl FnOnce(&str) -> Result<SocketAddr, String> + Send + 'static,
) -> SocketAddr {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return sa;
    }
    let owned = raw.to_string();
    match tokio::time::timeout(
        JOIN_RESOLVE_TIMEOUT,
        tokio::task::spawn_blocking(move || resolve(&owned)),
    )
    .await
    {
        Ok(Ok(Ok(addr))) => addr,
        _ => last,
    }
}

// trace: REQ-0006, AUF-20261006-069 (DEC-0061)
/// The address last resolved for each raw `host:port` of the join ladders (broker, relay,
/// front door). Written only by [`join_addr_remember`], read by the data path through
/// [`join_addr_known`] -- which therefore never waits for DNS. Bounded by the number of
/// configured names (at most three).
static JOIN_LAST_GOOD: std::sync::Mutex<Vec<(String, SocketAddr)>> =
    std::sync::Mutex::new(Vec::new());

/// The names with a lookup under way on a blocking thread. A lookup that outlives
/// `JOIN_RESOLVE_TIMEOUT` (a hanging `getaddrinfo`) keeps its thread; without this list every
/// further round would add one more thread per name, and the process end waits for all of
/// them. At most one lookup per name.
static JOIN_IN_FLIGHT: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// The claim on one name in [`JOIN_IN_FLIGHT`]. It moves INTO the blocking closure, so the
/// name is released when the lookup thread ends (also on a panic, also when the closure is
/// dropped unrun) -- not when the waiting side gives up.
struct JoinInFlight(String);

impl JoinInFlight {
    fn claim(raw: &str) -> Option<Self> {
        use ct_common::sync::MutexExt;
        let mut flying = JOIN_IN_FLIGHT.lock_safe();
        if flying.iter().any(|h| h == raw) {
            return None;
        }
        flying.push(raw.to_string());
        Some(Self(raw.to_string()))
    }
}

impl Drop for JoinInFlight {
    fn drop(&mut self) {
        use ct_common::sync::MutexExt;
        JOIN_IN_FLIGHT.lock_safe().retain(|h| *h != self.0);
    }
}

/// How often the [`JoinRefresher`] re-resolves the join names when nothing asks for it.
pub(crate) const JOIN_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The pause after every refresh round: however often a failing serve loop asks
/// ([`JoinRefresher::kick`]), the resolver is asked at most once per this gap.
pub(crate) const JOIN_REFRESH_MIN_GAP: std::time::Duration = std::time::Duration::from_secs(1);

/// The address to dial NOW for `raw`, without resolving: an IP:port literal is itself; a name
/// is the address [`join_addr_refresh`] learned last, or `start` (resolved at process start)
/// while there is none. Never blocks and never awaits -- safe on the admission path.
pub(crate) fn join_addr_known(raw: &str, start: SocketAddr) -> SocketAddr {
    use ct_common::sync::MutexExt;
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return sa;
    }
    JOIN_LAST_GOOD
        .lock_safe()
        .iter()
        .find(|(h, _)| h == raw)
        .map_or(start, |(_, a)| *a)
}

/// Write `now` as the address of `raw` if it differs from the known one (`start` while none
/// is remembered), and log the change. Compare and write happen under ONE lock, so two
/// answers for the same name cannot interleave. The log line is written AFTER the lock is
/// released: [`join_addr_known`] takes the same lock on the admission path, and a blocking
/// stderr must not hold an admission.
fn join_addr_remember(raw: &str, start: SocketAddr, now: SocketAddr) {
    use ct_common::sync::MutexExt;
    let last = {
        let mut known = JOIN_LAST_GOOD.lock_safe();
        let last = known
            .iter()
            .find(|(h, _)| h == raw)
            .map_or(start, |(_, a)| *a);
        if now == last {
            return;
        }
        match known.iter_mut().find(|(h, _)| h == raw) {
            Some(entry) => entry.1 = now,
            None => known.push((raw.to_string(), now)),
        }
        last
    };
    eprintln!("ct-agent channel: join address of {raw} changed: {last} -> {now}");
}

/// Re-resolve `raw` once via [`join_addr_now`] (off the reactor) and return the address known
/// afterwards. The LOOKUP ITSELF remembers its answer ([`join_addr_remember`]), on its own
/// thread: an answer that comes after `JOIN_RESOLVE_TIMEOUT` is still used, it is not thrown
/// away with the wait. A failed lookup is logged and writes nothing; a lookup that is still
/// running when the wait ends is logged once here. While an earlier lookup of the same name is
/// still on its thread ([`JoinInFlight`]) nothing is started: the known address is returned
/// at once. No lock is held across the await.
pub(crate) async fn join_addr_refresh(
    raw: &str,
    start: SocketAddr,
    resolve: fn(&str) -> Result<SocketAddr, String>,
) -> SocketAddr {
    use ct_common::sync::MutexExt;
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return sa;
    }
    let last = join_addr_known(raw, start);
    let Some(flight) = JoinInFlight::claim(raw) else {
        return last;
    };
    join_addr_now(raw, last, move |r: &str| {
        let _flight = flight;
        let now = resolve(r).map_err(|e| {
            eprintln!("ct-agent channel: lookup of {r} failed: {e}");
            e
        })?;
        join_addr_remember(r, start, now);
        Ok(now)
    })
    .await;
    if JOIN_IN_FLIGHT.lock_safe().iter().any(|h| h == raw) {
        eprintln!(
            "ct-agent channel: lookup of {raw} still running after {JOIN_RESOLVE_TIMEOUT:?}: \
             its answer is used when it comes, the name is not asked again until then"
        );
    }
    join_addr_known(raw, start)
}

/// `start` with every endpoint replaced by its currently known address: a direct rung looks
/// up `direct_raw`, the front-door rungs `front_door_raw` (left alone when `None`). Number,
/// order and kind of the rungs are untouched. A lookup only -- see [`join_addr_known`].
pub(crate) fn ladder_known(
    start: &[ChannelDialRung],
    direct_raw: &str,
    front_door_raw: Option<&str>,
) -> Vec<ChannelDialRung> {
    start
        .iter()
        .map(|rung| {
            let raw = if rung.kind.is_front_door() {
                front_door_raw
            } else {
                Some(direct_raw)
            };
            ChannelDialRung {
                endpoint: raw.map_or(rung.endpoint, |r| join_addr_known(r, rung.endpoint)),
                kind: rung.kind,
            }
        })
        .collect()
}

/// The `(raw name, start address)` pairs behind the rungs of `start` -- only for rungs that
/// are IN the ladder (no direct name under `CT_CHANNEL_FRONT_DOOR_ONLY`), each name once.
pub(crate) fn ladder_names(
    start: &[ChannelDialRung],
    direct_raw: &str,
    front_door_raw: Option<&str>,
) -> Vec<(String, SocketAddr)> {
    let mut names: Vec<(String, SocketAddr)> = Vec::new();
    for rung in start {
        let raw = if rung.kind.is_front_door() {
            front_door_raw
        } else {
            Some(direct_raw)
        };
        if let Some(raw) = raw {
            if !names.iter().any(|(n, _)| n == raw) {
                names.push((raw.to_string(), rung.endpoint));
            }
        }
    }
    names
}

/// The ONE background task that keeps [`JOIN_LAST_GOOD`] fresh for a serve member: every
/// `JOIN_REFRESH_INTERVAL`, or earlier when [`Self::kick`] reports a failed join, it
/// re-resolves each name once, then pauses `JOIN_REFRESH_MIN_GAP`. The task ends with this
/// value ([`crate::task_guard::TaskGuard`]).
pub(crate) struct JoinRefresher {
    kick: std::sync::Arc<tokio::sync::Notify>,
    _task: crate::task_guard::TaskGuard<()>,
}

impl JoinRefresher {
    /// `None` when there is nothing to refresh (every name is an IP:port literal): no task.
    pub(crate) fn spawn(
        names: Vec<(String, SocketAddr)>,
        resolve: fn(&str) -> Result<SocketAddr, String>,
    ) -> Option<Self> {
        let mut todo: Vec<(String, SocketAddr)> = Vec::new();
        for (raw, start) in names {
            if raw.parse::<SocketAddr>().is_err() && !todo.iter().any(|(n, _)| *n == raw) {
                todo.push((raw, start));
            }
        }
        if todo.is_empty() {
            return None;
        }
        let kick = std::sync::Arc::new(tokio::sync::Notify::new());
        let asked = kick.clone();
        let task = crate::task_guard::TaskGuard::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(JOIN_REFRESH_INTERVAL) => {}
                    _ = asked.notified() => {}
                }
                for (raw, start) in &todo {
                    join_addr_refresh(raw, *start, resolve).await;
                }
                tokio::time::sleep(JOIN_REFRESH_MIN_GAP).await;
            }
        });
        Some(Self { kick, _task: task })
    }

    /// Ask for a refresh round now (a join just failed). Never blocks; a kick during a
    /// running round is kept for exactly one more round.
    pub(crate) fn kick(&self) {
        self.kick.notify_one();
    }
}

impl Drop for JoinRefresher {
    fn drop(&mut self) {
        eprintln!("ct-agent channel: join address refresher ended (its serve member is gone)");
    }
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
        // AUF-20261006-060: kept alongside the resolved addresses above so a later join
        // attempt can re-resolve a hostname instead of being stuck with the startup address
        // (REQ-0006) -- not yet read outside the tests (AUF-20261006-061 wires it in).
        let raw = |k: &str| f(k).unwrap_or_default().trim().to_string();
        let broker_raw = raw("CT_CHANNEL_BROKER");
        let relay_raw = raw("CT_CHANNEL_RELAY");
        let front_door_raw = Some(raw("CT_CHANNEL_FRONT_DOOR")).filter(|s| !s.is_empty());
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
            Some(s) if !s.trim().is_empty() => {
                let raw = s.trim();
                let der = hex_bytes(raw).ok_or_else(|| {
                    format!(
                        "CT_CHANNEL_RELAY_GATE_CERT must be hex DER -- got {} character(s), \
                         {}",
                        raw.len(),
                        if raw.len() % 2 != 0 { "an odd count (one nibble lost?)" } else { "with a non-hex character in it" }
                    )
                })?;
                // ct-agent#26: same structural check as CT_CHANNEL_FRONT_DOOR_CERT above --
                // this field's own doc comment already promises "same treatment", but until
                // now only the front-door cert got it, leaving a hand-copied relay-gate cert
                // to fail as an opaque TLS error later instead of a named one here.
                der_certificate_shape(&der)
                    .map_err(|why| format!("invalid CT_CHANNEL_RELAY_GATE_CERT: {why}"))?;
                Some(CertificateDer::from(der))
            }
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
        // ct-agent#22 (b): opt-in accept-vs-relay race, off by default (pure helper, same
        // truthy handling as CT_CHANNEL_DIRECT_UPGRADE above).
        let accept_race = accept_race_enabled_from(f("CT_CHANNEL_ACCEPT_RACE").as_deref());
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
        // ct-agent#47: default ON, same truthy-opt-out idiom as
        // service_calls::call_persistent_enabled_from (only an explicit off value disables --
        // a typo can never silently reintroduce the exit(1)-on-death contract).
        let call_reconnect = crate::envflag::flag_named("CT_CHANNEL_CALL_RECONNECT", f("CT_CHANNEL_CALL_RECONNECT").as_deref(), true);
        Ok(Self {
            role,
            broker_addr,
            broker_raw,
            relay_addr,
            relay_raw,
            grant,
            holder,
            own_noise_private,
            listen_addr,
            advertise_addr,
            relay_only,
            front_door,
            front_door_raw,
            front_door_cert,
            circuit_relay,
            relay_gate_addr,
            relay_gate_cert,
            direct_upgrade,
            accept_race,
            relay_addr_direct,
            front_door_only,
            call_reconnect,
            join_resolve: resolve_socket_addr,
        })
    }
}
