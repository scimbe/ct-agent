//! Agent daemon configuration (M5.2a).
//!
//! Parsed from environment variables so the Agent runs as a configurable
//! container node in the Docker testbed.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// Transport protocol of the local Origin the Agent bridges to (M10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OriginProto {
    /// A TCP Origin — full-duplex byte stream (default).
    #[default]
    Tcp,
    /// A UDP Origin — datagram-preserving bridge.
    Udp,
}

impl OriginProto {
    pub fn parse(s: &str) -> Result<OriginProto, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(OriginProto::Tcp),
            "udp" => Ok(OriginProto::Udp),
            other => Err(format!("invalid CT_AGENT_ORIGIN_PROTO '{other}' (expected tcp|udp)")),
        }
    }
}

/// `CT_AGENT_ORIGIN_TLS`: whether the Agent terminates TLS for a raw-forwarded (Browser-Plane)
/// stream itself, or passes the bytes through to the Origin untouched.
pub const ORIGIN_TLS_ENV: &str = "CT_AGENT_ORIGIN_TLS";
/// `CT_AGENT_TLS_CERT`: the PEM certificate chain [`OriginTls::Terminate`] serves.
pub const TLS_CERT_ENV: &str = "CT_AGENT_TLS_CERT";
/// `CT_AGENT_TLS_KEY`: the PEM private key matching [`TLS_CERT_ENV`].
pub const TLS_KEY_ENV: &str = "CT_AGENT_TLS_KEY";
/// `CT_ACME_CERT_OUT_DIR`: where `ct-agent certificate` writes `fullchain.pem`/`privkey.pem` --
/// the default location [`OriginTls::Terminate`] reads them back from, so a host that already
/// renews its own Let's Encrypt certificate needs no second copy of the paths.
pub const ACME_CERT_OUT_DIR_ENV: &str = "CT_ACME_CERT_OUT_DIR";
/// The `CT_ACME_CERT_OUT_DIR` default, shared with `acme_orchestrate` (kept in sync by the test
/// there that pins it): one place the two commands agree on.
pub const DEFAULT_ACME_CERT_OUT_DIR: &str = "/shared/acme-cert";

/// What the Agent does with the TLS layer of a raw-forwarded stream (scimbe/ct-agent#204).
///
/// WHY: the Browser Plane forwards a relayed stream to the Origin verbatim, because an HTTPS
/// Origin terminates the browser's TLS itself. An SSH or other raw-TCP Origin (sshd, a
/// database) cannot -- it speaks its own protocol and has never heard of TLS. In Grün the
/// client's TLS session reaches this Agent byte-for-byte (the Edge only routes on SNI), so
/// the only place left to terminate it is HERE, with the hostname's own ACME certificate
/// (`ct-agent certificate` already renews exactly that pair): the Agent unwraps the TLS
/// and forwards plaintext to `CT_AGENT_ORIGIN`. That is what `ct-agent ssh` (an OpenSSH
/// ProxyCommand speaking SSH-over-TLS, like cloudflared's) connects to. In Gelb the Edge has
/// already stripped TLS and the relayed bytes arrive plain -- the serve path sniffs the first
/// bytes for a TLS ClientHello before terminating, so a Gelb deployment with this set on keeps
/// working unchanged, and an HTTPS Origin behind a `passthrough` Agent is untouched.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OriginTls {
    /// Forward the stream verbatim; TLS (if any) terminates at the Origin. The default.
    #[default]
    Passthrough,
    /// Terminate TLS at the Agent with this PEM certificate chain and private key, then forward
    /// the plaintext to the Origin. Only streams that begin with a TLS ClientHello are
    /// terminated; anything else is still forwarded raw.
    Terminate {
        /// PEM certificate chain (`fullchain.pem`), leaf first.
        cert: PathBuf,
        /// PEM private key (`privkey.pem`) for the leaf.
        key: PathBuf,
    },
}

impl OriginTls {
    /// Parse `CT_AGENT_ORIGIN_TLS` and, for `terminate`, the two path variables (falling back to
    /// the ACME output directory). Unset or blank means [`OriginTls::Passthrough`]; any value
    /// other than `passthrough`/`terminate` is an error naming the variable -- a typo must not
    /// silently leave an sshd exposed to raw TLS bytes it cannot read.
    pub fn from_env_with(get: &impl Fn(&str) -> Option<String>) -> Result<OriginTls, String> {
        let mode = get(ORIGIN_TLS_ENV).map(|v| v.trim().to_ascii_lowercase()).unwrap_or_default();
        match mode.as_str() {
            "" | "passthrough" => Ok(OriginTls::Passthrough),
            "terminate" => {
                let cert_dir = PathBuf::from(
                    get(ACME_CERT_OUT_DIR_ENV)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| DEFAULT_ACME_CERT_OUT_DIR.to_string()),
                );
                let path_or = |var: &str, default: PathBuf| -> PathBuf {
                    get(var)
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                        .unwrap_or(default)
                };
                Ok(OriginTls::Terminate {
                    cert: path_or(TLS_CERT_ENV, cert_dir.join("fullchain.pem")),
                    key: path_or(TLS_KEY_ENV, cert_dir.join("privkey.pem")),
                })
            }
            other => Err(format!("invalid {ORIGIN_TLS_ENV} '{other}' (expected passthrough|terminate)")),
        }
    }
}

/// Runtime configuration for the Agent daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// Edge address to dial (outbound).
    pub edge: SocketAddr,
    /// Local Origin service to expose through the tunnel.
    pub origin: SocketAddr,
    /// Whether the Origin speaks TCP or UDP.
    pub origin_proto: OriginProto,
    /// If set, the Agent runs a direct-path listener and advertises it at this
    /// IP (with the listener's bound port) so Clients can connect directly,
    /// bypassing the Edge relay (M11.4b-v). `None` disables P2P (relay only).
    pub direct_advertise_ip: Option<IpAddr>,
    /// If set, the Agent serves its Prometheus `/metrics` endpoint on this
    /// address (M14.2). `None` disables the endpoint.
    pub metrics_listen: Option<SocketAddr>,
    /// Browser Plane (#23): when true the Agent forwards each relayed stream to
    /// the Origin **verbatim** (raw TLS passthrough) instead of terminating a
    /// Noise session — the browser's TLS terminates at the Origin. Set with
    /// `CT_AGENT_MODE=browser`. Default `false` (Mesh Plane / Noise).
    pub browser_forward: bool,
    /// Browser Plane (#23): the public hostname this Agent binds to its routing
    /// token at the Edge (`CT_AGENT_HOSTNAME`), so an SNI-routed browser reaches
    /// this tunnel. `None` = no hostname bound.
    pub hostname: Option<String>,
    /// Firewall-fallback (#46): when true, if the configured edge port is blocked
    /// the Agent also tries the edge's unified `:443` front door (TLS-TCP with
    /// `ALPN=ct-edge`). `CT_AGENT_FALLBACK_443`; default `false`.
    pub fallback_443: bool,
    /// How many TLS-TCP fallback registrations to hold parked concurrently
    /// (#229): each is single-use and one-Client-at-a-time, so with a pool of
    /// 1 (the old, implicit behavior) a real browser page load's parallel
    /// per-origin connections drop every one but the first. `CT_AGENT_TCP_
    /// FALLBACK_POOL_SIZE`; default 6, matching the per-origin HTTP/1.1
    /// connection cap real browsers (Chrome, Firefox, Safari) actually use --
    /// a smaller pool trades away exactly the parallelism a real page load
    /// needs, which is the failure mode #229 was filed over. The Edge also
    /// tolerates brief bursts past the pool size with a short bounded wait
    /// (`wait_for_tcp_agent`) rather than failing outright. Only used in
    /// TLS-TCP fallback mode; QUIC already multiplexes and needs no pool.
    pub tcp_fallback_pool_size: usize,
    /// CADS-Tunnel#799: how many CONSUMED TLS-TCP fallback registrations (a
    /// Client relayed, the tunnel running) may be in flight on top of the
    /// `tcp_fallback_pool_size` parked ones. The pool keeps `tcp_fallback_pool_size`
    /// registrations parked at all times by spawning a replacement the moment the
    /// Edge consumes one (spare slot), so a burst of Clients no longer eats the
    /// whole pool and leaves the next Client with "no agent tunnel for token"
    /// until a tunnel finishes. This cap bounds the total to
    /// `pool_size + max_serving` connections. `CT_AGENT_TCP_FALLBACK_MAX_SERVING`;
    /// default 32, minimum 1.
    pub tcp_fallback_max_serving: usize,
    /// CADS-Tunnel#528: when true, the Browser-Plane TLS-TCP fallback prefers the
    /// **framed** `'F'` registration, whose relay phase is length-prefix framed on
    /// the edge↔agent hop so a keepalive can be interleaved *during* an in-flight
    /// request (an Origin that is silent for an LLM cold model load no longer has
    /// its connection dropped by a middlebox). `CT_AGENT_FRAMED_FALLBACK`.
    ///
    /// Default `false` **until the Edge side of #528 is deployed everywhere**: an
    /// Edge that does not know `'F'` refuses it, which costs one extra dial per
    /// registration before the `'L'` fallback takes over. That is harmless but
    /// pointless, so this stays opt-in rather than being paid on every edge in the
    /// fleet. Flip the default once the framed Edge is the deployed baseline.
    pub framed_fallback: bool,
    /// #16 operational escape hatch: when true, the Agent registers over the
    /// TLS-TCP fallback **exclusively** -- no QUIC dial at all, ever. For
    /// deployments whose UDP path to the edge is known-flaky ("UDP flapping"):
    /// rather than riding the automatic flap-through-and-upgrade cycle, the
    /// operator pins the agent to the transport that is actually stable for
    /// them (combine with `CT_AGENT_FALLBACK_443` to reach the `:443` front
    /// door). `CT_AGENT_REGISTER_TCP_ONLY`; default `false`.
    pub register_tcp_only: bool,
    /// ADR-0024 M3-followup: when set, a failed direct QUIC dial tries reaching
    /// the Edge's real QUIC endpoint through an RFC 9298 CONNECT-UDP tunnel
    /// (`crate::masque::dial_quic_via_masque`) before falling all the way back
    /// to the TLS-TCP framing fallback -- a genuine QUIC connection (migration,
    /// loss recovery) carried over a path that looks like ordinary HTTPS on the
    /// wire, for networks that block raw UDP outright. `None` = disabled
    /// (default): this needs a deployed `masque-proxy` (CADS-Tunnel ADR-0024 M2)
    /// registered on the Edge, so it stays opt-in rather than probed on every
    /// agent in the fleet.
    pub masque_fallback: Option<MasqueFallbackConfig>,
    /// ct-agent#45 slice 1: when true, a direct-connect handshake that carries
    /// **no** routing token (a pre-#45 client) is refused, not just one that
    /// carries the wrong token. `CT_DIRECT_REQUIRE_TOKEN`; default `false`
    /// (rollout mode: token-less clients are still served until every client
    /// sends the token, see `serve::DirectTokenPolicy`). Only consulted when
    /// `direct_advertise_ip` is set -- the relayed path never reads it.
    pub direct_require_token: bool,
    /// scimbe/ct-agent#204: whether a raw-forwarded stream's TLS is terminated here (with the
    /// hostname's own certificate, for SSH/raw-TCP Origins that cannot) or passed through to
    /// the Origin. `CT_AGENT_ORIGIN_TLS`; default [`OriginTls::Passthrough`]. Only consulted on
    /// the Browser-Plane raw-forward paths (`CT_AGENT_MODE=browser`); the Noise path never
    /// carries client TLS. See [`OriginTls`] for the Grün/Gelb reasoning.
    pub origin_tls: OriginTls,
}

/// The four values `dial_quic_via_masque` needs, read together (ADR-0024 M3-followup).
/// All-or-nothing: partially setting these is almost certainly a misconfiguration
/// (a copy-pasted proxy address with no matching SNI host, say), so `from_env_with`
/// treats "some but not all four set" as a hard config error rather than silently
/// leaving MASQUE disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueFallbackConfig {
    /// Where to dial TCP+TLS+h2 -- the Edge's own public front door
    /// (`CT_AGENT_MASQUE_PROXY`, e.g. `edge_host:443`).
    pub proxy_addr: SocketAddr,
    /// TLS SNI / `:authority` routing this connection to the Edge's registered
    /// MASQUE proxy target (`CT_AGENT_MASQUE_SNI_HOST`; must match `CT_EDGE_
    /// MASQUE_HOST` on that Edge deployment, CADS-Tunnel ADR-0024 M2).
    pub sni_host: String,
    /// The RFC 9298 CONNECT-UDP target to request (`CT_AGENT_MASQUE_TARGET`;
    /// must match, byte-for-byte once encoded, the deployed `masque-proxy`'s own
    /// `CT_MASQUE_PROXY_TARGET_ADDR` -- an operator-maintained convention across
    /// the two processes, not something this Agent can verify on its own).
    pub target: SocketAddr,
    /// The shared secret this Agent presents as `x-ct-masque-token`
    /// (`CT_AGENT_MASQUE_TOKEN`; must match the deployed `masque-proxy`'s own
    /// `CT_MASQUE_PROXY_TOKEN`, 64-hex). Target-restriction alone only answers
    /// WHERE a tunnel can go, not WHO may open one -- and that target is the
    /// Edge's own INTERNAL QUIC listener, so `masque-proxy` requires this token
    /// from every caller (fail-closed on its own side too).
    pub token: String,
}

/// Resolve a `host:port` (or `IP:port`) to a [`SocketAddr`] (#45). A literal
/// IP:port parses directly (no DNS); a hostname:port is resolved via the system
/// resolver — so Compose service names like `help-origin:443` / `edge:4433` work
/// on a shared Docker network instead of requiring churning literal IPs. Returns
/// the first resolved address.
fn resolve_addr(var: &str, s: &str) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;
    s.to_socket_addrs()
        .map_err(|e| format!("invalid {var} '{s}': {e}"))?
        .next()
        .ok_or_else(|| format!("{var} '{s}' resolved to no address"))
}

impl AgentConfig {
    /// CADS-Tunnel#795: a hostname the operator set that this agent will never bind.
    /// ct-agent binds `CT_AGENT_HOSTNAME` only in browser mode (`CT_AGENT_MODE=browser`)
    /// -- on QUIC via the `'H'` bind, on the TLS-TCP fallback via the `'B'/'L'/'F'`
    /// frames; the Noise-mode `'A'/'K'` registrations carry the token alone. A
    /// Noise-mode agent with a hostname therefore registers fine at the token level,
    /// logs "registered … serving", and the edge still answers every browser with
    /// "no tunnel registered for host" -- a silent outage that took an operator two
    /// hours to diagnose. This is the one-line warning that would have said so.
    pub fn hostname_unbound_notice(&self) -> Option<String> {
        match (&self.hostname, self.browser_forward) {
            (Some(host), false) => Some(format!(
                "ct-agent: WARNING: CT_AGENT_HOSTNAME='{host}' is set but CT_AGENT_MODE is not \
                 'browser' -- the hostname will NOT be bound on the edge, so browsers reaching \
                 https://{host} get 'no tunnel registered for host' while this agent reports \
                 itself registered. Set CT_AGENT_MODE=browser for a public (site) hostname, or \
                 unset CT_AGENT_HOSTNAME (CADS-Tunnel#795)."
            )),
            _ => None,
        }
    }

    /// Whether a registration on this configuration binds the public hostname
    /// (see [`Self::hostname_unbound_notice`]). Carried on the `registered` event so
    /// the timeline shows it, and appended to the registered log lines.
    pub fn binds_hostname(&self) -> bool {
        self.hostname.is_some() && self.browser_forward
    }

    /// Suffix for the Noise-path "registered" log lines: names the hostname that was
    /// NOT bound, or is empty when there is nothing to say.
    pub fn hostname_bind_note(&self) -> String {
        match (&self.hostname, self.browser_forward) {
            (Some(host), false) => {
                format!("; hostname '{host}' NOT bound -- CT_AGENT_MODE is not 'browser' (CADS-Tunnel#795)")
            }
            _ => String::new(),
        }
    }

    pub fn parse(edge: &str, origin: &str) -> Result<AgentConfig, String> {
        let edge = resolve_addr("CT_AGENT_EDGE", edge)?;
        let origin = resolve_addr("CT_AGENT_ORIGIN", origin)?;
        Ok(AgentConfig {
            edge,
            origin,
            origin_proto: OriginProto::default(),
            direct_advertise_ip: None,
            metrics_listen: None,
            browser_forward: false,
            hostname: None,
            fallback_443: false,
            tcp_fallback_pool_size: DEFAULT_TCP_FALLBACK_POOL_SIZE,
            tcp_fallback_max_serving: DEFAULT_TCP_FALLBACK_MAX_SERVING,
            framed_fallback: false,
            register_tcp_only: false,
            masque_fallback: None,
            direct_require_token: false,
            origin_tls: OriginTls::Passthrough,
        })
    }

    /// Read from `CT_AGENT_EDGE` (default `127.0.0.1:4433`),
    /// `CT_AGENT_ORIGIN` (default `127.0.0.1:8080`), `CT_AGENT_ORIGIN_PROTO`
    /// (`tcp` | `udp`, default `tcp`) and `CT_AGENT_DIRECT_ADVERTISE` (an IP the
    /// Agent advertises for its direct-path listener; unset = P2P disabled).
    pub fn from_env() -> Result<AgentConfig, String> {
        Self::from_env_with(|k| std::env::var(k).ok())
    }

    /// Parse the config from a variable lookup. `from_env` passes
    /// `std::env::var`; splitting the parsing out behind a getter lets every
    /// branch (defaults, blank optionals, invalid values) be unit-tested without
    /// mutating the global process environment (which races across tests).
    pub(crate) fn from_env_with(
        get: impl Fn(&str) -> Option<String>,
    ) -> Result<AgentConfig, String> {
        let edge = get("CT_AGENT_EDGE").unwrap_or_else(|| "127.0.0.1:4433".to_string());
        let origin = get("CT_AGENT_ORIGIN").unwrap_or_else(|| "127.0.0.1:8080".to_string());
        let proto = get("CT_AGENT_ORIGIN_PROTO").unwrap_or_else(|| "tcp".to_string());
        let mut cfg = Self::parse(&edge, &origin)?;
        cfg.origin_proto = OriginProto::parse(&proto)?;
        cfg.direct_advertise_ip = match get("CT_AGENT_DIRECT_ADVERTISE") {
            Some(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse::<IpAddr>()
                    .map_err(|e| format!("invalid CT_AGENT_DIRECT_ADVERTISE '{s}': {e}"))?,
            ),
            _ => None,
        };
        cfg.metrics_listen = match get("CT_AGENT_METRICS_LISTEN") {
            Some(s) if !s.trim().is_empty() => Some(
                s.trim()
                    .parse::<SocketAddr>()
                    .map_err(|e| format!("invalid CT_AGENT_METRICS_LISTEN '{s}': {e}"))?,
            ),
            _ => None,
        };
        // Browser Plane (#23): CT_AGENT_MODE=browser -> raw TLS passthrough.
        cfg.browser_forward =
            get("CT_AGENT_MODE").map(|m| m.trim().eq_ignore_ascii_case("browser")) == Some(true);
        cfg.hostname = get("CT_AGENT_HOSTNAME")
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        // Firewall-fallback (#46): CT_AGENT_FALLBACK_443 truthy -> also try :443.
        cfg.fallback_443 = truthy(&get, "CT_AGENT_FALLBACK_443");
        // #16: CT_AGENT_REGISTER_TCP_ONLY truthy -> never dial QUIC, TLS-TCP only.
        cfg.register_tcp_only = truthy(&get, "CT_AGENT_REGISTER_TCP_ONLY");
        // #528: CT_AGENT_FRAMED_FALLBACK truthy -> prefer the framed 'F' browser
        // registration over 'L'. Off by default, see the field's doc comment.
        cfg.framed_fallback = truthy(&get, "CT_AGENT_FRAMED_FALLBACK");
        // ct-agent#45 slice 1: CT_DIRECT_REQUIRE_TOKEN truthy -> a direct-connect
        // handshake without a routing token is refused. Off by default so that
        // upgrading one agent never locks out the already-deployed clients that
        // don't send the token yet.
        cfg.direct_require_token = truthy(&get, "CT_DIRECT_REQUIRE_TOKEN");
        cfg.tcp_fallback_pool_size = match get("CT_AGENT_TCP_FALLBACK_POOL_SIZE") {
            Some(s) if !s.trim().is_empty() => s
                .trim()
                .parse::<usize>()
                .map_err(|e| format!("invalid CT_AGENT_TCP_FALLBACK_POOL_SIZE '{s}': {e}"))
                .and_then(|n| {
                    if n == 0 {
                        Err("CT_AGENT_TCP_FALLBACK_POOL_SIZE must be at least 1".to_string())
                    } else {
                        Ok(n)
                    }
                })?,
            _ => DEFAULT_TCP_FALLBACK_POOL_SIZE,
        };
        // CADS-Tunnel#799: the spare-slot cap, same shape as the pool size.
        cfg.tcp_fallback_max_serving = match get("CT_AGENT_TCP_FALLBACK_MAX_SERVING") {
            Some(s) if !s.trim().is_empty() => s
                .trim()
                .parse::<usize>()
                .map_err(|e| format!("invalid CT_AGENT_TCP_FALLBACK_MAX_SERVING '{s}': {e}"))
                .and_then(|n| {
                    if n == 0 {
                        Err("CT_AGENT_TCP_FALLBACK_MAX_SERVING must be at least 1".to_string())
                    } else {
                        Ok(n)
                    }
                })?,
            _ => DEFAULT_TCP_FALLBACK_MAX_SERVING,
        };
        cfg.masque_fallback = parse_masque_fallback(&get)?;
        // scimbe/ct-agent#204: terminate TLS here for an sshd-style Origin, or pass it through.
        cfg.origin_tls = OriginTls::from_env_with(&get)?;
        Ok(cfg)
    }
}

/// Parses `CT_AGENT_MASQUE_PROXY` / `CT_AGENT_MASQUE_SNI_HOST` /
/// `CT_AGENT_MASQUE_TARGET` / `CT_AGENT_MASQUE_TOKEN` together (ADR-0024
/// M3-followup). None set at all -> `Ok(None)` (disabled, the default). All four
/// set -> `Ok(Some(..))`. Some but not all set -> `Err`, naming which are
/// missing, rather than silently treating it as disabled -- a half-set MASQUE
/// config is far more likely a typo than an intentional partial opt-out.
fn parse_masque_fallback(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<Option<MasqueFallbackConfig>, String> {
    let proxy = get("CT_AGENT_MASQUE_PROXY").filter(|s| !s.trim().is_empty());
    let sni_host = get("CT_AGENT_MASQUE_SNI_HOST").filter(|s| !s.trim().is_empty());
    let target = get("CT_AGENT_MASQUE_TARGET").filter(|s| !s.trim().is_empty());
    let token = get("CT_AGENT_MASQUE_TOKEN").filter(|s| !s.trim().is_empty());
    match (&proxy, &sni_host, &target, &token) {
        (None, None, None, None) => Ok(None),
        _ => {
            let mut missing = Vec::new();
            if proxy.is_none() {
                missing.push("CT_AGENT_MASQUE_PROXY");
            }
            if sni_host.is_none() {
                missing.push("CT_AGENT_MASQUE_SNI_HOST");
            }
            if target.is_none() {
                missing.push("CT_AGENT_MASQUE_TARGET");
            }
            if token.is_none() {
                missing.push("CT_AGENT_MASQUE_TOKEN");
            }
            // Bound once, by the type system, instead of re-checked with `unwrap`
            // after the manual completeness check above (ct-agent#176). The `else`
            // arm is unreachable in practice -- `missing` is non-empty whenever any
            // of the four is `None` -- but it is an error, not a panic.
            let (Some(proxy), Some(sni_host), Some(target), Some(token)) = (proxy, sni_host, target, token)
            else {
                return Err(format!(
                    "MASQUE fallback is only partially configured -- missing {}",
                    missing.join(", ")
                ));
            };
            Ok(Some(MasqueFallbackConfig {
                proxy_addr: resolve_addr("CT_AGENT_MASQUE_PROXY", &proxy)?,
                sni_host: sni_host.trim().to_string(),
                target: resolve_addr("CT_AGENT_MASQUE_TARGET", &target)?,
                token: token.trim().to_string(),
            }))
        }
    }
}

/// Read a boolean env flag: set and not `""`/`0`/`false` (case-insensitive,
/// trimmed) means on. The one shared reading of "truthy" across every boolean
/// `CT_AGENT_*` flag, so `=0` reliably means off everywhere instead of per-flag.
fn truthy(get: &impl Fn(&str) -> Option<String>, key: &str) -> bool {
    get(key)
        .map(|v| {
            let v = v.trim();
            !v.is_empty() && !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
        })
        .unwrap_or(false)
}

/// See [`AgentConfig::tcp_fallback_pool_size`].
const DEFAULT_TCP_FALLBACK_POOL_SIZE: usize = 6;

/// See [`AgentConfig::tcp_fallback_max_serving`].
const DEFAULT_TCP_FALLBACK_MAX_SERVING: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config() {
        let c = AgentConfig::parse("10.0.0.2:4433", "127.0.0.1:8080").unwrap();
        assert_eq!(c.edge, "10.0.0.2:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(c.origin_proto, OriginProto::Tcp, "defaults to TCP");
        assert_eq!(c.direct_advertise_ip, None, "P2P disabled by default");
    }

    #[test]
    fn resolves_hostname_and_literal_addresses() {
        // #45: a Compose service name (hostname:port) must resolve, not just a
        // literal IP:port — so help-origin:443 / edge:4433 work on a Docker network.
        // `localhost` is in the container's /etc/hosts, so it stands in for a
        // resolvable service name in the hermetic gate.
        let a = resolve_addr("X", "localhost:8443").expect("hostname resolves");
        assert_eq!(a.port(), 8443);
        assert!(a.ip().is_loopback(), "localhost -> loopback");

        // A literal IP:port parses directly (no DNS).
        assert_eq!(resolve_addr("X", "10.0.0.5:4433").unwrap(), "10.0.0.5:4433".parse().unwrap());

        // Missing port / unresolvable garbage -> a clear error (not a panic).
        assert!(resolve_addr("CT_AGENT_ORIGIN", "no-port-here").is_err());
    }

    #[test]
    fn fallback_443_reads_the_env_flag() {
        // #46: off by default; truthy values enable it; 0/false/empty keep it off.
        let base = |v: Option<&str>| {
            AgentConfig::from_env_with(|k| match k {
                "CT_AGENT_EDGE" => Some("127.0.0.1:4433".into()),
                "CT_AGENT_ORIGIN" => Some("127.0.0.1:8080".into()),
                "CT_AGENT_FALLBACK_443" => v.map(str::to_string),
                _ => None,
            })
            .unwrap()
            .fallback_443
        };
        assert!(!base(None), "default off");
        assert!(!base(Some("0")), "0 -> off");
        assert!(!base(Some("false")), "false -> off");
        assert!(!base(Some("")), "empty -> off");
        assert!(base(Some("1")), "1 -> on");
        assert!(base(Some("true")), "true -> on");
    }

    #[test]
    fn framed_fallback_is_off_until_explicitly_enabled() {
        // #528: the framed 'F' browser registration must stay OPT-IN while Edges
        // that don't know 'F' are still deployed -- every such Edge refuses it and
        // costs the agent an extra dial before 'L' takes over. Default-on would
        // impose that on the whole fleet for no gain, so pin the default here.
        let base = |v: Option<&str>| {
            AgentConfig::from_env_with(|k| match k {
                "CT_AGENT_EDGE" => Some("127.0.0.1:4433".into()),
                "CT_AGENT_ORIGIN" => Some("127.0.0.1:8080".into()),
                "CT_AGENT_FRAMED_FALLBACK" => v.map(str::to_string),
                _ => None,
            })
            .unwrap()
            .framed_fallback
        };
        assert!(!base(None), "default off -- opt-in until the framed Edge is the baseline");
        assert!(!base(Some("0")), "0 -> off");
        assert!(!base(Some("false")), "false -> off");
        assert!(!base(Some("")), "empty -> off");
        assert!(base(Some("1")), "1 -> on");
        assert!(base(Some("true")), "true -> on");
    }

    #[test]
    fn register_tcp_only_reads_the_env_flag() {
        // #16: off by default; truthy values enable it; 0/false/empty keep it off —
        // the same truthiness contract as CT_AGENT_FALLBACK_443, which it is meant
        // to be combined with.
        let base = |v: Option<&str>| {
            AgentConfig::from_env_with(|k| match k {
                "CT_AGENT_EDGE" => Some("127.0.0.1:4433".into()),
                "CT_AGENT_ORIGIN" => Some("127.0.0.1:8080".into()),
                "CT_AGENT_REGISTER_TCP_ONLY" => v.map(str::to_string),
                _ => None,
            })
            .unwrap()
            .register_tcp_only
        };
        assert!(!base(None), "default off");
        assert!(!base(Some("0")), "0 -> off");
        assert!(!base(Some("false")), "false -> off");
        assert!(!base(Some("")), "empty -> off");
        assert!(base(Some("1")), "1 -> on");
        assert!(base(Some("true")), "true -> on");
    }

    #[test]
    fn direct_require_token_reads_the_env_flag() {
        // ct-agent#45 slice 1: off by default (rollout mode, pre-#45 clients keep
        // working); truthy values switch the direct listener to token-required.
        // Same truthiness contract as the other CT_AGENT_* boolean flags.
        let base = |v: Option<&str>| {
            AgentConfig::from_env_with(|k| match k {
                "CT_AGENT_EDGE" => Some("127.0.0.1:4433".into()),
                "CT_AGENT_ORIGIN" => Some("127.0.0.1:8080".into()),
                "CT_DIRECT_REQUIRE_TOKEN" => v.map(str::to_string),
                _ => None,
            })
            .unwrap()
            .direct_require_token
        };
        assert!(!base(None), "default off (rollout-compatible)");
        assert!(!base(Some("0")), "0 -> off");
        assert!(!base(Some("false")), "false -> off");
        assert!(!base(Some("")), "empty -> off");
        assert!(base(Some("1")), "1 -> on");
        assert!(base(Some("true")), "true -> on");
    }

    #[test]
    fn parses_direct_advertise_ip() {
        assert_eq!("10.5.0.4".parse::<IpAddr>().unwrap(), "10.5.0.4".parse::<IpAddr>().unwrap());
        // A parsed IP round-trips into an advertised SocketAddr with the port.
        let ip: IpAddr = "10.5.0.4".parse().unwrap();
        let sa = SocketAddr::new(ip, 40001);
        assert_eq!(sa.to_string(), "10.5.0.4:40001");
    }

    #[test]
    fn origin_proto_parses_tcp_udp_and_rejects_others() {
        assert_eq!(OriginProto::parse("tcp").unwrap(), OriginProto::Tcp);
        assert_eq!(OriginProto::parse("UDP").unwrap(), OriginProto::Udp);
        assert_eq!(OriginProto::parse(" udp ").unwrap(), OriginProto::Udp);
        assert!(OriginProto::parse("sctp").is_err());
    }

    #[test]
    fn rejects_bad_edge() {
        assert!(AgentConfig::parse("nope", "127.0.0.1:8080").is_err());
    }

    #[test]
    fn rejects_bad_origin() {
        assert!(AgentConfig::parse("10.0.0.2:4433", "nope").is_err());
    }

    // #20 TC1: cover config.rs::from_env via the from_env_with getter seam
    // (deterministic, no global-env mutation).
    fn get_from<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn from_env_defaults_when_all_unset() {
        let c = AgentConfig::from_env_with(|_| None).unwrap();
        assert_eq!(c.edge, "127.0.0.1:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(c.origin_proto, OriginProto::Tcp);
        assert_eq!(c.direct_advertise_ip, None);
        assert_eq!(c.metrics_listen, None);
    }

    #[test]
    fn from_env_reads_every_var() {
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_EDGE", "10.0.0.2:4433"),
            ("CT_AGENT_ORIGIN", "127.0.0.1:9000"),
            ("CT_AGENT_ORIGIN_PROTO", "udp"),
            ("CT_AGENT_DIRECT_ADVERTISE", "10.5.0.4"),
            ("CT_AGENT_METRICS_LISTEN", "0.0.0.0:9101"),
        ]))
        .unwrap();
        assert_eq!(c.edge, "10.0.0.2:4433".parse().unwrap());
        assert_eq!(c.origin, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(c.origin_proto, OriginProto::Udp);
        assert_eq!(c.direct_advertise_ip, Some("10.5.0.4".parse().unwrap()));
        assert_eq!(c.metrics_listen, Some("0.0.0.0:9101".parse().unwrap()));
    }

    #[test]
    fn from_env_blank_optionals_are_treated_as_unset() {
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_DIRECT_ADVERTISE", "   "),
            ("CT_AGENT_METRICS_LISTEN", ""),
        ]))
        .unwrap();
        assert_eq!(c.direct_advertise_ip, None);
        assert_eq!(c.metrics_listen, None);
    }

    #[test]
    fn from_env_rejects_each_invalid_value() {
        for (var, needle) in [
            ("CT_AGENT_EDGE", "CT_AGENT_EDGE"),
            ("CT_AGENT_ORIGIN", "CT_AGENT_ORIGIN"),
            ("CT_AGENT_ORIGIN_PROTO", "CT_AGENT_ORIGIN_PROTO"),
            ("CT_AGENT_DIRECT_ADVERTISE", "CT_AGENT_DIRECT_ADVERTISE"),
            ("CT_AGENT_METRICS_LISTEN", "CT_AGENT_METRICS_LISTEN"),
        ] {
            let err = AgentConfig::from_env_with(get_from(&[(var, "nope")]))
                .unwrap_err();
            assert!(err.contains(needle), "{var}: unexpected error {err}");
        }
    }

    #[test]
    fn from_env_browser_mode_enables_raw_forward() {
        // #23 BP2: CT_AGENT_MODE=browser -> raw TLS passthrough; default off.
        assert!(!AgentConfig::from_env_with(|_| None).unwrap().browser_forward);
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_MODE", "Browser")])).unwrap();
        assert!(c.browser_forward, "CT_AGENT_MODE=browser enables raw forward");
    }

    #[test]
    fn hostname_without_browser_mode_is_called_out_795() {
        // CADS-Tunnel#795: a Noise-mode agent never binds its hostname; say so.
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_HOSTNAME", "site-x.example")]))
            .unwrap();
        assert!(!c.binds_hostname());
        let notice = c.hostname_unbound_notice().expect("hostname set without browser mode warns");
        assert!(notice.contains("site-x.example") && notice.contains("CT_AGENT_MODE=browser"));
        assert!(notice.contains("no tunnel registered for host"), "names the symptom the operator sees");
        assert!(c.hostname_bind_note().contains("NOT bound"));

        // Browser mode with a hostname: bound, nothing to warn about.
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_HOSTNAME", "site-x.example"),
            ("CT_AGENT_MODE", "browser"),
        ]))
        .unwrap();
        assert!(c.binds_hostname());
        assert!(c.hostname_unbound_notice().is_none());
        assert_eq!(c.hostname_bind_note(), "");

        // No hostname at all (either mode): nothing to bind, nothing to say.
        for env in [&[][..], &[("CT_AGENT_MODE", "browser")][..]] {
            let c = AgentConfig::from_env_with(get_from(env)).unwrap();
            assert!(!c.binds_hostname());
            assert!(c.hostname_unbound_notice().is_none());
            assert_eq!(c.hostname_bind_note(), "");
        }
    }

    #[test]
    fn from_env_wrapper_reads_the_process_environment() {
        // Exercise the thin from_env() wrapper (delegates to from_env_with with
        // std::env::var). No test in this crate sets CT_AGENT_* and the hermetic
        // gate has none, so it resolves the documented defaults.
        let c = AgentConfig::from_env().expect("defaults parse");
        assert_eq!(c.origin_proto, OriginProto::Tcp);
    }

    #[test]
    fn masque_fallback_is_disabled_when_none_of_the_four_vars_are_set() {
        // ADR-0024 M3-followup: the default, no-op state.
        let c = AgentConfig::from_env_with(|_| None).unwrap();
        assert_eq!(c.masque_fallback, None);
    }

    #[test]
    fn masque_fallback_parses_when_all_four_vars_are_set() {
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_MASQUE_PROXY", "10.0.0.9:443"),
            ("CT_AGENT_MASQUE_SNI_HOST", "masque.example.org"),
            ("CT_AGENT_MASQUE_TARGET", "10.0.0.9:4433"),
            ("CT_AGENT_MASQUE_TOKEN", "a1b2c3"),
        ]))
        .unwrap();
        let masque = c.masque_fallback.expect("all four set -> Some");
        assert_eq!(masque.proxy_addr, "10.0.0.9:443".parse().unwrap());
        assert_eq!(masque.sni_host, "masque.example.org");
        assert_eq!(masque.target, "10.0.0.9:4433".parse().unwrap());
        assert_eq!(masque.token, "a1b2c3");
    }

    #[test]
    fn masque_fallback_errors_loudly_on_partial_configuration() {
        // A half-set MASQUE config is far more likely a typo (copy-pasted proxy
        // address, forgotten SNI host) than an intentional partial opt-out --
        // silently treating it as disabled would hide that mistake.
        let err = AgentConfig::from_env_with(get_from(&[("CT_AGENT_MASQUE_PROXY", "10.0.0.9:443")]))
            .unwrap_err();
        assert!(err.contains("CT_AGENT_MASQUE_SNI_HOST"), "names the missing var: {err}");
        assert!(err.contains("CT_AGENT_MASQUE_TARGET"), "names the missing var: {err}");
        assert!(err.contains("CT_AGENT_MASQUE_TOKEN"), "names the missing var: {err}");
    }

    #[test]
    fn origin_tls_defaults_to_passthrough_when_unset_or_named() {
        // scimbe/ct-agent#204: the default must stay the pre-#204 behaviour (TLS terminates at
        // the Origin) -- an HTTPS Origin behind an upgraded agent is untouched.
        assert_eq!(AgentConfig::from_env_with(|_| None).unwrap().origin_tls, OriginTls::Passthrough);
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_ORIGIN_TLS", "passthrough")])).unwrap();
        assert_eq!(c.origin_tls, OriginTls::Passthrough);
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_ORIGIN_TLS", " PassThrough ")])).unwrap();
        assert_eq!(c.origin_tls, OriginTls::Passthrough, "case-insensitive, trimmed");
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_ORIGIN_TLS", "")])).unwrap();
        assert_eq!(c.origin_tls, OriginTls::Passthrough, "blank counts as unset");
    }

    #[test]
    fn origin_tls_terminate_defaults_to_the_acme_output_pair() {
        // With no explicit paths the pair `ct-agent certificate` writes is used -- the host
        // already renews exactly that certificate, so no second configuration of the paths.
        let c = AgentConfig::from_env_with(get_from(&[("CT_AGENT_ORIGIN_TLS", "terminate")])).unwrap();
        assert_eq!(
            c.origin_tls,
            OriginTls::Terminate {
                cert: PathBuf::from("/shared/acme-cert/fullchain.pem"),
                key: PathBuf::from("/shared/acme-cert/privkey.pem"),
            }
        );
        // A relocated ACME output dir moves both defaults with it.
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_ORIGIN_TLS", "terminate"),
            ("CT_ACME_CERT_OUT_DIR", "/var/lib/ct/certs"),
        ]))
        .unwrap();
        assert_eq!(
            c.origin_tls,
            OriginTls::Terminate {
                cert: PathBuf::from("/var/lib/ct/certs/fullchain.pem"),
                key: PathBuf::from("/var/lib/ct/certs/privkey.pem"),
            }
        );
    }

    #[test]
    fn origin_tls_terminate_takes_explicit_paths() {
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_ORIGIN_TLS", "terminate"),
            ("CT_AGENT_TLS_CERT", "/etc/ssl/site/chain.pem"),
            ("CT_AGENT_TLS_KEY", "/etc/ssl/site/key.pem"),
            ("CT_ACME_CERT_OUT_DIR", "/ignored"),
        ]))
        .unwrap();
        assert_eq!(
            c.origin_tls,
            OriginTls::Terminate {
                cert: PathBuf::from("/etc/ssl/site/chain.pem"),
                key: PathBuf::from("/etc/ssl/site/key.pem"),
            }
        );
        // One explicit path still leaves the other on its default.
        let c = AgentConfig::from_env_with(get_from(&[
            ("CT_AGENT_ORIGIN_TLS", "terminate"),
            ("CT_AGENT_TLS_KEY", "/etc/ssl/site/key.pem"),
        ]))
        .unwrap();
        assert_eq!(
            c.origin_tls,
            OriginTls::Terminate {
                cert: PathBuf::from("/shared/acme-cert/fullchain.pem"),
                key: PathBuf::from("/etc/ssl/site/key.pem"),
            }
        );
    }

    #[test]
    fn origin_tls_rejects_unknown_values_naming_the_variable() {
        // A typo ("terminat") must fail loudly: silently passing raw TLS through to an sshd
        // would just look like a broken tunnel.
        let err = AgentConfig::from_env_with(get_from(&[("CT_AGENT_ORIGIN_TLS", "terminat")])).unwrap_err();
        assert!(err.contains("CT_AGENT_ORIGIN_TLS"), "names the variable: {err}");
        assert!(err.contains("terminat"), "echoes the bad value: {err}");
        assert!(err.contains("passthrough|terminate"), "lists the accepted values: {err}");
    }
}
