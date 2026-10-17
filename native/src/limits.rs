//! Configurable resource limits and timeouts for the agent's listeners and relay paths.
//!
//! Every limit has a conservative default chosen so that sustained, high-throughput,
//! *authenticated* traffic (for example a remote-desktop stream carried over WebSockets through
//! a tunnel) is unaffected, while connections that have not authenticated yet, or that sit idle,
//! are bounded tightly. Each can be overridden through an environment variable; an unset, empty
//! or unparseable value falls back to the default, and values are clamped to a sane range so a
//! typo can neither disable a pre-authentication bound nor starve the transport.
//!
//! | Variable | Default | Meaning |
//! |----------|---------|---------|
//! | `CT_AGENT_QUIC_MAX_STREAMS` | 100 | concurrent bidirectional streams a peer may open per QUIC connection |
//! | `CT_AGENT_QUIC_STREAM_WINDOW` | 2 MiB | per-stream receive window (bytes) |
//! | `CT_AGENT_QUIC_CONN_WINDOW` | 16 MiB | per-connection receive window (bytes) |
//! | `CT_AGENT_QUIC_DATAGRAM_BUFFER` | 0 (off) | QUIC datagram receive buffer (bytes); the agent uses no datagrams |
//! | `CT_AGENT_RELAY_SETUP_SECS` | 30 | relayed stream: handshake plus local-auth gate, before the peer is authenticated |
//! | `CT_AGENT_RELAY_FIRST_BYTE_SECS` | 30 | relayed raw stream: time to the client's first byte |
//! | `CT_AGENT_RELAY_IDLE_SECS` | 0 (off) | relayed raw stream: close after this long without traffic in either direction |

use std::time::Duration;

/// QUIC streams a peer may have open at once on one connection.
pub const QUIC_MAX_STREAMS_ENV: &str = "CT_AGENT_QUIC_MAX_STREAMS";
/// Per-stream receive window in bytes.
pub const QUIC_STREAM_WINDOW_ENV: &str = "CT_AGENT_QUIC_STREAM_WINDOW";
/// Per-connection receive window in bytes.
pub const QUIC_CONN_WINDOW_ENV: &str = "CT_AGENT_QUIC_CONN_WINDOW";
/// QUIC datagram receive buffer in bytes (0 = datagrams off).
pub const QUIC_DATAGRAM_BUFFER_ENV: &str = "CT_AGENT_QUIC_DATAGRAM_BUFFER";
/// Seconds a relayed stream has to reach the authenticated state.
pub const RELAY_SETUP_SECS_ENV: &str = "CT_AGENT_RELAY_SETUP_SECS";
/// Seconds a relayed raw stream has to deliver its first byte.
pub const RELAY_FIRST_BYTE_SECS_ENV: &str = "CT_AGENT_RELAY_FIRST_BYTE_SECS";
/// Seconds of silence after which an established relayed raw stream is closed (0 = never).
pub const RELAY_IDLE_SECS_ENV: &str = "CT_AGENT_RELAY_IDLE_SECS";

const DEFAULT_MAX_STREAMS: u32 = 100;
const MAX_STREAMS_CEILING: u32 = 10_000;
const DEFAULT_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
const DEFAULT_CONN_WINDOW: u32 = 16 * 1024 * 1024;
/// Below this a stream cannot make useful progress over a long path.
const MIN_WINDOW: u32 = 64 * 1024;
const DEFAULT_PREAUTH_SECS: u64 = 30;

fn parse<T: std::str::FromStr>(raw: Option<&str>) -> Option<T> {
    raw.and_then(|s| s.trim().parse::<T>().ok())
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Resolved QUIC transport limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicLimits {
    pub max_bidi_streams: u32,
    pub stream_window: u32,
    pub conn_window: u32,
    /// `None` switches the datagram extension's receive buffer off.
    pub datagram_buffer: Option<usize>,
}

impl QuicLimits {
    /// The shipped defaults.
    pub const DEFAULT: Self = Self {
        max_bidi_streams: DEFAULT_MAX_STREAMS,
        stream_window: DEFAULT_STREAM_WINDOW,
        conn_window: DEFAULT_CONN_WINDOW,
        datagram_buffer: None,
    };

    /// Resolve from raw values (the test seam for [`QuicLimits::from_env`]). Unparseable or
    /// zero values fall back to the default; windows are clamped to at least [`MIN_WINDOW`], the
    /// connection window to at least the stream window, and the stream count to a ceiling.
    pub fn resolve(
        streams: Option<&str>,
        stream_window: Option<&str>,
        conn_window: Option<&str>,
        datagram: Option<&str>,
    ) -> Self {
        let max_bidi_streams = parse::<u32>(streams)
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_MAX_STREAMS)
            .min(MAX_STREAMS_CEILING);
        let stream_window = parse::<u32>(stream_window)
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_STREAM_WINDOW)
            .max(MIN_WINDOW);
        let conn_window = parse::<u32>(conn_window)
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_CONN_WINDOW)
            .max(stream_window);
        let datagram_buffer = parse::<usize>(datagram).filter(|&n| n > 0);
        Self {
            max_bidi_streams,
            stream_window,
            conn_window,
            datagram_buffer,
        }
    }

    pub fn from_env() -> Self {
        Self::resolve(
            env(QUIC_MAX_STREAMS_ENV).as_deref(),
            env(QUIC_STREAM_WINDOW_ENV).as_deref(),
            env(QUIC_CONN_WINDOW_ENV).as_deref(),
            env(QUIC_DATAGRAM_BUFFER_ENV).as_deref(),
        )
    }

    /// Apply to a transport config. The agent opens no unidirectional streams and uses no
    /// datagrams, so a peer is allowed none of either unless the datagram buffer is configured.
    pub fn apply(&self, t: &mut quinn::TransportConfig) {
        t.max_concurrent_bidi_streams(self.max_bidi_streams.into());
        t.max_concurrent_uni_streams(0u32.into());
        t.stream_receive_window(self.stream_window.into());
        t.receive_window(self.conn_window.into());
        t.datagram_receive_buffer_size(self.datagram_buffer);
    }
}

/// Seconds-valued pre-authentication bound: 0, unset or garbage means the default, so the bound
/// can never be switched off by accident.
fn preauth(raw: Option<&str>) -> Duration {
    Duration::from_secs(
        parse::<u64>(raw)
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_PREAUTH_SECS),
    )
}

/// Time a relayed stream has to complete its handshake and local-auth gate.
pub fn relay_setup_timeout() -> Duration {
    preauth(env(RELAY_SETUP_SECS_ENV).as_deref())
}

/// [`relay_setup_timeout`] from a raw value.
pub fn relay_setup_timeout_from(raw: Option<&str>) -> Duration {
    preauth(raw)
}

/// Time a relayed raw stream has to deliver its first byte.
pub fn relay_first_byte_timeout() -> Duration {
    preauth(env(RELAY_FIRST_BYTE_SECS_ENV).as_deref())
}

/// [`relay_first_byte_timeout`] from a raw value.
pub fn relay_first_byte_timeout_from(raw: Option<&str>) -> Duration {
    preauth(raw)
}

/// Idle bound for an established relayed raw stream; `None` (the default) never times out.
pub fn relay_idle_timeout() -> Option<Duration> {
    relay_idle_timeout_from(env(RELAY_IDLE_SECS_ENV).as_deref())
}

/// [`relay_idle_timeout`] from a raw value.
pub fn relay_idle_timeout_from(raw: Option<&str>) -> Option<Duration> {
    parse::<u64>(raw)
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_apply_when_unset_or_invalid() {
        assert_eq!(
            QuicLimits::resolve(None, None, None, None),
            QuicLimits::DEFAULT
        );
        assert_eq!(
            QuicLimits::resolve(Some("x"), Some(""), Some("-1"), Some("nope")),
            QuicLimits::DEFAULT
        );
        assert_eq!(
            QuicLimits::resolve(Some("0"), Some("0"), Some("0"), Some("0")),
            QuicLimits::DEFAULT
        );
    }

    #[test]
    fn values_are_clamped_to_a_sane_range() {
        let l = QuicLimits::resolve(Some("999999"), Some("10"), Some("10"), None);
        assert_eq!(l.max_bidi_streams, MAX_STREAMS_CEILING);
        assert_eq!(l.stream_window, MIN_WINDOW);
        assert_eq!(
            l.conn_window, MIN_WINDOW,
            "connection window never below the stream window"
        );
        let l = QuicLimits::resolve(None, Some("8388608"), Some("1048576"), Some("4096"));
        assert_eq!(l.stream_window, 8_388_608);
        assert_eq!(l.conn_window, 8_388_608);
        assert_eq!(l.datagram_buffer, Some(4096));
    }

    #[test]
    fn defaults_leave_room_for_sustained_throughput() {
        // 100 ms path: stream window / RTT >= 20 MB/s per stream, far above a desktop stream.
        let per_stream_bytes_per_sec = u64::from(DEFAULT_STREAM_WINDOW) * 10;
        assert!(per_stream_bytes_per_sec >= 20_000_000);
    }

    #[test]
    fn preauth_bounds_cannot_be_disabled() {
        assert_eq!(relay_setup_timeout_from(None), Duration::from_secs(30));
        assert_eq!(relay_setup_timeout_from(Some("0")), Duration::from_secs(30));
        assert_eq!(
            relay_first_byte_timeout_from(Some("junk")),
            Duration::from_secs(30)
        );
        assert_eq!(
            relay_first_byte_timeout_from(Some("5")),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn idle_bound_is_opt_in() {
        assert_eq!(relay_idle_timeout_from(None), None);
        assert_eq!(relay_idle_timeout_from(Some("0")), None);
        assert_eq!(
            relay_idle_timeout_from(Some("600")),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn applied_config_builds() {
        let mut t = quinn::TransportConfig::default();
        QuicLimits::DEFAULT.apply(&mut t);
    }

    #[tokio::test]
    async fn quic_peer_cannot_exceed_the_stream_limit() {
        let limits = QuicLimits {
            max_bidi_streams: 2,
            ..QuicLimits::DEFAULT
        };
        let (server, cert) = crate::transport::build_direct_listener_with(
            (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            limits,
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let held = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            // Hold the connection open; never read, never close.
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(conn);
        });
        let client = crate::transport::dial_quic(addr, cert).await.unwrap();
        for _ in 0..2 {
            let (mut s, _r) = client.open_bi().await.unwrap();
            s.write_all(b"x").await.unwrap();
        }
        let third = tokio::time::timeout(Duration::from_millis(500), client.open_bi()).await;
        assert!(
            third.is_err(),
            "a third stream must wait for credit that never comes"
        );
        held.abort();
    }
}
