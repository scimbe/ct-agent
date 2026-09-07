//! The one process-wide `reqwest::Client`.
//!
//! Before this module every HTTP call site built its own client on the spot
//! (`reqwest::Client::builder()...build()` or a bare `reqwest::Client::new()`).
//! Each build constructs a fresh TLS config, root-store and connector, and each
//! resulting client owns a connection pool that is thrown away the moment the
//! call returns -- so a renewal loop or bridge tool polling the control plane
//! every few minutes re-did a full TLS handshake every time, in a process that
//! is meant to run for months. One shared client means one connection pool
//! and one TLS session cache per process: keep-alive and session resumption
//! actually get to work across calls.
//!
//! Semantics at every migrated call site are unchanged: a site that relied on
//! a whole-request timeout other than [`DEFAULT_TIMEOUT`] applies its own via
//! `RequestBuilder::timeout` (reqwest honours a per-request timeout over the
//! client's). Sites that need a *different* client configuration (a custom
//! redirect policy, a download-specific user agent) keep their own builder.

use std::sync::OnceLock;
use std::time::Duration;

/// Whole-request bound of the shared client. The value the majority of the
/// migrated sites already used (`manifest publish`, the bridge tools, the ACME
/// directory fetch); the others override it per request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on establishing a new connection (TCP + TLS). Previously no site set
/// one -- the whole-request timeout covered it implicitly. Stated explicitly
/// here so a stalled connect fails fast even under a generous request bound.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an idle pooled connection is kept before being dropped. Long enough
/// that a 15-minute admission poll does not benefit (that is a fresh connect
/// anyway), short enough that a burst of bridge-tool calls reuses one
/// connection without leaving sockets open for hours afterwards.
pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

static SHARED: OnceLock<reqwest::Client> = OnceLock::new();

/// The process-wide client. Cheap to call: `reqwest::Client` is an `Arc` handle,
/// so every caller shares the same pool. Built once with [`DEFAULT_TIMEOUT`],
/// [`CONNECT_TIMEOUT`], [`POOL_IDLE_TIMEOUT`] and a `ct-agent/<version>` user
/// agent; a builder failure (an unlikely TLS-backend build error) falls back to
/// `reqwest::Client::new()` -- the same fallback idiom the individual sites used,
/// a client without the intended timeouts being strictly safer than a panic
/// (ct-agent#176).
pub fn shared() -> reqwest::Client {
    SHARED
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(DEFAULT_TIMEOUT)
                .user_agent(format!("ct-agent/{}", env!("CARGO_PKG_VERSION")))
                .pool_idle_timeout(POOL_IDLE_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_returns_a_client_on_every_call() {
        // `Client` is a cloneable handle; both calls must succeed and hand out a
        // usable client. Nothing is sent -- building the request is enough to
        // prove the handle is live.
        let a = shared();
        let b = shared();
        let req_a = a.get("http://127.0.0.1:9/").build();
        let req_b = b.get("http://127.0.0.1:9/").build();
        assert!(req_a.is_ok(), "first shared() client builds a request");
        assert!(req_b.is_ok(), "second shared() client builds a request");
    }

    #[test]
    fn per_request_timeout_overrides_the_default() {
        let req = shared().get("http://127.0.0.1:9/").timeout(Duration::from_secs(5)).build().unwrap();
        assert_eq!(req.timeout(), Some(&Duration::from_secs(5)));
    }
}
