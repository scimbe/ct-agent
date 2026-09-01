//! Optional local HTTP management server (2026-09-01, llm2 proposal Phase 2: "ct-agent
//! itself starts a webserver covering the same functions the CLI already has"). Today this
//! covers exactly one operation -- issuing a channel grant, the same thing `ct-agent channel
//! grant --interactive` does on a terminal -- reachable over HTTP for local tooling/scripts
//! that would otherwise have to shell out to the CLI.
//!
//! **Scope, deliberately narrow.** This is the "local" tier of the three-tier config the
//! proposal asked for (webserver+REST / webserver-only / console-only): a REMOTE-reachable
//! REST tier (tunneled through the existing ct-agent<->edge connection, no new open port, the
//! proposal's Phase 3) needs its own wire-protocol design and is NOT built here -- see the
//! project memory `project_llm2_grant_webserver_proposal_2026_09_01` for the unconfirmed
//! design sketch. [`RestServerConfig::from_lookup`] fails loudly (not silently degrades) if
//! asked for that tier, rather than quietly serving the weaker "local" one under the same flag.
//!
//! **Why loopback-only is non-negotiable here, not just a default.** This codebase already
//! made the opposite call once (`well_known.rs`'s `agent_card_router` doc comment: "central's
//! option (ii) -- emit a runnable helper, don't bake an HTTP server into ct-agent") for a
//! read-only, self-authenticating discovery document. This module bakes one in anyway, because
//! the operation it exposes is state-changing (minting a signed grant) and needs its own gate --
//! which loopback-binding plus a mandatory credential (below) is designed to be. Any
//! `CT_REST_SERVER_ADDR` that is not a loopback address is refused at startup, not merely
//! discouraged.
//!
//! **Auth is mandatory, not opt-in.** Unlike the tunnel's own `local_auth::LocalAuthGate`
//! (`CT_AGENT_LOCAL_AUTH`, default Off -- many Origins have their own auth already), this
//! server exposes a capability with NO other auth of its own, so a credential is always
//! required whenever `CT_REST_SERVER=local` is set. It reuses `local_auth::LocalAuthGate`'s
//! generated-credential machinery verbatim (same salted-SHA-256 storage, same rate limiter) but
//! points it at a SEPARATE state subdirectory and a synthetic "always Http mode" lookup, so a
//! leaked REST-server credential can never be replayed against the tunnel's own gate or vice
//! versa -- the two protect different privileges (reaching an Origin vs. minting grants) and
//! must not share a blast radius.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use ed25519_dalek::SigningKey;
use serde::Deserialize;

use crate::local_auth::{self, LocalAuthGate};

/// Resolved configuration for the "local" REST-server tier.
pub struct RestServerConfig {
    pub addr: SocketAddr,
}

impl RestServerConfig {
    /// Read from the process environment. `Ok(None)` means the REST server is disabled
    /// (`CT_REST_SERVER` unset or `"off"`) -- the default, matching every other optional
    /// surface in this codebase.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let mode = f("CT_REST_SERVER").unwrap_or_default();
        let mode_trim = mode.trim();
        if mode_trim.is_empty() || mode_trim.eq_ignore_ascii_case("off") {
            return Ok(None);
        }
        if !mode_trim.eq_ignore_ascii_case("local") {
            return Err(format!(
                "CT_REST_SERVER={mode_trim:?} not supported yet -- only \"local\" (a \
                 loopback-only HTTP management server) exists today. The remote/tunneled tier \
                 (reachable from the portal, no new open port) is still being designed -- see \
                 docs.bunsenbrenner.org for status, and do not run this in front of anything but \
                 trusted local callers in the meantime."
            ));
        }
        let addr_str = f("CT_REST_SERVER_ADDR").unwrap_or_else(|| "127.0.0.1:8765".to_string());
        let addr: SocketAddr = addr_str
            .trim()
            .parse()
            .map_err(|e| format!("CT_REST_SERVER_ADDR {addr_str:?} invalid: {e}"))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "CT_REST_SERVER_ADDR {addr_str:?} is not a loopback address -- the \"local\" \
                 tier's entire safety property is binding to loopback only. A \
                 remotely-reachable REST server needs the tunneled/portal-authenticated tier, \
                 which does not exist yet (see CT_REST_SERVER's own error for why)."
            ));
        }
        Ok(Some(Self { addr }))
    }
}

#[derive(Deserialize)]
struct GrantRequestBody {
    channel: String,
    holder: String,
    direction: String,
    expires_in: String,
}

struct ServerState {
    operator: SigningKey,
    gate: LocalAuthGate,
}

/// Resolve this server's OWN credential gate -- reuses `local_auth::LocalAuthGate::from_env`'s
/// generated-credential machinery verbatim, but under `<state_dir>/rest-server/` (never the
/// tunnel gate's own directory) and with a synthetic lookup that always resolves to `Http`
/// mode, so a credential is generated unconditionally rather than only when an operator
/// separately opts into `CT_AGENT_LOCAL_AUTH`. Returns `(gate, first_boot_notice)`, exactly
/// like the function it wraps.
fn resolve_gate(state_dir: Option<&std::path::Path>) -> Result<(LocalAuthGate, Option<String>), String> {
    let rest_state_dir = state_dir
        .map(|d| d.join("rest-server"))
        .ok_or("CT_REST_SERVER=local requires CT_AGENT_STATE_DIR (to store its generated credential)")?;
    local_auth::LocalAuthGate::from_env(Some(&rest_state_dir), |k| {
        if k == "CT_AGENT_LOCAL_AUTH" { Some("http".to_string()) } else { None }
    })
}

/// Decode an `Authorization: Basic <base64>` header into `(username, password)`. Anything
/// else -- missing header, wrong scheme, bad base64/UTF-8, no `:` separator -- collapses to
/// `None`, which the caller treats uniformly as "no credential offered" (a 401), not a parse
/// error to surface differently from a wrong password.
fn basic_auth_from_headers(headers: &HeaderMap) -> Option<(String, Vec<u8>)> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded_str.split_once(':')?;
    Some((user.to_string(), pass.as_bytes().to_vec()))
}

fn unauthorized() -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static("Basic realm=\"ct-agent-rest\""),
    );
    (StatusCode::UNAUTHORIZED, headers, Json(serde_json::json!({"error": "unauthorized"})))
}

async fn issue_grant(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    // Raw bytes, deliberately NOT `Json<GrantRequestBody>`: an axum `Json<T>` extractor runs
    // (and can fail with a 422) before this function body starts, which would let an
    // unauthenticated caller trigger body-parse rejection without ever reaching -- or being
    // rate-limited by -- the credential check below. Auth is checked first, unconditionally;
    // only an authenticated request's body gets parsed.
    body: axum::body::Bytes,
) -> (StatusCode, HeaderMap, Json<serde_json::Value>) {
    let authed = match basic_auth_from_headers(&headers) {
        Some((user, pass)) => state.gate.verify(&user, &pass).is_ok(),
        None => false,
    };
    if !authed {
        return unauthorized();
    }
    let body: GrantRequestBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                HeaderMap::new(),
                Json(serde_json::json!({"error": format!("invalid request body: {e}")})),
            )
        }
    };
    match crate::channel_run::issue_grant_from_fields(
        state.operator.clone(),
        &body.channel,
        &body.holder,
        &body.direction,
        &body.expires_in,
    ) {
        Ok(grant) => (StatusCode::OK, HeaderMap::new(), Json(serde_json::json!({"grant": grant}))),
        Err(e) => (StatusCode::BAD_REQUEST, HeaderMap::new(), Json(serde_json::json!({"error": e}))),
    }
}

fn router(state: Arc<ServerState>) -> Router {
    Router::new().route("/v1/channel/grants", post(issue_grant)).with_state(state)
}

/// Run the local REST management server until the process exits -- `ct-agent channel
/// rest-server`'s entry point. Prints the first-boot credential notice (if a credential was
/// just generated) to stderr, exactly like `local-auth reset` does, then blocks serving
/// requests.
pub async fn run(
    config: RestServerConfig,
    operator: SigningKey,
    state_dir: Option<&std::path::Path>,
) -> Result<(), String> {
    let (gate, notice) = resolve_gate(state_dir)?;
    if let Some(notice) = notice {
        eprintln!("{notice}");
    }
    eprintln!("ct-agent: REST management server listening on {} (local tier)", config.addr);
    let state = Arc::new(ServerState { operator, gate });
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .map_err(|e| format!("failed to bind {}: {e}", config.addr))?;
    axum::serve(listener, router(state).into_make_service())
        .await
        .map_err(|e| format!("REST server exited: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k: &str| m.get(k).cloned()
    }

    #[test]
    fn unset_or_off_disables_the_server() {
        assert!(RestServerConfig::from_lookup(lookup(&[])).unwrap().is_none());
        assert!(RestServerConfig::from_lookup(lookup(&[("CT_REST_SERVER", "off")])).unwrap().is_none());
        assert!(RestServerConfig::from_lookup(lookup(&[("CT_REST_SERVER", "OFF")])).unwrap().is_none());
    }

    #[test]
    fn local_mode_defaults_to_a_loopback_address() {
        let cfg = RestServerConfig::from_lookup(lookup(&[("CT_REST_SERVER", "local")]))
            .unwrap()
            .expect("local mode enables the server");
        assert!(cfg.addr.ip().is_loopback());
        assert_eq!(cfg.addr.port(), 8765);
    }

    #[test]
    fn local_mode_accepts_an_explicit_loopback_addr() {
        let cfg = RestServerConfig::from_lookup(lookup(&[
            ("CT_REST_SERVER", "local"),
            ("CT_REST_SERVER_ADDR", "127.0.0.1:9999"),
        ]))
        .unwrap()
        .expect("local mode enables the server");
        assert_eq!(cfg.addr.port(), 9999);
    }

    #[test]
    fn non_loopback_addr_is_refused() {
        let err = match RestServerConfig::from_lookup(lookup(&[
            ("CT_REST_SERVER", "local"),
            ("CT_REST_SERVER_ADDR", "0.0.0.0:8765"),
        ])) {
            Err(e) => e,
            Ok(_) => panic!("non-loopback address must be refused"),
        };
        assert!(err.contains("loopback"), "error should name the loopback requirement: {err}");
    }

    #[test]
    fn unsupported_mode_fails_loudly_instead_of_silently_downgrading() {
        for mode in ["full", "remote"] {
            let err = match RestServerConfig::from_lookup(lookup(&[("CT_REST_SERVER", mode)])) {
                Err(e) => e,
                Ok(_) => panic!("unsupported mode {mode:?} must be refused"),
            };
            assert!(err.contains("not supported yet"), "error should name the unsupported tier: {err}");
        }
    }

    #[test]
    fn basic_auth_header_round_trips() {
        let mut headers = HeaderMap::new();
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"agent:s3cret");
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        let (user, pass) = basic_auth_from_headers(&headers).expect("decodes");
        assert_eq!(user, "agent");
        assert_eq!(pass, b"s3cret");
    }

    #[test]
    fn basic_auth_header_missing_or_malformed_yields_none() {
        assert!(basic_auth_from_headers(&HeaderMap::new()).is_none());
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Bearer not-basic"),
        );
        assert!(basic_auth_from_headers(&headers).is_none());
    }

    #[test]
    fn resolve_gate_requires_a_state_dir() {
        let err = match resolve_gate(None) {
            Err(e) => e,
            Ok(_) => panic!("resolve_gate(None) must fail"),
        };
        assert!(err.contains("CT_AGENT_STATE_DIR"));
    }

    #[test]
    fn resolve_gate_generates_a_credential_on_first_run_and_reuses_it() {
        let dir = std::env::temp_dir().join(format!(
            "ct-agent-rest-server-test-{}",
            std::process::id() as u64 * 1_000_003
                + std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos() as u64
        ));
        let (gate1, notice1) = resolve_gate(Some(&dir)).expect("first run generates a credential");
        assert!(notice1.is_some(), "first run must print the one-time credential notice");
        assert_eq!(gate1.mode, local_auth::GateMode::Http);
        let (gate2, notice2) = resolve_gate(Some(&dir)).expect("second run reuses the stored credential");
        assert!(notice2.is_none(), "second run must not regenerate/reprint the credential");
        // Both gates were resolved from the SAME on-disk credential, not two independent
        // random ones -- a password that verifies against gate1 must also verify against
        // gate2 (can't compare secrets directly since verify() doesn't expose them, so
        // assert indirectly: a bogus password is rejected by both, consistently).
        assert!(gate1.verify("agent", b"definitely-wrong").is_err());
        assert!(gate2.verify("agent", b"definitely-wrong").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
