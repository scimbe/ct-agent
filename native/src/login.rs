//! `ct-agent login` — RFC 8628 (OAuth 2.0 Device Authorization Grant) against the
//! Keycloak realm's public `ct-agent-cli` client (device grant enabled, no client
//! secret — a CLI cannot keep one confidential), so an operator no longer has to log
//! into the portal in a browser and hand-copy a bearer token into `CT_OIDC_TOKEN`.
//!
//! Three pieces:
//!
//! 1. [`request_device_code`] / [`poll_for_token`]: the RFC 8628 state machine —
//!    `POST {issuer}/protocol/openid-connect/auth/device` to get a `user_code` +
//!    `verification_uri` to show the operator, then poll
//!    `POST {issuer}/protocol/openid-connect/token` at the server-specified
//!    `interval` until the operator finishes (or declines, or the code expires).
//!    `{issuer}` reuses the exact `CT_OIDC_ISSUER` knob and
//!    `<issuer>/protocol/openid-connect/{auth,token}` derivation CADS-Tunnel's own
//!    portal login already uses (`crates/control-plane/src/portal.rs`'s
//!    `PortalOidc::from_lookup`) — one issuer convention across both repos, not a
//!    redundant second one.
//! 2. [`StoredToken`] + [`persist_stored_token`]/[`read_stored_token`]: the on-disk
//!    cache, written via [`crate::secret_file::write_private`] (never a plain
//!    `fs::write` — see that module's doc comment for why the create-time mode
//!    matters). Located by [`token_store_path`]: an explicit
//!    `CT_AGENT_LOGIN_TOKEN_FILE`, else `<CT_AGENT_STATE_DIR>/oidc-token.json`
//!    (reusing the same persistent-volume convention `onboard.rs` already uses for
//!    the bound identity/agent/tenant files), else `$HOME/.ct-agent/oidc-token.json`
//!    for an interactive/dev machine with no state dir configured.
//! 3. [`resolve_oidc_token`]: what every `CT_OIDC_TOKEN` consumer now calls instead
//!    of reading the env var directly. `CT_OIDC_TOKEN` explicitly set in the
//!    environment always wins (existing scripts/CI keep working unchanged); only
//!    when it is UNSET does this fall back to the stored token, transparently
//!    refreshing it first if it is expired (or within [`ACCESS_TOKEN_EXPIRY_SKEW`]
//!    of expiring) and a refresh token was stored. No refresh token, or a refresh
//!    that fails, is a loud error telling the operator to run `ct-agent login`
//!    again — never a silent fall-through to a token that is probably already
//!    rejected server-side.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// The realm's public, device-grant-enabled CLI client (no client secret — see this
/// module's doc comment). Overridable via `CT_OIDC_CLI_CLIENT_ID` for a realm that
/// names it differently.
const DEFAULT_CLIENT_ID: &str = "ct-agent-cli";

/// Safety margin before a stored access token's recorded expiry: a token judged
/// "still valid" here must survive the network round-trip to whatever endpoint
/// actually uses it, not merely be valid at the instant of this check.
const ACCESS_TOKEN_EXPIRY_SKEW_SECS: u64 = 30;

/// Default request timeout for every call this module makes (device-code request,
/// token poll, refresh) — matches the timeout this codebase's other one-shot
/// `reqwest::Client`s already use (see `dns01_propagation::build_http`).
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// RFC 8628 §3.2 device authorization response.
#[derive(Debug, Clone, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

/// The token endpoint's success response (RFC 6749 §5.1) — a subset shared by the
/// device-grant poll and the refresh-grant call, both of which land here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    /// Seconds until the access token expires, relative to *this response*. `None`
    /// only if the IdP omits it — Keycloak always sends it, but a token that
    /// arrives with it missing is treated as already stale (see
    /// [`StoredToken::from_token_response`]) rather than trusted indefinitely.
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_expires_in: Option<u64>,
}

/// The token endpoint's error response (RFC 6749 §5.2 / RFC 8628 §3.5).
#[derive(Debug, Clone, Deserialize)]
struct TokenErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

impl Default for TokenErrorResponse {
    fn default() -> Self {
        Self { error: "unknown_error".to_string(), error_description: None }
    }
}

/// Outcome of a device-grant poll or a refresh call.
#[derive(Debug)]
pub enum LoginError {
    /// RFC 8628 `expired_token` (the user never finished authorizing in time), or
    /// this client's own [`request_device_code`]-supplied `expires_in` deadline
    /// elapsed first (belt-and-suspenders — a clock-skewed or non-compliant IdP
    /// must not poll forever).
    ExpiredToken,
    /// RFC 8628 `access_denied` — the user declined at the verification page.
    AccessDenied,
    /// A network-level failure (connect, timeout, TLS, unparseable body).
    Http(String),
    /// Any other OAuth `error` the token endpoint returned (e.g. `invalid_grant`
    /// on a dead refresh token, `invalid_client`).
    Other(String),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoginError::ExpiredToken => write!(f, "expired_token"),
            LoginError::AccessDenied => write!(f, "access_denied"),
            LoginError::Http(m) => write!(f, "{m}"),
            LoginError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for LoginError {}

/// `{issuer}/protocol/openid-connect/auth/device` — Keycloak's device-authorization
/// endpoint, same trailing-slash handling as `PortalOidc::from_lookup`'s derivation.
fn device_auth_url(issuer: &str) -> String {
    format!("{}/protocol/openid-connect/auth/device", issuer.trim_end_matches('/'))
}

/// `{issuer}/protocol/openid-connect/token` — same derivation as `device_auth_url`.
fn token_url(issuer: &str) -> String {
    format!("{}/protocol/openid-connect/token", issuer.trim_end_matches('/'))
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder().timeout(HTTP_TIMEOUT).build().unwrap_or_else(|_| reqwest::Client::new())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `POST {device_auth_url}`: `client_id` + `scope=openid`, per RFC 8628 §3.1. Public
/// client, no secret — the whole point of the device grant here.
async fn request_device_code(
    http: &reqwest::Client,
    device_auth_url: &str,
    client_id: &str,
) -> Result<DeviceCodeResponse, String> {
    let resp = http
        .post(device_auth_url)
        .form(&[("client_id", client_id), ("scope", "openid")])
        .send()
        .await
        .map_err(|e| format!("device authorization request to {device_auth_url} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("device authorization request to {device_auth_url} failed: {status} {body}"));
    }
    resp.json()
        .await
        .map_err(|e| format!("device authorization response from {device_auth_url} was not valid JSON: {e}"))
}

/// RFC 8628 §3.4/§3.5 device-grant poll loop against `token_url`, waking every
/// `interval` (adjusted on `slow_down`, RFC 8628 §3.5) until success, an
/// unrecoverable OAuth error, or `expires_in` elapses client-side.
///
/// `expires_in` is a wall-clock BUDGET, not a hard IdP-side cutoff this function
/// merely relays: even an IdP that (incorrectly) never returns `expired_token`
/// itself is still bounded, so this never polls forever.
async fn poll_for_token(
    http: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    device_code: &str,
    interval: Duration,
    expires_in: Duration,
) -> Result<TokenResponse, LoginError> {
    poll_for_token_with_backoff(http, token_url, client_id, device_code, interval, expires_in, SLOW_DOWN_BACKOFF).await
}

/// RFC 8628 §3.5's minimum `slow_down` back-off, applied every time the token
/// endpoint returns `slow_down` (added to the interval each time, so repeated
/// `slow_down`s keep backing off further).
const SLOW_DOWN_BACKOFF: Duration = Duration::from_secs(5);

/// [`poll_for_token`]'s real implementation, with the `slow_down` back-off amount
/// injectable so tests can exercise the back-off behavior without a multi-second
/// real (or paused-clock-fragile — real localhost I/O interleaved with a paused
/// clock proved unreliable here) sleep. Production always goes through
/// [`poll_for_token`], which fixes it at the real [`SLOW_DOWN_BACKOFF`].
#[allow(clippy::too_many_arguments)]
async fn poll_for_token_with_backoff(
    http: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    device_code: &str,
    mut interval: Duration,
    expires_in: Duration,
    slow_down_backoff: Duration,
) -> Result<TokenResponse, LoginError> {
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() >= expires_in {
            return Err(LoginError::ExpiredToken);
        }
        tokio::time::sleep(interval).await;

        let resp = http
            .post(token_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", client_id),
            ])
            .send()
            .await
            .map_err(|e| LoginError::Http(e.to_string()))?;

        if resp.status().is_success() {
            return resp.json().await.map_err(|e| LoginError::Http(e.to_string()));
        }

        let body: TokenErrorResponse = resp.json().await.unwrap_or_default();
        match body.error.as_str() {
            "authorization_pending" => continue,
            // RFC 8628 §3.5: back off by (at least) the configured amount and keep polling.
            "slow_down" => {
                interval += slow_down_backoff;
                continue;
            }
            "expired_token" => return Err(LoginError::ExpiredToken),
            "access_denied" => return Err(LoginError::AccessDenied),
            other => return Err(LoginError::Other(body.error_description.unwrap_or_else(|| other.to_string()))),
        }
    }
}

/// `POST {token_url}` with `grant_type=refresh_token` (RFC 6749 §6).
async fn refresh_access_token(
    http: &reqwest::Client,
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse, LoginError> {
    let resp = http
        .post(token_url)
        .form(&[("grant_type", "refresh_token"), ("refresh_token", refresh_token), ("client_id", client_id)])
        .send()
        .await
        .map_err(|e| LoginError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let body: TokenErrorResponse = resp.json().await.unwrap_or_default();
        return Err(LoginError::Other(body.error_description.unwrap_or(body.error)));
    }
    resp.json().await.map_err(|e| LoginError::Http(e.to_string()))
}

/// What `ct-agent login` persists to disk — the token endpoint's response plus
/// enough context (`issuer`/`client_id`, absolute expiry instants) that a later
/// `resolve_oidc_token()` call needs no other config to decide whether to refresh.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct StoredToken {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    /// Unix epoch seconds. `None` means the IdP's response carried no `expires_in`
    /// at all — treated as already-stale by [`resolve_oidc_token`] (never trusted
    /// indefinitely just because we don't know better).
    access_expires_at: Option<u64>,
    #[serde(default)]
    refresh_expires_at: Option<u64>,
    issuer: String,
    client_id: String,
}

impl StoredToken {
    fn from_token_response(tok: &TokenResponse, issuer: &str, client_id: &str, now: u64) -> Self {
        Self {
            access_token: tok.access_token.clone(),
            refresh_token: tok.refresh_token.clone(),
            access_expires_at: tok.expires_in.map(|secs| now + secs),
            refresh_expires_at: tok.refresh_expires_in.map(|secs| now + secs),
            issuer: issuer.to_string(),
            client_id: client_id.to_string(),
        }
    }
}

/// Where the stored login lives: an explicit `CT_AGENT_LOGIN_TOKEN_FILE`, else
/// `<CT_AGENT_STATE_DIR>/oidc-token.json` (the same persistent-state-directory
/// convention `onboard.rs`'s `OnboardedAgent::persist` already uses for the bound
/// identity), else `$HOME/.ct-agent/oidc-token.json` for a workstation with no
/// state dir configured.
fn token_store_path(f: impl Fn(&str) -> Option<String>) -> Result<PathBuf, String> {
    if let Some(p) = f("CT_AGENT_LOGIN_TOKEN_FILE").filter(|s| !s.trim().is_empty()) {
        return Ok(PathBuf::from(p));
    }
    if let Some(dir) = f("CT_AGENT_STATE_DIR").filter(|s| !s.trim().is_empty()) {
        return Ok(PathBuf::from(dir).join("oidc-token.json"));
    }
    if let Some(home) = f("HOME").filter(|s| !s.trim().is_empty()) {
        return Ok(PathBuf::from(home).join(".ct-agent").join("oidc-token.json"));
    }
    Err(
        "cannot determine where to store the login token: set CT_AGENT_LOGIN_TOKEN_FILE \
         (an explicit file path), CT_AGENT_STATE_DIR (a persistent state directory), or HOME"
            .to_string(),
    )
}

fn persist_stored_token(path: &Path, tok: &StoredToken) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(tok)
        .expect("StoredToken has no non-serializable fields (all String/Option<u64>)");
    crate::secret_file::write_private(path, &json)
}

fn read_stored_token(path: &Path) -> Result<StoredToken, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| format!("stored token file is corrupt: {e}"))
}

/// `ct-agent login`'s config: just the realm issuer (reusing `CT_OIDC_ISSUER`,
/// CADS-Tunnel's own knob for the exact same realm — see this module's doc
/// comment) and, rarely, an override of the public client id.
pub struct LoginConfig {
    pub issuer: String,
    pub client_id: String,
}

impl LoginConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let issuer = f("CT_OIDC_ISSUER").filter(|s| !s.trim().is_empty()).ok_or(
            "CT_OIDC_ISSUER required (the Keycloak realm URL, e.g. \
             https://auth.bunsenbrenner.org/realms/ct-demo — the same value the portal's \
             own login already uses)",
        )?;
        let client_id =
            f("CT_OIDC_CLI_CLIENT_ID").filter(|s| !s.trim().is_empty()).unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string());
        Ok(Self { issuer, client_id })
    }
}

/// `ct-agent login`: run the full RFC 8628 device flow interactively (prints the
/// verification URL/code to stderr, polls, persists on success) and report the
/// outcome to stdout/stderr. Returns `Err` with a message ready to print — never
/// panics on a declined or expired login, only on a config error.
pub async fn run_login(cfg: LoginConfig) -> Result<(), String> {
    let http = build_http_client();
    let device = request_device_code(&http, &device_auth_url(&cfg.issuer), &cfg.client_id).await?;

    eprintln!(
        "ct-agent: open the URL below and enter the code to finish logging in:\n\n    {}\n\n    code: {}\n",
        device.verification_uri, device.user_code
    );
    if let Some(complete) = &device.verification_uri_complete {
        eprintln!("Or, for one-click login:\n\n    {complete}\n");
    }
    eprintln!("waiting for you to authorize...");

    let interval = Duration::from_secs(device.interval.unwrap_or(5));
    let expires_in = Duration::from_secs(device.expires_in);
    let tok = poll_for_token(&http, &token_url(&cfg.issuer), &cfg.client_id, &device.device_code, interval, expires_in)
        .await
        .map_err(|e| match e {
            LoginError::ExpiredToken => {
                "login timed out waiting for authorization — run `ct-agent login` again".to_string()
            }
            LoginError::AccessDenied => "login was declined".to_string(),
            LoginError::Http(m) => format!("login failed: {m}"),
            LoginError::Other(m) => format!("login failed: {m}"),
        })?;

    let stored = StoredToken::from_token_response(&tok, &cfg.issuer, &cfg.client_id, now_unix());
    let path = token_store_path(|k| std::env::var(k).ok())?;
    persist_stored_token(&path, &stored).map_err(|e| format!("failed to save login at {}: {e}", path.display()))?;
    eprintln!("ct-agent: logged in — token saved to {}", path.display());
    Ok(())
}

/// What every `CT_OIDC_TOKEN` consumer now calls. `CT_OIDC_TOKEN` explicitly set in
/// the environment always wins (unchanged behavior for existing scripts/CI); only
/// when it is absent does this read the token `ct-agent login` stored, silently
/// refreshing it first if it is expired (or close to it) and a refresh token was
/// saved. No stored login, an unrefreshable stale token, or a failed refresh is a
/// loud error naming `ct-agent login` as the fix — never a silent fall-through to a
/// token that is probably already being rejected server-side.
pub async fn resolve_oidc_token() -> Result<String, String> {
    if let Some(t) = std::env::var("CT_OIDC_TOKEN").ok().filter(|s| !s.trim().is_empty()) {
        return Ok(t);
    }

    let path = token_store_path(|k| std::env::var(k).ok())?;
    let stored = read_stored_token(&path).map_err(|e| {
        format!(
            "CT_OIDC_TOKEN is not set and no stored login was found at {} ({e}). Run `ct-agent login`.",
            path.display()
        )
    })?;

    let now = now_unix();
    let is_stale = match stored.access_expires_at {
        Some(exp) => now + ACCESS_TOKEN_EXPIRY_SKEW_SECS >= exp,
        // Unknown expiry: never trusted indefinitely (see `StoredToken`'s doc comment).
        None => true,
    };
    if !is_stale {
        return Ok(stored.access_token);
    }

    let refresh_token = stored.refresh_token.clone().ok_or_else(|| {
        "the stored login has expired and no refresh token is available. Run `ct-agent login` again.".to_string()
    })?;
    let http = build_http_client();
    let refreshed = refresh_access_token(&http, &token_url(&stored.issuer), &stored.client_id, &refresh_token)
        .await
        .map_err(|e| format!("the stored login has expired and refreshing it failed ({e}). Run `ct-agent login` again."))?;

    let new_stored = StoredToken::from_token_response(&refreshed, &stored.issuer, &stored.client_id, now);
    persist_stored_token(&path, &new_stored)
        .map_err(|e| format!("refreshed the login but failed to save it at {}: {e}", path.display()))?;
    Ok(new_stored.access_token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State as AxState;
    use axum::routing::post;
    use axum::Router;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    /// Per-process scratch dir for the on-disk tests, same idiom as
    /// `secret_file::tests::scratch` — no dev-dependency needed for two files.
    fn scratch(what: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ct-login-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // ---- token-file persistence (secret_file.rs pattern) ----

    #[cfg(unix)]
    #[test]
    fn stored_token_file_is_created_at_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let path = dir.join("oidc-token.json");
        let tok = StoredToken {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            access_expires_at: Some(123),
            refresh_expires_at: Some(456),
            issuer: "https://kc.example/realms/ct".into(),
            client_id: "ct-agent-cli".into(),
        };

        persist_stored_token(&path, &tok).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the login token is a secret, never wider than 0600");
        assert_eq!(read_stored_token(&path).unwrap(), tok);
    }

    #[test]
    fn token_store_path_prefers_explicit_file_then_state_dir_then_home() {
        // Explicit file wins over everything else.
        let mut m = HashMapAlias::new();
        m.insert("CT_AGENT_LOGIN_TOKEN_FILE".to_string(), "/explicit/path.json".to_string());
        m.insert("CT_AGENT_STATE_DIR".to_string(), "/state".to_string());
        m.insert("HOME".to_string(), "/home/x".to_string());
        assert_eq!(token_store_path(|k| m.get(k).cloned()).unwrap(), PathBuf::from("/explicit/path.json"));

        // No explicit file: CT_AGENT_STATE_DIR wins over HOME.
        let mut m = HashMapAlias::new();
        m.insert("CT_AGENT_STATE_DIR".to_string(), "/state".to_string());
        m.insert("HOME".to_string(), "/home/x".to_string());
        assert_eq!(token_store_path(|k| m.get(k).cloned()).unwrap(), PathBuf::from("/state/oidc-token.json"));

        // Neither explicit file nor state dir: falls back to $HOME/.ct-agent.
        let mut m = HashMapAlias::new();
        m.insert("HOME".to_string(), "/home/x".to_string());
        assert_eq!(
            token_store_path(|k| m.get(k).cloned()).unwrap(),
            PathBuf::from("/home/x/.ct-agent/oidc-token.json")
        );

        // None of the three set: a clear config error, not a panic or a cwd guess.
        let m = HashMapAlias::new();
        assert!(token_store_path(|k| m.get(k).cloned()).is_err());
    }

    type HashMapAlias = std::collections::HashMap<String, String>;

    // ---- device-grant poll state machine ----

    /// A mock Keycloak device-authorization + token endpoint, driven by a small
    /// shared script so each test can dictate exactly what `/token` returns on
    /// each successive poll — same "minimal in-memory mock server, real HTTP
    /// round-trips" shape as `acme_client::tests::MockAcme`.
    struct MockIdp {
        /// One entry consumed per `/token` POST; the last entry repeats once
        /// exhausted (so a test only has to script the interesting prefix).
        script: Vec<MockTokenReply>,
        calls: AtomicU32,
        /// Wall-clock (virtual, under `start_paused`) instant of each `/token`
        /// call, so a test can assert on the actual spacing between polls.
        call_times: Mutex<Vec<tokio::time::Instant>>,
    }

    #[derive(Clone)]
    enum MockTokenReply {
        Pending,
        SlowDown,
        Success { access_token: &'static str, refresh_token: Option<&'static str>, expires_in: u64 },
        ExpiredToken,
        AccessDenied,
    }

    async fn spawn_mock_idp(script: Vec<MockTokenReply>) -> (String, Arc<MockIdp>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let state = Arc::new(MockIdp { script, calls: AtomicU32::new(0), call_times: Mutex::new(Vec::new()) });
        let app = Router::new()
            .route("/protocol/openid-connect/auth/device", post(device_auth))
            .route("/protocol/openid-connect/token", post(token))
            .with_state(state.clone());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base, state)
    }

    async fn device_auth() -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "device_code": "dc-1",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://kc.example/realms/ct/device",
            "verification_uri_complete": "https://kc.example/realms/ct/device?user_code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 1,
        }))
    }

    async fn token(AxState(s): AxState<Arc<MockIdp>>) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        s.call_times.lock().unwrap().push(tokio::time::Instant::now());
        let idx = s.calls.fetch_add(1, Ordering::SeqCst) as usize;
        let reply = s.script.get(idx).or_else(|| s.script.last()).cloned().unwrap_or(MockTokenReply::Pending);
        match reply {
            MockTokenReply::Pending => {
                (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "authorization_pending"})))
                    .into_response()
            }
            MockTokenReply::SlowDown => {
                (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "slow_down"}))).into_response()
            }
            MockTokenReply::ExpiredToken => {
                (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "expired_token"}))).into_response()
            }
            MockTokenReply::AccessDenied => {
                (StatusCode::BAD_REQUEST, axum::Json(serde_json::json!({"error": "access_denied"}))).into_response()
            }
            MockTokenReply::Success { access_token, refresh_token, expires_in } => (
                StatusCode::OK,
                axum::Json(serde_json::json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "expires_in": expires_in,
                    "token_type": "Bearer",
                })),
            )
                .into_response(),
        }
    }

    // These use small REAL durations rather than `start_paused` + a virtual clock:
    // `poll_for_token`'s loop interleaves `tokio::time::sleep` with a real HTTP
    // round-trip through the mock axum server on the same runtime, and that
    // combination proved unreliable under a paused clock (auto-advance and the
    // real localhost I/O raced, occasionally starving the mock server's task and
    // tripping the client-side budget early). Every duration below is small
    // enough that the whole module's test suite still runs in well under a
    // second; assertions use generous tolerance windows for a loaded CI runner.

    #[tokio::test]
    async fn poll_keeps_polling_through_authorization_pending_then_succeeds() {
        let (base, state) = spawn_mock_idp(vec![
            MockTokenReply::Pending,
            MockTokenReply::Pending,
            MockTokenReply::Success { access_token: "at-1", refresh_token: Some("rt-1"), expires_in: 300 },
        ])
        .await;
        let http = reqwest::Client::new();

        let tok = poll_for_token(
            &http,
            &format!("{base}/protocol/openid-connect/token"),
            "ct-agent-cli",
            "dc-1",
            Duration::from_millis(30),
            Duration::from_secs(10),
        )
        .await
        .expect("eventually succeeds");

        assert_eq!(tok.access_token, "at-1");
        assert_eq!(tok.refresh_token.as_deref(), Some("rt-1"));
        assert_eq!(state.calls.load(Ordering::SeqCst), 3, "two pending polls, then the success poll");
    }

    #[tokio::test]
    async fn poll_backs_off_on_slow_down_and_keeps_polling() {
        let (base, state) = spawn_mock_idp(vec![
            MockTokenReply::Pending,
            MockTokenReply::SlowDown,
            MockTokenReply::Pending,
            MockTokenReply::Success { access_token: "at-2", refresh_token: None, expires_in: 300 },
        ])
        .await;
        let http = reqwest::Client::new();
        let base_interval = Duration::from_millis(30);
        let backoff = Duration::from_millis(200);

        let tok = poll_for_token_with_backoff(
            &http,
            &format!("{base}/protocol/openid-connect/token"),
            "ct-agent-cli",
            "dc-1",
            base_interval,
            Duration::from_secs(10),
            backoff,
        )
        .await
        .expect("eventually succeeds");
        assert_eq!(tok.access_token, "at-2");

        let times = state.call_times.lock().unwrap();
        assert_eq!(times.len(), 4);
        // interval=base_interval until the slow_down at call #2; from then on
        // interval=base_interval+backoff. Lower bound is exact (the loop never
        // sleeps less); upper bound leaves headroom for scheduler jitter.
        let gap = |a: usize, b: usize| times[b].duration_since(times[a]);
        let slack = Duration::from_millis(150);
        assert!(gap(0, 1) >= base_interval && gap(0, 1) < base_interval + slack, "pre-slow_down gap ~{base_interval:?}: got {:?}", gap(0, 1));
        let backed_off = base_interval + backoff;
        assert!(gap(1, 2) >= backed_off && gap(1, 2) < backed_off + slack, "post-slow_down gap ~{backed_off:?}: got {:?}", gap(1, 2));
        assert!(gap(2, 3) >= backed_off && gap(2, 3) < backed_off + slack, "the new interval sticks for later polls too: got {:?}", gap(2, 3));
    }

    #[tokio::test]
    async fn poll_stops_on_expired_token() {
        let (base, _state) = spawn_mock_idp(vec![MockTokenReply::Pending, MockTokenReply::ExpiredToken]).await;
        let http = reqwest::Client::new();

        let err = poll_for_token(
            &http,
            &format!("{base}/protocol/openid-connect/token"),
            "ct-agent-cli",
            "dc-1",
            Duration::from_millis(30),
            Duration::from_secs(10),
        )
        .await
        .expect_err("expired_token must stop polling, not retry");
        assert!(matches!(err, LoginError::ExpiredToken));
    }

    #[tokio::test]
    async fn poll_stops_on_access_denied() {
        let (base, _state) = spawn_mock_idp(vec![MockTokenReply::AccessDenied]).await;
        let http = reqwest::Client::new();

        let err = poll_for_token(
            &http,
            &format!("{base}/protocol/openid-connect/token"),
            "ct-agent-cli",
            "dc-1",
            Duration::from_millis(30),
            Duration::from_secs(10),
        )
        .await
        .expect_err("access_denied must stop polling immediately");
        assert!(matches!(err, LoginError::AccessDenied));
    }

    #[tokio::test]
    async fn poll_gives_up_client_side_once_the_overall_budget_elapses() {
        // The IdP never says expired_token (a non-compliant/misbehaving one) --
        // this client's own `expires_in` budget must still bound the loop.
        let (base, state) = spawn_mock_idp(vec![MockTokenReply::Pending]).await;
        let http = reqwest::Client::new();

        let err = poll_for_token(
            &http,
            &format!("{base}/protocol/openid-connect/token"),
            "ct-agent-cli",
            "dc-1",
            Duration::from_millis(50),
            Duration::from_millis(120),
        )
        .await
        .expect_err("must give up once the client-side budget elapses");
        assert!(matches!(err, LoginError::ExpiredToken));
        assert!(state.calls.load(Ordering::SeqCst) <= 3, "bounded by the budget, not unbounded");
    }

    // ---- request_device_code ----

    #[tokio::test]
    async fn request_device_code_parses_the_full_rfc8628_response() {
        let (base, _state) = spawn_mock_idp(vec![]).await;
        let http = reqwest::Client::new();
        let d = request_device_code(&http, &format!("{base}/protocol/openid-connect/auth/device"), "ct-agent-cli")
            .await
            .unwrap();
        assert_eq!(d.device_code, "dc-1");
        assert_eq!(d.user_code, "ABCD-EFGH");
        assert_eq!(d.verification_uri, "https://kc.example/realms/ct/device");
        assert_eq!(d.verification_uri_complete.as_deref(), Some("https://kc.example/realms/ct/device?user_code=ABCD-EFGH"));
        assert_eq!(d.expires_in, 600);
        assert_eq!(d.interval, Some(1));
    }

    // ---- resolve_oidc_token / refresh ----

    /// Serializes every test that mutates process env vars (`CT_OIDC_TOKEN`,
    /// `CT_AGENT_LOGIN_TOKEN_FILE`, `CT_AGENT_STATE_DIR`, `HOME`) — `std::env::set_var`
    /// is process-global, so concurrent `cargo test` threads touching the same
    /// vars would otherwise race each other's assertions.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn clear_env() {
        for k in ["CT_OIDC_TOKEN", "CT_AGENT_LOGIN_TOKEN_FILE", "CT_AGENT_STATE_DIR"] {
            std::env::remove_var(k);
        }
    }

    #[tokio::test]
    async fn resolve_oidc_token_prefers_the_explicit_env_var() {
        let _g = ENV_MUTEX.lock().unwrap();
        clear_env();
        std::env::set_var("CT_OIDC_TOKEN", "explicit-env-token");
        // No stored file exists at all -- must not even be consulted.
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", "/nonexistent/dir/oidc-token.json");

        let tok = resolve_oidc_token().await.unwrap();
        assert_eq!(tok, "explicit-env-token");
        clear_env();
    }

    #[tokio::test]
    async fn resolve_oidc_token_falls_back_to_a_stored_unexpired_token() {
        let _g = ENV_MUTEX.lock().unwrap();
        clear_env();
        let dir = scratch("resolve-valid");
        let path = dir.join("oidc-token.json");
        let stored = StoredToken {
            access_token: "stored-valid".into(),
            refresh_token: None,
            access_expires_at: Some(now_unix() + 3600),
            refresh_expires_at: None,
            issuer: "https://kc.example/realms/ct".into(),
            client_id: "ct-agent-cli".into(),
        };
        persist_stored_token(&path, &stored).unwrap();
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", path.to_str().unwrap());

        let tok = resolve_oidc_token().await.unwrap();
        assert_eq!(tok, "stored-valid", "no network call needed -- the stored token isn't stale");
        clear_env();
    }

    #[tokio::test]
    async fn resolve_oidc_token_refreshes_an_expired_stored_token() {
        let _g = ENV_MUTEX.lock().unwrap();
        clear_env();
        let (base, _state) =
            spawn_mock_idp(vec![MockTokenReply::Success { access_token: "refreshed-at", refresh_token: Some("refreshed-rt"), expires_in: 300 }])
                .await;
        let dir = scratch("resolve-refresh");
        let path = dir.join("oidc-token.json");
        let stored = StoredToken {
            access_token: "stale".into(),
            refresh_token: Some("old-rt".into()),
            access_expires_at: Some(now_unix().saturating_sub(10)),
            refresh_expires_at: Some(now_unix() + 3600),
            issuer: base.clone(),
            client_id: "ct-agent-cli".into(),
        };
        persist_stored_token(&path, &stored).unwrap();
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", path.to_str().unwrap());

        let tok = resolve_oidc_token().await.unwrap();
        assert_eq!(tok, "refreshed-at");

        // The refreshed token is re-persisted so the next call doesn't refresh again.
        let reread = read_stored_token(&path).unwrap();
        assert_eq!(reread.access_token, "refreshed-at");
        assert_eq!(reread.refresh_token.as_deref(), Some("refreshed-rt"));
        clear_env();
    }

    #[tokio::test]
    async fn resolve_oidc_token_fails_loudly_with_no_refresh_token_available() {
        let _g = ENV_MUTEX.lock().unwrap();
        clear_env();
        let dir = scratch("resolve-no-refresh");
        let path = dir.join("oidc-token.json");
        let stored = StoredToken {
            access_token: "stale".into(),
            refresh_token: None,
            access_expires_at: Some(now_unix().saturating_sub(10)),
            refresh_expires_at: None,
            issuer: "https://kc.example/realms/ct".into(),
            client_id: "ct-agent-cli".into(),
        };
        persist_stored_token(&path, &stored).unwrap();
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", path.to_str().unwrap());

        let err = resolve_oidc_token().await.expect_err("expired + no refresh token must be a loud error");
        assert!(err.contains("ct-agent login"), "must point the operator at the fix: {err}");
        clear_env();
    }

    #[tokio::test]
    async fn resolve_oidc_token_fails_loudly_when_nothing_is_configured_at_all() {
        let _g = ENV_MUTEX.lock().unwrap();
        clear_env();
        // No CT_OIDC_TOKEN, and no stored file at the (deliberately bogus) explicit path.
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", "/nonexistent/dir/oidc-token.json");

        let err = resolve_oidc_token().await.expect_err("must fail loudly, not silently proceed unauthenticated");
        assert!(err.contains("ct-agent login"));
        clear_env();
    }
}
