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
//!    environment always wins (existing scripts/CI keep working unchanged); then
//!    `CT_OIDC_TOKEN_FILE` (piece 4); only when neither is set does this fall back
//!    to the stored token, transparently refreshing it first if it is expired (or
//!    within [`ACCESS_TOKEN_EXPIRY_SKEW_SECS`] of expiring) and a refresh token was
//!    stored. No refresh token, or a refresh the IdP REJECTS, is a loud error
//!    telling the operator to run `ct-agent login` again or to provide
//!    `CT_OIDC_TOKEN_FILE` — never a silent fall-through to a token that is
//!    probably already rejected server-side.
//! 4. Unattended operation (ct-agent#181). A sidecar that runs for months cannot
//!    answer "run `ct-agent login`", so three things degrade that case gracefully
//!    instead of silently breaking `channel register` and the `bridge/*` tools:
//!    * **`CT_OIDC_TOKEN_FILE`** -- a path to a file holding one bearer token (a
//!      long-lived service-account credential), read on EVERY resolve call so a
//!      rotated file is picked up without a restart. Trimmed; an empty file means
//!      "not configured" and the stored login is used. Precedence: `CT_OIDC_TOKEN`
//!      > `CT_OIDC_TOKEN_FILE` > the stored login.
//!    * **[`OidcCredentialState`]** / [`oidc_credential_state`]: what the stored
//!      credential looks like WITHOUT refreshing it -- `bridge/config` reports it as
//!      `oidc_credential` so the portal can say "expired" before an owner clicks a
//!      tool into an error.
//!    * **[`resolve_oidc_token_with_retry`]**: the bridge tools' entry point. A
//!      TRANSIENT refresh failure (the IdP unreachable, a 5xx) is retried with
//!      backoff; only a DEFINITIVE one (no refresh token, `invalid_grant`) surfaces
//!      the actionable message. The first time the credential is found expired and
//!      not refreshable, one structured line goes to stderr (once per process).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
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
    let status = resp.status();
    // ct-agent#181: only an OAuth error the IdP actually pronounced (`invalid_grant`
    // on a dead refresh token, RFC 6749 §5.2) is `Other` -- definitive to the retry
    // wrapper. A 5xx, or a non-JSON body from whatever answered in the IdP's place,
    // is `Http`: transient, worth retrying, never "run ct-agent login".
    if status.is_server_error() {
        return Err(LoginError::Http(format!("token endpoint answered {status}")));
    }
    if !status.is_success() {
        let body: TokenErrorResponse = resp
            .json()
            .await
            .map_err(|e| LoginError::Http(format!("token endpoint answered {status} with an unparseable body: {e}")))?;
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

    /// Expired, or within [`ACCESS_TOKEN_EXPIRY_SKEW_SECS`] of it, at `now`. An
    /// unknown expiry is stale (see the field's doc comment).
    fn is_stale(&self, now: u64) -> bool {
        match self.access_expires_at {
            Some(exp) => now + ACCESS_TOKEN_EXPIRY_SKEW_SECS >= exp,
            None => true,
        }
    }

    /// The stored refresh token, if there is one and -- when the IdP said how long
    /// it lives -- it has not expired itself at `now`.
    fn usable_refresh_token(&self, now: u64) -> Option<&str> {
        self.refresh_token
            .as_deref()
            .filter(|t| !t.is_empty())
            .filter(|_| self.refresh_expires_at.is_none_or(|exp| now < exp))
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
    // StoredToken has no non-serializable fields (all String/Option<u64>), so this
    // cannot fail in practice; surfaced as an io error rather than a panic (ct-agent#176).
    let json = serde_json::to_vec_pretty(tok).map_err(std::io::Error::other)?;
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

/// What the stored/env OIDC credential looks like right now, WITHOUT refreshing
/// anything (ct-agent#181). Reported by `bridge/config` as `oidc_credential`
/// (see [`OidcCredentialState::as_str`]); the fresh cases keep their pre-#181
/// spellings so the portal's hint mapping is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OidcCredentialState {
    /// `CT_OIDC_TOKEN` is set, or `CT_OIDC_TOKEN_FILE` names a non-empty file --
    /// either way the environment supplies the bearer and the stored login is moot.
    Env,
    /// A stored login whose access token is not (about to be) expired.
    StoredFresh,
    /// A stored login whose access token is expired but whose refresh token is
    /// present and, as far as its recorded expiry says, still good: the next
    /// resolve will refresh it. Working as designed, but worth showing.
    StoredExpiredRefreshable,
    /// A stored login that is expired AND cannot be refreshed (no refresh token,
    /// or the refresh token's own recorded expiry has passed). Every tool that
    /// needs a plane login will fail until a re-login or `CT_OIDC_TOKEN_FILE`.
    StoredExpiredNoRefresh,
    /// No credential of any kind (no env token, no readable stored login).
    None,
}

impl OidcCredentialState {
    /// The `oidc_credential` value `bridge/config` reports.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OidcCredentialState::Env => "env",
            OidcCredentialState::StoredFresh => "stored",
            OidcCredentialState::StoredExpiredRefreshable => "stored-expired-refreshable",
            OidcCredentialState::StoredExpiredNoRefresh => "stored-expired",
            OidcCredentialState::None => "none",
        }
    }
}

/// [`OidcCredentialState`] from the process environment and the stored login on
/// disk, judged against the wall clock. Never refreshes and never touches the
/// network. Emits the once-per-process degraded line (see [`note_degraded`]) when
/// it finds the credential expired and not refreshable.
pub(crate) fn oidc_credential_state() -> OidcCredentialState {
    let state = oidc_credential_state_from(|k| std::env::var(k).ok(), now_unix());
    if state == OidcCredentialState::StoredExpiredNoRefresh {
        note_degraded();
    }
    state
}

/// Pure core of [`oidc_credential_state`]: `f` is the env lookup (so tests drive it
/// with a map), `now` the clock. Applies exactly [`resolve_oidc_token`]'s
/// precedence and its expiry rule ([`StoredToken::is_stale`]).
fn oidc_credential_state_from(f: impl Fn(&str) -> Option<String>, now: u64) -> OidcCredentialState {
    if env_token(&f).is_some() {
        return OidcCredentialState::Env;
    }
    if let Ok(Some(_)) = token_from_file(&f) {
        return OidcCredentialState::Env;
    }
    let Ok(path) = token_store_path(&f) else {
        return OidcCredentialState::None;
    };
    let Ok(stored) = read_stored_token(&path) else {
        return OidcCredentialState::None;
    };
    if !stored.is_stale(now) {
        OidcCredentialState::StoredFresh
    } else if stored.usable_refresh_token(now).is_some() {
        OidcCredentialState::StoredExpiredRefreshable
    } else {
        OidcCredentialState::StoredExpiredNoRefresh
    }
}

/// `CT_OIDC_TOKEN`, if set to something non-blank.
fn env_token(f: impl Fn(&str) -> Option<String>) -> Option<String> {
    f("CT_OIDC_TOKEN").filter(|s| !s.trim().is_empty())
}

/// The bearer in the file `CT_OIDC_TOKEN_FILE` names (ct-agent#181), read fresh on
/// every call so a rotated file is picked up without a restart. `Ok(None)` when the
/// variable is unset/blank OR the file is empty after trimming ("not configured" --
/// the stored login is used instead); `Err` when the variable names a file that
/// cannot be read, which the caller treats as transient (a rotation in progress).
fn token_from_file(f: impl Fn(&str) -> Option<String>) -> Result<Option<String>, String> {
    let Some(path) = f("CT_OIDC_TOKEN_FILE").map(|p| p.trim().to_string()).filter(|p| !p.is_empty()) else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("CT_OIDC_TOKEN_FILE={path} could not be read: {e}"))?;
    let token = raw.trim();
    Ok((!token.is_empty()).then(|| token.to_string()))
}

/// The tail of every DEFINITIVE resolve error: what an operator can do about it,
/// including the unattended option (ct-agent#181).
const UNATTENDED_HINT: &str = "or provide a long-lived credential via CT_OIDC_TOKEN_FILE";

/// Printed at most once per process, the first time a resolve or a state probe
/// finds the stored credential expired and not refreshable (ct-agent#181). One
/// structured line an operator can alert on, rather than the same failure text
/// once per bridge-tool call.
static DEGRADED_LOGGED: AtomicBool = AtomicBool::new(false);

fn note_degraded() {
    if !DEGRADED_LOGGED.swap(true, Ordering::SeqCst) {
        eprintln!(
            "ct-agent: oidc credential expired and not refreshable — bridge tools needing a plane login \
             will fail until re-login or CT_OIDC_TOKEN_FILE is provided"
        );
    }
}

/// How a resolve failed, for [`resolve_oidc_token_with_retry`] (ct-agent#181).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolveError {
    /// Retrying cannot help: nothing configured, no refresh token, the IdP
    /// rejected the refresh (`invalid_grant`). The message names the fix.
    Definitive(String),
    /// Retrying may help: the IdP was unreachable or answered 5xx, or
    /// `CT_OIDC_TOKEN_FILE` was momentarily unreadable.
    Transient(String),
}

impl ResolveError {
    fn into_message(self) -> String {
        match self {
            ResolveError::Definitive(m) | ResolveError::Transient(m) => m,
        }
    }
}

/// What every `CT_OIDC_TOKEN` consumer now calls. `CT_OIDC_TOKEN` explicitly set in
/// the environment always wins (unchanged behavior for existing scripts/CI); then
/// `CT_OIDC_TOKEN_FILE` (ct-agent#181, re-read on every call); only when neither is
/// set does this read the token `ct-agent login` stored, silently refreshing it
/// first if it is expired (or close to it) and a refresh token was saved. No stored
/// login, an unrefreshable stale token, or a rejected refresh is a loud error
/// naming `ct-agent login` -- and the `CT_OIDC_TOKEN_FILE` alternative -- as the
/// fix; never a silent fall-through to a token that is probably already being
/// rejected server-side. Callers that must not treat an unreachable IdP as
/// "re-login required" use [`resolve_oidc_token_with_retry`].
pub async fn resolve_oidc_token() -> Result<String, String> {
    resolve_oidc_token_classified().await.map_err(ResolveError::into_message)
}

/// [`resolve_oidc_token`] keeping the definitive/transient distinction.
pub(crate) async fn resolve_oidc_token_classified() -> Result<String, ResolveError> {
    let env = |k: &str| std::env::var(k).ok();
    if let Some(t) = env_token(env) {
        return Ok(t);
    }
    match token_from_file(env) {
        Ok(Some(t)) => return Ok(t),
        Ok(None) => {}
        Err(e) => return Err(ResolveError::Transient(e)),
    }

    let path = token_store_path(env).map_err(ResolveError::Definitive)?;
    let stored = read_stored_token(&path).map_err(|e| {
        ResolveError::Definitive(format!(
            "CT_OIDC_TOKEN is not set and no stored login was found at {} ({e}). Run `ct-agent login`, \
             {UNATTENDED_HINT}.",
            path.display()
        ))
    })?;

    let now = now_unix();
    if !stored.is_stale(now) {
        return Ok(stored.access_token);
    }

    let Some(refresh_token) = stored.usable_refresh_token(now) else {
        note_degraded();
        let why = if stored.refresh_token.as_deref().is_some_and(|t| !t.is_empty()) {
            "its refresh token has expired too"
        } else {
            "no refresh token is available"
        };
        return Err(ResolveError::Definitive(format!(
            "the stored login has expired and {why}. Run `ct-agent login` again, {UNATTENDED_HINT}."
        )));
    };
    let http = build_http_client();
    let token_endpoint = token_url(&stored.issuer);
    let refreshed = match refresh_access_token(&http, &token_endpoint, &stored.client_id, refresh_token).await {
        Ok(r) => r,
        Err(LoginError::Http(m)) => {
            return Err(ResolveError::Transient(format!(
                "the stored login has expired and refreshing it failed with a transient error ({m}); the IdP \
                 may be unreachable"
            )))
        }
        Err(e) => {
            note_degraded();
            return Err(ResolveError::Definitive(format!(
                "the stored login has expired and the IdP rejected the refresh ({e}). Run `ct-agent login` \
                 again, {UNATTENDED_HINT}."
            )));
        }
    };

    let new_stored = StoredToken::from_token_response(&refreshed, &stored.issuer, &stored.client_id, now);
    persist_stored_token(&path, &new_stored).map_err(|e| {
        ResolveError::Definitive(format!("refreshed the login but failed to save it at {}: {e}", path.display()))
    })?;
    Ok(new_stored.access_token)
}

/// Retry budget the bridge tools use with [`resolve_oidc_token_with_retry`]:
/// three tries, 500ms then 1s between them. Bounded so a bridge-tool call that
/// needs the plane still answers within a few seconds of a genuinely dead IdP
/// (each try is additionally capped by [`HTTP_TIMEOUT`]).
pub const OIDC_REFRESH_RETRY_ATTEMPTS: u32 = 3;
pub const OIDC_REFRESH_RETRY_BASE: Duration = Duration::from_millis(500);
/// Cap on the doubling retry delay.
const OIDC_REFRESH_RETRY_MAX: Duration = Duration::from_secs(5);

/// [`resolve_oidc_token`] for unattended callers (ct-agent#181): up to `attempts`
/// tries, sleeping `base` (doubling, capped at [`OIDC_REFRESH_RETRY_MAX`]) between
/// them, but ONLY over transient failures -- a definitive one (nothing configured,
/// no refresh token, `invalid_grant`) returns its actionable message at once. If
/// every try was transient the error says so and does NOT tell the operator to
/// re-login: the stored login is fine, the IdP is not.
pub async fn resolve_oidc_token_with_retry(attempts: u32, base: Duration) -> Result<String, String> {
    let attempts = attempts.max(1);
    let mut delay = base;
    let mut last = String::new();
    for attempt in 1..=attempts {
        match resolve_oidc_token_classified().await {
            Ok(t) => return Ok(t),
            Err(ResolveError::Definitive(m)) => return Err(m),
            Err(ResolveError::Transient(m)) => {
                if attempt < attempts {
                    eprintln!(
                        "ct-agent: oidc refresh attempt {attempt}/{attempts} failed ({m}); retrying in {}ms (#181)",
                        delay.as_millis()
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(OIDC_REFRESH_RETRY_MAX);
                }
                last = m;
            }
        }
    }
    Err(format!(
        "{last} -- gave up after {attempts} attempt(s). The stored login itself is still refreshable; this is an \
         IdP/network problem, not a re-login problem"
    ))
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
        /// A 503 with a non-OAuth body -- what an IdP behind a restarting proxy
        /// looks like (ct-agent#181: transient).
        ServerError,
        /// RFC 6749 §5.2 `invalid_grant`: the refresh token is dead (definitive).
        InvalidGrant,
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
            MockTokenReply::ServerError => {
                (StatusCode::SERVICE_UNAVAILABLE, "<html>upstream restarting</html>").into_response()
            }
            MockTokenReply::InvalidGrant => (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({"error": "invalid_grant", "error_description": "Token is not active"})),
            )
                .into_response(),
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
        // Upper bounds only guard against a runaway sleep: a loaded CI runner has
        // shown a 1 s stall on the first HTTP round-trip (PR #187), so the slack is
        // generous; the exact lower bounds are what prove the backoff.
        let slack = Duration::from_secs(3);
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
    /// vars would otherwise race each other's assertions. A tokio mutex, not a
    /// std one, because every holder is an async test that must keep the guard
    /// across its `.await`s (the env is read inside the awaited call) -- exactly the
    /// case clippy's `await_holding_lock` rejects for a std guard.
    static ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn clear_env() {
        for k in ["CT_OIDC_TOKEN", "CT_OIDC_TOKEN_FILE", "CT_AGENT_LOGIN_TOKEN_FILE", "CT_AGENT_STATE_DIR"] {
            std::env::remove_var(k);
        }
    }

    fn stored_at(
        dir: &str,
        access_expires_at: Option<u64>,
        refresh: Option<&str>,
        refresh_expires_at: Option<u64>,
    ) -> PathBuf {
        let path = scratch(dir).join("oidc-token.json");
        let tok = StoredToken {
            access_token: format!("at-{dir}"),
            refresh_token: refresh.map(str::to_string),
            access_expires_at,
            refresh_expires_at,
            issuer: "https://kc.example/realms/ct".into(),
            client_id: "ct-agent-cli".into(),
        };
        persist_stored_token(&path, &tok).unwrap();
        path
    }

    // ---- ct-agent#181: credential state, CT_OIDC_TOKEN_FILE, refresh retry ----

    #[test]
    fn oidc_credential_state_classifies_each_variant() {
        // Lookup-map driven, like `token_store_path`'s test: no process env touched.
        let now = 1_000_000u64;
        let with_file = |path: &Path| {
            let mut m = HashMapAlias::new();
            m.insert("CT_AGENT_LOGIN_TOKEN_FILE".to_string(), path.to_str().unwrap().to_string());
            m
        };
        let state = |m: &HashMapAlias| oidc_credential_state_from(|k| m.get(k).cloned(), now);

        // env: CT_OIDC_TOKEN set, whatever is on disk.
        let dead = stored_at("state-env", Some(now - 10), None, None);
        let mut m = with_file(&dead);
        m.insert("CT_OIDC_TOKEN".to_string(), "explicit".to_string());
        assert_eq!(state(&m), OidcCredentialState::Env);
        // A blank CT_OIDC_TOKEN does not count (same rule as resolve_oidc_token).
        m.insert("CT_OIDC_TOKEN".to_string(), "   ".to_string());
        assert_eq!(state(&m), OidcCredentialState::StoredExpiredNoRefresh);

        // env via CT_OIDC_TOKEN_FILE holding a token; an EMPTY file is "not configured".
        let file = scratch("state-file").join("token");
        std::fs::write(&file, "  file-token
").unwrap();
        let mut m = with_file(&dead);
        m.insert("CT_OIDC_TOKEN_FILE".to_string(), file.to_str().unwrap().to_string());
        assert_eq!(state(&m), OidcCredentialState::Env);
        std::fs::write(&file, "
").unwrap();
        assert_eq!(state(&m), OidcCredentialState::StoredExpiredNoRefresh, "empty token file falls through");

        // stored (fresh): expiry well past the skew.
        let fresh = stored_at("state-fresh", Some(now + 3600), Some("rt"), None);
        assert_eq!(state(&with_file(&fresh)), OidcCredentialState::StoredFresh);
        // Inside the skew window counts as expired.
        let skewed = stored_at("state-skew", Some(now + ACCESS_TOKEN_EXPIRY_SKEW_SECS - 1), Some("rt"), None);
        assert_eq!(state(&with_file(&skewed)), OidcCredentialState::StoredExpiredRefreshable);

        // stored-expired-refreshable: refresh token present, its own expiry (if any) ahead.
        let refreshable = stored_at("state-refreshable", Some(now - 10), Some("rt"), Some(now + 60));
        assert_eq!(state(&with_file(&refreshable)), OidcCredentialState::StoredExpiredRefreshable);
        let unknown_expiry = stored_at("state-unknown", None, Some("rt"), None);
        assert_eq!(state(&with_file(&unknown_expiry)), OidcCredentialState::StoredExpiredRefreshable);

        // stored-expired: no refresh token, or one whose recorded expiry has passed.
        let no_refresh = stored_at("state-norefresh", Some(now - 10), None, None);
        assert_eq!(state(&with_file(&no_refresh)), OidcCredentialState::StoredExpiredNoRefresh);
        let dead_refresh = stored_at("state-deadrefresh", Some(now - 10), Some("rt"), Some(now - 1));
        assert_eq!(state(&with_file(&dead_refresh)), OidcCredentialState::StoredExpiredNoRefresh);
        let empty_refresh = stored_at("state-emptyrefresh", Some(now - 10), Some(""), None);
        assert_eq!(state(&with_file(&empty_refresh)), OidcCredentialState::StoredExpiredNoRefresh);

        // none: no file at the path, a corrupt file, or no path resolvable at all.
        let missing = scratch("state-missing").join("nope.json");
        assert_eq!(state(&with_file(&missing)), OidcCredentialState::None);
        let corrupt = scratch("state-corrupt").join("oidc-token.json");
        std::fs::write(&corrupt, b"{not json").unwrap();
        assert_eq!(state(&with_file(&corrupt)), OidcCredentialState::None);
        assert_eq!(state(&HashMapAlias::new()), OidcCredentialState::None);

        // The reported spellings: the three pre-#181 ones unchanged.
        assert_eq!(OidcCredentialState::Env.as_str(), "env");
        assert_eq!(OidcCredentialState::StoredFresh.as_str(), "stored");
        assert_eq!(OidcCredentialState::None.as_str(), "none");
        assert_eq!(OidcCredentialState::StoredExpiredRefreshable.as_str(), "stored-expired-refreshable");
        assert_eq!(OidcCredentialState::StoredExpiredNoRefresh.as_str(), "stored-expired");
    }

    #[tokio::test]
    async fn token_file_beats_the_stored_login_and_is_reread_when_it_changes() {
        let _g = ENV_MUTEX.lock().await;
        clear_env();
        let stored = stored_at("file-prec", Some(now_unix() + 3600), None, None);
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", stored.to_str().unwrap());
        let file = scratch("file-prec-token").join("token");
        std::fs::write(&file, " tok-1 
").unwrap();
        std::env::set_var("CT_OIDC_TOKEN_FILE", file.to_str().unwrap());

        assert_eq!(resolve_oidc_token().await.unwrap(), "tok-1", "file wins over the stored login, trimmed");

        // Rotated on disk: picked up by the very next call, no restart.
        std::fs::write(&file, "tok-2
").unwrap();
        assert_eq!(resolve_oidc_token().await.unwrap(), "tok-2");

        // CT_OIDC_TOKEN still wins over the file.
        std::env::set_var("CT_OIDC_TOKEN", "explicit");
        assert_eq!(resolve_oidc_token().await.unwrap(), "explicit");
        std::env::remove_var("CT_OIDC_TOKEN");

        // Emptied: not configured -> the stored (fresh) login is used.
        std::fs::write(&file, "
").unwrap();
        assert_eq!(resolve_oidc_token().await.unwrap(), "at-file-prec");

        // Unreadable: transient (a rotation in progress), never "run ct-agent login".
        std::fs::remove_file(&file).unwrap();
        match resolve_oidc_token_classified().await {
            Err(ResolveError::Transient(m)) => assert!(m.contains("CT_OIDC_TOKEN_FILE"), "{m}"),
            other => panic!("expected a transient error, got {other:?}"),
        }
        clear_env();
    }

    #[tokio::test]
    async fn resolve_with_retry_recovers_from_a_transient_idp_failure() {
        let _g = ENV_MUTEX.lock().await;
        clear_env();
        let (base, state) = spawn_mock_idp(vec![
            MockTokenReply::ServerError,
            MockTokenReply::Success {
                access_token: "refreshed-after-503",
                refresh_token: Some("rt-2"),
                expires_in: 300,
            },
        ])
        .await;
        let path = scratch("retry-transient").join("oidc-token.json");
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

        let tok = resolve_oidc_token_with_retry(3, Duration::from_millis(10)).await.expect("second try succeeds");
        assert_eq!(tok, "refreshed-after-503");
        assert_eq!(state.calls.load(Ordering::SeqCst), 2, "one failed try, one successful retry");
        assert_eq!(read_stored_token(&path).unwrap().refresh_token.as_deref(), Some("rt-2"));
        clear_env();
    }

    #[tokio::test]
    async fn resolve_with_retry_gives_up_transiently_without_demanding_a_relogin() {
        let _g = ENV_MUTEX.lock().await;
        clear_env();
        let (base, state) = spawn_mock_idp(vec![MockTokenReply::ServerError]).await;
        let path = scratch("retry-exhausted").join("oidc-token.json");
        let stored = StoredToken {
            access_token: "stale".into(),
            refresh_token: Some("old-rt".into()),
            access_expires_at: Some(now_unix().saturating_sub(10)),
            refresh_expires_at: None,
            issuer: base.clone(),
            client_id: "ct-agent-cli".into(),
        };
        persist_stored_token(&path, &stored).unwrap();
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", path.to_str().unwrap());

        let err = resolve_oidc_token_with_retry(3, Duration::from_millis(10)).await.expect_err("all tries 503");
        assert_eq!(state.calls.load(Ordering::SeqCst), 3, "every attempt was spent");
        assert!(!err.contains("ct-agent login"), "an unreachable IdP is not a re-login problem: {err}");
        assert!(err.contains("3 attempt"), "{err}");
        clear_env();
    }

    #[tokio::test]
    async fn resolve_with_retry_stops_on_invalid_grant_and_names_the_unattended_option() {
        let _g = ENV_MUTEX.lock().await;
        clear_env();
        let (base, state) = spawn_mock_idp(vec![MockTokenReply::InvalidGrant]).await;
        let path = scratch("retry-invalid-grant").join("oidc-token.json");
        let stored = StoredToken {
            access_token: "stale".into(),
            refresh_token: Some("dead-rt".into()),
            access_expires_at: Some(now_unix().saturating_sub(10)),
            refresh_expires_at: Some(now_unix() + 3600),
            issuer: base.clone(),
            client_id: "ct-agent-cli".into(),
        };
        persist_stored_token(&path, &stored).unwrap();
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", path.to_str().unwrap());

        let err = resolve_oidc_token_with_retry(5, Duration::from_millis(10))
            .await
            .expect_err("invalid_grant is final");
        assert_eq!(state.calls.load(Ordering::SeqCst), 1, "a definitive rejection is not retried");
        assert!(err.contains("Token is not active"), "carries the IdP's reason: {err}");
        assert!(err.contains("ct-agent login"), "names the interactive fix: {err}");
        assert!(err.contains("CT_OIDC_TOKEN_FILE"), "names the unattended fix: {err}");

        // The no-refresh-token case is definitive too, with the same two options.
        let no_refresh = stored_at("retry-no-refresh", Some(now_unix() - 10), None, None);
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", no_refresh.to_str().unwrap());
        match resolve_oidc_token_classified().await {
            Err(ResolveError::Definitive(m)) => {
                assert!(m.contains("ct-agent login") && m.contains("CT_OIDC_TOKEN_FILE"), "{m}");
            }
            other => panic!("expected a definitive error, got {other:?}"),
        }
        clear_env();
    }

    #[tokio::test]
    async fn resolve_oidc_token_prefers_the_explicit_env_var() {
        let _g = ENV_MUTEX.lock().await;
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
        let _g = ENV_MUTEX.lock().await;
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
        let _g = ENV_MUTEX.lock().await;
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
        let _g = ENV_MUTEX.lock().await;
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
        let _g = ENV_MUTEX.lock().await;
        clear_env();
        // No CT_OIDC_TOKEN, and no stored file at the (deliberately bogus) explicit path.
        std::env::set_var("CT_AGENT_LOGIN_TOKEN_FILE", "/nonexistent/dir/oidc-token.json");

        let err = resolve_oidc_token().await.expect_err("must fail loudly, not silently proceed unauthenticated");
        assert!(err.contains("ct-agent login"));
        clear_env();
    }
}
