//! `ct-agent signup` — self-service tunnel creation via `CADS-Tunnel`'s
//! `POST /me/signup`, authenticated with the OIDC access token `ct-agent login`'s
//! device-code flow already obtains (see [`crate::login::resolve_oidc_token`])
//! instead of a portal session cookie. This is the CLI-driven counterpart to the
//! portal browser's "Create tunnel" button.
//!
//! Anti-abuse (repeat free-account creation): this also computes and reports a
//! device+user fingerprint — `sha256(machine_id || "\0" || os_username)` — that the
//! control plane uses to cap how many distinct free accounts one machine can create
//! (see `ct-control-plane`'s `SqliteLedger::account_for_subject_with_device_cap`).
//! `machine_id()` returning `None` (an unsupported platform, or the file/registry
//! value being unreadable) is not fatal: `signup()` still runs, just without that
//! signal, and the server-side cap simply does not apply to this call (fail-open,
//! matches how every other unfingerprinted caller — including the portal itself —
//! is treated).
//!
//! Deliberately does NOT chain into serving in this same process (unlike `ct-agent
//! onboard`, whose join-token/identity-binding flow this repo's own serve
//! bootstrap already has deep, existing wiring for) — that bootstrap (edge-cert
//! fetch, capability output, etc.) is substantial pre-existing machinery this
//! command has no reason to duplicate or risk destabilizing. `signup` prints the
//! resulting routing token; the operator (or a wrapper script) sets `CT_AGENT_TOKEN`
//! and runs `ct-agent` normally to actually start serving.

use ct_control_plane::client::{ControlPlaneClient, CpError, SignupResult};

/// Best-effort machine identifier, platform-specific:
/// - Linux: `/etc/machine-id` (falls back to `/var/lib/dbus/machine-id`, the same
///   file under its pre-systemd location — some minimal/container images only have
///   this one).
/// - macOS: `IOPlatformUUID` via `ioreg -rd1 -c IOPlatformExpertDevice`.
/// - Windows: the `MachineGuid` value under
///   `HKLM\SOFTWARE\Microsoft\Cryptography` via `reg query` (readable without
///   elevation on stock Windows).
///
/// `None` on any failure (missing file, command not found, unexpected output) --
/// never an error, since the caller treats absence as "skip the device-cap check
/// entirely", not as a reason to fail signup itself.
fn machine_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let s = s.trim();
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find_map(|l| l.split("IOPlatformUUID").nth(1))
            .and_then(|rest| rest.split('"').nth(1))
            .map(|s| s.to_string())
    }
    #[cfg(target_os = "windows")]
    {
        let out = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .find(|l| l.contains("MachineGuid"))
            .and_then(|l| l.split_whitespace().last())
            .map(|s| s.to_string())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// The local OS username, tried in the Unix (`USER`) then Windows (`USERNAME`)
/// env-var convention. `None` (not an error) if neither is set.
fn os_username() -> Option<String> {
    std::env::var("USER").ok().or_else(|| std::env::var("USERNAME").ok())
}

/// `sha256(machine_id || "\0" || os_username)`, hex-encoded — `None` if either
/// input is unavailable (see [`machine_id`]'s doc for why that's fail-open, not an
/// error).
pub fn device_fingerprint() -> Option<String> {
    use sha2::{Digest, Sha256};
    let id = machine_id()?;
    let user = os_username()?;
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(b"\0");
    hasher.update(user.as_bytes());
    Some(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run `ct-agent signup <name>`: resolve a bearer token (env `CT_OIDC_TOKEN`, else
/// whatever `ct-agent login` stored — see [`crate::login::resolve_oidc_token`]),
/// compute the device fingerprint, and call `POST /me/signup` against `cp_url`.
pub async fn run_signup(cp_url: &str, name: &str) -> Result<SignupResult, String> {
    let token = crate::login::resolve_oidc_token().await?;
    let fingerprint = device_fingerprint();
    ControlPlaneClient::new(cp_url)
        .signup(name, &token, fingerprint.as_deref())
        .await
        .map_err(|e| match e {
            CpError::Status(status) if status.as_u16() == 403 => format!(
                "ct-agent: signup refused (403) -- this is almost certainly the anti-abuse \
                 device limit; see https://bunsenbrenner.org/device-limit-reached for how to \
                 request a reset: {e}"
            ),
            other => format!("ct-agent: signup failed: {other}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_fingerprint_is_deterministic_for_the_same_machine_and_user() {
        // Whatever this test host actually reports (real values, or None on an
        // unsupported/sandboxed environment), two calls must agree -- the whole
        // point is a STABLE per-(machine, user) hash, not a random one.
        assert_eq!(device_fingerprint(), device_fingerprint());
    }

    #[test]
    fn hex_encode_matches_a_known_vector() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
