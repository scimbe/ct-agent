//! Revoking one channel grant (`ct-agent channel grant-revoke`, `bridge/channel-revoke`).
//!
//! A grant is stateless, so withdrawing the holder's membership alone does not stop an old,
//! unexpired grant from working again after a re-add. The control plane therefore keeps a
//! revocation list keyed by the SHA-256 of the signed grant; this module puts a grant on it.
//! The edge refuses the digest at admission and cuts live splices carrying it, and a running
//! forward session notices through its own re-check (`grant_watch`).
//!
//! Two ways to authorize the same request, either suffices because revoking only restricts:
//! - the channel operator signs `ct-grant-revoke:v1|channel|digest|expires_at` (CLI; no login
//!   needed, works from the machine that holds the operator key);
//! - the channel's owner session (bridge tool; the OIDC bearer the portal already uses).

use ct_common::channel::SignedChannelGrant;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

use super::grant_watch::grant_digest;
use crate::codec::{hex_decode, hex_encode};

/// The grant to revoke, hex as `ct-agent channel grant` printed it (the member's
/// `CT_CHANNEL_GRANT`). When unset the grant is re-derived from the `CT_GRANT_*` fields of
/// `channel grant`; signing is deterministic, so the same fields give the same grant.
pub const REVOKE_GRANT_ENV: &str = "CT_REVOKE_GRANT";

/// The most of a control-plane error body that is shown to the operator.
const BODY_SNIPPET_CHARS: usize = 200;

fn snippet(body: &str) -> String {
    let body = body.trim();
    let mut out: String = body.chars().take(BODY_SNIPPET_CHARS).collect();
    if body.chars().count() > BODY_SNIPPET_CHARS {
        out.push_str("...");
    }
    out
}

/// Mirror of `ct_common::channel::grant_revoke_signing_bytes` (not in the pinned tag yet; the
/// control plane pins the same bytes).
pub fn revoke_signing_bytes(channel: &[u8; 32], digest: &[u8; 32], expires_at: u64) -> Vec<u8> {
    let mut out = b"ct-grant-revoke:v1|".to_vec();
    out.extend_from_slice(channel);
    out.push(b'|');
    out.extend_from_slice(digest);
    out.push(b'|');
    out.extend_from_slice(&expires_at.to_le_bytes());
    out
}

/// Decode a grant given as hex.
pub fn decode_grant_hex(s: &str) -> Result<SignedChannelGrant, String> {
    let bytes = hex_decode::<{ SignedChannelGrant::WIRE_LEN }>(s.trim()).ok_or_else(|| {
        format!(
            "the grant must be the hex `ct-agent channel grant` printed ({} hex characters)",
            SignedChannelGrant::WIRE_LEN * 2
        )
    })?;
    SignedChannelGrant::decode(&bytes).map_err(|e| format!("the grant is malformed: {e}"))
}

/// What the control plane needs about one grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeTarget {
    pub channel: [u8; 32],
    pub digest: [u8; 32],
    pub expires_at: u64,
}

impl RevokeTarget {
    pub fn of(grant: &SignedChannelGrant) -> Self {
        Self {
            channel: grant.grant.channel.0,
            digest: grant_digest(grant),
            expires_at: grant.grant.expires_at,
        }
    }

    /// The request body; `operator` adds the operator signature (CLI route).
    pub fn body(&self, operator: Option<&SigningKey>) -> serde_json::Value {
        let mut body = serde_json::json!({
            "grant_digest": hex_encode(&self.digest),
            "expires_at": self.expires_at,
        });
        if let Some(op) = operator {
            let sig = op.sign(&revoke_signing_bytes(&self.channel, &self.digest, self.expires_at));
            body["operator_sig"] = hex_encode(&sig.to_bytes()).into();
        }
        body
    }
}

/// The control plane's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    /// The digest was already on the list (revoking twice is not an error).
    pub already: bool,
}

/// `ct-agent channel grant-revoke`: inputs from the environment.
pub struct GrantRevokeRequest {
    pub cp_url: String,
    pub operator: SigningKey,
    pub grant: SignedChannelGrant,
}

impl GrantRevokeRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let cp_url = f("CT_AGENT_CP_URL")
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .ok_or("CT_AGENT_CP_URL is required (the control plane that keeps the revocation list)")?;
        let operator = super::cli_config::req_key(&f, "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")?;
        let grant = match f(REVOKE_GRANT_ENV).filter(|s| !s.trim().is_empty()) {
            Some(hex) => decode_grant_hex(&hex)?,
            None => {
                let issued = super::OperatorGrantRequest::from_lookup(&f).map_err(|e| {
                    format!("name the grant to revoke with {REVOKE_GRANT_ENV}=<its hex>, or give the CT_GRANT_* fields it was issued with: {e}")
                })?;
                decode_grant_hex(&issued.issue())?
            }
        };
        // The control plane would refuse a grant this operator did not sign; say so before sending.
        operator
            .verifying_key()
            .verify(&grant.grant.signing_bytes(), &ed25519_dalek::Signature::from_bytes(&grant.signature))
            .map_err(|_| {
                "that grant was not signed by the operator key in CT_CHANNEL_OPERATOR_KEY; nothing was sent"
                    .to_string()
            })?;
        Ok(Self { cp_url, operator, grant })
    }

    /// What the operator sees after a successful revoke: which grant it was.
    pub fn describe(&self, out: &RevokeOutcome) -> String {
        let g = &self.grant.grant;
        format!(
            "{} grant {} (channel {}, holder {}, expires {})",
            if out.already { "already revoked:" } else { "revoked:" },
            hex_encode(&self.target().digest),
            hex_encode(&g.channel.0),
            hex_encode(&g.holder),
            g.expires_at
        )
    }

    pub fn target(&self) -> RevokeTarget {
        RevokeTarget::of(&self.grant)
    }

    pub fn url(&self) -> String {
        format!("{}/channel/{}/grant-revoke", self.cp_url, hex_encode(&self.grant.grant.channel.0))
    }

    pub async fn send(&self) -> Result<RevokeOutcome, String> {
        let body = self.target().body(Some(&self.operator));
        post_revoke(&self.url(), None, &body).await
    }
}

/// Owner-session route, used by the bridge tool: `POST /me/channels/:channel/grants/revoke`.
pub async fn revoke_as_owner(cp_url: &str, token: &str, grant: &SignedChannelGrant) -> Result<RevokeOutcome, String> {
    let t = RevokeTarget::of(grant);
    let url = format!("{}/me/channels/{}/grants/revoke", cp_url.trim_end_matches('/'), hex_encode(&t.channel));
    post_revoke(&url, Some(token), &t.body(None)).await
}

async fn post_revoke(url: &str, bearer: Option<&str>, body: &serde_json::Value) -> Result<RevokeOutcome, String> {
    let mut req = crate::http::shared().post(url).json(body);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.map_err(|e| format!("POST {url}: {e}"))?;
    interpret(resp.status().as_u16(), &resp.text().await.unwrap_or_default())
}

/// Turn the control plane's answer into a result with a reason an operator can act on.
pub fn interpret(status: u16, body: &str) -> Result<RevokeOutcome, String> {
    match status {
        200 => {
            let v: serde_json::Value = serde_json::from_str(body).map_err(|e| format!("unreadable answer: {e}"))?;
            if v.get("revoked").and_then(|r| r.as_bool()) != Some(true) {
                return Err(format!("the control plane answered 200 without confirming the revocation: {}", snippet(body)));
            }
            Ok(RevokeOutcome { already: v.get("already").and_then(|a| a.as_bool()).unwrap_or(false) })
        }
        400 => Err(format!("the control plane rejected the request as malformed: {}", snippet(body))),
        403 => Err("not authorized: the operator signature does not match the key this channel was registered with \
                    (or you are not the channel's owner)"
            .to_string()),
        404 | 405 => Err("the control plane does not know this channel, or is too old to keep a grant revocation list".to_string()),
        s => Err(format!("the control plane answered {s}: {}", snippet(body))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights};

    fn lookup<'a>(pairs: &'a [(&'a str, String)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
    }

    fn op() -> SigningKey {
        SigningKey::from_bytes(&[0x01; 32])
    }

    #[test]
    fn the_signed_bytes_match_the_control_plane_vector() {
        // sha256(revoke_bytes(channel 0x11*32, digest 0x01*32, 2000)), pinned by the control plane.
        use sha2::{Digest as _, Sha256};
        let b = revoke_signing_bytes(&[0x11; 32], &[1; 32], 2000);
        assert!(b.starts_with(b"ct-grant-revoke:v1|"));
        assert_eq!(
            hex_encode(&Sha256::digest(&b)),
            "91c32e4a8bb5cf5b4b4558386703235bf9237894886927054867028a96d1fbf9"
        );
    }

    #[test]
    fn a_grant_given_as_hex_and_one_rederived_from_its_fields_are_the_same_grant() {
        let holder = SigningKey::from_bytes(&[0x02; 32]).verifying_key().to_bytes();
        let channel = [0x5c; 32];
        let env = [
            ("CT_AGENT_CP_URL", "https://cp.example/".to_string()),
            ("CT_CHANNEL_OPERATOR_KEY", hex_encode(&[0x01; 32])),
            ("CT_GRANT_CHANNEL", hex_encode(&channel)),
            ("CT_GRANT_MEMBER_HOLDER", hex_encode(&holder)),
            ("CT_GRANT_DIRECTION", "initiate".to_string()),
            ("CT_GRANT_EXPIRES", "4000000000".to_string()),
        ];
        let derived = GrantRevokeRequest::from_lookup(lookup(&env)).unwrap();

        let issued_hex = hex_encode(&derived.grant.encode());
        let mut with_hex = env.to_vec();
        with_hex.retain(|(k, _)| !k.starts_with("CT_GRANT_"));
        with_hex.push((REVOKE_GRANT_ENV, issued_hex));
        let from_hex = GrantRevokeRequest::from_lookup(lookup(&with_hex)).unwrap();

        assert_eq!(derived.target(), from_hex.target(), "same digest either way");
        assert_eq!(derived.cp_url, "https://cp.example");
        assert_eq!(
            derived.url(),
            format!("https://cp.example/channel/{}/grant-revoke", hex_encode(&channel))
        );
    }

    #[test]
    fn the_operator_route_signs_exactly_what_the_control_plane_verifies() {
        let signed = SignedChannelGrant {
            grant: ChannelGrant {
                channel: ChannelId([0x11; 32]),
                holder: [0x22; 32],
                direction: Direction::Both,
                rights: Rights::Read,
                delegable: false,
                expires_at: 2000,
            },
            signature: [0xaa; 64],
        };
        let t = RevokeTarget::of(&signed);
        assert_eq!(hex_encode(&t.digest), "76e43324c486202745e98926f6362b6966ee3935f24aa72a784f77deb103d662");
        let body = t.body(Some(&op()));
        assert_eq!(body["expires_at"], 2000);
        let sig = hex_decode::<64>(body["operator_sig"].as_str().unwrap()).unwrap();
        let vk = op().verifying_key();
        vk.verify_strict(&revoke_signing_bytes(&t.channel, &t.digest, 2000), &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("the control plane verifies the operator signature over these bytes");
        assert!(t.body(None).get("operator_sig").is_none(), "the owner route carries no signature");
    }

    #[test]
    fn missing_inputs_say_what_to_provide() {
        let e = GrantRevokeRequest::from_lookup(|_| None).err().unwrap();
        assert!(e.contains("CT_AGENT_CP_URL"));
        let only_cp = [("CT_AGENT_CP_URL", "https://cp".to_string()), ("CT_CHANNEL_OPERATOR_KEY", hex_encode(&[1; 32]))];
        let e = GrantRevokeRequest::from_lookup(lookup(&only_cp)).err().unwrap();
        assert!(e.contains(REVOKE_GRANT_ENV), "{e}");
        assert!(decode_grant_hex("zz").is_err());
    }

    #[test]
    fn the_answers_map_to_actionable_results() {
        assert_eq!(interpret(200, r#"{"revoked":true,"already":false}"#), Ok(RevokeOutcome { already: false }));
        assert_eq!(interpret(200, r#"{"revoked":true,"already":true}"#), Ok(RevokeOutcome { already: true }));
        assert!(interpret(403, "").unwrap_err().contains("not authorized"));
        assert!(interpret(404, "").unwrap_err().contains("too old"));
        assert!(interpret(500, "boom").unwrap_err().contains("500"));
    }

    #[test]
    fn a_200_that_does_not_say_revoked_is_not_a_success() {
        for body in ["{}", r#"{"already":true}"#, r#"{"revoked":false}"#, r#"{"revoked":"yes"}"#, "ok"] {
            assert!(interpret(200, body).is_err(), "{body:?}");
        }
    }

    #[test]
    fn a_long_error_body_is_cut() {
        let err = interpret(500, &"x".repeat(5000)).unwrap_err();
        assert!(err.len() < 400, "{} bytes", err.len());
        assert!(err.ends_with("..."));
    }

    #[test]
    fn the_grant_length_is_the_one_the_wire_format_defines() {
        let g = SignedChannelGrant {
            grant: ChannelGrant {
                channel: ChannelId([1; 32]),
                holder: [2; 32],
                direction: Direction::Both,
                rights: Rights::Read,
                delegable: false,
                expires_at: 1,
            },
            signature: [3; 64],
        };
        assert_eq!(g.encode().len(), SignedChannelGrant::WIRE_LEN);
        assert!(decode_grant_hex(&hex_encode(&g.encode())).is_ok());
        assert!(decode_grant_hex(&hex_encode(&g.encode()[1..])).is_err(), "one byte short");
    }

    #[test]
    fn a_grant_the_operator_did_not_sign_is_refused_before_sending() {
        let holder = SigningKey::from_bytes(&[0x02; 32]).verifying_key().to_bytes();
        let issue_with = |operator_key: u8| {
            let env = [
                ("CT_AGENT_CP_URL", "https://cp.example".to_string()),
                ("CT_CHANNEL_OPERATOR_KEY", hex_encode(&[operator_key; 32])),
                ("CT_GRANT_CHANNEL", hex_encode(&[0x5c; 32])),
                ("CT_GRANT_MEMBER_HOLDER", hex_encode(&holder)),
                ("CT_GRANT_DIRECTION", "initiate".to_string()),
                ("CT_GRANT_EXPIRES", "4000000000".to_string()),
            ];
            hex_encode(&GrantRevokeRequest::from_lookup(lookup(&env)).unwrap().grant.encode())
        };
        let foreign = issue_with(0x09);
        let env = [
            ("CT_AGENT_CP_URL", "https://cp.example".to_string()),
            ("CT_CHANNEL_OPERATOR_KEY", hex_encode(&[0x01; 32])),
            (REVOKE_GRANT_ENV, foreign),
        ];
        let err = GrantRevokeRequest::from_lookup(lookup(&env)).err().unwrap();
        assert!(err.contains("not signed by the operator key"), "{err}");
        // and the operator's own grant says which one it was
        let own = [
            ("CT_AGENT_CP_URL", "https://cp.example".to_string()),
            ("CT_CHANNEL_OPERATOR_KEY", hex_encode(&[0x01; 32])),
            (REVOKE_GRANT_ENV, issue_with(0x01)),
        ];
        let req = GrantRevokeRequest::from_lookup(lookup(&own)).unwrap();
        let line = req.describe(&RevokeOutcome { already: false });
        assert!(line.starts_with("revoked: grant "), "{line}");
        assert!(line.contains(&hex_encode(&[0x5c; 32])) && line.contains(&hex_encode(&holder)) && line.contains("expires 4000000000"), "{line}");
    }
}
