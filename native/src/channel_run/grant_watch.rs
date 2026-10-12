//! Re-checking the peer's grant while a forward session runs.
//!
//! A channel grant is verified once, when the session starts, and is stateless: nothing in it
//! says it was withdrawn. Once a session is on a direct path (direct upgrade, DCUtR, fallback)
//! the edge is no longer in the data path either, so the member itself has to ask. The accept
//! side of a forward session therefore asks the control plane every `interval` whether the
//! peer's grant (identified by the SHA-256 of its signed bytes) is still good, and ends the
//! session when the answer is `revoked` or `not-member`.
//!
//! Fail-closed: an answer that cannot be read does not end the session at once, but if no
//! `valid` answer has arrived for `grace` the session ends. A control plane that does not know
//! the endpoint at all (404/405) ends it immediately, because then nothing would ever check.
//!
//! The digest and the signed bytes are computed here, not taken from `ct-common`: this crate
//! pins `ct-common` by release tag, and the helpers do not exist in a tag yet. The golden
//! vectors in the tests are the same ones the control plane pins, so a drift on either side
//! fails a test rather than a revocation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ct_common::channel::SignedChannelGrant;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use tokio::sync::oneshot;

/// Seconds between two re-checks (default 30, floor 5).
pub const RECHECK_SECS_ENV: &str = "CT_CHANNEL_GRANT_RECHECK_SECS";
/// Seconds without a `valid` answer after which the session ends (default 90).
pub const RECHECK_GRACE_SECS_ENV: &str = "CT_CHANNEL_GRANT_RECHECK_GRACE_SECS";

const DEFAULT_INTERVAL_SECS: u64 = 30;
const MIN_INTERVAL_SECS: u64 = 5;
const DEFAULT_GRACE_SECS: u64 = 90;
/// Bound on one status request, so a stalled control plane counts as unreadable.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to ask, and how long an unreadable answer is tolerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchConfig {
    pub interval: Duration,
    pub grace: Duration,
}

impl WatchConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// A malformed value is an error (the operator asked for something we cannot honour);
    /// an interval below the floor is raised to it, a grace shorter than one interval is
    /// raised to one interval (it could not otherwise ever see a second attempt).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let read = |key: &str, default: u64| -> Result<u64, String> {
            match f(key).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
                None => Ok(default),
                Some(s) => s
                    .parse::<u64>()
                    .map_err(|_| format!("{key} must be a whole number of seconds, got {s:?}")),
            }
        };
        let interval = read(RECHECK_SECS_ENV, DEFAULT_INTERVAL_SECS)?.max(MIN_INTERVAL_SECS);
        let grace = read(RECHECK_GRACE_SECS_ENV, DEFAULT_GRACE_SECS)?.max(interval);
        Ok(Self {
            interval: Duration::from_secs(interval),
            grace: Duration::from_secs(grace),
        })
    }
}

/// SHA-256 of the grant's signed wire form: the key of the control plane's revocation list.
pub fn grant_digest(grant: &SignedChannelGrant) -> [u8; 32] {
    Sha256::digest(grant.encode()).into()
}

/// The bytes a member signs to ask about `peer`'s grant. Mirror of
/// `ct_common::channel::grant_status_signing_bytes`.
pub fn status_signing_bytes(channel: &[u8; 32], peer: &[u8; 32], digest: &[u8; 32], ts: u64) -> Vec<u8> {
    let mut out = b"ct-grant-status:v1|".to_vec();
    out.extend_from_slice(channel);
    out.push(b'|');
    out.extend_from_slice(peer);
    out.push(b'|');
    out.extend_from_slice(digest);
    out.push(b'|');
    out.extend_from_slice(&ts.to_le_bytes());
    out
}

/// What the control plane says about the peer's grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    Valid,
    Revoked,
    NotMember,
}

/// Why no state could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusError {
    /// The control plane has no such endpoint (404/405): it can never answer.
    Unsupported,
    /// A transient or unintelligible failure.
    Unreadable(String),
}

pub type StatusFuture<'a> = Pin<Box<dyn Future<Output = Result<GrantState, StatusError>> + Send + 'a>>;

/// Where the answers come from (the control plane in production, a script in tests).
pub trait GrantStatusSource: Send + Sync {
    fn status(&self) -> StatusFuture<'_>;
}

/// The peer whose grant is watched, plus the source and timing: everything the gate needs to
/// start a watch once the peer's grant has verified.
#[derive(Clone)]
pub struct WatchSetup {
    pub source: Arc<dyn GrantStatusSource>,
    pub config: WatchConfig,
}

impl std::fmt::Debug for WatchSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchSetup").field("config", &self.config).finish_non_exhaustive()
    }
}

/// How a session starts its watch: the peer's grant is only known once it has verified, so
/// the source is built then, from that grant.
/// Builds the status source for a verified peer grant.
pub type SourceFactory = Arc<dyn Fn(&SignedChannelGrant) -> Arc<dyn GrantStatusSource> + Send + Sync>;

#[derive(Clone)]
pub struct WatchPlan {
    pub factory: SourceFactory,
    pub config: WatchConfig,
}

impl std::fmt::Debug for WatchPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchPlan").field("config", &self.config).finish_non_exhaustive()
    }
}

impl WatchPlan {
    /// The production plan: ask the control plane at `cp_url`, signing as `holder`.
    pub fn control_plane(cp_url: &str, holder: &SigningKey, own: &SignedChannelGrant, config: WatchConfig) -> Self {
        let (cp_url, holder, channel) = (cp_url.to_string(), holder.clone(), own.grant.channel.0);
        Self {
            factory: Arc::new(move |peer: &SignedChannelGrant| {
                Arc::new(CpStatusSource::new(&cp_url, holder.clone(), channel, peer.grant.holder, grant_digest(peer)))
                    as Arc<dyn GrantStatusSource>
            }),
            config,
        }
    }
}

/// Ask the control plane's `POST /channel/grant-status`.
pub struct CpStatusSource {
    base: String,
    holder: SigningKey,
    channel: [u8; 32],
    peer: [u8; 32],
    digest: [u8; 32],
}

impl CpStatusSource {
    pub fn new(base: &str, holder: SigningKey, channel: [u8; 32], peer: [u8; 32], digest: [u8; 32]) -> Self {
        Self { base: base.trim_end_matches('/').to_string(), holder, channel, peer, digest }
    }

    async fn ask(&self) -> Result<GrantState, StatusError> {
        let ts = crate::codec::now_unix();
        let sig = self.holder.sign(&status_signing_bytes(&self.channel, &self.peer, &self.digest, ts));
        let body = serde_json::json!({
            "channel": crate::codec::hex_encode(&self.channel),
            "asker": crate::codec::hex_encode(&self.holder.verifying_key().to_bytes()),
            "peer": crate::codec::hex_encode(&self.peer),
            "grant_digest": crate::codec::hex_encode(&self.digest),
            "ts": ts,
            "sig": crate::codec::hex_encode(&sig.to_bytes()),
        });
        let resp = crate::http::shared()
            .post(format!("{}/channel/grant-status", self.base))
            .timeout(REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| StatusError::Unreadable(format!("request failed: {e}")))?;
        let code = resp.status();
        if code == reqwest::StatusCode::NOT_FOUND || code == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Err(StatusError::Unsupported);
        }
        // 403 means the control plane no longer counts this member as one: nothing about the
        // peer can be asked, and nothing this member does on the channel is authorized.
        if code == reqwest::StatusCode::FORBIDDEN {
            return Ok(GrantState::NotMember);
        }
        if !code.is_success() {
            return Err(StatusError::Unreadable(format!("control plane answered {code}")));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| StatusError::Unreadable(format!("unreadable answer: {e}")))?;
        match v.get("state").and_then(|s| s.as_str()) {
            Some("valid") => Ok(GrantState::Valid),
            Some("revoked") => Ok(GrantState::Revoked),
            Some("not-member") => Ok(GrantState::NotMember),
            other => Err(StatusError::Unreadable(format!("unknown state {other:?}"))),
        }
    }
}

impl GrantStatusSource for CpStatusSource {
    fn status(&self) -> StatusFuture<'_> {
        Box::pin(self.ask())
    }
}

/// Run the watch until the grant ends or the session does. `end` is the session's way of
/// hearing about it; when its receiver is dropped (the session is over) the loop stops.
pub async fn watch_peer_grant(setup: WatchSetup, mut end: oneshot::Sender<String>) {
    let mut last_valid = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(setup.config.interval) => {}
            _ = end.closed() => return,
        }
        let verdict = tokio::select! {
            v = setup.source.status() => v,
            _ = end.closed() => return,
        };
        let reason = match verdict {
            Ok(GrantState::Valid) => {
                last_valid = tokio::time::Instant::now();
                continue;
            }
            Ok(GrantState::Revoked) => "the peer's grant was revoked".to_string(),
            Ok(GrantState::NotMember) => "the peer is no longer a member of the channel".to_string(),
            Err(StatusError::Unsupported) => {
                "the control plane cannot re-check grants (no /channel/grant-status); \
                 refusing to keep a forward session nobody can revoke"
                    .to_string()
            }
            Err(StatusError::Unreadable(why)) => {
                let silent = last_valid.elapsed();
                if silent < setup.config.grace {
                    eprintln!(
                        "ct-agent channel: grant re-check unreadable for {}s (limit {}s): {why}",
                        silent.as_secs(),
                        setup.config.grace.as_secs()
                    );
                    continue;
                }
                format!(
                    "the peer's grant could not be re-checked for {}s ({why}); failing closed",
                    silent.as_secs()
                )
            }
        };
        let _ = end.send(reason);
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[test]
    fn digest_and_status_bytes_match_the_control_plane_vectors() {
        // Same vector the control plane pins (CADS-Tunnel ct-common
        // grant_digest_and_revoke_bytes_are_pinned_for_cross_repo_use).
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
        assert_eq!(
            crate::codec::hex_encode(&grant_digest(&signed)),
            "76e43324c486202745e98926f6362b6966ee3935f24aa72a784f77deb103d662"
        );
        let b = status_signing_bytes(&[0x11; 32], &[2; 32], &[1; 32], 5);
        assert!(b.starts_with(b"ct-grant-status:v1|"));
        assert_eq!(b.len(), 19 + 32 + 1 + 32 + 1 + 32 + 1 + 8);
        assert_eq!(&b[b.len() - 8..], &5u64.to_le_bytes());
    }

    #[test]
    fn config_defaults_floors_and_rejects_garbage() {
        let none = |_: &str| None;
        let d = WatchConfig::from_lookup(none).unwrap();
        assert_eq!((d.interval.as_secs(), d.grace.as_secs()), (30, 90));
        let f = |k: &str| match k {
            RECHECK_SECS_ENV => Some("1".to_string()),
            RECHECK_GRACE_SECS_ENV => Some("2".to_string()),
            _ => None,
        };
        let c = WatchConfig::from_lookup(f).unwrap();
        assert_eq!((c.interval.as_secs(), c.grace.as_secs()), (5, 5), "floor, and grace >= interval");
        let bad = |k: &str| (k == RECHECK_SECS_ENV).then(|| "soon".to_string());
        assert!(WatchConfig::from_lookup(bad).unwrap_err().contains(RECHECK_SECS_ENV));
    }

    struct Script(Mutex<VecDeque<Result<GrantState, StatusError>>>);
    impl Script {
        fn new(v: Vec<Result<GrantState, StatusError>>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(v.into())))
        }
    }
    impl GrantStatusSource for Script {
        fn status(&self) -> StatusFuture<'_> {
            // Once the script runs out the control plane stays unreachable.
            let next = self.0.lock().unwrap().pop_front();
            Box::pin(async move { next.unwrap_or(Err(StatusError::Unreadable("down".into()))) })
        }
    }

    fn setup(src: Arc<Script>) -> WatchSetup {
        WatchSetup {
            source: src,
            config: WatchConfig { interval: Duration::from_secs(30), grace: Duration::from_secs(90) },
        }
    }

    async fn run(src: Arc<Script>) -> (Option<String>, Duration) {
        let (tx, rx) = oneshot::channel();
        let started = tokio::time::Instant::now();
        let h = tokio::spawn(watch_peer_grant(setup(src), tx));
        let got = rx.await.ok();
        let _ = h.await;
        (got, started.elapsed())
    }

    #[tokio::test(start_paused = true)]
    async fn a_revoked_answer_ends_the_session_at_the_next_tick_and_valid_ones_do_not() {
        let (why, after) = run(Script::new(vec![
            Ok(GrantState::Valid),
            Ok(GrantState::Valid),
            Ok(GrantState::Revoked),
        ]))
        .await;
        assert!(why.unwrap().contains("revoked"));
        assert_eq!(after, Duration::from_secs(90), "third tick, not before");
    }

    #[tokio::test(start_paused = true)]
    async fn removal_from_the_channel_ends_the_session() {
        let (why, _) = run(Script::new(vec![Ok(GrantState::NotMember)])).await;
        assert!(why.unwrap().contains("no longer a member"));
    }

    #[tokio::test(start_paused = true)]
    async fn an_unreadable_state_is_tolerated_for_the_grace_and_then_fails_closed() {
        // Valid at 30 s, then the control plane goes away: the session survives until 90 s
        // after the last valid answer (120 s), and not a tick longer.
        let (why, after) = run(Script::new(vec![Ok(GrantState::Valid)])).await;
        assert!(why.unwrap().contains("failing closed"));
        assert_eq!(after, Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn a_recovered_control_plane_resets_the_grace() {
        let (why, after) = run(Script::new(vec![
            Err(StatusError::Unreadable("blip".into())),
            Err(StatusError::Unreadable("blip".into())),
            Ok(GrantState::Valid), // at 90 s
        ]))
        .await;
        assert!(why.unwrap().contains("failing closed"));
        assert_eq!(after, Duration::from_secs(180), "the clock restarted at the valid answer");
    }

    #[tokio::test(start_paused = true)]
    async fn a_control_plane_without_the_endpoint_ends_the_session_at_once() {
        let (why, after) = run(Script::new(vec![Err(StatusError::Unsupported)])).await;
        assert!(why.unwrap().contains("cannot re-check"));
        assert_eq!(after, Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn the_watch_stops_when_the_session_is_gone() {
        let (tx, rx) = oneshot::channel::<String>();
        let h = tokio::spawn(watch_peer_grant(setup(Script::new(vec![])), tx));
        drop(rx);
        tokio::time::timeout(Duration::from_secs(1), h).await.expect("watch must stop").unwrap();
    }
}
