//! End-to-end check of the paired peer's channel grant (security audit finding: the peer's holder
//! is not bound to an operator-signed grant).
//!
//! Admission hands a member the peer's Noise key together with the peer's holder key and the
//! holder's attestation over that Noise key (#101). All three come from the broker. The
//! attestation proves only that `holder` signed `(channel, holder, noise)` -- nothing proves that
//! the operator ever granted `holder` anything. A compromised or malicious broker can therefore
//! mint its own holder key, attest its own Noise key with it, and be pinned and served as a fully
//! authenticated member: call every non-bridge tool on a serving member, or impersonate the
//! service provider towards an initiator and read its prompts.
//!
//! The fix, entirely between the two members: right after the Noise handshake each side sends its
//! own operator-signed grant as the first bytes inside the encrypted session, and the other side
//! checks it before a single application byte flows in either direction:
//!
//! * the grant verifies against the operator public key (`CT_CHANNEL_OPERATOR_PUBKEY`) and has
//!   not expired;
//! * it is for this member's own channel;
//! * its holder is the peer holder admission attested the pinned Noise key with;
//! * its direction is the complement of this member's role (an initiator needs a peer that may
//!   accept, and vice versa; `Both` satisfies either).
//!
//! It is implemented as a wrapper around the session's `local` side ([`PeerGrantGate`]), so every
//! session runner -- direct, relay, the upgradable and the DCUtR ones -- gets it without a change
//! to the wire protocol below the Noise session. It is a protocol change between members, though:
//! a member that sends the prelude to one that does not expect it corrupts that member's first
//! application bytes. It is therefore opt-in (`CT_CHANNEL_REQUIRE_PEER_GRANT`) and has to be
//! switched on for every member of a channel together.
//!
//! ## The grant's end is enforced for as long as the session runs
//!
//! The check above is a *point-in-time* admission decision: it ran once, right after the Noise
//! handshake. A session admitted at 10:00 with a grant that expires at 10:05 kept running at
//! 11:00 -- and kept forwarding TCP streams (#255) -- for as long as both members stayed
//! connected. INC-20260930-101: a revoked or expired grant has to end the session it authorized.
//! [`GrantLifetime`] is that clock. It is armed with this member's OWN grant expiry when the gate
//! is built, re-armed with the EARLIER of the two expiries as soon as the peer's grant verifies,
//! and it also carries a [`GrantRevokeHandle`] for a revocation that reaches this member while
//! the session runs. When it fires, the session's plaintext side EOFs and the local side is
//! closed underneath it, which ends every forwarded stream on both members within
//! [`GRANT_TEARDOWN_BUDGET`] and leaves the initiate side's listener refusing new connections.
//!
//! ## Telling a grant end from any other session end (ct-agent#267)
//!
//! From outside, every session end looks the same: the session future returns. A forward
//! initiator must reconnect after a peer restart or a relay/network drop, but must NOT after its
//! grant ran out or was revoked. So the end is recorded as state, not inferred from log text:
//! whoever runs a session inside [`with_grant_end_record`] gets the [`GrantEndRecord`] that every
//! gate built within that scope writes its end reason into, at the same moment it logs it.
//
// trace: AUF-20260930-005 (INC-20260930-101)
// trace: AUF-20261004-022 (ct-agent#267)

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ct_common::channel::{Direction, SignedChannelGrant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

use super::ChannelRole;

/// Switch for the peer-grant check (off by default; see the module doc for the rollout).
pub const REQUIRE_PEER_GRANT_ENV: &str = "CT_CHANNEL_REQUIRE_PEER_GRANT";
/// The operator public key peer grants are checked against (64 hex).
pub const OPERATOR_PUBKEY_ENV: &str = "CT_CHANNEL_OPERATOR_PUBKEY";

/// Prefix of the grant prelude, so a peer that does not speak it is refused with a clear message
/// instead of a signature error on its application bytes.
const MAGIC: &[u8; 5] = b"CTPG1";
/// Length of the prelude each side sends: the magic, then the fixed-size encoded grant.
pub(crate) const PRELUDE_LEN: usize = MAGIC.len() + SignedChannelGrant::WIRE_LEN;
/// How long a peer has, after the Noise handshake, to present its grant.
pub(crate) const PEER_GRANT_TIMEOUT: Duration = Duration::from_secs(10);
/// The budget INC-20260930-101 gives a session whose grant ended: within it every forwarded
/// stream of that session is closed on BOTH members and no new one is opened. Nothing here ever
/// waits this out -- [`GrantLifetime`] ends the session on the next poll of its plaintext side --
/// it is the bound the tests assert against, named once so they and this doc cannot drift apart.
pub const GRANT_TEARDOWN_BUDGET: Duration = Duration::from_secs(5);

/// The configuration of the check: on, with the operator key to verify against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGrantPolicy {
    pub operator: [u8; 32],
}

impl PeerGrantPolicy {
    /// `Ok(None)` when the check is off; `Err` when it is on without a usable operator key, so a
    /// half-configured member fails closed at join time instead of silently skipping the check.
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`from_env`](Self::from_env) over a variable lookup (the testable seam).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        if !crate::envflag::flag_named(
            REQUIRE_PEER_GRANT_ENV,
            f(REQUIRE_PEER_GRANT_ENV).as_deref(),
            false,
        ) {
            return Ok(None);
        }
        let raw = f(OPERATOR_PUBKEY_ENV).unwrap_or_default();
        let operator = crate::codec::hex_decode::<32>(raw.trim()).ok_or_else(|| {
            format!(
                "{REQUIRE_PEER_GRANT_ENV} is on but {OPERATOR_PUBKEY_ENV} is not a 64-hex operator public key \
                 -- the peer's grant cannot be checked, refusing to join"
            )
        })?;
        Ok(Some(Self { operator }))
    }
}

/// Everything one session needs to check its peer: the policy, this member's own grant (sent to
/// the peer, and the channel to compare with), the peer holder admission attested, and this
/// member's role.
#[derive(Debug, Clone)]
pub struct PeerGrantCheck {
    pub policy: PeerGrantPolicy,
    pub own_grant: SignedChannelGrant,
    pub peer_holder: [u8; 32],
    pub role: ChannelRole,
}

impl PeerGrantCheck {
    /// The prelude this member sends: the magic, then its own encoded grant.
    fn prelude(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PRELUDE_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.own_grant.encode());
        out
    }

    /// Check the peer's prelude at `now` (unix seconds). Pure.
    pub fn verify(&self, prelude: &[u8], now: u64) -> Result<SignedChannelGrant, String> {
        let body = prelude
            .strip_prefix(MAGIC.as_slice())
            .ok_or("the peer did not present a channel grant (is CT_CHANNEL_REQUIRE_PEER_GRANT on for it?)")?;
        let grant = SignedChannelGrant::decode(body)
            .map_err(|e| format!("the peer's grant is malformed: {e}"))?;
        ct_common::channel::verify_stateless(&self.policy.operator, &grant, now).map_err(|e| {
            format!("the peer's grant does not verify against the operator key: {e}")
        })?;
        if grant.grant.channel != self.own_grant.grant.channel {
            return Err("the peer's grant is for a different channel".to_string());
        }
        if grant.grant.holder != self.peer_holder {
            return Err(
                "the peer's grant is for another holder than the one admission attested"
                    .to_string(),
            );
        }
        let complementary = matches!(
            (self.role, grant.grant.direction),
            (_, Direction::Both)
                | (ChannelRole::Initiate, Direction::Accept)
                | (ChannelRole::Accept, Direction::Initiate)
        );
        if !complementary {
            return Err(format!(
                "the peer's grant does not allow the opposite direction of this member's role ({:?})",
                self.role
            ));
        }
        Ok(grant)
    }
}

/// Ends one session from the outside when its member learns the peer's grant was revoked
/// (AUF-20260930-005). Broker-side delivery of a revocation is `bridge/channel-revoke`, which is
/// not built yet; this is the enforcement seam it drives when it is, and the seam the tests
/// revoke through. Dropping the handle without revoking leaves the session alone -- the expiry
/// clock is then the only thing that ends it.
pub struct GrantRevokeHandle(oneshot::Sender<String>);

impl GrantRevokeHandle {
    /// End the session this handle came from: every stream it forwards is closed and no new one
    /// is opened. `reason` is what the operator reads in the `channel_session` event.
    pub fn revoke(self, reason: impl Into<String>) {
        let _ = self.0.send(reason.into());
    }
}

/// Where a session's grant end is recorded for its caller (ct-agent#267, see the module doc):
/// `Some(reason)` once a [`PeerGrantGate`] built inside [`with_grant_end_record`] saw its grant
/// expire or get revoked, `None` for every other way a session can end.
#[derive(Clone, Default)]
pub(crate) struct GrantEndRecord(Arc<Mutex<Option<String>>>);

impl GrantEndRecord {
    fn set(&self, why: &str) {
        if let Ok(mut slot) = self.0.lock() {
            slot.get_or_insert_with(|| why.to_string());
        }
    }

    /// The recorded grant end, if any. Reading does not clear it.
    pub(crate) fn ended(&self) -> Option<String> {
        self.0.lock().ok().and_then(|slot| slot.clone())
    }
}

tokio::task_local! {
    /// The record of the session currently running in this task -- a task-local rather than one
    /// more parameter through the dozen-argument join path, which builds its gate deep inside
    /// (`gate_local`). Outside a [`with_grant_end_record`] scope there is none, and a gate then
    /// records nothing (every caller that does not ask, unchanged).
    static GRANT_END_RECORD: GrantEndRecord;
}

/// Run `session` with `record` as the place every [`PeerGrantGate`] it builds writes its grant end
/// into (ct-agent#267). The gate must be built inside `session` -- on this task, not a spawned one.
pub(crate) async fn with_grant_end_record<F: std::future::Future>(
    record: GrantEndRecord,
    session: F,
) -> F::Output {
    GRANT_END_RECORD.scope(record, session).await
}

/// When the members' grants stop authorizing this session -- the expiry clock and the revocation
/// side-channel, polled from the session's own plaintext side (see the module doc).
///
/// Both are polled, never awaited in a task of their own: the session pump holds a read on its
/// `local` at all times, so registering `cx` on the timer here is enough for the *next* poll,
/// milliseconds after the grant ends, to be the one that tears the session down.
struct GrantLifetime {
    /// Fires when the earlier of the two members' grants expires. `None` when this session has
    /// no grant to watch (the check is off) or once it has already ended.
    expiry: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The revocation channel; `None` once nobody can revoke any more (the handle was dropped
    /// without being used, or the session has ended).
    revoke: Option<oneshot::Receiver<String>>,
    /// Set exactly once, the operator-facing reason the session ended.
    ended: Option<String>,
    /// ct-agent#267: the caller's record of that end, when the session runs inside
    /// [`with_grant_end_record`].
    record: Option<GrantEndRecord>,
}

impl GrantLifetime {
    /// A timer for a grant that expires at `expires_at` (unix seconds, the clock the grants
    /// themselves are written in). `now_unix()` truncates to the second, so the timer can fire
    /// up to a second EARLY and never late -- the safe direction for an authorization that has
    /// run out.
    fn timer(expires_at: u64) -> Pin<Box<tokio::time::Sleep>> {
        let left = expires_at.saturating_sub(crate::codec::now_unix());
        Box::pin(tokio::time::sleep(Duration::from_secs(left)))
    }

    /// Whether this session is over, registering `cx` on whichever of the two ends can still
    /// happen. Cheap and idempotent: once ended it answers from `ended` alone.
    fn poll_ended(&mut self, cx: &mut Context<'_>) -> bool {
        if self.ended.is_some() {
            return true;
        }
        let expired = match self.expiry.as_mut() {
            Some(timer) => std::future::Future::poll(timer.as_mut(), cx).is_ready(),
            None => false,
        };
        if expired {
            return self.end("the channel grant expired".to_string());
        }
        let revoked = match self.revoke.as_mut() {
            Some(rx) => std::future::Future::poll(Pin::new(rx), cx),
            None => Poll::Pending,
        };
        match revoked {
            Poll::Ready(Ok(why)) => self.end(format!("the channel grant was revoked: {why}")),
            // Nobody holds the handle (never taken, or dropped unused): only expiry can end it.
            Poll::Ready(Err(_)) => {
                self.revoke = None;
                false
            }
            Poll::Pending => false,
        }
    }

    /// Record the end once -- logged and emitted, because "my forward died" must be answerable
    /// from this member's own output without a broker round trip -- and report it as ended.
    fn end(&mut self, why: String) -> bool {
        eprintln!("ct-agent channel: {why} -- ending the session and every stream it forwards");
        crate::events::emit(
            crate::events::CHANNEL_SESSION,
            serde_json::json!({ "state": "grant_ended", "reason": why }),
        );
        self.expiry = None;
        self.revoke = None;
        if let Some(record) = &self.record {
            record.set(&why);
        }
        self.ended = Some(why);
        true
    }

    /// The reason the session ended, for the error writers get.
    fn reason(&self) -> &str {
        self.ended.as_deref().unwrap_or("the channel grant ended")
    }
}

/// The session's `local` side with the grant exchange in front of it (see the module doc). With
/// no check it is a transparent pass-through.
///
/// Towards the peer (what the session reads from here) it first yields this member's prelude,
/// then holds all application data back until the peer's grant has been verified. From the peer
/// (what the session writes here) it consumes exactly the peer's prelude, verifies it, and only
/// then passes bytes on to the real `local`. A missing, late (past [`PEER_GRANT_TIMEOUT`]) or
/// invalid grant fails both directions with `PermissionDenied`, ending the session.
///
/// It is also where the session's grant *lifetime* is enforced (AUF-20260930-005): see
/// [`GrantLifetime`] and the module doc.
pub struct PeerGrantGate<P> {
    inner: P,
    gate: Option<Gate>,
    life: GrantLifetime,
    revoker: Option<GrantRevokeHandle>,
}

struct Gate {
    check: PeerGrantCheck,
    out: Vec<u8>,
    out_pos: usize,
    peer: Vec<u8>,
    verified: bool,
    failed: Option<String>,
    reader: Option<Waker>,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<P> PeerGrantGate<P> {
    pub fn new(inner: P, check: Option<PeerGrantCheck>) -> Self {
        // This member's own grant already bounds the session before the peer's is known; the
        // peer's expiry is folded in (as the earlier of the two) the moment it verifies.
        let expiry = check
            .as_ref()
            .map(|c| GrantLifetime::timer(c.own_grant.grant.expires_at));
        let (revoker, revoke) = oneshot::channel();
        let gate = check.map(|check| Gate {
            out: check.prelude(),
            out_pos: 0,
            peer: Vec::with_capacity(PRELUDE_LEN),
            verified: false,
            failed: None,
            reader: None,
            deadline: Box::pin(tokio::time::sleep(PEER_GRANT_TIMEOUT)),
            check,
        });
        Self {
            inner,
            gate,
            life: GrantLifetime {
                expiry,
                revoke: Some(revoke),
                ended: None,
                record: GRANT_END_RECORD.try_with(GrantEndRecord::clone).ok(),
            },
            revoker: Some(GrantRevokeHandle(revoker)),
        }
    }

    /// The handle that ends this session on a revocation -- `None` on every call after the
    /// first, since a session has exactly one owner of its teardown.
    pub fn revoke_handle(&mut self) -> Option<GrantRevokeHandle> {
        self.revoker.take()
    }
}

fn denied(why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("channel peer grant: {why}"),
    )
}

impl Gate {
    fn fail(&mut self, why: String) -> io::Error {
        let err = denied(&why);
        crate::events::emit(
            crate::events::CHANNEL_SESSION,
            serde_json::json!({ "state": "refused", "reason": why }),
        );
        self.failed = Some(why);
        if let Some(w) = self.reader.take() {
            w.wake();
        }
        err
    }

    fn done(&self) -> bool {
        self.verified && self.out_pos == self.out.len()
    }
}

// `AsyncWrite` as well as `AsyncRead` (AUF-20260930-005): when the grant ends, the read side
// closes the local side itself rather than only reporting EOF upwards -- see `poll_read`.
impl<P: AsyncRead + AsyncWrite + Unpin> AsyncRead for PeerGrantGate<P> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.life.poll_ended(cx) {
            // EOF towards the session pump, so it FINs the peer and the whole session ends; and
            // the local side shut down underneath it, so the forward engine (#255) -- which owns
            // every forwarded stream in a JoinSet and the initiate side's listener -- sees its
            // own end of this duplex go EOF at once. That second half is what makes the 5 s
            // budget independent of the peer: a peer that never closes cannot keep this member's
            // streams alive, and the listener is gone before the next connection can be opened.
            let _ = Pin::new(&mut this.inner).poll_shutdown(cx);
            return Poll::Ready(Ok(()));
        }
        if let Some(g) = this.gate.as_mut() {
            if g.out_pos < g.out.len() {
                let n = buf.remaining().min(g.out.len() - g.out_pos);
                buf.put_slice(&g.out[g.out_pos..g.out_pos + n]);
                g.out_pos += n;
                if g.done() {
                    this.gate = None;
                }
                return Poll::Ready(Ok(()));
            }
            if let Some(why) = &g.failed {
                return Poll::Ready(Err(denied(why)));
            }
            if !g.verified {
                if std::future::Future::poll(g.deadline.as_mut(), cx).is_ready() {
                    let secs = PEER_GRANT_TIMEOUT.as_secs();
                    return Poll::Ready(Err(
                        g.fail(format!("the peer did not present its grant within {secs}s"))
                    ));
                }
                g.reader = Some(cx.waker().clone());
                return Poll::Pending;
            }
            this.gate = None;
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<P: AsyncWrite + Unpin> AsyncWrite for PeerGrantGate<P> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.life.poll_ended(cx) {
            // Nothing the peer sends reaches this member's local side after its grant ended.
            return Poll::Ready(Err(denied(this.life.reason())));
        }
        if let Some(g) = this.gate.as_mut() {
            if let Some(why) = &g.failed {
                return Poll::Ready(Err(denied(why)));
            }
            if !g.verified {
                let take = data.len().min(PRELUDE_LEN - g.peer.len());
                g.peer.extend_from_slice(&data[..take]);
                if g.peer.len() == PRELUDE_LEN {
                    match g.check.verify(&g.peer, crate::codec::now_unix()) {
                        Ok(peer) => {
                            g.verified = true;
                            // From here the session is bounded by the EARLIER of the two grants:
                            // a peer whose grant runs out first must not keep forwarding on ours.
                            let ends_at = g
                                .check
                                .own_grant
                                .grant
                                .expires_at
                                .min(peer.grant.expires_at);
                            this.life.expiry = Some(GrantLifetime::timer(ends_at));
                            if let Some(w) = g.reader.take() {
                                w.wake();
                            }
                        }
                        Err(why) => return Poll::Ready(Err(g.fail(why))),
                    }
                    if g.done() {
                        this.gate = None;
                    }
                }
                return Poll::Ready(Ok(take));
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(g) = this.gate.as_mut() {
            if !g.verified && g.failed.is_none() {
                // The peer closed without presenting a grant: nothing of ours is released.
                let _ =
                    g.fail("the peer closed the session before presenting its grant".to_string());
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Rights};
    use ed25519_dalek::{Signer as _, SigningKey};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const NOW: u64 = 1_000_000;
    const CHANNEL: [u8; 32] = [0x5c; 32];

    fn grant(
        operator: &SigningKey,
        channel: [u8; 32],
        holder: [u8; 32],
        direction: Direction,
        expires_at: u64,
    ) -> SignedChannelGrant {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder,
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        SignedChannelGrant {
            signature: operator.sign(&g.signing_bytes()).to_bytes(),
            grant: g,
        }
    }

    fn prelude_of(g: &SignedChannelGrant) -> Vec<u8> {
        [MAGIC.as_slice(), &g.encode()].concat()
    }

    struct Fixture {
        operator: SigningKey,
        initiator: [u8; 32],
        acceptor: [u8; 32],
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                operator: SigningKey::from_bytes(&[0x01; 32]),
                initiator: SigningKey::from_bytes(&[0x02; 32])
                    .verifying_key()
                    .to_bytes(),
                acceptor: SigningKey::from_bytes(&[0x03; 32])
                    .verifying_key()
                    .to_bytes(),
            }
        }

        fn check(&self, role: ChannelRole) -> PeerGrantCheck {
            let (own, peer, dir) = match role {
                ChannelRole::Initiate => (self.initiator, self.acceptor, Direction::Initiate),
                ChannelRole::Accept => (self.acceptor, self.initiator, Direction::Accept),
            };
            PeerGrantCheck {
                policy: PeerGrantPolicy {
                    operator: self.operator.verifying_key().to_bytes(),
                },
                // Valid at the real clock too: the gate checks with `now_unix()`.
                own_grant: grant(
                    &self.operator,
                    CHANNEL,
                    own,
                    dir,
                    crate::codec::now_unix() + 3600,
                ),
                peer_holder: peer,
                role,
            }
        }
    }

    #[test]
    fn a_genuine_peer_grant_is_accepted() {
        let f = Fixture::new();
        let acceptor_grant = grant(
            &f.operator,
            CHANNEL,
            f.acceptor,
            Direction::Accept,
            NOW + 60,
        );
        assert!(f
            .check(ChannelRole::Initiate)
            .verify(&prelude_of(&acceptor_grant), NOW)
            .is_ok());
        let both = grant(&f.operator, CHANNEL, f.acceptor, Direction::Both, NOW + 60);
        assert!(
            f.check(ChannelRole::Initiate)
                .verify(&prelude_of(&both), NOW)
                .is_ok(),
            "Both satisfies either role"
        );
    }

    #[test]
    fn a_broker_minted_identity_is_refused() {
        // The audit's attack: the broker invents a holder, attests its own Noise key with it and
        // has no operator signature to show -- whatever it signs itself with is not the operator.
        let f = Fixture::new();
        let broker = SigningKey::from_bytes(&[0x66; 32]);
        let broker_holder = broker.verifying_key().to_bytes();
        let mut check = f.check(ChannelRole::Initiate);
        check.peer_holder = broker_holder;
        let self_signed = grant(&broker, CHANNEL, broker_holder, Direction::Accept, NOW + 60);
        let err = check.verify(&prelude_of(&self_signed), NOW).unwrap_err();
        assert!(
            err.contains("does not verify against the operator key"),
            "{err}"
        );
    }

    #[test]
    fn every_mismatch_is_refused_with_its_reason() {
        let f = Fixture::new();
        let check = f.check(ChannelRole::Initiate);
        let cases = [
            (
                grant(
                    &f.operator,
                    [0x77; 32],
                    f.acceptor,
                    Direction::Accept,
                    NOW + 60,
                ),
                "different channel",
            ),
            (
                grant(
                    &f.operator,
                    CHANNEL,
                    f.initiator,
                    Direction::Accept,
                    NOW + 60,
                ),
                "another holder",
            ),
            (
                grant(
                    &f.operator,
                    CHANNEL,
                    f.acceptor,
                    Direction::Initiate,
                    NOW + 60,
                ),
                "opposite direction",
            ),
            (
                grant(&f.operator, CHANNEL, f.acceptor, Direction::Accept, NOW),
                "does not verify",
            ),
        ];
        for (g, why) in cases {
            let err = check.verify(&prelude_of(&g), NOW).unwrap_err();
            assert!(err.contains(why), "expected '{why}': {err}");
        }
        let err = check.verify(b"GET / HTTP/1.1\r\n", NOW).unwrap_err();
        assert!(err.contains("did not present a channel grant"), "{err}");
    }

    #[test]
    fn the_policy_is_off_by_default_and_fails_closed_without_an_operator_key() {
        let lookup = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(PeerGrantPolicy::from_lookup(lookup(&[])), Ok(None));
        assert!(
            PeerGrantPolicy::from_lookup(lookup(&[(REQUIRE_PEER_GRANT_ENV, "1")]))
                .unwrap_err()
                .contains(OPERATOR_PUBKEY_ENV)
        );
        let key = "11".repeat(32);
        let key: &'static str = Box::leak(key.into_boxed_str());
        let pairs: &'static [(&'static str, &'static str)] = Box::leak(Box::new([
            (REQUIRE_PEER_GRANT_ENV, "on"),
            (OPERATOR_PUBKEY_ENV, key),
        ]));
        assert_eq!(
            PeerGrantPolicy::from_lookup(lookup(pairs)),
            Ok(Some(PeerGrantPolicy {
                operator: [0x11; 32]
            }))
        );
    }

    /// Two gated sessions joined by an in-memory "tunnel" (standing in for the Noise pump): returns
    /// the two application ends.
    fn session_pair(
        a: Option<PeerGrantCheck>,
        b: Option<PeerGrantCheck>,
    ) -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        tokio::task::JoinHandle<()>,
    ) {
        let (app_a, local_a) = tokio::io::duplex(4096);
        let (app_b, local_b) = tokio::io::duplex(4096);
        let mut gate_a = PeerGrantGate::new(local_a, a);
        let mut gate_b = PeerGrantGate::new(local_b, b);
        let tunnel = tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut gate_a, &mut gate_b).await;
        });
        (app_a, app_b, tunnel)
    }

    #[tokio::test]
    async fn verified_members_exchange_application_data() {
        let f = Fixture::new();
        let (mut a, mut b, tunnel) = session_pair(
            Some(f.check(ChannelRole::Initiate)),
            Some(f.check(ChannelRole::Accept)),
        );
        a.write_all(b"prompt").await.unwrap();
        let mut got = [0u8; 6];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"prompt");
        b.write_all(b"answer").await.unwrap();
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"answer");
        tunnel.abort();
    }

    #[tokio::test]
    async fn an_unverified_peer_never_sees_application_data() {
        // The acceptor presents a grant signed by someone else. The initiator refuses it, and its
        // prompt -- written before the exchange completes -- never leaves it.
        let f = Fixture::new();
        let mut forged = f.check(ChannelRole::Accept);
        forged.own_grant = grant(
            &SigningKey::from_bytes(&[0x66; 32]),
            CHANNEL,
            f.acceptor,
            Direction::Accept,
            crate::codec::now_unix() + 3600,
        );
        let (mut a, mut b, tunnel) =
            session_pair(Some(f.check(ChannelRole::Initiate)), Some(forged));
        a.write_all(b"secret prompt").await.unwrap();
        let mut got = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), b.read_to_end(&mut got)).await;
        assert!(
            !String::from_utf8_lossy(&got).contains("secret"),
            "the prompt leaked: {got:?}"
        );
        assert!(read.is_ok(), "the session ended instead of hanging");
        tunnel.abort();
    }

    #[tokio::test]
    async fn without_a_check_the_gate_is_transparent() {
        let (mut a, mut b, tunnel) = session_pair(None, None);
        a.write_all(b"plain").await.unwrap();
        let mut got = [0u8; 5];
        b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"plain");
        tunnel.abort();
    }

    /// The real Noise session runner on both ends, gated: the grant exchange rides inside the
    /// encrypted session in front of the application bytes, and a forged grant ends it.
    async fn noise_session(forge_acceptor: bool) -> (Vec<u8>, bool) {
        use super::super::run_channel_session_on_stream;
        use ct_common::noise::generate_static_keypair;
        let f = Fixture::new();
        let (a, b) = (generate_static_keypair(), generate_static_keypair());
        let (a_priv, a_pub, b_priv, b_pub) = (a.private, a.public, b.private, b.public);
        let (a_transport, b_transport) = tokio::io::duplex(16 * 1024);
        let (mut a_app, a_local) = tokio::io::duplex(16 * 1024);
        let (mut b_app, b_local) = tokio::io::duplex(16 * 1024);
        let mut b_check = f.check(ChannelRole::Accept);
        if forge_acceptor {
            b_check.own_grant = grant(
                &SigningKey::from_bytes(&[0x66; 32]),
                CHANNEL,
                f.acceptor,
                Direction::Accept,
                crate::codec::now_unix() + 3600,
            );
        }
        let a_gate = PeerGrantGate::new(a_local, Some(f.check(ChannelRole::Initiate)));
        let b_gate = PeerGrantGate::new(b_local, Some(b_check));
        let a_task = tokio::spawn(async move {
            let (r, w) = tokio::io::split(a_transport);
            run_channel_session_on_stream(w, r, ChannelRole::Initiate, &a_priv, &b_pub, a_gate)
                .await
        });
        let b_task = tokio::spawn(async move {
            let (r, w) = tokio::io::split(b_transport);
            run_channel_session_on_stream(w, r, ChannelRole::Accept, &b_priv, &a_pub, b_gate).await
        });
        a_app.write_all(b"secret prompt").await.unwrap();
        let mut got = vec![0u8; 13];
        let received =
            tokio::time::timeout(Duration::from_secs(5), b_app.read_exact(&mut got)).await;
        let a_failed = match received {
            Ok(Ok(_)) => false,
            _ => {
                got.clear();
                // The session runner still drains the stream (bounded, 30 s) before it returns.
                matches!(
                    tokio::time::timeout(Duration::from_secs(60), a_task).await,
                    Ok(Ok(Err(_)))
                )
            }
        };
        b_task.abort();
        (got, a_failed)
    }

    #[tokio::test]
    async fn over_a_real_noise_session_verified_members_talk() {
        let (got, _) = noise_session(false).await;
        assert_eq!(got, b"secret prompt");
    }

    #[tokio::test(start_paused = true)]
    async fn over_a_real_noise_session_a_forged_grant_ends_the_session_before_any_data() {
        let (got, a_failed) = noise_session(true).await;
        assert!(got.is_empty(), "nothing reached the impostor: {got:?}");
        assert!(a_failed, "the initiator's session ended with an error");
    }

    /// AUF-20260930-005 (INC-20260930-101): the grant's expiry ends the session it authorized,
    /// and closes the local side with it -- the mechanism the forward engines' teardown rests on
    /// (`channel_run::tests` proves the end-to-end effect on real forwarded TCP streams).
    #[tokio::test(start_paused = true)]
    async fn an_expiring_grant_ends_the_session_and_closes_the_local_side() {
        let f = Fixture::new();
        let mut check = f.check(ChannelRole::Initiate);
        check.own_grant = grant(
            &f.operator,
            CHANNEL,
            f.initiator,
            Direction::Initiate,
            crate::codec::now_unix() + 1,
        );
        let (mut app, local) = tokio::io::duplex(4096);
        let mut gate = PeerGrantGate::new(local, Some(check));
        let mut prelude = vec![0u8; PRELUDE_LEN];
        gate.read_exact(&mut prelude).await.unwrap();

        // Past the expiry the session's plaintext side reads EOF -- within the budget, and
        // without the peer having done anything at all.
        let mut more = [0u8; 1];
        let n = tokio::time::timeout(GRANT_TEARDOWN_BUDGET, gate.read(&mut more))
            .await
            .expect("the session ends within the teardown budget, not at some later timeout")
            .expect("an expired grant ends the session as an EOF, so the peer gets a clean FIN");
        assert_eq!(n, 0);
        // ... and the local side itself is closed, which is what the forward engine sees.
        let mut rest = Vec::new();
        app.read_to_end(&mut rest)
            .await
            .expect("the local side is shut down, not left dangling");
        assert!(rest.is_empty());
        // Nothing the peer sends can reach the local side any more.
        assert!(gate.write_all(b"late").await.is_err());
    }

    /// AUF-20260930-005: the same end, reached by a revocation instead of the clock.
    #[tokio::test(start_paused = true)]
    async fn a_revoked_grant_ends_the_session() {
        let f = Fixture::new();
        let (mut app, local) = tokio::io::duplex(4096);
        let mut gate = PeerGrantGate::new(local, Some(f.check(ChannelRole::Initiate)));
        let revoke = gate
            .revoke_handle()
            .expect("the first caller owns the teardown");
        assert!(
            gate.revoke_handle().is_none(),
            "a session has exactly one revoke handle"
        );
        let mut prelude = vec![0u8; PRELUDE_LEN];
        gate.read_exact(&mut prelude).await.unwrap();

        revoke.revoke("the operator revoked the peer's grant");
        let mut more = [0u8; 1];
        let n = tokio::time::timeout(GRANT_TEARDOWN_BUDGET, gate.read(&mut more))
            .await
            .expect("a revocation ends the session within the teardown budget")
            .expect("as an EOF, same as an expiry");
        assert_eq!(n, 0);
        let mut rest = Vec::new();
        app.read_to_end(&mut rest).await.unwrap();
    }

    /// The handle dropped unused must not look like a revocation -- a closed oneshot is "nobody
    /// can revoke", not "revoked".
    #[tokio::test(start_paused = true)]
    async fn dropping_the_revoke_handle_unused_leaves_the_session_alone() {
        let f = Fixture::new();
        let (app, local) = tokio::io::duplex(4096);
        let mut gate = PeerGrantGate::new(local, Some(f.check(ChannelRole::Accept)));
        drop(gate.revoke_handle());
        let mut prelude = vec![0u8; PRELUDE_LEN];
        gate.read_exact(&mut prelude).await.unwrap();
        // Still only the peer-grant timeout can end this session, minutes before the grant's own
        // expiry (an hour out, see `Fixture::check`) would.
        let mut more = [0u8; 1];
        let err = tokio::time::timeout(PEER_GRANT_TIMEOUT * 2, gate.read(&mut more))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        drop(app);
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_never_presents_its_grant_is_dropped_after_the_timeout() {
        // An ungated peer (an old member) that sends nothing: the gated side gives up.
        let f = Fixture::new();
        let (app, local) = tokio::io::duplex(4096);
        let mut gate = PeerGrantGate::new(local, Some(f.check(ChannelRole::Initiate)));
        drop(app);
        let mut prelude = vec![0u8; PRELUDE_LEN];
        gate.read_exact(&mut prelude).await.unwrap();
        let mut more = [0u8; 1];
        let err = tokio::time::timeout(PEER_GRANT_TIMEOUT * 2, gate.read(&mut more))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
