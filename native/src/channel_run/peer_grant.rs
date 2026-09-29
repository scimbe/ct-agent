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

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ct_common::channel::{Direction, SignedChannelGrant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        if !crate::envflag::flag_named(REQUIRE_PEER_GRANT_ENV, f(REQUIRE_PEER_GRANT_ENV).as_deref(), false) {
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
        let grant = SignedChannelGrant::decode(body).map_err(|e| format!("the peer's grant is malformed: {e}"))?;
        ct_common::channel::verify_stateless(&self.policy.operator, &grant, now)
            .map_err(|e| format!("the peer's grant does not verify against the operator key: {e}"))?;
        if grant.grant.channel != self.own_grant.grant.channel {
            return Err("the peer's grant is for a different channel".to_string());
        }
        if grant.grant.holder != self.peer_holder {
            return Err("the peer's grant is for another holder than the one admission attested".to_string());
        }
        let complementary = matches!(
            (self.role, grant.grant.direction),
            (_, Direction::Both) | (ChannelRole::Initiate, Direction::Accept) | (ChannelRole::Accept, Direction::Initiate)
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

/// The session's `local` side with the grant exchange in front of it (see the module doc). With
/// no check it is a transparent pass-through.
///
/// Towards the peer (what the session reads from here) it first yields this member's prelude,
/// then holds all application data back until the peer's grant has been verified. From the peer
/// (what the session writes here) it consumes exactly the peer's prelude, verifies it, and only
/// then passes bytes on to the real `local`. A missing, late (past [`PEER_GRANT_TIMEOUT`]) or
/// invalid grant fails both directions with `PermissionDenied`, ending the session.
pub struct PeerGrantGate<P> {
    inner: P,
    gate: Option<Gate>,
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
        Self { inner, gate }
    }
}

fn denied(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, format!("channel peer grant: {why}"))
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

impl<P: AsyncRead + Unpin> AsyncRead for PeerGrantGate<P> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
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
                    return Poll::Ready(Err(g.fail(format!("the peer did not present its grant within {secs}s"))));
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
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if let Some(g) = this.gate.as_mut() {
            if let Some(why) = &g.failed {
                return Poll::Ready(Err(denied(why)));
            }
            if !g.verified {
                let take = data.len().min(PRELUDE_LEN - g.peer.len());
                g.peer.extend_from_slice(&data[..take]);
                if g.peer.len() == PRELUDE_LEN {
                    match g.check.verify(&g.peer, crate::codec::now_unix()) {
                        Ok(_) => {
                            g.verified = true;
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
                let _ = g.fail("the peer closed the session before presenting its grant".to_string());
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

    fn grant(operator: &SigningKey, channel: [u8; 32], holder: [u8; 32], direction: Direction, expires_at: u64) -> SignedChannelGrant {
        let g = ChannelGrant { channel: ChannelId(channel), holder, direction, rights: Rights::ReadWrite, delegable: false, expires_at };
        SignedChannelGrant { signature: operator.sign(&g.signing_bytes()).to_bytes(), grant: g }
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
                initiator: SigningKey::from_bytes(&[0x02; 32]).verifying_key().to_bytes(),
                acceptor: SigningKey::from_bytes(&[0x03; 32]).verifying_key().to_bytes(),
            }
        }

        fn check(&self, role: ChannelRole) -> PeerGrantCheck {
            let (own, peer, dir) = match role {
                ChannelRole::Initiate => (self.initiator, self.acceptor, Direction::Initiate),
                ChannelRole::Accept => (self.acceptor, self.initiator, Direction::Accept),
            };
            PeerGrantCheck {
                policy: PeerGrantPolicy { operator: self.operator.verifying_key().to_bytes() },
                // Valid at the real clock too: the gate checks with `now_unix()`.
                own_grant: grant(&self.operator, CHANNEL, own, dir, crate::codec::now_unix() + 3600),
                peer_holder: peer,
                role,
            }
        }
    }

    #[test]
    fn a_genuine_peer_grant_is_accepted() {
        let f = Fixture::new();
        let acceptor_grant = grant(&f.operator, CHANNEL, f.acceptor, Direction::Accept, NOW + 60);
        assert!(f.check(ChannelRole::Initiate).verify(&prelude_of(&acceptor_grant), NOW).is_ok());
        let both = grant(&f.operator, CHANNEL, f.acceptor, Direction::Both, NOW + 60);
        assert!(f.check(ChannelRole::Initiate).verify(&prelude_of(&both), NOW).is_ok(), "Both satisfies either role");
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
        assert!(err.contains("does not verify against the operator key"), "{err}");
    }

    #[test]
    fn every_mismatch_is_refused_with_its_reason() {
        let f = Fixture::new();
        let check = f.check(ChannelRole::Initiate);
        let cases = [
            (grant(&f.operator, [0x77; 32], f.acceptor, Direction::Accept, NOW + 60), "different channel"),
            (grant(&f.operator, CHANNEL, f.initiator, Direction::Accept, NOW + 60), "another holder"),
            (grant(&f.operator, CHANNEL, f.acceptor, Direction::Initiate, NOW + 60), "opposite direction"),
            (grant(&f.operator, CHANNEL, f.acceptor, Direction::Accept, NOW), "does not verify"),
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
            move |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
        };
        assert_eq!(PeerGrantPolicy::from_lookup(lookup(&[])), Ok(None));
        assert!(PeerGrantPolicy::from_lookup(lookup(&[(REQUIRE_PEER_GRANT_ENV, "1")])).unwrap_err().contains(OPERATOR_PUBKEY_ENV));
        let key = "11".repeat(32);
        let key: &'static str = Box::leak(key.into_boxed_str());
        let pairs: &'static [(&'static str, &'static str)] =
            Box::leak(Box::new([(REQUIRE_PEER_GRANT_ENV, "on"), (OPERATOR_PUBKEY_ENV, key)]));
        assert_eq!(PeerGrantPolicy::from_lookup(lookup(pairs)), Ok(Some(PeerGrantPolicy { operator: [0x11; 32] })));
    }

    /// Two gated sessions joined by an in-memory "tunnel" (standing in for the Noise pump): returns
    /// the two application ends.
    fn session_pair(
        a: Option<PeerGrantCheck>,
        b: Option<PeerGrantCheck>,
    ) -> (tokio::io::DuplexStream, tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
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
        let (mut a, mut b, tunnel) = session_pair(Some(f.check(ChannelRole::Initiate)), Some(f.check(ChannelRole::Accept)));
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
        forged.own_grant =
            grant(&SigningKey::from_bytes(&[0x66; 32]), CHANNEL, f.acceptor, Direction::Accept, crate::codec::now_unix() + 3600);
        let (mut a, mut b, tunnel) = session_pair(Some(f.check(ChannelRole::Initiate)), Some(forged));
        a.write_all(b"secret prompt").await.unwrap();
        let mut got = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), b.read_to_end(&mut got)).await;
        assert!(!String::from_utf8_lossy(&got).contains("secret"), "the prompt leaked: {got:?}");
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
            b_check.own_grant =
                grant(&SigningKey::from_bytes(&[0x66; 32]), CHANNEL, f.acceptor, Direction::Accept, crate::codec::now_unix() + 3600);
        }
        let a_gate = PeerGrantGate::new(a_local, Some(f.check(ChannelRole::Initiate)));
        let b_gate = PeerGrantGate::new(b_local, Some(b_check));
        let a_task = tokio::spawn(async move {
            let (r, w) = tokio::io::split(a_transport);
            run_channel_session_on_stream(w, r, ChannelRole::Initiate, &a_priv, &b_pub, a_gate).await
        });
        let b_task = tokio::spawn(async move {
            let (r, w) = tokio::io::split(b_transport);
            run_channel_session_on_stream(w, r, ChannelRole::Accept, &b_priv, &a_pub, b_gate).await
        });
        a_app.write_all(b"secret prompt").await.unwrap();
        let mut got = vec![0u8; 13];
        let received = tokio::time::timeout(Duration::from_secs(5), b_app.read_exact(&mut got)).await;
        let a_failed = match received {
            Ok(Ok(_)) => false,
            _ => {
                got.clear();
                // The session runner still drains the stream (bounded, 30 s) before it returns.
                matches!(tokio::time::timeout(Duration::from_secs(60), a_task).await, Ok(Ok(Err(_))))
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
        let err = tokio::time::timeout(PEER_GRANT_TIMEOUT * 2, gate.read(&mut more)).await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }
}
