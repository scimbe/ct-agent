//! Phase-2 consolidation PR4 — the **parity proof** between this crate's channel-join
//! client (`crate::channel::present_channel_join_on_stream` /
//! `present_channel_relay_join_on_stream`, the bodies that PR5 deletes) and ct_common's
//! verbatim port of them (`ct_common::channel_wire::io::…`, CADS-Tunnel v0.4.19).
//!
//! For every scripted broker behaviour the fix history knows — a pre-challenge `NO`
//! (#129), a framed `NO|len|token` (#524), the 10-byte `possession` token whose length
//! byte IS 0x0A (#524 collision), the rich `OK relay-only <noise> <holder> <attest> r=…
//! sp=…\n` line (#101/#121/#28), a bare `EX` (#21), an empty ack after possession (#148/
//! #23), leading NUL keepalives (#500) and an oversized unterminated ack (#23) — and for
//! EVERY parameter combination (`phase_marker` × `finish_send_after_sig` × `ka_tick_wait`),
//! both implementations are driven over a `tokio::io::duplex` against the same script with a
//! recording writer, and must produce **byte-identical client writes**, the same number of
//! send-half shutdowns, and an identical result: the same `Ok(outcome)` field for field, or
//! the same `Err` `Display` text with the same `DroppedLegBeforeAck` downcast. Each script
//! also pins the outcome it is EXPECTED to produce, so "both wrong the same way" cannot pass.
//!
//! This file can only exist between PR4 (the pins bump that makes the port available) and
//! PR5 (which replaces the local bodies with re-exports) — which is exactly why those two
//! are separate PRs. Deterministic and hermetic: in-memory duplexes only, every await bounded.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ct_common::channel::{ChannelJoinRequest, Direction};
use ct_common::channel_wire::io::{
    present_channel_join_on_stream as new_join, present_channel_relay_join_on_stream as new_relay_join,
};
use ct_common::channel_wire::test_support::{hex_encode, signed_grant, ScriptedBroker};
use ct_common::channel_wire::{
    ChannelJoinOutcome as NewOutcome, DroppedLegBeforeAck as NewDropped, PHASE_MARKER_RELAY, PHASE_MARKER_RENDEZVOUS,
    PHASE_PREAMBLE_MAGIC,
};
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::channel::{
    present_channel_join_on_stream as old_join, present_channel_relay_join_on_stream as old_relay_join,
    ChannelJoinOutcome as OldOutcome, DroppedLegBeforeAck as OldDropped,
};

/// Every await in this file is bounded by this.
const BOUND: Duration = Duration::from_secs(5);
/// The exchange budget handed to both implementations. No script ever waits it out: every
/// script either acks, refuses, closes, or trips the ack cap immediately.
const EXCHANGE: Duration = Duration::from_secs(5);

const CHALLENGE: [u8; 32] = [0x5au8; 32];
const NOISE: [u8; 32] = [0xAAu8; 32];
const HOLDER: [u8; 32] = [0xBBu8; 32];
const ATTEST: [u8; 64] = [0xCCu8; 64];
const REFLEXIVE: &str = "203.0.113.9:41000";

/// What the scripted broker does. Every variant except `PreChallengeNo` first plays the
/// admission up to the possession signature (`ScriptedBroker::until_ack`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Script {
    /// A pre-challenge validation refusal: bare `NO`, then close (#129).
    PreChallengeNo,
    /// After possession: `NO | len | "not-member"`, then close (#524).
    FramedNo,
    /// After possession: `NO | 0x0A | "possession"` — the length byte is the newline (#524).
    PossessionToken0x0A,
    /// After possession: the rich `OK` line with the attested triple and the tags, `\n`-terminated,
    /// then close (#101/#121/#28).
    RichOk,
    /// After possession: bare `EX`, then close (#21).
    BareEx,
    /// After possession: nothing at all — the leg dies (#148/#23).
    EmptyAfterPossession,
    /// After possession: three NUL keepalives, then `OK 198.51.100.9:8008`, then close (#500).
    LeadingNuls,
    /// After possession: 512 × `X`, no terminator, held open (#23 cap).
    OversizeAck,
}

const SCRIPTS: [Script; 8] = [
    Script::PreChallengeNo,
    Script::FramedNo,
    Script::PossessionToken0x0A,
    Script::RichOk,
    Script::BareEx,
    Script::EmptyAfterPossession,
    Script::LeadingNuls,
    Script::OversizeAck,
];

const MARKERS: [Option<u8>; 3] = [None, Some(PHASE_MARKER_RENDEZVOUS), Some(PHASE_MARKER_RELAY)];

/// Which implementation to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Impl {
    Old,
    New,
}

/// A write half that records every byte the client writes and counts `shutdown`s, so the
/// two implementations' wire output can be compared byte for byte.
struct Recording<W> {
    inner: W,
    wrote: Arc<Mutex<Vec<u8>>>,
    shutdowns: Arc<AtomicUsize>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Recording<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            this.wrote.lock().unwrap().extend_from_slice(&buf[..*n]);
        }
        r
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let r = Pin::new(&mut this.inner).poll_shutdown(cx);
        if r.is_ready() {
            this.shutdowns.fetch_add(1, Ordering::SeqCst);
        }
        r
    }
}

/// The two outcome enums have the same shape; normalise both into one comparable type.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Norm {
    Admitted {
        peer_endpoint: String,
        peer_noise_pubkey: Option<[u8; 32]>,
        peer_holder: Option<[u8; 32]>,
        peer_attestation: Option<[u8; 64]>,
        observed_reflexive: Option<SocketAddr>,
    },
    Refused {
        category: Option<String>,
    },
    ParkExpired,
}

impl From<OldOutcome> for Norm {
    fn from(o: OldOutcome) -> Self {
        match o {
            OldOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive } => {
                Norm::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive }
            }
            OldOutcome::Refused { category } => Norm::Refused { category },
            OldOutcome::ParkExpired => Norm::ParkExpired,
        }
    }
}

impl From<NewOutcome> for Norm {
    fn from(o: NewOutcome) -> Self {
        match o {
            NewOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive } => {
                Norm::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive }
            }
            NewOutcome::Refused { category } => Norm::Refused { category },
            NewOutcome::ParkExpired => Norm::ParkExpired,
        }
    }
}

/// What an `Err` looks like from the outside: its `Display` text (ct-agent's
/// `channel_run/errors.rs` classifies by text) and whether it downcasts to the typed
/// dropped-leg error, with which leg.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ErrShape {
    display: String,
    dropped_leg: Option<&'static str>,
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl ErrShape {
    fn old(e: BoxError) -> Self {
        ErrShape { display: e.to_string(), dropped_leg: e.downcast_ref::<OldDropped>().map(|d| d.leg) }
    }
    fn new(e: BoxError) -> Self {
        ErrShape { display: e.to_string(), dropped_leg: e.downcast_ref::<NewDropped>().map(|d| d.leg) }
    }
}

/// Everything observable about one run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trace {
    wrote: Vec<u8>,
    shutdowns: usize,
    result: Result<Norm, ErrShape>,
}

fn request() -> (ChannelJoinRequest, SigningKey) {
    let holder = SigningKey::from_bytes(&[0x41u8; 32]);
    let request = ChannelJoinRequest {
        grant: signed_grant([0x14u8; 32], &holder, Direction::Initiate),
        endpoint: "203.0.113.14:1414".to_string(),
    };
    (request, holder)
}

fn rich_ok_line() -> String {
    format!("OK relay-only {} {} {} r={REFLEXIVE} sp=1\n", hex_encode(&NOISE), hex_encode(&HOLDER), hex_encode(&ATTEST))
}

/// Play `script` on the broker side of `server`.
async fn play(script: Script, server: DuplexStream) {
    if script == Script::PreChallengeNo {
        // Read the (optionally phase-marked) framed join, then refuse before any challenge.
        let (mut sr, mut sw) = tokio::io::split(server);
        let mut head = [0u8; 2];
        sr.read_exact(&mut head).await.expect("join head");
        let len = if head[0] == PHASE_PREAMBLE_MAGIC {
            let mut len = [0u8; 2];
            sr.read_exact(&mut len).await.expect("join length");
            u16::from_be_bytes(len)
        } else {
            u16::from_be_bytes(head)
        };
        let mut body = vec![0u8; len as usize];
        sr.read_exact(&mut body).await.expect("join body");
        sw.write_all(b"NO").await.expect("refusal");
        sw.shutdown().await.expect("close");
        return;
    }
    let mut ex = ScriptedBroker::new(CHALLENGE).until_ack(server).await;
    match script {
        Script::PreChallengeNo => unreachable!(),
        Script::FramedNo => {
            let mut frame = b"NO".to_vec();
            frame.push(b"not-member".len() as u8);
            frame.extend_from_slice(b"not-member");
            ex.send.write_all(&frame).await.expect("framed refusal");
            ex.send.shutdown().await.expect("close");
        }
        Script::PossessionToken0x0A => {
            let mut frame = b"NO".to_vec();
            frame.push(0x0A);
            frame.extend_from_slice(b"possession");
            ex.send.write_all(&frame).await.expect("framed refusal");
            ex.send.shutdown().await.expect("close");
        }
        Script::RichOk => {
            ex.send.write_all(rich_ok_line().as_bytes()).await.expect("rich ack");
            ex.send.shutdown().await.expect("close");
        }
        Script::BareEx => {
            ex.send.write_all(b"EX").await.expect("park-expiry token");
            ex.send.shutdown().await.expect("close");
        }
        Script::EmptyAfterPossession => {
            // The leg dies: drop BOTH halves. A split duplex signals EOF to the peer only
            // when the whole stream is gone -- dropping just the write half would leave a
            // client that never finishes its own send half (finish_send_after_sig = false,
            // and every relay leg) waiting for an EOF that never comes.
            drop(ex.send);
            drop(ex.recv);
            return;
        }
        Script::LeadingNuls => {
            ex.send.write_all(&[0u8, 0u8, 0u8]).await.expect("keepalive NULs");
            ex.send.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
            ex.send.shutdown().await.expect("close");
        }
        Script::OversizeAck => {
            ex.send.write_all(&[b'X'; 512]).await.expect("garbage");
            // Held open: the cap, not EOF, must end the read. Wait for the client to give up.
            let mut sink = [0u8; 64];
            let _ = tokio::time::timeout(BOUND, ex.recv.read(&mut sink)).await;
        }
    }
    // Keep the read half alive until the client is done, so its writes never fail early.
    let mut sink = [0u8; 64];
    let _ = tokio::time::timeout(BOUND, async {
        while let Ok(n) = ex.recv.read(&mut sink).await {
            if n == 0 {
                break;
            }
        }
    })
    .await;
}

/// Drive one implementation of the BROKER leg against `script` with the given parameters.
async fn drive_broker_leg(which: Impl, script: Script, marker: Option<u8>, finish: bool, ka: bool) -> Trace {
    let (request, holder) = request();
    let (client, server) = tokio::io::duplex(8192);
    let broker = tokio::spawn(play(script, server));
    let (cr, cw) = tokio::io::split(client);
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let rec = Recording { inner: cw, wrote: wrote.clone(), shutdowns: shutdowns.clone() };
    let result = tokio::time::timeout(BOUND, async {
        match which {
            Impl::Old => old_join(rec, cr, &request, &holder, EXCHANGE, finish, marker, ka).await.map(Norm::from).map_err(ErrShape::old),
            Impl::New => new_join(rec, cr, &request, &holder, EXCHANGE, finish, marker, ka).await.map(Norm::from).map_err(ErrShape::new),
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{which:?} {script:?} marker={marker:?} finish={finish} ka={ka}: exceeded the {BOUND:?} bound"));
    let _ = tokio::time::timeout(BOUND, broker).await;
    let wrote = wrote.lock().unwrap().clone();
    Trace { wrote, shutdowns: shutdowns.load(Ordering::SeqCst), result }
}

/// Drive one implementation of the RELAY leg against `script` with the given marker.
async fn drive_relay_leg(which: Impl, script: Script, marker: Option<u8>) -> Trace {
    let (request, holder) = request();
    let (client, server) = tokio::io::duplex(8192);
    let broker = tokio::spawn(play(script, server));
    let (mut cr, cw) = tokio::io::split(client);
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut rec = Recording { inner: cw, wrote: wrote.clone(), shutdowns: shutdowns.clone() };
    let result = tokio::time::timeout(BOUND, async {
        match which {
            Impl::Old => old_relay_join(&mut rec, &mut cr, &request, &holder, marker).await.map(Norm::from).map_err(ErrShape::old),
            Impl::New => new_relay_join(&mut rec, &mut cr, &request, &holder, marker).await.map(Norm::from).map_err(ErrShape::new),
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{which:?} relay {script:?} marker={marker:?}: exceeded the {BOUND:?} bound"));
    drop(rec);
    drop(cr);
    let _ = tokio::time::timeout(BOUND, broker).await;
    let wrote = wrote.lock().unwrap().clone();
    Trace { wrote, shutdowns: shutdowns.load(Ordering::SeqCst), result }
}

/// The outcome each script MUST produce (checked on the new implementation, so parity is a
/// parity with the right answer, not merely with each other). `leg` is what a dropped leg
/// must be named on this reader.
fn check_expected(script: Script, leg: &'static str, trace: &Trace, ctx: &str) {
    match (script, &trace.result) {
        (Script::PreChallengeNo, Ok(Norm::Refused { category: None })) => {}
        // The relay-leg reader `read_exact`s the challenge, so a pre-challenge `NO` is an Err there
        // (a known asymmetry carried over unchanged, design §1(h)); the broker leg classifies it.
        (Script::PreChallengeNo, Err(e)) if leg == "relay" => assert!(e.dropped_leg.is_none(), "{ctx}: {e:?}"),
        (Script::FramedNo, Ok(Norm::Refused { category: Some(c) })) => assert_eq!(c, "not-member", "{ctx}"),
        (Script::PossessionToken0x0A, Ok(Norm::Refused { category: Some(c) })) => assert_eq!(c, "possession", "{ctx}"),
        (Script::RichOk, Ok(Norm::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive })) => {
            assert_eq!(peer_endpoint, "relay-only", "{ctx}");
            assert_eq!((peer_noise_pubkey, peer_holder, peer_attestation), (&Some(NOISE), &Some(HOLDER), &Some(ATTEST)), "{ctx}");
            assert_eq!(*observed_reflexive, Some(REFLEXIVE.parse().unwrap()), "{ctx}");
        }
        (Script::BareEx, Ok(Norm::ParkExpired)) => {}
        (Script::EmptyAfterPossession, Err(e)) => assert_eq!(e.dropped_leg, Some(leg), "{ctx}: {e:?}"),
        (Script::LeadingNuls, Ok(Norm::Admitted { peer_endpoint, .. })) => assert_eq!(peer_endpoint, "198.51.100.9:8008", "{ctx}"),
        (Script::OversizeAck, Err(e)) => assert!(e.display.contains("without a terminator"), "{ctx}: {e:?}"),
        (script, other) => panic!("{ctx}: {script:?} produced an unexpected result {other:?}"),
    }
}

#[tokio::test]
async fn broker_leg_parity_across_every_script_and_parameter_combination_p2() {
    for script in SCRIPTS {
        for marker in MARKERS {
            for finish in [true, false] {
                for ka in [true, false] {
                    let ctx = format!("broker leg {script:?} marker={marker:?} finish_send_after_sig={finish} ka_tick_wait={ka}");
                    let old = drive_broker_leg(Impl::Old, script, marker, finish, ka).await;
                    let new = drive_broker_leg(Impl::New, script, marker, finish, ka).await;
                    assert_eq!(old.wrote, new.wrote, "{ctx}: client writes differ");
                    assert_eq!(old.shutdowns, new.shutdowns, "{ctx}: send-half shutdown count differs");
                    assert_eq!(old.result, new.result, "{ctx}: results differ");
                    check_expected(script, "rendezvous", &new, &ctx);
                    // The wire the broker saw must start the way the marker says.
                    match marker {
                        Some(p) => assert_eq!(&new.wrote[..2], &[PHASE_PREAMBLE_MAGIC, p], "{ctx}: preamble"),
                        None => assert_ne!(new.wrote[0], PHASE_PREAMBLE_MAGIC, "{ctx}: no preamble"),
                    }
                    assert_eq!(new.shutdowns, usize::from(finish && script != Script::PreChallengeNo), "{ctx}: shutdown iff finish_send_after_sig after possession");
                }
            }
        }
    }
}

#[tokio::test]
async fn relay_leg_parity_across_every_script_and_marker_p2() {
    for script in SCRIPTS {
        for marker in MARKERS {
            let ctx = format!("relay leg {script:?} marker={marker:?}");
            let old = drive_relay_leg(Impl::Old, script, marker).await;
            let new = drive_relay_leg(Impl::New, script, marker).await;
            assert_eq!(old.wrote, new.wrote, "{ctx}: client writes differ");
            assert_eq!(old.shutdowns, new.shutdowns, "{ctx}: send-half shutdown count differs");
            assert_eq!(old.result, new.result, "{ctx}: results differ");
            check_expected(script, "relay", &new, &ctx);
            assert_eq!(new.shutdowns, 0, "{ctx}: the relay leg never closes its send half (the session follows)");
        }
    }
}
