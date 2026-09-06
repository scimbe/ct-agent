//! Bridges an established RFC 9298 CONNECT-UDP tunnel (an h2 `SendStream`/`RecvStream`
//! pair, already past the Extended CONNECT handshake -- see `mod.rs`'s
//! `dial_quic_via_masque`) to quinn's [`quinn::AsyncUdpSocket`] trait, so a real
//! `quinn::Endpoint` can run its actual QUIC state machine over the tunnel exactly as
//! it would over a kernel UDP socket. quinn has no idea this isn't a real socket --
//! that's the whole point (ADR-0024 M3): the rest of this agent's code gets back an
//! ordinary [`quinn::Connection`].
//!
//! Two background tasks own the h2 stream halves (`SendStream`/`RecvStream` are
//! separate, independently `Send` handles) and pump raw UDP payloads to/from two
//! **bounded** `tokio::sync::mpsc` channels; [`MasqueUdpSocket`]'s `try_send`/`poll_recv`
//! are just channel operations, never touching h2 directly -- `AsyncUdpSocket`'s
//! methods take `&self` and must never block, which a live h2 stream write/read could.
//!
//! ct-agent#177: the pumps used to be `unbounded_channel`s, so a slow consumer (a
//! stalled h2 stream on the way out, a stalled quinn endpoint on the way in) grew
//! memory without limit for the lifetime of the session. Each pump now holds at most
//! [`PUMP_CAPACITY`] datagrams (capsules are already capped at ~64 KiB each, so that
//! is ~16 MiB worst case per direction). A datagram offered to a full pump is
//! **dropped and counted**, never blocked on -- exactly what a kernel UDP socket does
//! when its buffer is full, and what QUIC's loss recovery is built to absorb. The
//! counts are readable per socket ([`MasqueUdpSocket::dropped_datagrams`]) and
//! process-wide ([`dropped_datagrams_total`], rendered on `/metrics` as
//! `ct_agent_masque_dropped_datagrams_total{direction}`), and every
//! [`DROP_LOG_EVERY`]-th drop per socket and direction is logged once.
//!
//! ct-agent#180: both pump tasks are owned by the socket (as
//! [`crate::task_guard::TaskGuard`]s), so dropping the socket -- which happens when
//! quinn drops the endpoint built over it -- aborts them. Before, the inbound pump
//! could sit in `recv_stream.data().await` for as long as the proxy kept the h2
//! stream open after the QUIC side was long gone, and the outbound pump lived
//! until the sender side was dropped: two tasks per dead tunnel, never counted.

use super::capsule;
use crate::task_guard::TaskGuard;
use bytes::Bytes;
use ct_common::sync::MutexExt;
use quinn::udp::{RecvMeta, Transmit};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// How many datagrams each pump (outbound to the proxy, inbound from it) may hold
/// before further ones are dropped (ct-agent#177).
pub(super) const PUMP_CAPACITY: usize = 256;

/// Log one line per this many drops in one direction of one socket -- a rate limit,
/// so a sustained overload never turns into a per-datagram log flood.
const DROP_LOG_EVERY: u64 = 1000;

/// Process-wide drop totals across every MASQUE socket that ever existed, for the
/// `/metrics` scrape (a socket's own counters die with the socket; the scrape wants
/// a monotonic counter).
static DROPPED_OUTBOUND_TOTAL: AtomicU64 = AtomicU64::new(0);
static DROPPED_INBOUND_TOTAL: AtomicU64 = AtomicU64::new(0);

/// `(outbound, inbound)` datagrams dropped on full pumps, summed over every MASQUE
/// socket this process has opened (ct-agent#177).
pub(super) fn dropped_datagrams_total() -> (u64, u64) {
    (DROPPED_OUTBOUND_TOTAL.load(Ordering::Relaxed), DROPPED_INBOUND_TOTAL.load(Ordering::Relaxed))
}

/// Which pump a datagram was dropped from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    /// This agent -> the proxy -> the tunneled target (`try_send` side).
    Outbound,
    /// The tunneled target -> the proxy -> this agent (`poll_recv` side).
    Inbound,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Outbound => "outbound",
            Direction::Inbound => "inbound",
        }
    }
}

/// Per-socket drop counters, shared between the socket handle (outbound drops happen
/// in `try_send`) and the inbound pump task (inbound drops happen there).
#[derive(Debug, Default)]
pub(super) struct DropCounters {
    outbound: AtomicU64,
    inbound: AtomicU64,
}

impl DropCounters {
    /// Record one dropped datagram in `dir`: bumps the per-socket and the process-wide
    /// counter, and logs once per [`DROP_LOG_EVERY`] drops.
    fn note_drop(&self, dir: Direction) {
        let (local, global) = match dir {
            Direction::Outbound => (&self.outbound, &DROPPED_OUTBOUND_TOTAL),
            Direction::Inbound => (&self.inbound, &DROPPED_INBOUND_TOTAL),
        };
        let n = local.fetch_add(1, Ordering::Relaxed) + 1;
        global.fetch_add(1, Ordering::Relaxed);
        if n % DROP_LOG_EVERY == 0 {
            eprintln!(
                "ct-agent masque: {} pump full -- {n} datagrams dropped on this tunnel so far \
                 (capacity {PUMP_CAPACITY}; ct-agent#177)",
                dir.as_str()
            );
        }
    }

    /// `(outbound, inbound)` drops on this socket.
    fn get(&self) -> (u64, u64) {
        (self.outbound.load(Ordering::Relaxed), self.inbound.load(Ordering::Relaxed))
    }
}

/// The pump's receiving side is gone (the socket or its pump task was dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PumpClosed;

/// Offer `payload` to a bounded pump without ever waiting: queued, or -- if the pump
/// is full -- dropped and counted in `dir` (UDP semantics, ct-agent#177). `Err` only
/// when the pump's receiver is gone, which is the one condition a caller must react to.
pub(super) fn offer(
    tx: &mpsc::Sender<Vec<u8>>,
    counters: &DropCounters,
    dir: Direction,
    payload: Vec<u8>,
) -> Result<(), PumpClosed> {
    match tx.try_send(payload) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => {
            counters.note_drop(dir);
            Ok(())
        }
        Err(TrySendError::Closed(_)) => Err(PumpClosed),
    }
}

pub(super) struct MasqueUdpSocket {
    to_send: mpsc::Sender<Vec<u8>>,
    recv_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    drops: Arc<DropCounters>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    /// The two h2 pump tasks (ct-agent#180): aborted when this socket is dropped.
    /// `None` only for a socket assembled by [`MasqueUdpSocket::from_parts`] (tests
    /// driving the pump channels directly, no tasks behind them).
    _pumps: Option<[TaskGuard<()>; 2]>,
}

impl std::fmt::Debug for MasqueUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueUdpSocket")
            .field("local_addr", &self.local_addr)
            .field("dropped_datagrams", &self.dropped_datagrams())
            .finish()
    }
}

impl MasqueUdpSocket {
    /// Spawns the two pump tasks and returns the socket plus the logical peer
    /// address the caller must pass to `Endpoint::connect` -- there is only ever
    /// one real peer on this bridged transport (the tunneled Edge), so this and
    /// every `RecvMeta::addr` this socket ever reports are the SAME synthetic
    /// loopback address, in `target`'s own IP family (so quinn's own IPv4/IPv6
    /// bookkeeping stays internally consistent; the actual byte value is never a
    /// real route, only a label).
    pub(super) fn spawn(
        mut send_stream: h2::SendStream<Bytes>,
        mut recv_stream: h2::RecvStream,
        target: SocketAddr,
    ) -> (Self, SocketAddr) {
        let loopback = |port: u16| {
            if target.is_ipv6() {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            }
        };
        let peer_addr = loopback(target.port());
        let local_addr = loopback(0);

        let (to_send_tx, mut to_send_rx) = mpsc::channel::<Vec<u8>>(PUMP_CAPACITY);
        let (recv_tx, recv_rx) = mpsc::channel::<Vec<u8>>(PUMP_CAPACITY);
        let drops = Arc::new(DropCounters::default());

        // Outbound pump: this agent -> the proxy -> the tunneled target.
        let outbound = TaskGuard::spawn(async move {
            while let Some(payload) = to_send_rx.recv().await {
                // Both encoders fail only for a length beyond 2^62 -- impossible for a
                // UDP payload quinn hands us -- and the alternative to skipping the one
                // datagram would be a panic on the data plane (ct-agent#176).
                let framed = match capsule::udp_datagram_payload::encode(&payload)
                    .and_then(|p| capsule::encode_datagram(&p))
                {
                    Ok(framed) => framed,
                    Err(_) => continue,
                };
                if send_stream.send_data(Bytes::from(framed), false).is_err() {
                    break; // tunnel gone -- poll_recv's own end-of-channel surfaces this to quinn
                }
            }
        });

        // Inbound pump: the tunneled target -> the proxy -> this agent.
        let inbound_drops = Arc::clone(&drops);
        let inbound = TaskGuard::spawn(async move {
            let mut buf: Vec<u8> = Vec::new();
            loop {
                let chunk = recv_stream.data().await;
                let Some(Ok(chunk)) = chunk else { return };
                if recv_stream.flow_control().release_capacity(chunk.len()).is_err() {
                    return;
                }
                buf.extend_from_slice(&chunk);
                loop {
                    match capsule::decode(&buf) {
                        Ok(Some((cap_type, value, consumed))) => {
                            if cap_type == 0x00 {
                                if let Some(udp_payload) = capsule::udp_datagram_payload::decode(value) {
                                    if offer(&recv_tx, &inbound_drops, Direction::Inbound, udp_payload.to_vec())
                                        .is_err()
                                    {
                                        return; // MasqueUdpSocket dropped
                                    }
                                }
                            }
                            buf.drain(..consumed);
                        }
                        Ok(None) => break, // capsule still arriving
                        Err(_) => return,  // protocol violation -- tear down
                    }
                }
            }
        });

        let mut socket = Self::from_parts(to_send_tx, recv_rx, drops, local_addr, peer_addr);
        socket._pumps = Some([outbound, inbound]);
        (socket, peer_addr)
    }

    /// Assemble a socket over already-created pump channels. `spawn` is the only
    /// production caller; tests use it to drive the bounded pumps directly, without
    /// an h2 tunnel behind them.
    pub(super) fn from_parts(
        to_send: mpsc::Sender<Vec<u8>>,
        recv_rx: mpsc::Receiver<Vec<u8>>,
        drops: Arc<DropCounters>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Self {
        Self { to_send, recv_rx: Mutex::new(recv_rx), drops, local_addr, peer_addr, _pumps: None }
    }

    /// `(outbound, inbound)` datagrams this socket dropped because the respective
    /// pump was full (ct-agent#177). Monotonic for the socket's lifetime.
    pub(super) fn dropped_datagrams(&self) -> (u64, u64) {
        self.drops.get()
    }
}

impl quinn::AsyncUdpSocket for MasqueUdpSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        // `try_send` below never blocks and never reports "would block": a full
        // outbound pump DROPS the datagram (ct-agent#177), the same way a kernel UDP
        // socket with a full send buffer would -- so there is nothing for a poller to
        // wait on, and this is always immediately ready. Real backpressure lives at
        // the h2 stream (send_data's own flow control) inside the pump task, not here
        // (AsyncUdpSocket::try_send must never block).
        struct AlwaysWritable;
        impl std::fmt::Debug for AlwaysWritable {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("AlwaysWritable")
            }
        }
        impl quinn::UdpPoller for AlwaysWritable {
            fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        offer(&self.to_send, &self.drops, Direction::Outbound, transmit.contents.to_vec())
            .map_err(|PumpClosed| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE tunnel closed"))
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut rx = self.recv_rx.lock_safe();
        match rx.poll_recv(cx) {
            Poll::Ready(Some(payload)) => {
                let n = payload.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&payload[..n]);
                meta[0] = RecvMeta {
                    addr: self.peer_addr,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE tunnel closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn may_fragment(&self) -> bool {
        // The tunnel carries whole capsule-framed datagrams over a reliable HTTP/2
        // stream -- no IP-level fragmentation concept applies, so telling quinn
        // "no" (skip GSO/segmentation-offload path selection it would otherwise
        // probe for) is both correct and simpler than pretending otherwise.
        false
    }
}
