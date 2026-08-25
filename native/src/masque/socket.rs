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
//! `tokio::sync::mpsc` channels; [`MasqueUdpSocket`]'s `try_send`/`poll_recv` are
//! just channel operations, never touching h2 directly -- `AsyncUdpSocket`'s methods
//! take `&self` and must never block, which a live h2 stream write/read could.

use super::capsule;
use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};
use tokio::sync::mpsc;

pub(super) struct MasqueUdpSocket {
    to_send: mpsc::UnboundedSender<Vec<u8>>,
    recv_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl std::fmt::Debug for MasqueUdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueUdpSocket").field("local_addr", &self.local_addr).finish()
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

        let (to_send_tx, mut to_send_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        // Outbound pump: this agent -> the proxy -> the tunneled target.
        tokio::spawn(async move {
            while let Some(payload) = to_send_rx.recv().await {
                let framed = capsule::encode_datagram(&capsule::udp_datagram_payload::encode(&payload));
                if send_stream.send_data(Bytes::from(framed), false).is_err() {
                    break; // tunnel gone -- poll_recv's own end-of-channel surfaces this to quinn
                }
            }
        });

        // Inbound pump: the tunneled target -> the proxy -> this agent.
        tokio::spawn(async move {
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
                                    if recv_tx.send(udp_payload.to_vec()).is_err() {
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

        (Self { to_send: to_send_tx, recv_rx: Mutex::new(recv_rx), local_addr, peer_addr }, peer_addr)
    }
}

impl quinn::AsyncUdpSocket for MasqueUdpSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        // The outbound pump above only ever needs channel capacity (unbounded),
        // never real socket-writability -- there is nothing for a poller to wait
        // on, so this is always immediately ready. Real backpressure lives at the
        // h2 stream (send_data's own flow control) inside that pump task, not here
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
        self.to_send
            .send(transmit.contents.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE tunnel closed"))
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [io::IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut rx = self.recv_rx.lock().unwrap_or_else(|e| e.into_inner());
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
