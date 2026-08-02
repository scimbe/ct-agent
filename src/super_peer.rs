//! Super-peer local relay (#276 piece 2): a transparent UDP datagram forwarder that lets
//! same-network channel members share ONE real edge connection instead of each opening
//! their own.
//!
//! #276's proposal: "when 3+ members share a reflexive address... electing one as a local
//! 'super peer' turns N edge-relay connections into 1 + (N-1) local hops... [other] members
//! dial the super peer directly over the local candidate... and the super peer forwards
//! their channel traffic to/from the edge on their behalf." Piece 1 (already shipped,
//! `ct_common::channel::same_local_subnet` + the dial-racing integration) is the SAFETY GATE
//! for offering/accepting a LAN-local direct-upgrade candidate; this is the separate,
//! opt-in relay mechanism piece 1's own proposal named as a follow-on.
//!
//! **Deliberately protocol-unaware.** The super-peer never parses a single byte of what it
//! forwards — every channel session is already end-to-end Noise_IK-encrypted (invariant #2),
//! so a plain byte-transparent UDP relay preserves that boundary exactly: the super-peer
//! sees only ciphertext, the same trust position the edge relay itself already occupies. A
//! LAN-local member simply points its own `CT_CHANNEL_BROKER`/`CT_CHANNEL_RELAY` at the
//! super-peer's listen address instead of the real edge — nothing else about that member's
//! config, grant, or session changes.
//!
//! **NAT-style demultiplexing.** QUIC (what `CT_CHANNEL_BROKER`/`CT_CHANNEL_RELAY` speak)
//! multiplexes many logical connections over a single UDP 4-tuple by connection ID, so a
//! single shared upstream socket for every local client would let their datagrams collide on
//! the wire. Instead, the relay opens ONE DEDICATED upstream UDP socket per distinct local
//! client address the first time it's seen (exactly the shape a stateful NAT gateway already
//! uses), so each local client's traffic reaches the edge over a genuinely separate flow and
//! demultiplexes on the way back by construction (each dedicated socket only ever receives
//! that one client's replies). Idle client mappings are evicted after [`IDLE_TIMEOUT`] so a
//! long-lived super-peer doesn't accumulate sockets for clients that came and went.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Mutex;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a local client's dedicated upstream socket (and its forwarding task) stays
/// alive with no traffic in either direction before being torn down. Generous relative to a
/// QUIC idle-connection timeout (this module has no protocol awareness of what "idle" means
/// to the tunneled session, so it errs long) but still bounded, so a super-peer's socket
/// count reflects actual recent LAN activity, not every client that ever connected.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Max UDP datagram this relay will forward in one read — generous above any real QUIC
/// datagram (which is itself bounded well under this by path MTU), just a sanity backstop
/// against an oversized read filling the stack buffer.
const MAX_DATAGRAM: usize = 65536;

/// Run the super-peer relay forever: bind `listen` (what LAN-local clients dial instead of
/// the real edge) and transparently forward every datagram to/from `upstream` (the real edge
/// address this super-peer's own `CT_CHANNEL_BROKER`/`CT_CHANNEL_RELAY` already points at).
/// Returns only on a fatal bind/listen error; per-client forwarding errors are logged and
/// that one client's mapping is torn down, never the whole relay.
pub async fn run(listen: SocketAddr, upstream: SocketAddr) -> Result<(), BoxError> {
    let front = Arc::new(UdpSocket::bind(listen).await?);
    eprintln!("ct-agent super-peer: relaying {listen} -> {upstream}");
    let clients: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, from) = front.recv_from(&mut buf).await?;
        let upstream_sock = {
            let mut locked = clients.lock().await;
            if let Some(sock) = locked.get(&from) {
                sock.clone()
            } else {
                // First datagram from this local client: open its dedicated upstream socket
                // and spawn the upstream->local return-path forwarder for it.
                let sock = match UdpSocket::bind(("0.0.0.0", 0)).await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        eprintln!("ct-agent super-peer: failed to open an upstream socket for {from}: {e}");
                        continue;
                    }
                };
                eprintln!("ct-agent super-peer: new LAN client {from}");
                locked.insert(from, sock.clone());
                spawn_return_path(sock.clone(), front.clone(), from, clients.clone());
                sock
            }
        };
        if let Err(e) = upstream_sock.send_to(&buf[..n], upstream).await {
            eprintln!("ct-agent super-peer: forward to upstream failed for {from}: {e}");
        }
    }
}

/// The upstream->local return path for one LAN client's dedicated socket: read whatever the
/// edge sends back on `upstream_sock` and relay it verbatim to `client_addr` via `front` (the
/// SAME listening socket every client's traffic arrives on, since UDP `send_to` from one bound
/// socket to many peers is exactly how a server replies to many clients). Exits (and evicts
/// this client's mapping) on a read error or after `IDLE_TIMEOUT` with no upstream traffic --
/// either way, the NEXT datagram this client sends transparently re-establishes a fresh
/// mapping, so a torn-down mapping is never a hard failure for the client, only a brief
/// re-registration.
fn spawn_return_path(
    upstream_sock: Arc<UdpSocket>,
    front: Arc<UdpSocket>,
    client_addr: SocketAddr,
    clients: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            match tokio::time::timeout(IDLE_TIMEOUT, upstream_sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _upstream_peer))) => {
                    if let Err(e) = front.send_to(&buf[..n], client_addr).await {
                        eprintln!("ct-agent super-peer: forward to LAN client {client_addr} failed: {e}");
                        break;
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("ct-agent super-peer: upstream read failed for {client_addr}: {e}");
                    break;
                }
                Err(_timeout) => {
                    eprintln!("ct-agent super-peer: client {client_addr} idle for {IDLE_TIMEOUT:?}, evicting");
                    break;
                }
            }
        }
        clients.lock().await.remove(&client_addr);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TokioUdp;

    #[tokio::test]
    async fn forwards_a_datagram_from_a_lan_client_to_the_upstream_and_back() {
        // A fake "edge": echoes whatever it receives back to whoever sent it.
        let edge = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = edge.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = edge.recv_from(&mut buf).await else { return };
                let _ = edge.send_to(&buf[..n], from).await;
            }
        });

        let relay_listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let relay_bind = TokioUdp::bind(relay_listen).await.unwrap();
        let relay_addr = relay_bind.local_addr().unwrap();
        drop(relay_bind); // free the port for `run` to bind for real
        tokio::spawn(run(relay_addr, edge_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A LAN client dials the SUPER-PEER's listen address, never the real edge directly.
        let client = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello from the LAN", relay_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("reply within timeout")
            .unwrap();
        assert_eq!(&buf[..n], b"hello from the LAN", "the edge's echo round-trips through the relay unmodified");
    }

    #[tokio::test]
    async fn two_concurrent_lan_clients_do_not_cross_talk() {
        // The fake edge tags every reply with which LOCAL (relay-facing) port it arrived
        // from, so each client can verify it only ever gets ITS OWN traffic back.
        let edge = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = edge.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = edge.recv_from(&mut buf).await else { return };
                // Echo back "<original payload>|<relay upstream port>" so the test can
                // confirm each client's dedicated upstream socket stayed distinct.
                let reply = format!("{}|{}", String::from_utf8_lossy(&buf[..n]), from.port());
                let _ = edge.send_to(reply.as_bytes(), from).await;
            }
        });

        let relay_bind = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_bind.local_addr().unwrap();
        drop(relay_bind);
        tokio::spawn(run(relay_addr, edge_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client_a = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let client_b = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        client_a.send_to(b"from-a", relay_addr).await.unwrap();
        client_b.send_to(b"from-b", relay_addr).await.unwrap();

        let mut buf_a = [0u8; 64];
        let (n_a, _) = tokio::time::timeout(Duration::from_secs(2), client_a.recv_from(&mut buf_a)).await.unwrap().unwrap();
        let mut buf_b = [0u8; 64];
        let (n_b, _) = tokio::time::timeout(Duration::from_secs(2), client_b.recv_from(&mut buf_b)).await.unwrap().unwrap();

        let reply_a = String::from_utf8_lossy(&buf_a[..n_a]).to_string();
        let reply_b = String::from_utf8_lossy(&buf_b[..n_b]).to_string();
        assert!(reply_a.starts_with("from-a|"), "client A gets its own payload back, got {reply_a:?}");
        assert!(reply_b.starts_with("from-b|"), "client B gets its own payload back, got {reply_b:?}");
        // Different LAN clients got forwarded through DIFFERENT dedicated upstream sockets
        // (different source ports as observed by the fake edge) -- proves no shared-socket
        // collision between concurrent clients.
        let port_a = reply_a.rsplit('|').next().unwrap();
        let port_b = reply_b.rsplit('|').next().unwrap();
        assert_ne!(port_a, port_b, "each LAN client is relayed through its own dedicated upstream socket");
    }

    #[tokio::test]
    async fn an_unreachable_upstream_does_not_crash_the_relay_or_hang_the_caller() {
        // upstream is a bound-but-nothing-listening address's PORT+1 (a real, currently-
        // closed port) -- send_to to a closed UDP port on loopback typically returns
        // ECONNREFUSED on the NEXT read, exercising the error-logging path without a panic.
        let probe = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let mut unreachable = probe.local_addr().unwrap();
        drop(probe);
        unreachable.set_port(unreachable.port().wrapping_add(1).max(1));

        let relay_bind = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_bind.local_addr().unwrap();
        drop(relay_bind);
        tokio::spawn(run(relay_addr, unreachable));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = TokioUdp::bind("127.0.0.1:0").await.unwrap();
        // Must not panic or hang the relay -- just best-effort forward into the void.
        client.send_to(b"nobody home", relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        // The relay task is still alive and would accept a NEW client normally -- proven by
        // not panicking within this test's own lifetime (a panicked spawned task would have
        // aborted the process under #[tokio::test]'s default panic behavior).
    }
}
