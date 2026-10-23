//! nat-lab-only (`--features nat-lab`) harness for #248/#238's UDP reflexive-discovery fix:
//! a minimal standalone QUIC "whoami" echo server (the exact wire protocol the real edge's
//! new `'W'` op speaks, reimplemented here in ~15 lines so this binary needs no dependency
//! on the separate CADS-Tunnel repo) plus a CLI wrapper around
//! `ct_agent::channel_run`'s own `discover_udp_reflexive`, so the real client-side discovery
//! code can be exercised against a real two-separate-NAT topology
//! (`scripts/nat-lab-reflexive.sh`), not just loopback unit tests.
//!
//! Usage:
//!   whoami_lab echo <listen-addr>     -- runs the echo server forever
//!   whoami_lab query <target-addr>    -- one whoami query, prints the reported address (or ERR)
//!
//! #296 punch pair -- does a peer reach the listener on the reflexive address the listener
//! advertises? Both roles print `REFLEXIVE <addr>`, then wait (up to 15 s) for the peer's
//! reflexive address to appear in `<peer-file>` (the lab script writes it there):
//!   whoami_lab punch-listen <echo-addr> <peer-file> [--throwaway]
//!       -- one endpoint that dials and listens (`transport::build_channel_endpoint`); learns
//!          its reflexive THROUGH that endpoint, or with `--throwaway` from a separate socket
//!          as before #296. Sends one punch toward the peer from the listening socket, then
//!          accepts: `ACCEPTED <remote>` (exit 0) or `NO-INBOUND` (exit 1).
//!   whoami_lab punch-dial <echo-addr> <peer-file>
//!       -- learns its reflexive through its own endpoint and dials the peer's from that same
//!          socket for up to 15 s: `CONNECTED <peer>` (exit 0) or `UNREACHABLE` (exit 1).

// ct-agent#176: the data plane is panic-free by construction. Every `unwrap`/`expect`/
// `panic!`/`unreachable!`/`todo!`/`unimplemented!` in NON-test code is a build error
// (CI runs clippy with -D warnings); a provably-infallible site may carry a scoped
// `#[allow(clippy::expect_used)]` with a one-line proof. Tests keep their unwraps.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or("usage: whoami_lab <echo|query|punch-listen|punch-dial> <addr> [...]")?;
    let addr: SocketAddr = args.next().ok_or("missing address")?.parse()?;

    match cmd.as_str() {
        "echo" => run_echo_server(addr).await,
        "query" => {
            match ct_agent::channel_run::discover_udp_reflexive(addr, std::time::Duration::from_secs(5)).await {
                Some(reported) => {
                    println!("REFLEXIVE {reported}");
                    Ok(())
                }
                None => {
                    eprintln!("whoami_lab: no reflexive address reported (unreachable, timeout, or malformed reply)");
                    std::process::exit(1);
                }
            }
        }
        "punch-listen" | "punch-dial" => {
            let peer_file = args.next().ok_or("missing <peer-file>")?;
            let throwaway = args.next().as_deref() == Some("--throwaway");
            if cmd == "punch-listen" {
                punch_listen(addr, &peer_file, throwaway).await
            } else {
                punch_dial(addr, &peer_file).await
            }
        }
        other => Err(format!("unknown subcommand {other:?} (expected echo|query|punch-listen|punch-dial)").into()),
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const PUNCH_WINDOW: std::time::Duration = std::time::Duration::from_secs(15);

/// #296: print this role's reflexive address for the lab script, at once (stdout is a file).
fn announce(reflexive: SocketAddr) {
    use std::io::Write;
    println!("REFLEXIVE {reflexive}");
    let _ = std::io::stdout().flush();
}

/// #296: the peer's reflexive address, once the lab script has written it to `path`.
async fn read_peer(path: &str) -> Result<SocketAddr, BoxError> {
    let deadline = tokio::time::Instant::now() + PUNCH_WINDOW;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(addr) = text.trim().parse::<SocketAddr>() {
                return Ok(addr);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("no peer address in {path} within {PUNCH_WINDOW:?}").into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// #296: the listening half. The endpoint dials and listens on one socket; only where the
/// ADVERTISED reflexive comes from differs between the two modes, so the pair isolates exactly
/// what #296 is about.
async fn punch_listen(echo: SocketAddr, peer_file: &str, throwaway: bool) -> Result<(), BoxError> {
    let timeout = std::time::Duration::from_secs(5);
    let (endpoint, _cert) = ct_agent::transport::build_channel_endpoint()?;
    let reflexive = if throwaway {
        ct_agent::channel_run::discover_udp_reflexive(echo, timeout).await
    } else {
        ct_agent::channel_run::whoami_via(&endpoint, echo, timeout).await
    }
    .ok_or("no reflexive address reported")?;
    announce(reflexive);
    let peer = read_peer(peer_file).await?;
    // The punch: one QUIC Initial from the listening socket toward the peer's mapping, so a NAT
    // that filters by remote address lets the peer's dial in. Its own outcome does not matter.
    if let Ok(connecting) = endpoint.connect(peer, "localhost") {
        tokio::spawn(async move {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(3), connecting).await;
        });
    }
    match tokio::time::timeout(PUNCH_WINDOW, async {
        let incoming = endpoint.accept().await?;
        incoming.await.ok()
    })
    .await
    {
        Ok(Some(conn)) => {
            println!("ACCEPTED {}", conn.remote_address());
            conn.close(0u32.into(), b"punch ok");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            Ok(())
        }
        _ => {
            println!("NO-INBOUND");
            std::process::exit(1);
        }
    }
}

/// #296: the dialing half -- from the socket its own reflexive was learned through, so the
/// listener's punch (aimed at that reflexive) and this dial use the same mapping.
async fn punch_dial(echo: SocketAddr, peer_file: &str) -> Result<(), BoxError> {
    let (endpoint, _cert) = ct_agent::transport::build_channel_endpoint()?;
    let reflexive = ct_agent::channel_run::whoami_via(&endpoint, echo, std::time::Duration::from_secs(5))
        .await
        .ok_or("no reflexive address reported")?;
    announce(reflexive);
    let peer = read_peer(peer_file).await?;
    let deadline = tokio::time::Instant::now() + PUNCH_WINDOW;
    while tokio::time::Instant::now() < deadline {
        let attempt = tokio::time::timeout(std::time::Duration::from_secs(3), endpoint.connect(peer, "localhost")?).await;
        if let Ok(Ok(conn)) = attempt {
            println!("CONNECTED {peer}");
            conn.close(0u32.into(), b"punch ok");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    println!("UNREACHABLE");
    std::process::exit(1);
}

/// The exact wire protocol the real edge's `'W'` op speaks (CADS-Tunnel
/// `crates/edge/src/serve.rs`): accept a bi stream, read one role byte, reply with a
/// 1-byte length + the connection's own `remote_address()` as a UTF-8 string. Reimplemented
/// standalone (self-signed cert, no admission/PoW gate -- matches the real op's own
/// "safe unauthenticated" design) so this lab binary needs no CADS-Tunnel dependency.
async fn run_echo_server(listen: SocketAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)?;
    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    let endpoint = quinn::Endpoint::server(server_config, listen)?;
    eprintln!("whoami_lab echo: listening on {listen}");
    loop {
        let Some(incoming) = endpoint.accept().await else { break };
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else { return };
            let remote = conn.remote_address();
            let Ok((mut send, mut recv)) = conn.accept_bi().await else { return };
            let mut role = [0u8; 1];
            if recv.read_exact(&mut role).await.is_err() || role[0] != b'W' {
                return;
            }
            let addr = remote.to_string();
            let bytes = addr.as_bytes();
            let _ = send.write_all(&[bytes.len() as u8]).await;
            let _ = send.write_all(bytes).await;
            let _ = send.finish();
            eprintln!("whoami_lab echo: served {remote}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
    }
    Ok(())
}
