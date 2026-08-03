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

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or("usage: whoami_lab <echo|query> <addr>")?;
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
        other => Err(format!("unknown subcommand {other:?} (expected echo|query)").into()),
    }
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
