//! scimbe/ct-agent#204 end-to-end: the system `ssh`, through `ct-agent ssh` as its ProxyCommand,
//! through an in-process TLS terminator, reaches the host's REAL sshd on 127.0.0.1:22.
//!
//! `#[ignore]`d because it needs a running sshd and an `ssh` binary on the host; run it with
//! `cargo test --test ssh_proxycommand_e2e -- --ignored`. Lives under `tests/` (not in a
//! module's `cfg(test)`) because `CARGO_BIN_EXE_<name>` is only set for integration tests.
//!
//! What "reached sshd" means here: the SSH transport handshake completes and authentication is
//! then refused for a user that has no key (`Permission denied`). A broken transport fails
//! EARLIER with a different message (`kex_exchange_identification` / `Connection closed`),
//! which is exactly what the negative assertions pin.

use std::sync::Arc;

use ct_agent::serve::{serve_duplex_to_origin, OriginTerminator};

/// A fresh rcgen CA plus a leaf for `host`, written to `dir` as `ca.pem` / `fullchain.pem` /
/// `privkey.pem`. A copy of `ct_agent::ssh_access::test_pki` (a `cfg(test)` item this crate
/// cannot see from here).
fn write_test_pki(dir: &std::path::Path, host: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "ct-agent e2e test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![host.to_string()])
        .unwrap()
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .unwrap();
    let ca = dir.join("ca.pem");
    let cert = dir.join("fullchain.pem");
    let key = dir.join("privkey.pem");
    std::fs::write(&ca, ca_cert.pem()).unwrap();
    std::fs::write(&cert, leaf.pem()).unwrap();
    std::fs::write(&key, leaf_key.serialize_pem()).unwrap();
    (ca, cert, key)
}

#[tokio::test]
#[ignore = "needs a running sshd on 127.0.0.1:22 and an `ssh` binary on PATH"]
async fn ssh_client_through_proxycommand_reaches_a_real_sshd() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, cert, key) = write_test_pki(dir.path(), "ssh.test.invalid");
    let terminator = Arc::new(OriginTerminator::load(&cert, &key).expect("test pair loads"));

    // The "agent": a loopback listener terminating TLS and forwarding plaintext to sshd.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let sshd: std::net::SocketAddr = "127.0.0.1:22".parse().unwrap();
    let agent = tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let t = Arc::clone(&terminator);
            tokio::spawn(async move {
                if let Err(e) = serve_duplex_to_origin(tcp, sshd, Some(t)).await {
                    eprintln!("e2e terminator: relay ended with: {e}");
                }
            });
        }
    });

    // The ProxyCommand, exactly as the `ssh-config` stanza would put it -- plus the hidden
    // `--connect` override, because ssh.test.invalid does not resolve and must not.
    let proxy = format!(
        "{} ssh --port {port} --ca {} --connect 127.0.0.1:{port} ssh.test.invalid",
        env!("CARGO_BIN_EXE_ct-agent"),
        ca.display()
    );
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::process::Command::new("ssh")
            .arg("-o")
            .arg(format!("ProxyCommand={proxy}"))
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=no"])
            .args(["-o", "UserKnownHostsFile=/dev/null"])
            .args(["-o", "ConnectTimeout=10"])
            .arg("nobody@ssh.test.invalid")
            .arg("true")
            .output(),
    )
    .await
    .expect("ssh returns within 30 s")
    .expect("ssh binary runs");
    agent.abort();

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("Permission denied"),
        "the SSH transport must reach sshd and be refused at auth; stderr:\n{stderr}\nstdout:\n{stdout}"
    );
    assert!(
        !stderr.contains("Connection closed") && !stderr.contains("kex_exchange_identification"),
        "a transport-level failure means the TLS/ProxyCommand path broke; stderr:\n{stderr}"
    );
    assert!(!output.status.success(), "auth for `nobody` must not succeed");
}
