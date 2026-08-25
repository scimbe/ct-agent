//! ADR-0024 M3: dial the Edge's real QUIC endpoint through an RFC 9298 CONNECT-UDP
//! tunnel (CADS-Tunnel's `masque-proxy`, M2) when raw UDP is blocked but outbound
//! TCP/443 (HTTPS) isn't -- restoring genuine QUIC properties (connection
//! migration, loss recovery) that the existing bare TLS-TCP-framed fallback
//! (`transport.rs`'s TCP-fallback ladder) doesn't have, over a path that's
//! otherwise indistinguishable from ordinary HTTPS traffic on the wire.
//!
//! See CADS-Tunnel's `docs/adr/0024-masque-connect-udp-fallback.md` for the full
//! design and M1 (`spike-masque-h2/`)/M2 (`masque-proxy`) that proved the transport
//! layer this module's [`dial_quic_via_masque`] builds on. **Not yet wired into the
//! agent's reconnect loop or `ladder.rs`'s `EdgeRung`** -- that's the deliberately
//! separate follow-up (mirrors M2's own proxy-backend-then-registration split), so
//! this lands as a real, independently testable unit first.

mod capsule;
mod socket;
#[cfg(test)]
mod tests;
mod varint;

use crate::transport::{agent_keepalive_and_max_idle, quic_client_config};
use h2::ext::Protocol;
use http::{Method, Request};
use quinn::Endpoint;
use rustls::pki_types::CertificateDer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Aborts the wrapped task when dropped, unless [`AbortOnDrop::disarm`] was called
/// first. `JoinHandle`'s own `Drop` impl only DETACHES a task -- it keeps running
/// to completion in the background regardless -- so a bare `tokio::spawn(...)`
/// with no handle kept at all leaks exactly as much as one whose handle is simply
/// dropped. See `dial_quic_via_masque_with_proxy_roots`'s own doc comment at its
/// call site for the real outage this fixed.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    /// Called on the one path where the task must keep running: skips the abort
    /// this guard would otherwise perform on drop.
    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

const CONNECT_UDP_PATH_PREFIX: &str = "/.well-known/masque/udp";

/// RFC 9298 section 2's target_host encoding -- see CADS-Tunnel's `masque-proxy`
/// crate for the matching server-side function; must produce byte-identical output
/// to it, since the proxy compares this client's request path against its own
/// precomputed value verbatim (ADR-0024 M2's by-construction target restriction).
fn encode_target_host(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => v4.ip().to_string(),
        SocketAddr::V6(v6) => v6.ip().to_string().replace(':', "%3A"),
    }
}

fn connect_udp_path(target: SocketAddr) -> String {
    format!("{CONNECT_UDP_PATH_PREFIX}/{}/{}/", encode_target_host(&target), target.port())
}

/// Dials the Edge's real QUIC endpoint through a MASQUE (RFC 9298 CONNECT-UDP)
/// tunnel and returns an ordinary [`quinn::Connection`] -- indistinguishable, to
/// the rest of this agent's code, from one [`crate::transport::dial_quic`] itself
/// would return, since it's the same real QUIC handshake and connection state
/// machine, just carried over a bridged transport instead of a kernel UDP socket.
///
/// * `proxy_tcp_addr` -- where to dial TCP+TLS+h2 (the Edge's own public front
///   door, e.g. `(edge_ip, 443)` -- see `crates/masque-proxy`'s own doc for why
///   this is the SAME port the existing TLS-TCP fallback already uses, not a new
///   listener).
/// * `sni_host` -- the TLS SNI / `:authority` hostname routing this connection to
///   the Edge's registered MASQUE proxy target (`CT_EDGE_MASQUE_HOST` on the Edge
///   side -- ADR-0024 M2).
/// * `target` -- the RFC 9298 CONNECT-UDP target this client is requesting. Must
///   match, byte-for-byte once encoded, whatever `masque-proxy`'s own
///   `CT_MASQUE_PROXY_TARGET_ADDR` is configured to on that deployment (its own
///   by-construction restriction, M2) -- an operator-maintained convention across
///   the two processes, not something this function can verify on its own.
/// * `edge_cert` -- the Edge's certificate this agent already trusts for QUIC
///   (reused here for BOTH the outer TLS-to-the-proxy-front-door layer and the
///   inner tunneled QUIC handshake's own cert pinning -- one trust anchor, not two).
/// * `token` -- the shared secret sent as `x-ct-masque-token`. `masque-proxy`
///   hard-restricts *where* a tunnel can go (its one configured target) but that
///   alone says nothing about *who* may open one -- since the target is the
///   Edge's own INTERNAL QUIC listener, the proxy also requires this token from
///   every caller (fail-closed on its own side: `CT_MASQUE_PROXY_TOKEN`). Must
///   match that deployment's token byte-for-byte.
pub async fn dial_quic_via_masque(
    proxy_tcp_addr: SocketAddr,
    sni_host: &str,
    target: SocketAddr,
    edge_cert: CertificateDer<'static>,
    token: &str,
) -> Result<quinn::Connection, BoxError> {
    // This hop terminates at the Edge's public masque.<zone> front door, which
    // presents a REAL publicly-trusted cert (Let's Encrypt via deSEC DNS-01, same
    // as Portal/Auth) -- not the Edge's own self-signed QUIC-pinned `edge_cert`.
    // `edge_cert` is still the right (and only) trust anchor for the INNER
    // tunneled QUIC handshake, which really is that pinned cert (see
    // `dial_quic_via_masque_with_proxy_roots`, below, which this production entry
    // point wraps with the real public CA set).
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    dial_quic_via_masque_with_proxy_roots(proxy_tcp_addr, sni_host, target, edge_cert, token, roots).await
}

/// Same as [`dial_quic_via_masque`], but with the OUTER (agent-to-proxy-front-door)
/// trust root injected rather than hardcoded to the real public CA set -- lets
/// tests exercise this function against a self-signed test cert without needing a
/// real publicly-trusted one, while production always goes through the wrapper
/// above.
async fn dial_quic_via_masque_with_proxy_roots(
    proxy_tcp_addr: SocketAddr,
    sni_host: &str,
    target: SocketAddr,
    edge_cert: CertificateDer<'static>,
    token: &str,
    proxy_roots: rustls::RootCertStore,
) -> Result<quinn::Connection, BoxError> {
    let tcp = TcpStream::connect(proxy_tcp_addr).await?;

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(proxy_roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
        .map_err(|e| format!("invalid MASQUE SNI host {sni_host:?}: {e}"))?;
    let tls = connector.connect(server_name, tcp).await?;

    let (send_request, connection) = h2::client::handshake(tls).await?;
    // ADR-0024 M4: found live causing a real outage on kali.bunsenbrenner.org --
    // this task (and the TCP+TLS socket it owns, driving the h2 Connection for
    // its whole life) MUST be aborted on every failure path below, not just left
    // to `tokio::spawn`'s fire-and-forget default. Before the outer-TLS trust-
    // anchor fix, every dial attempt failed at the TLS handshake above, before
    // this point was ever reached, so the leak was dormant; once TLS started
    // succeeding, every subsequent failure (extended-CONNECT timeout, a
    // non-200 response, a QUIC handshake failure) leaked one socket + one
    // zombie task per attempt -- on kali's flaky network, repeated reconnect
    // attempts exhausted file descriptors within seconds, silently breaking the
    // UNRELATED TLS-TCP fallback's own real traffic (no crash, no error logged,
    // just "connection reset" once the process ran out of sockets to open).
    // `AbortOnDrop` guarantees the abort on every `?`/early-return exit below
    // via ordinary Rust drop semantics; only `success.disarm()` on the one
    // actual success path skips it, since the connection must keep being
    // driven for the tunnel's whole lifetime once it's real.
    let connection_task = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await; // driven for its side effects, same as ADR-0024 M1's own client
    }));

    let mut send_request = send_request.ready().await?;
    // ADR-0024 M1 finding: `ready()` resolving does not guarantee the proxy's
    // SETTINGS_ENABLE_CONNECT_PROTOCOL=1 frame has already been processed --
    // bounded poll, not a one-shot check.
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    if !send_request.is_extended_connect_protocol_enabled() {
        return Err("MASQUE proxy never enabled the HTTP/2 extended CONNECT protocol (RFC 9220) \
                     within 500ms -- not a real CONNECT-UDP proxy, or unreachable"
            .into());
    }

    let path = connect_udp_path(target);
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{sni_host}{path}"))
        .header("x-ct-masque-token", token)
        .body(())?;
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, client_send) = send_request.send_request(request, false)?;
    let response = response_fut.await?;
    if response.status() != 200 {
        return Err(format!("MASQUE proxy refused the CONNECT-UDP request: HTTP {}", response.status()).into());
    }

    // `peer_addr` is a synthetic label, not a real route (see socket.rs's own doc):
    // there is only one real peer on this bridged transport, reached via the h2
    // stream. It must be the SAME value the socket itself will report in every
    // `RecvMeta::addr` -- `MasqueUdpSocket::spawn` derives and returns it so this
    // caller and the socket can never disagree on it.
    let (masque_socket, peer_addr) = socket::MasqueUdpSocket::spawn(client_send, response.into_body(), target);

    let (keep_alive, max_idle) = agent_keepalive_and_max_idle();
    let client_cfg = quic_client_config(edge_cert, Some(keep_alive), max_idle)?;
    let mut endpoint = Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::new(masque_socket),
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_cfg);

    let connecting = endpoint.connect(peer_addr, "localhost")?;
    let conn = connecting.await?;
    // Real tunnel established -- the connection-driving task must now keep
    // running for the tunnel's whole life, not be aborted on this function
    // returning (every prior `?`/early-return above still aborts it correctly).
    connection_task.disarm();
    Ok(conn)
}

