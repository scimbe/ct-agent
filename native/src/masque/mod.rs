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
pub async fn dial_quic_via_masque(
    proxy_tcp_addr: SocketAddr,
    sni_host: &str,
    target: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<quinn::Connection, BoxError> {
    let tcp = TcpStream::connect(proxy_tcp_addr).await?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert.clone())?;
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
        .map_err(|e| format!("invalid MASQUE SNI host {sni_host:?}: {e}"))?;
    let tls = connector.connect(server_name, tcp).await?;

    let (send_request, connection) = h2::client::handshake(tls).await?;
    tokio::spawn(async move {
        let _ = connection.await; // driven for its side effects, same as ADR-0024 M1's own client
    });

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
    Ok(conn)
}

