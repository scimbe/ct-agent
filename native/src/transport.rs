//! Agent → Edge transport (ADR-0004).
//!
//! The Agent dials outbound (no inbound ports). QUIC/UDP-443 is primary; when
//! outbound UDP is blocked it falls back to HTTP/2 over TCP/443.
//!
//! P1.2a implements the transport-selection decision and the QUIC dialer. The
//! actual TCP fallback transport (P1.2c) and reconnect-on-drop (P1.2b) follow.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use std::path::Path;

use ct_common::credential::SignedCredential;
use ct_common::RoutingToken;
use quinn::{Connection, Endpoint};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Generate a self-signed cert/key for the Agent's direct-path listener.
fn self_signed() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), BoxError> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    Ok((cert, key))
}

/// Build the Agent's direct-path QUIC **server** endpoint bound to `addr`
/// (M11.3b) — a listener for direct Client connections that bypass the Edge
/// relay. Returns the endpoint and its self-signed cert (advertised to Clients
/// so they can trust the direct path).
pub fn build_direct_listener_at(
    addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    install_crypto_provider();
    let (cert, key) = self_signed()?;
    let server_config = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key)?;
    let endpoint = Endpoint::server(server_config, addr)?;
    Ok((endpoint, cert))
}

/// Build the direct-path listener on `0.0.0.0:0` (reachable on the container's
/// bridge IP, ephemeral port).
pub fn build_direct_listener() -> Result<(Endpoint, CertificateDer<'static>), BoxError> {
    build_direct_listener_at(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
}

/// A rustls verifier that accepts **any** server certificate but still checks the
/// handshake signature is internally consistent (the peer holds the key for the cert
/// it presented). This is intentional for the Agent-Fabric A2A channel dialer
/// (#72/#100): the QUIC/TLS layer is only transport, and the *real* mutual
/// authentication is the Noise_IK session keyed on the members' pinned static keys —
/// a transport-layer MITM cannot complete the Noise handshake without the peer's
/// private key. So the initiator needs no pre-shared transport cert (only the peer's
/// Noise key), which is what lets the A2A one-liner stay self-contained.
#[derive(Debug)]
struct AcceptAnyServerCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Build the Agent-Fabric A2A channel **dialer** (#72/#100): a QUIC client endpoint
/// that trusts any responder transport cert (see [`AcceptAnyServerCert`]), so the
/// initiator can dial a paired peer without a pre-shared cert. Authentication is the
/// Noise_IK session run over the connection, not the QUIC cert.
pub fn build_channel_dialer() -> Result<Endpoint, BoxError> {
    // #114 #4: cache the runtime-independent rustls/QUIC client config so it is built
    // ONCE, not rebuilt (rustls builder + cert verifier + QUIC crypto) on every channel
    // dial (broker, relay, and each direct-peer / ladder rung). The UDP socket is still
    // bound per call: a quinn `Endpoint`'s driver is tied to its creating tokio runtime,
    // so it cannot be safely memoized process-wide (that would break across runtimes);
    // reusing one `Endpoint` per join flow is a separate, localized follow.
    static CLIENT_CONFIG: OnceLock<quinn::ClientConfig> = OnceLock::new();
    let cfg = match CLIENT_CONFIG.get() {
        Some(c) => c.clone(),
        None => {
            install_crypto_provider();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let crypto = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(provider)))
                .with_no_client_auth();
            let mut cfg = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
            ));
            // #139: bound a dead-but-connected direct link at the transport level. Without a
            // max_idle_timeout a QUIC connection that handshakes then goes silent (asymmetric NAT, a
            // middlebox dropping post-handshake packets) never dies, so an await on it — `open_bi`,
            // the Noise_IK handshake, the pump — can hang forever with no relay fallback. A ~20s idle
            // timeout kills such a connection so those awaits error and the direct path can fall
            // back; a 5s keepalive (< the idle timeout) holds a *live* but idle data session open so
            // the timeout only ever fires on a genuinely dead path.
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(std::time::Duration::from_secs(20)).expect("20s < quinn max idle"),
            ));
            transport.keep_alive_interval(Some(std::time::Duration::from_secs(5)));
            cfg.transport_config(Arc::new(transport));
            // A concurrent racer may win the set(); either config is equivalent.
            let _ = CLIENT_CONFIG.set(cfg.clone());
            cfg
        }
    };
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Advertise the Agent's direct-path listener to the Edge (M11.4b-ii): send a
/// `'D'` message — `token(32) | addr_len(1) | addr | cert_len(2 BE) | cert` — so
/// Clients querying with `'P'` can discover and connect to it directly.
pub async fn advertise_direct_listener(
    conn: &Connection,
    token: &RoutingToken,
    addr: SocketAddr,
    cert: &CertificateDer<'_>,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"D").await?;
    send.write_all(&token.0).await?;
    let a = addr.to_string();
    let ab = a.as_bytes();
    send.write_all(&[ab.len() as u8]).await?;
    send.write_all(ab).await?;
    let cb = cert.as_ref();
    send.write_all(&(cb.len() as u16).to_be_bytes()).await?;
    send.write_all(cb).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("direct-listener advertisement rejected".into())
    }
}

/// Transport the Agent uses to reach the Edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Primary: QUIC over UDP/443.
    Quic,
    /// Fallback when outbound UDP is blocked: HTTP/2 over TCP/443.
    TcpFallback,
}

/// Select the transport given whether outbound UDP is reachable. QUIC is
/// preferred; TCP fallback is used only when UDP is blocked (ADR-0004).
pub fn select_transport(udp_reachable: bool) -> Transport {
    if udp_reachable {
        Transport::Quic
    } else {
        Transport::TcpFallback
    }
}

/// Probe whether outbound QUIC/UDP to `edge` works (M12.1): attempt a QUIC
/// handshake within `timeout`. Returns `true` if it connects — the input to
/// [`select_transport`] (QUIC vs the TCP fallback when UDP is blocked).
pub async fn probe_udp_reachable(
    edge: SocketAddr,
    edge_cert: CertificateDer<'static>,
    timeout: Duration,
) -> bool {
    matches!(
        tokio::time::timeout(timeout, dial_quic(edge, edge_cert)).await,
        Ok(Ok(_))
    )
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// QUIC keepalive on the Agent's control connection to the Edge (issue #2).
/// Without it, quinn's idle timeout tears down the registered connection, the
/// Edge evicts the tunnel, and a Client arriving seconds later gets "no relay".
/// 5s also keeps the cross-host NAT/UDP mapping warm; the idle timeout sits
/// comfortably above it.
const AGENT_KEEPALIVE: Duration = Duration::from_secs(5);
const AGENT_MAX_IDLE: Duration = Duration::from_secs(30);

fn client_endpoint(edge_cert: CertificateDer<'static>) -> Result<Endpoint, BoxError> {
    client_endpoint_with(edge_cert, Some(AGENT_KEEPALIVE), AGENT_MAX_IDLE)
}

/// Build the Agent's QUIC client endpoint trusting `edge_cert`, applying a
/// `keep_alive_interval` and `max_idle_timeout` so the registered control
/// connection to the Edge stays alive across idle gaps (issue #2).
fn client_endpoint_with(
    edge_cert: CertificateDer<'static>,
    keep_alive: Option<Duration>,
    max_idle: Duration,
) -> Result<Endpoint, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(keep_alive);
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(max_idle).map_err(|_| "agent max_idle_timeout out of range")?,
    ));
    cfg.transport_config(Arc::new(transport));
    // Bind all interfaces (not loopback) so the Agent can reach a non-local Edge.
    let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))?;
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

/// Dial the Edge over QUIC, returning the established connection. `edge_cert` is
/// the Edge's certificate the Agent trusts for this dial.
pub async fn dial_quic(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<Connection, BoxError> {
    let endpoint = client_endpoint(edge_cert)?;
    let conn = endpoint.connect(edge_addr, "localhost")?.await?;
    Ok(conn)
}

/// Dial the Edge over QUIC within `timeout`, mapping a timeout/failure to a
/// clear, actionable error instead of quinn's bare `TimedOut` (issue #3 /
/// P1.2c-1). Agent registration is currently QUIC/UDP-only, so a blocked UDP
/// path is the common cause; the error names it and points at the TCP-fallback
/// work still to come, rather than leaving the operator with an opaque timeout.
pub async fn dial_quic_or_blocked_error(
    edge_addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    timeout: Duration,
) -> Result<Connection, BoxError> {
    match tokio::time::timeout(timeout, dial_quic(edge_addr, edge_cert)).await {
        Ok(Ok(conn)) => Ok(conn),
        _ => Err(format!(
            "edge UDP/QUIC unreachable at {edge_addr} — agent registration requires UDP; \
             TCP-fallback registration is not yet implemented (issue #3 / P1.2c). \
             Open UDP/{} between hosts, or track the fallback work.",
            edge_addr.port()
        )
        .into()),
    }
}

/// Present `signed` to the Edge over a fresh bidirectional stream and await the
/// Edge's decision. Returns `Ok(())` only if the Edge accepted the credential.
pub async fn present_credential(
    conn: &Connection,
    signed: &SignedCredential,
) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(&signed.encode()).await?;
    send.finish()?;
    let ack = recv.read_to_end(64).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected credential".into())
    }
}

/// Register this Agent's tunnel for `token` with the Edge over `conn`: open a
/// control stream, send `role='A' | token(32)`, and await the Edge's `OK`.
pub async fn register_tunnel(conn: &Connection, token: &RoutingToken) -> Result<(), BoxError> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let mut msg = vec![b'A'];
    msg.extend_from_slice(&token.0);
    send.write_all(&msg).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected tunnel registration".into())
    }
}

/// Bind a public hostname to this Agent's routing token at the Edge (#23 BP3b):
/// open a control stream and send `role='H' | token(32) | host_len(2 BE) | host`,
/// then await the Edge's `OK`. Enables SNI-routed browser access to this tunnel.
pub async fn bind_hostname(
    conn: &Connection,
    token: &RoutingToken,
    host: &str,
) -> Result<(), BoxError> {
    let hb = host.as_bytes();
    if hb.is_empty() || hb.len() > 253 {
        return Err("hostname length out of range (1..=253)".into());
    }
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"H").await?;
    send.write_all(&token.0).await?;
    send.write_all(&(hb.len() as u16).to_be_bytes()).await?;
    send.write_all(hb).await?;
    send.finish()?;
    let ack = recv.read_to_end(8).await?;
    if ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected hostname binding".into())
    }
}

/// Register this Agent's tunnel for `token` over a generic byte stream — the
/// TLS-over-TCP fallback (issue #3 / P1.2c-2): write `role='A' | token(32)` and
/// await the Edge's `OK`. Unlike the QUIC path (which opens a fresh bi-stream
/// per client), a TCP agent uses one stream, so the *same* stream then carries
/// the relayed tunnel — a TCP-fallback agent serves one client at a time.
pub async fn register_tunnel_stream<S>(
    stream: &mut S,
    token: &RoutingToken,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    register_tunnel_stream_with_role(stream, token, b'A').await
}

/// First byte of a parked-registration PING frame (Edge → ping-capable Agent):
/// `0xF9 | counter(8 BE)`, 9 bytes total.
const TCP_PING_MAGIC: u8 = 0xF9;

/// First byte of the matching PONG reply (Agent → Edge): `0xFA | counter(8 BE)`,
/// echoing the PING's counter verbatim, 9 bytes total.
const TCP_PONG_MAGIC: u8 = 0xFA;

/// Single-byte STOP sentinel the Edge writes exactly once, strictly before any
/// relayed byte, to end the ping phase unambiguously. It is deliberately NOT a
/// 9-byte frame: the reader must consume this one byte and nothing more, so the
/// Noise handshake that follows starts on a byte-exact stream boundary.
const TCP_PING_STOP: u8 = 0xFB;

/// Register this Agent's tunnel over a generic byte stream as **ping-capable**
/// (ct-agent#15): identical to [`register_tunnel_stream`] except the role byte is
/// `'K'` instead of `'A'`. A `'K'`-aware Edge parks the registration exactly as
/// it parks an `'A'`, but additionally sends real-payload PING frames over the
/// otherwise-idle connection while waiting for a Client — see
/// [`await_ping_phase_end`], which the caller MUST drive before treating the
/// stream as carrying relayed bytes.
///
/// Why this exists: a bare TCP keepalive is an ACK-only segment, and some
/// enterprise firewall/DPI/SASE gateways do not count ACK-only segments as
/// activity for their own idle-timeout bookkeeping, so a parked fallback
/// connection still got torn down after the 10s/10s keepalive tightening
/// (9b42d9e). PING/PONG puts genuine payload on the wire in both directions.
pub async fn register_tunnel_stream_ping_capable<S>(
    stream: &mut S,
    token: &RoutingToken,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    register_tunnel_stream_with_role(stream, token, b'K').await
}

/// Shared body of the `'A'`/`'K'` TCP-fallback registration: both roles have a
/// byte-identical wire format (`role(1) | token(32)` → 2-byte `OK`/`NO` ack), so
/// the only thing that varies is the role byte itself.
async fn register_tunnel_stream_with_role<S>(
    stream: &mut S,
    token: &RoutingToken,
    role: u8,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut msg = vec![role];
    msg.extend_from_slice(&token.0);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    let mut ack = [0u8; 2];
    stream.read_exact(&mut ack).await?;
    if &ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected tunnel registration".into())
    }
}

/// Drive the ping phase of a `'K'` registration to its end: answer every PING
/// with a PONG until the Edge writes [`TCP_PING_STOP`], then return with the
/// stream positioned exactly at the first relayed byte.
///
/// Wire contract (Edge side: `park_and_ping` / `send_ping_and_await_pong`):
/// * `0xF9 | counter(8 BE)` — PING. Reply `0xFA | counter(8 BE)`, same counter.
/// * `0xFB` — STOP, a lone byte. Ping phase over; a Client is now spliced in.
///
/// Note the framing asymmetry: STOP is one byte, PING is nine, so this reads the
/// discriminator byte first and only then the counter. Blindly reading 9 bytes
/// would swallow the first 8 bytes of the Noise handshake.
///
/// The Edge fully awaits each PONG before the next PING and writes STOP strictly
/// before it starts relaying, so TCP ordering guarantees the only bytes that can
/// arrive here are `0xF9` and `0xFB` frames. Anything else — an unexpected
/// discriminator or an I/O error — means the peer is not a conforming Edge or
/// the stream has desynchronised; both are propagated as a connection error
/// rather than guessed at, because handing a desynchronised stream to the Noise
/// handshake would fail later and far more confusingly. The caller's reconnect
/// ladder then redials, which is the correct recovery.
pub async fn await_ping_phase_end<S>(stream: &mut S) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut disc = [0u8; 1];
        stream.read_exact(&mut disc).await?;
        match disc[0] {
            TCP_PING_MAGIC => {
                let mut counter = [0u8; 8];
                stream.read_exact(&mut counter).await?;
                let mut pong = [0u8; 9];
                pong[0] = TCP_PONG_MAGIC;
                pong[1..].copy_from_slice(&counter);
                stream.write_all(&pong).await?;
                stream.flush().await?;
            }
            TCP_PING_STOP => return Ok(()),
            other => {
                return Err(format!(
                    "edge sent an unexpected byte 0x{other:02X} during the ping phase \
                     (expected PING 0x{TCP_PING_MAGIC:02X} or STOP 0x{TCP_PING_STOP:02X})"
                )
                .into())
            }
        }
    }
}

/// Register **and** bind a public hostname in one message over a TLS-TCP stream
/// (issue #41 FB3): the Browser Plane's TCP fallback. Sends the `'B'` frame —
/// `'B' | token(32) | host_len(u16 BE) | host` — so a UDP-blocked browser-mode
/// agent both registers its token and claims its hostname atomically, mirroring
/// the QUIC path's separate `'A'` register + `'H'` bind. Awaits the 2-byte "OK".
pub async fn register_tunnel_stream_browser<S>(
    stream: &mut S,
    token: &RoutingToken,
    host: &str,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    register_tunnel_stream_browser_with_role(stream, token, host, b'B').await
}

/// The ping-capable Browser-Plane registration: exactly what
/// [`register_tunnel_stream_ping_capable`] (`'K'`) is to the Noise path's `'A'`,
/// but for `'B'`. Byte-identical wire format to `'B'` apart from the role byte;
/// after the `OK`, the Edge PINGs this connection while it sits parked, so the
/// caller must drive [`await_ping_phase_end`] before treating the stream as
/// carrying relayed bytes.
///
/// Why this exists, beyond symmetry: `'K'` only ever covered the Noise/mesh path,
/// so a Browser-Plane agent (`CT_AGENT_MODE=browser`) could not benefit from the
/// ping treatment at all -- upgrading such an agent to the release carrying `'K'`
/// changed nothing for it. Measured on the deployment where this was found: a
/// parked fallback connection dies after ~10-15s idle (5s request spacing -> 4/4
/// OK, 20s spacing -> 1/4), because the middlebox on that path ignores ACK-only
/// keepalive segments. Real payload traffic is the only thing that keeps it alive.
pub async fn register_tunnel_stream_browser_ping_capable<S>(
    stream: &mut S,
    token: &RoutingToken,
    host: &str,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    register_tunnel_stream_browser_with_role(stream, token, host, b'L').await
}

/// The **framed** Browser-Plane registration (CADS-Tunnel#528): byte-identical to
/// `'B'`/`'L'` apart from the role byte `'F'`, and it keeps the whole `'L'` park
/// phase — the Edge PINGs this connection while it sits parked, so the caller
/// still drives [`await_ping_phase_end`] first. What `'F'` changes is what comes
/// **after** the `STOP` byte: the relay phase is length-prefix framed in both
/// directions on the edge↔agent hop (`ct_common::fallback_framing`), instead of
/// being a raw byte pump. Drive it with [`crate::serve::serve_framed_duplex_to_origin`].
///
/// Why: `'L'` only keeps a *parked* connection alive. Once a request is delivered
/// the framing stops and the connection is transparent again, so a request whose
/// Origin is silent longer than the middlebox idle timeout — an LLM cold model
/// load is the case this was found on — has neither relay traffic nor any way to
/// inject a keepalive, and the middlebox drops the connection mid-request. Framing
/// the relay phase makes a payload-carrying keepalive interleavable *during* an
/// in-flight request, the same trick HTTP/2 PING (RFC 7540 §6.7) exists for.
///
/// Same fallback shape as `'L'`: an Edge that predates `'F'` treats the unknown
/// role byte as a hard protocol error and drops the connection without an ack, so
/// any failure here means redialing and registering `'L'` (then `'B'`) on a fresh
/// stream — see `serve::tcp_connect_register_serve`.
pub async fn register_tunnel_stream_browser_framed_capable<S>(
    stream: &mut S,
    token: &RoutingToken,
    host: &str,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    register_tunnel_stream_browser_with_role(stream, token, host, b'F').await
}

/// Shared body of the `'B'`/`'L'`/`'F'` Browser-Plane registration: all three roles
/// have a byte-identical wire format (`role(1) | token(32) | host_len(2 BE) | host`
/// → 2-byte `OK`/`NO` ack), so only the role byte varies.
async fn register_tunnel_stream_browser_with_role<S>(
    stream: &mut S,
    token: &RoutingToken,
    host: &str,
    role: u8,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let host_bytes = host.as_bytes();
    let host_len: u16 = host_bytes
        .len()
        .try_into()
        .map_err(|_| "hostname too long for the browser-register frame")?;
    let mut msg = vec![role];
    msg.extend_from_slice(&token.0);
    msg.extend_from_slice(&host_len.to_be_bytes());
    msg.extend_from_slice(host_bytes);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    let mut ack = [0u8; 2];
    stream.read_exact(&mut ack).await?;
    if &ack == b"OK" {
        Ok(())
    } else {
        Err("edge rejected browser hostname registration".into())
    }
}

/// Connect to the Edge over **TLS-over-TCP** — the UDP-blocked fallback dialer
/// (issue #3 / P1.2c-4), trusting `edge_cert` (the CA root). Mirrors the Client's
/// `tcp_tls_connect`; the returned stream is then used with
/// [`register_tunnel_stream`] to register the Agent when QUIC/UDP is unavailable.
pub async fn tcp_tls_connect(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    // #46 FB-b: advertise ALPN `ct-edge` so the unified :443 front door (#31 FD2)
    // classifies this as the data-plane relay (EdgeRelay) and routes it to
    // serve_tcp_connection — the register ('A'/'B') + revoke ('R') path.
    tcp_tls_connect_with_alpn(addr, edge_cert, b"ct-edge").await
}

/// Connect to the unified `:443` **front door** for the Agent-Fabric A2A channel
/// route (#106): TLS-over-TCP to `addr`, trusting `edge_cert`, advertising ALPN
/// `ct-edge-channel` so the front door (#31/#46 pattern) classifies this as the
/// channel broker/relay and dispatches it to the channel admit+pair path — the
/// fallback dialer for a restrictive network that blocks the direct channel ports.
/// The returned stream is then split and driven with
/// [`crate::channel::present_channel_join_on_stream`].
pub async fn tcp_tls_connect_channel(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    // #500 K2 (v0.4.13): offer the park-keepalive-capable id FIRST, the legacy id as
    // fallback. A current edge's server-preference selects `-ka` (it will send one NUL of
    // application payload per 10s while this member is parked -- stripped by the ack
    // readers -- and treats a clean EOF as unambiguous member death, enabling instant
    // corpse detection); an older edge only knows the bare id and behaves exactly as
    // before. The whole capability handshake lives in this ALPN list.
    tcp_tls_connect_with_alpns_sni(
        addr,
        edge_cert,
        &[b"ct-edge-channel-ka", b"ct-edge-channel"],
        DEFAULT_SNI,
    )
    .await
}

/// The SNI every non-fallback TLS-TCP dial presents. The client pins the edge's raw
/// certificate (`roots.add(edge_cert)`) instead of doing hostname-based CA validation, so
/// this value is never checked against the certificate — it is pure ClientHello metadata.
const DEFAULT_SNI: &str = "localhost";

/// The synthetic SNI hostname of the DPI-resistant `:443` fallback route (#106
/// boring-alpn). An RFC 2606 `.invalid` TLD: it deliberately never resolves, and never
/// needs to — the client dials a raw [`SocketAddr`], so no name lookup happens on either
/// end; the edge uses it purely as a routing key in the ClientHello. Locked in lockstep
/// with the edge side (CADS-Tunnel front door): changing it here alone breaks the route.
pub const CHANNEL_FALLBACK_SNI: &str = "edge-cdn.invalid";

/// The "boring" ALPN of the DPI-resistant `:443` fallback route (#106 boring-alpn):
/// ordinary HTTP/2, i.e. exactly what a middlebox expects to see offered to a `:443`
/// endpoint. Paired with [`CHANNEL_FALLBACK_SNI`]; also locked with the edge side.
pub const CHANNEL_FALLBACK_ALPN: &[u8] = b"h2";

/// Connect to the unified `:443` front door for the channel route the **DPI-resistant**
/// way (#106 boring-alpn): same endpoint and same wire protocol as
/// [`tcp_tls_connect_channel`], but the ClientHello offers ALPN `h2` under SNI
/// `edge-cdn.invalid` instead of the distinctive `ct-edge-channel` ALPN under an
/// obviously-wrong `localhost` SNI. Motivated by a real support case (2026-08-12): a
/// corporate/sandbox network fingerprinted both giveaways and dropped the join bytes
/// before they ever reached the broker. The edge routes this pair to the SAME channel
/// broker handler, so nothing about the join/possession/ack protocol changes — only the
/// outer TLS ClientHello.
pub async fn tcp_tls_connect_channel_boring(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    // #500 K2 (v0.4.13): [h2, http/1.1] -- the single most ordinary ClientHello on the
    // internet, so the DPI camouflage is fully preserved. A current edge deliberately
    // SELECTS `http/1.1` as the keepalive signal (its server-preference lists it before
    // h2); an older edge only knows h2 and behaves exactly as before. Unremarkable to any
    // observer, unambiguous to both ends.
    tcp_tls_connect_with_alpns_sni(
        addr,
        edge_cert,
        &[CHANNEL_FALLBACK_ALPN, b"http/1.1"],
        CHANNEL_FALLBACK_SNI,
    )
    .await
}

/// #500/#495-2a: whether this channel dial's TLS negotiation selected a KA-generation id
/// (plain `ct-edge-channel-ka`, or `http/1.1` on the boring leg -- the edge's deliberate
/// keepalive signal). A KA-generation edge understands the park keepalive AND the
/// optional `[0xFF, phase]` join preamble; an old edge selected a legacy id and must
/// receive byte-identical legacy traffic.
pub fn ka_negotiated(tls: &tokio_rustls::client::TlsStream<TcpStream>) -> bool {
    matches!(
        tls.get_ref().1.alpn_protocol(),
        Some(p) if p == b"ct-edge-channel-ka" || p == b"http/1.1"
    )
}

/// Enable TCP keepalive on `stream` (#229): a parked TLS-TCP fallback
/// registration is otherwise a plain, silent TCP connection with nothing to
/// refresh it over however long it sits waiting for a Client -- over a real,
/// geographically distant network, any NAT/firewall between the Agent and
/// the Edge can drop an idle mapping without either endpoint noticing, so a
/// Client later delivered onto that "parked" connection gets nothing back.
/// Best-effort: unsupported platforms or an already-broken socket just
/// don't get the option.
///
/// **20s/20s with the OS-default retry count** (~200s worst-case dead-connection
/// detection on Linux). These were briefly 10s/10s + `with_retries(3)` (~40s) to
/// mirror an edge-side tightening (CADS-Tunnel #15, `5e3dd3c`) -- but the edge
/// REVERTED that a day later (`58864ae`) and the agent side was never pulled back
/// with it, so this end kept claiming to mirror an edge setting that no longer
/// exists. The revert's two reasons apply verbatim here:
///
/// * It didn't fix what it targeted. The parked-registration flapping continued at
///   exactly the same rate after the tightening (measured next day on the same
///   deployment: 5s request spacing -> 4/4 OK, 20s -> 1/4). The cause is a middlebox
///   that ignores ACK-only segments entirely, so no keepalive *timing* can help --
///   which is why the real-payload `'K'`/`'L'` park roles, and now #528's framed
///   relay keepalive, exist instead.
/// * Its blast radius was wider than intended, in the exact direction #528 is about:
///   this runs on EVERY TLS-TCP dial, not just parked registrations, so a 5x tighter
///   window also cut how long a legitimately quiet *in-flight* connection may stay
///   quiet. On the edge that produced a live regression (an LLM call going quiet for
///   15-20s), and an agent-side kill during the same silence is the same user-visible
///   failure seen from the other end of the wire.
///
/// So dead-connection detection here is deliberately slow; liveness during a relay is
/// the framed keepalive's job (`serve::serve_framed_duplex_to_origin`, ~24s verdict),
/// not TCP's.
fn apply_tcp_keepalive(stream: &TcpStream) {
    let sock = socket2::SockRef::from(stream);
    // No `with_retries`: an explicit TCP_KEEPCNT bound is what made the reverted
    // tightening kill quiet in-flight connections early. The OS default (~9 on Linux)
    // is the value the edge went back to, and this side matches it again.
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(20))
        .with_interval(Duration::from_secs(20));
    let _ = sock.set_tcp_keepalive(&ka);
}

/// TLS-over-TCP dialer to `addr` trusting `edge_cert`, advertising `alpn` in the
/// ClientHello (issue #3 / P1.2c-4 core, generalized for #106). The ALPN selects
/// which unified `:443` front-door route the connection is classified into:
/// `ct-edge` → the data-plane relay, `ct-edge-channel` → the A2A channel broker.
/// Harmless on the direct TLS listeners (they advertise no ALPN, so the offer is
/// ignored). The thin [`tcp_tls_connect`] / [`tcp_tls_connect_channel`] wrappers
/// pin the two protocol strings.
pub async fn tcp_tls_connect_with_alpn(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    alpn: &[u8],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    tcp_tls_connect_with_alpn_sni(addr, edge_cert, alpn, DEFAULT_SNI).await
}

/// [`tcp_tls_connect_with_alpn`] with the ClientHello's **SNI** chosen by the caller too.
/// Both are free-form here: the certificate is pinned by value, so neither participates in
/// validation — they are the two routing keys the unified `:443` front door classifies on,
/// and (being plaintext in the ClientHello) the only part of the connection a middlebox can
/// see. The existing `ct-edge` / `ct-edge-channel` / `ct-edge-relay` callers keep
/// [`DEFAULT_SNI`] deliberately: those routes work on the networks that already use them,
/// and the edge now classifies on SNI as well (#106 boring-alpn), so changing their SNI
/// would silently re-route them. Only the new fallback rung opts into a different pair.
pub async fn tcp_tls_connect_with_alpn_sni(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    alpn: &[u8],
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    tcp_tls_connect_with_alpns_sni(addr, edge_cert, &[alpn], sni).await
}

/// [`tcp_tls_connect_with_alpn_sni`] offering an ordered LIST of ALPN ids (#500 K2): the
/// server's preference over this list is the capability negotiation -- see the channel
/// dialers above for the two concrete offer tables. Single-id callers use the thin wrapper.
pub async fn tcp_tls_connect_with_alpns_sni(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    alpns: &[&[u8]],
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BoxError> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(edge_cert)?;
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpns.iter().map(|a| a.to_vec()).collect();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await?;
    apply_tcp_keepalive(&tcp);
    let server_name = rustls::pki_types::ServerName::try_from(sni)?.to_owned();
    Ok(connector.connect(server_name, tcp).await?)
}

/// Load an Edge certificate (DER) the Edge published to a shared path.
pub fn load_cert(path: impl AsRef<Path>) -> std::io::Result<CertificateDer<'static>> {
    Ok(CertificateDer::from(std::fs::read(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_quic_when_udp_reachable() {
        assert_eq!(select_transport(true), Transport::Quic);
    }

    #[tokio::test]
    async fn apply_tcp_keepalive_actually_sets_the_socket_option() {
        // #229: a parked TLS-TCP fallback connection is otherwise a plain,
        // silent TCP socket an idle NAT/firewall can drop unnoticed. Prove
        // apply_tcp_keepalive isn't a silent no-op -- read the option back.
        let bind = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = bind.local_addr().unwrap();
        let accept = tokio::spawn(async move { bind.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accept.await.unwrap();

        let sock = socket2::SockRef::from(&client);
        assert!(!sock.keepalive().unwrap(), "keepalive is off by default before applying it");
        apply_tcp_keepalive(&client);
        assert!(sock.keepalive().unwrap(), "apply_tcp_keepalive must actually enable SO_KEEPALIVE");
    }

    #[tokio::test]
    async fn apply_tcp_keepalive_stays_at_20s_20s_with_no_explicit_retry_bound() {
        // The values, and the fact that they land on the wire at all (not just that
        // apply_tcp_keepalive compiles). They were briefly 10s/10s + TCP_KEEPCNT=3 to
        // mirror an edge tightening; the EDGE reverted that a day later (CADS-Tunnel
        // 58864ae) because it didn't reduce the flapping it targeted -- the middlebox
        // ignores ACK-only segments, so no timing helps -- and because it killed quiet
        // in-flight connections early (a 15-20s silent LLM call), which is a
        // user-visible failure. This side kept the tightened values and a doc claiming
        // to "mirror the edge" until #528. Pin the reverted values so the two ends of
        // the same connection cannot silently drift apart again.
        let bind = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = bind.local_addr().unwrap();
        let accept = tokio::spawn(async move { bind.accept().await.unwrap().0 });
        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accept.await.unwrap();

        apply_tcp_keepalive(&client);
        let sock = socket2::SockRef::from(&client);
        assert!(sock.keepalive().unwrap_or(false), "SO_KEEPALIVE must be enabled");
        assert_eq!(
            sock.keepalive_time().unwrap(),
            Duration::from_secs(20),
            "TCP_KEEPIDLE stays at 20s -- matching the edge after its revert"
        );
        assert_eq!(
            sock.keepalive_interval().unwrap(),
            Duration::from_secs(20),
            "TCP_KEEPINTVL stays at 20s -- matching the edge after its revert"
        );
        assert!(
            sock.keepalive_retries().unwrap() > 3,
            "TCP_KEEPCNT must be left at the OS default (~9 on Linux), NOT bounded to 3: \
             an explicit low bound is what killed quiet in-flight connections early"
        );
    }

    #[tokio::test]
    async fn build_channel_dialer_reuses_config_but_binds_its_own_socket() {
        // #114 #4 (frozen): the client config is now built once and reused across dials,
        // but each dialer still binds its OWN UDP socket (a quinn Endpoint's driver is
        // tied to its creating runtime, so it can't be shared process-wide). Both calls
        // must yield working, independently-bound client endpoints.
        let a = build_channel_dialer().expect("first dialer builds");
        let b = build_channel_dialer().expect("second dialer builds (config cache hit)");
        let la = a.local_addr().expect("a is bound");
        let lb = b.local_addr().expect("b is bound");
        assert_ne!(la, lb, "each dialer binds its own socket (endpoints are not shared)");
        assert!(la.port() != 0 && lb.port() != 0, "both endpoints are bound to a real port");
    }

    #[tokio::test]
    async fn direct_listener_accepts_a_connection() {
        // M11.3b: the Agent's direct-path listener accepts a Client that trusts
        // its advertised cert and connects directly (bypassing the Edge relay).
        let (listener, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let addr = listener.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap().await.unwrap();
            let (mut s, mut r) = conn.accept_bi().await.unwrap();
            let data = r.read_to_end(64).await.unwrap();
            s.write_all(&data).await.unwrap();
            s.finish().unwrap();
            conn.closed().await;
        });

        let client = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = client
            .connect(addr, "localhost")
            .expect("cfg")
            .await
            .expect("direct conn");
        let (mut s, mut r) = conn.open_bi().await.unwrap();
        s.write_all(b"direct-hello").await.unwrap();
        s.finish().unwrap();
        let echoed = r.read_to_end(64).await.unwrap();
        assert_eq!(echoed, b"direct-hello", "direct listener accepts and echoes");
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    #[test]
    fn falls_back_to_tcp_when_udp_blocked() {
        assert_eq!(select_transport(false), Transport::TcpFallback);
    }

    #[tokio::test]
    async fn probe_reachable_edge_selects_quic() {
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let accept = tokio::spawn(async move {
            if let Some(inc) = server.accept().await {
                let _ = inc.await;
            }
        });
        let reachable = probe_udp_reachable(addr, cert, Duration::from_secs(2)).await;
        assert!(reachable, "QUIC to a live edge is reachable");
        assert_eq!(select_transport(reachable), Transport::Quic);
        accept.abort();
    }

    #[tokio::test]
    async fn probe_dead_udp_selects_tcp_fallback() {
        // Nothing listening at this UDP address → probe times out.
        let (_ep, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("cert");
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let reachable = probe_udp_reachable(dead_addr, cert, Duration::from_millis(400)).await;
        assert!(!reachable, "blocked UDP is not reachable");
        assert_eq!(select_transport(reachable), Transport::TcpFallback);
    }

    #[tokio::test]
    async fn agent_connects_and_registers_over_tls_tcp() {
        // issue #3 / P1.2c-4: the agent dials the real edge over TLS-TCP and
        // registers ('A') through the edge's TCP handler, which parks it.
        use ct_common::pow::Challenge;
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use ct_edge::serve::serve_tcp_connection;
        use ct_edge::state::EdgeState;
        use quinn::Connection;

        let ca = Ca::new("test-ca").expect("ca");
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .expect("dual edge");
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x77; 32]);
        let state = std::sync::Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge {
            nonce: [0u8; 16],
            difficulty: 0,
        };

        // Minimal edge TCP loop: accept one TLS connection, serve it.
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            // The trailing None is ct-edge's per-connection cap (no cap in this test).
            let _ = serve_tcp_connection(tls, &state_e, &challenge, None).await;
        });

        // Agent: connect over TLS-TCP (trusting the CA root) and register.
        let mut stream = tcp_tls_connect(tcp_addr, ca_root)
            .await
            .expect("agent TLS-TCP connect");
        register_tunnel_stream(&mut stream, &token)
            .await
            .expect("register over TLS-TCP");

        // The edge's 'A' handler parked this TCP agent.
        for _ in 0..100 {
            if state.has_tcp_agent(&token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.has_tcp_agent(&token),
            "agent registered over TLS-TCP and is parked at the edge"
        );
        edge.abort();
    }

    #[tokio::test]
    async fn agent_registers_through_the_443_front_door_via_alpn() {
        // #46 FB-b: the agent's TLS-TCP connect advertises ALPN=ct-edge, so the
        // unified :443 front door (#31 FD2) classifies it as EdgeRelay and routes
        // it to serve_tcp_connection — the firewall-fallback register path. Same as
        // the direct-listener test above, but the edge runs the FRONT DOOR.
        use ct_common::pow::Challenge;
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use ct_edge::serve::serve_front_door;
        use ct_edge::state::EdgeState;
        use quinn::Connection;

        let ca = Ca::new("test-ca").expect("ca");
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .expect("dual edge");
        let fd_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x46; 32]);
        let state = std::sync::Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge {
            nonce: [0u8; 16],
            difficulty: 0,
        };

        // Edge FRONT DOOR: classify by ALPN/SNI and dispatch (no portal wired).
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let proxies: std::collections::HashMap<String, ct_edge::serve::ProxyTarget> =
                std::collections::HashMap::new();
            // The two trailing Nones are ct-edge's per-connection cap and admission permit.
            let _ = serve_front_door(tcp, &state_e, &acceptor, &proxies, None, &challenge, None, None, None, None, None, None, None).await;
        });

        // Agent: TLS-TCP connect (ALPN=ct-edge set in tcp_tls_connect) + register.
        let mut stream = tcp_tls_connect(fd_addr, ca_root)
            .await
            .expect("agent TLS-TCP connect via the front door");
        register_tunnel_stream(&mut stream, &token)
            .await
            .expect("register through the :443 front door");

        for _ in 0..100 {
            if state.has_tcp_agent(&token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.has_tcp_agent(&token),
            "agent registered through the front door (ALPN=ct-edge -> EdgeRelay)"
        );
        edge.abort();
    }

    /// Accept one TCP connection on `listener` and return the raw ClientHello's SNI and
    /// ALPN offer, without completing the handshake — the only place those two values are
    /// observable is the plaintext ClientHello, which is exactly what a DPI middlebox sees.
    async fn observe_client_hello(
        listener: tokio::net::TcpListener,
    ) -> (Option<String>, Vec<Vec<u8>>) {
        let (tcp, _) = listener.accept().await.unwrap();
        let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp)
            .await
            .expect("read ClientHello");
        let hello = start.client_hello();
        let sni = hello.server_name().map(|s| s.to_string());
        let alpn = hello
            .alpn()
            .map(|it| it.map(|p| p.to_vec()).collect())
            .unwrap_or_default();
        (sni, alpn)
    }

    #[tokio::test]
    async fn the_boring_fallback_dial_puts_h2_and_the_invalid_sni_on_the_wire() {
        // #106 boring-alpn (real 2026-08-12 support case): the whole point of this rung is
        // what a middlebox sees in the plaintext ClientHello. The distinctive
        // `ct-edge-channel` ALPN and the obviously-wrong `localhost` SNI are the two
        // fingerprints that got the tester's join dropped, so assert the ACTUAL bytes
        // offered, not just that the wrapper compiles.
        install_crypto_provider();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(observe_client_hello(listener));

        let (cert, _key) = self_signed().unwrap();
        // The handshake cannot complete (the server never answers), which is fine: the
        // ClientHello is already on the wire by then.
        let _ = tcp_tls_connect_channel_boring(addr, cert).await;

        let (sni, alpn) = server.await.unwrap();
        assert_eq!(
            sni.as_deref(),
            Some(CHANNEL_FALLBACK_SNI),
            "the fallback rung presents the reserved .invalid SNI, not {DEFAULT_SNI:?}"
        );
        // #500 K2 (v0.4.13): [h2, http/1.1] -- both ids ordinary web ALPNs, camouflage
        // preserved; a current edge selects http/1.1 as the keepalive signal, an old edge
        // (h2-only list) keeps behaving exactly as before.
        assert_eq!(
            alpn,
            vec![CHANNEL_FALLBACK_ALPN.to_vec(), b"http/1.1".to_vec()],
            "the boring offer is the ordinary [h2, http/1.1] pair"
        );
        assert_eq!(CHANNEL_FALLBACK_SNI, "edge-cdn.invalid", "locked with the edge front door");
        assert_eq!(CHANNEL_FALLBACK_ALPN, b"h2", "locked with the edge front door");
    }

    /// #25 (the v0.4.14 compatibility promise, previously untested): [`ka_negotiated`]
    /// is the half of the phase-marker gate that keeps a legacy edge byte-identical —
    /// complete a REAL TLS handshake with [`tcp_tls_connect_channel`] against a server
    /// that only speaks the legacy channel id and assert the dial is classified non-KA
    /// (so no `[0xFF, phase]` preamble may ever be sent there); a `-ka`-selecting
    /// server is the positive control.
    #[tokio::test]
    async fn ka_negotiated_is_false_on_a_legacy_alpn_edge_and_true_on_a_ka_edge_25() {
        install_crypto_provider();
        async fn handshake_with_server_alpns(
            alpns: Vec<Vec<u8>>,
        ) -> tokio_rustls::client::TlsStream<TcpStream> {
            let (cert, key) = self_signed().unwrap();
            let mut sc = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .unwrap();
            sc.alpn_protocols = alpns;
            let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(sc));
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    // Hold the accepted stream open until the client side is done.
                    let _ = tokio::io::AsyncReadExt::read(&mut tls, &mut [0u8; 1]).await;
                }
            });
            tcp_tls_connect_channel(addr, cert).await.expect("handshake completes")
        }

        let legacy = handshake_with_server_alpns(vec![b"ct-edge-channel".to_vec()]).await;
        assert!(
            !ka_negotiated(&legacy),
            "a legacy-only edge must classify non-KA -- no marker, no NUL keepalive"
        );
        let ka = handshake_with_server_alpns(vec![
            b"ct-edge-channel-ka".to_vec(),
            b"ct-edge-channel".to_vec(),
        ])
        .await;
        assert!(ka_negotiated(&ka), "a -ka-selecting edge classifies KA-generation");
    }

    #[tokio::test]
    async fn the_existing_channel_front_door_dial_keeps_its_alpn_and_sni() {
        // The DPI-resistant rung is ADDITIVE: the established `ct-edge-channel` route must
        // keep offering exactly what today's edge classifies on, or every network where the
        // current fallback already works would silently re-route (the edge now dispatches on
        // SNI as well). This pins that the boring dialer did not leak into the shared path.
        install_crypto_provider();
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(observe_client_hello(listener));

        let (cert, _key) = self_signed().unwrap();
        let _ = tcp_tls_connect_channel(addr, cert).await;

        let (sni, alpn) = server.await.unwrap();
        assert_eq!(sni.as_deref(), Some(DEFAULT_SNI), "unchanged SNI on the established route");
        // #500 K2 (v0.4.13): the -ka id is offered FIRST, the legacy id stays as the
        // fallback every old edge selects -- the route itself is unchanged (both ids
        // classify to the channel broker).
        assert_eq!(
            alpn,
            vec![b"ct-edge-channel-ka".to_vec(), b"ct-edge-channel".to_vec()],
            "the channel offer is [ka, legacy] with the legacy id preserved"
        );
    }

    #[tokio::test]
    async fn register_tunnel_stream_sends_role_and_token_and_reads_ok() {
        // issue #3 / P1.2c-2: the TCP-fallback register primitive writes
        // 'A' | token(32) and accepts the edge's OK over a generic stream.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x42; 32]);

        // Mock edge: read role+token, verify, ack "OK".
        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut hdr = [0u8; 33];
            edge_side.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], b'A', "role byte");
            assert_eq!(&hdr[1..], &t.0, "token echoed");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream(&mut agent_side, &token)
            .await
            .expect("register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_browser_sends_b_frame_token_and_host() {
        // issue #41 FB3: the browser-mode TCP fallback writes a single
        // 'B' | token(32) | host_len(u16 BE) | host frame and accepts the OK.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x37; 32]);
        let host = "help.bunsenbrenner.org";

        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut role = [0u8; 1];
            edge_side.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'B', "browser register role byte");
            let mut tok = [0u8; 32];
            edge_side.read_exact(&mut tok).await.unwrap();
            assert_eq!(&tok, &t.0, "token echoed");
            let mut len = [0u8; 2];
            edge_side.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut host_buf = vec![0u8; n];
            edge_side.read_exact(&mut host_buf).await.unwrap();
            assert_eq!(host_buf, b"help.bunsenbrenner.org", "hostname echoed");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_browser(&mut agent_side, &token, host)
            .await
            .expect("browser-register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_browser_ping_capable_sends_l_and_an_otherwise_identical_frame() {
        // The Browser-Plane counterpart to 'K'. 'K' only ever covered the Noise path,
        // so a CT_AGENT_MODE=browser agent -- which registers with 'B' -- could not
        // get the ping treatment at all, and kept flapping on every release. Its
        // parked fallback connection dies after ~10-15s idle when the path's
        // middlebox ignores ACK-only keepalives (measured live: 5s request spacing
        // -> 4/4 OK, 20s spacing -> 1/4).
        //
        // Pin that 'L' differs from 'B' in the role byte ONLY: same token, same
        // length-prefixed hostname, same 2-byte ack. Anything else would make the
        // two arms diverge on the edge, which is exactly what the shared
        // `admit_tcp_agent_b` there is built to prevent.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x41; 32]);
        let host = "sort.bunsenbrenner.org";

        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut role = [0u8; 1];
            edge_side.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'L', "ping-capable browser role byte");
            let mut tok = [0u8; 32];
            edge_side.read_exact(&mut tok).await.unwrap();
            assert_eq!(&tok, &t.0, "token echoed, exactly as in 'B'");
            let mut len = [0u8; 2];
            edge_side.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut host_buf = vec![0u8; n];
            edge_side.read_exact(&mut host_buf).await.unwrap();
            assert_eq!(host_buf, b"sort.bunsenbrenner.org", "hostname echoed, exactly as in 'B'");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_browser_ping_capable(&mut agent_side, &token, host)
            .await
            .expect("ping-capable browser-register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_browser_framed_capable_sends_f_and_an_otherwise_identical_frame()
    {
        // #528: 'F' is 'L' with a framed relay phase. The REGISTRATION frame must stay
        // byte-identical apart from the role byte -- the edge admits all three browser
        // roles ('B'/'L'/'F') through one shared parser, so any divergence here would
        // fork that parser for no reason. What differs comes strictly after STOP.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x4f; 32]);
        let host = "sort.bunsenbrenner.org";

        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut role = [0u8; 1];
            edge_side.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'F', "framed browser role byte");
            let mut tok = [0u8; 32];
            edge_side.read_exact(&mut tok).await.unwrap();
            assert_eq!(&tok, &t.0, "token echoed, exactly as in 'B'/'L'");
            let mut len = [0u8; 2];
            edge_side.read_exact(&mut len).await.unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut host_buf = vec![0u8; n];
            edge_side.read_exact(&mut host_buf).await.unwrap();
            assert_eq!(host_buf, host.as_bytes(), "hostname echoed, exactly as in 'B'/'L'");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_browser_framed_capable(&mut agent_side, &token, host)
            .await
            .expect("framed browser-register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn the_framed_registration_keeps_the_park_phase_byte_for_byte() {
        // #528's contract in one test: 'F' changes ONLY what follows the STOP byte.
        // The park phase (PING/PONG, then a lone 0xFB) is the shared `'L'` one, so a
        // framed agent must answer pings exactly as before -- and the first byte after
        // STOP is already relay FRAMING, not raw payload.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x4e; 32]);
        let host = "sort.bunsenbrenner.org";

        let edge = tokio::spawn(async move {
            let mut role = [0u8; 1];
            edge_side.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'F');
            let mut tok = [0u8; 32];
            edge_side.read_exact(&mut tok).await.unwrap();
            let mut len = [0u8; 2];
            edge_side.read_exact(&mut len).await.unwrap();
            let mut host_buf = vec![0u8; u16::from_be_bytes(len) as usize];
            edge_side.read_exact(&mut host_buf).await.unwrap();
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();

            let mut ping = [0u8; 9];
            ping[0] = TCP_PING_MAGIC;
            ping[1..].copy_from_slice(&7u64.to_be_bytes());
            edge_side.write_all(&ping).await.unwrap();
            edge_side.flush().await.unwrap();
            let mut pong = [0u8; 9];
            edge_side.read_exact(&mut pong).await.unwrap();
            assert_eq!(pong[0], TCP_PONG_MAGIC, "a framed agent still PONGs while parked");
            assert_eq!(&pong[1..], &7u64.to_be_bytes());

            // STOP and the first relay frame in one write: the agent must consume the
            // single STOP byte and leave the DATA frame's discriminator untouched.
            let mut after = vec![TCP_PING_STOP];
            ct_common::fallback_framing::write_data_frame(&mut after, b"hi").await.unwrap();
            edge_side.write_all(&after).await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_browser_framed_capable(&mut agent_side, &token, host)
            .await
            .expect("register");
        await_ping_phase_end(&mut agent_side).await.expect("ping phase ends at STOP");
        assert_eq!(
            ct_common::fallback_framing::read_frame(&mut agent_side).await.unwrap(),
            ct_common::fallback_framing::Frame::Data(b"hi".to_vec()),
            "the bytes after STOP parse as a relay frame -- no park byte leaked into them"
        );
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn a_ping_capable_browser_registration_answers_pings_then_relays_after_stop() {
        // End-to-end shape of the 'L' path as the agent sees it: register, answer the
        // Edge's PINGs while parked, and treat the first byte AFTER stop as relayed
        // browser data -- not as another ping frame. `await_ping_phase_end` is shared
        // with 'K', so this proves it composes correctly with the browser frame too.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x42; 32]);
        let host = "sort.bunsenbrenner.org";

        let edge = tokio::spawn(async move {
            // Consume the 'L' registration frame.
            let mut role = [0u8; 1];
            edge_side.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'L');
            let mut tok = [0u8; 32];
            edge_side.read_exact(&mut tok).await.unwrap();
            let mut len = [0u8; 2];
            edge_side.read_exact(&mut len).await.unwrap();
            let mut host_buf = vec![0u8; u16::from_be_bytes(len) as usize];
            edge_side.read_exact(&mut host_buf).await.unwrap();
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();

            // Two ping/pong round trips while "parked", each echoed with its counter.
            for counter in [1u64, 2u64] {
                let mut ping = [0u8; 9];
                ping[0] = 0xF9;
                ping[1..].copy_from_slice(&counter.to_be_bytes());
                edge_side.write_all(&ping).await.unwrap();
                edge_side.flush().await.unwrap();
                let mut pong = [0u8; 9];
                edge_side.read_exact(&mut pong).await.unwrap();
                assert_eq!(pong[0], 0xFA, "PONG magic");
                assert_eq!(&pong[1..], &counter.to_be_bytes(), "counter echoed verbatim");
            }

            // STOP, then a real relayed byte in the SAME write -- the sharp case: the
            // agent must consume exactly the 1-byte STOP and leave the payload intact.
            edge_side.write_all(&[0xFB, b'X']).await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_browser_ping_capable(&mut agent_side, &token, host)
            .await
            .expect("register");
        await_ping_phase_end(&mut agent_side).await.expect("ping phase ends at STOP");

        let mut first_relayed = [0u8; 1];
        agent_side.read_exact(&mut first_relayed).await.expect("relayed byte follows STOP");
        assert_eq!(
            first_relayed[0], b'X',
            "the byte after STOP is relayed payload -- no ping byte may leak into it"
        );
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_ping_capable_sends_k_and_the_same_token_frame() {
        // ct-agent#15: the 'K' registration is byte-identical to 'A' except for
        // the role byte -- 'K' | token(32), then the same 2-byte OK ack.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x5a; 32]);

        let t = token.clone();
        let edge = tokio::spawn(async move {
            let mut hdr = [0u8; 33];
            edge_side.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], b'K', "ping-capable role byte");
            assert_eq!(&hdr[1..], &t.0, "token echoed");
            edge_side.write_all(b"OK").await.unwrap();
            edge_side.flush().await.unwrap();
        });

        register_tunnel_stream_ping_capable(&mut agent_side, &token)
            .await
            .expect("ping-capable register over a TLS-TCP-style stream");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn ping_phase_answers_every_ping_with_a_counter_echoing_pong_then_stops() {
        // ct-agent#15 core contract: PING 0xF9|counter(8 BE) -> PONG
        // 0xFA|<same counter>, repeated, until the single-byte STOP 0xFB ends
        // the phase. Counters are deliberately NOT 0,1,2 so a PONG that echoed
        // a loop index instead of the received counter would fail here.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let counters: [u64; 3] = [0, 7, u64::MAX];

        let edge = tokio::spawn(async move {
            for c in counters {
                let mut ping = [0u8; 9];
                ping[0] = TCP_PING_MAGIC;
                ping[1..].copy_from_slice(&c.to_be_bytes());
                edge_side.write_all(&ping).await.unwrap();
                edge_side.flush().await.unwrap();

                let mut pong = [0u8; 9];
                edge_side.read_exact(&mut pong).await.unwrap();
                assert_eq!(pong[0], TCP_PONG_MAGIC, "PONG magic byte");
                assert_eq!(
                    u64::from_be_bytes(pong[1..].try_into().unwrap()),
                    c,
                    "PONG echoes the PING's counter verbatim"
                );
            }
            edge_side.write_all(&[TCP_PING_STOP]).await.unwrap();
            edge_side.flush().await.unwrap();
            edge_side
        });

        await_ping_phase_end(&mut agent_side)
            .await
            .expect("ping phase ends cleanly on STOP");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn ping_phase_consumes_the_stop_byte_and_not_one_byte_more() {
        // The whole point of the single-byte STOP sentinel: the Noise handshake
        // that follows must start on a byte-exact stream boundary. STOP is 1
        // byte while PING is 9, so a reader that blindly pulled 9 bytes per
        // frame would swallow the first 8 handshake bytes. Write STOP
        // immediately followed by relayed payload and prove every payload byte
        // survives untouched.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        const RELAYED: &[u8] = b"\xe9first-noise-handshake-bytes";

        let edge = tokio::spawn(async move {
            let mut ping = [0u8; 9];
            ping[0] = TCP_PING_MAGIC;
            ping[1..].copy_from_slice(&42u64.to_be_bytes());
            edge_side.write_all(&ping).await.unwrap();
            let mut pong = [0u8; 9];
            edge_side.read_exact(&mut pong).await.unwrap();
            // STOP and the relayed bytes in ONE write: nothing about the
            // hand-off may depend on them arriving in separate segments.
            let mut tail = vec![TCP_PING_STOP];
            tail.extend_from_slice(RELAYED);
            edge_side.write_all(&tail).await.unwrap();
            edge_side.flush().await.unwrap();
            edge_side
        });

        await_ping_phase_end(&mut agent_side).await.unwrap();
        let mut relayed = [0u8; RELAYED.len()];
        agent_side.read_exact(&mut relayed).await.unwrap();
        assert_eq!(
            &relayed, RELAYED,
            "the post-STOP stream is handed off completely unmodified"
        );
        let _edge = edge.await.unwrap();
    }

    #[tokio::test]
    async fn ping_phase_rejects_an_unexpected_discriminator_byte() {
        // A conforming Edge only ever writes 0xF9 or 0xFB before the hand-off,
        // so anything else means a desynchronised stream / non-conforming peer.
        // Feeding that to the Noise handshake would fail later and far more
        // confusingly, so it is surfaced here as a connection error.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let edge = tokio::spawn(async move {
            edge_side.write_all(&[0x01]).await.unwrap();
            edge_side.flush().await.unwrap();
            edge_side
        });
        let e = await_ping_phase_end(&mut agent_side)
            .await
            .expect_err("a non-PING/non-STOP byte is a protocol violation");
        assert!(
            e.to_string().contains("0x01"),
            "the offending byte is named in the error: {e}"
        );
        let _edge = edge.await.unwrap();
    }

    #[tokio::test]
    async fn ping_phase_propagates_eof_mid_frame() {
        // The Edge died between the PING discriminator and its counter. The
        // stream is unusable; propagate rather than hand a truncated frame on.
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            edge_side.write_all(&[TCP_PING_MAGIC, 0x00]).await.unwrap();
            edge_side.flush().await.unwrap();
            drop(edge_side);
        });
        assert!(
            await_ping_phase_end(&mut agent_side).await.is_err(),
            "a truncated PING frame is a connection error"
        );
    }

    #[tokio::test]
    async fn ping_capable_registration_round_trips_over_a_real_tcp_socket() {
        // End-to-end over a real socket rather than an in-memory duplex: a fake
        // Edge that implements just the 'K' admission + one real PING/PONG +
        // STOP + a payload echo, driven by the real client functions. Proves
        // the register -> ping-phase -> hand-off sequence works when the frames
        // can be split across real TCP segments.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = RoutingToken([0x6b; 32]);

        let t = token.clone();
        let edge = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut hdr = [0u8; 33];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], b'K');
            assert_eq!(&hdr[1..], &t.0);
            s.write_all(b"OK").await.unwrap();

            // One parked PING round trip, fully awaited (as the real Edge does).
            let mut ping = [0u8; 9];
            ping[0] = TCP_PING_MAGIC;
            ping[1..].copy_from_slice(&9u64.to_be_bytes());
            s.write_all(&ping).await.unwrap();
            let mut pong = [0u8; 9];
            s.read_exact(&mut pong).await.unwrap();
            assert_eq!(pong[0], TCP_PONG_MAGIC);
            assert_eq!(u64::from_be_bytes(pong[1..].try_into().unwrap()), 9);

            // A Client arrived: STOP, then relay (echo one payload).
            s.write_all(&[TCP_PING_STOP]).await.unwrap();
            let mut payload = [0u8; 5];
            s.read_exact(&mut payload).await.unwrap();
            s.write_all(&payload).await.unwrap();
            s.flush().await.unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        register_tunnel_stream_ping_capable(&mut stream, &token)
            .await
            .unwrap();
        await_ping_phase_end(&mut stream).await.unwrap();
        stream.write_all(b"relay").await.unwrap();
        let mut back = [0u8; 5];
        stream.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"relay", "post-STOP payload relays verbatim");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn a_legacy_edge_drops_a_k_registration_without_any_ack() {
        // The compatibility premise, pinned as a test: a pre-'K' Edge does NOT
        // reply "NO" to an unknown role byte -- it treats it as a hard protocol
        // error and closes the connection with no ack at all. So the failure the
        // caller's fallback must trigger on is an EOF reading the ack, not a
        // "NO". (The 'A' path's own "NO" rejection is covered separately by
        // register_tunnel_stream_errors_on_non_ok_ack.)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let edge = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut role = [0u8; 1];
            s.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'K');
            drop(s); // unknown role byte -> hard error, connection dropped
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let r = register_tunnel_stream_ping_capable(&mut stream, &RoutingToken([0x11; 32])).await;
        assert!(
            r.is_err(),
            "a legacy Edge's ack-less drop surfaces as a registration error"
        );
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn register_tunnel_stream_errors_on_non_ok_ack() {
        let (mut agent_side, mut edge_side) = tokio::io::duplex(1024);
        let token = RoutingToken([0x01; 32]);
        let edge = tokio::spawn(async move {
            let mut hdr = [0u8; 33];
            edge_side.read_exact(&mut hdr).await.unwrap();
            edge_side.write_all(b"NO").await.unwrap(); // rejection
            edge_side.flush().await.unwrap();
        });
        let r = register_tunnel_stream(&mut agent_side, &token).await;
        assert!(r.is_err(), "a non-OK ack is a rejection");
        edge.await.unwrap();
    }

    #[tokio::test]
    async fn keepalive_holds_the_connection_across_an_idle_gap() {
        // issue #2: a server with a 1s idle timeout evicts an idle peer, but a
        // client with a 300ms keepalive holds the connection open past 2s of no
        // application traffic — so the edge retains the tunnel registration
        // instead of leaving a later client with "no relay".
        install_crypto_provider();
        let (cert, key) = self_signed().unwrap();
        let mut sc = quinn::ServerConfig::with_single_cert(vec![cert.clone()], key).unwrap();
        let mut st = quinn::TransportConfig::default();
        st.max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_secs(1)).unwrap()));
        // Deliberately NO keepalive on the server side.
        sc.transport_config(std::sync::Arc::new(st));
        let server = Endpoint::server(sc, (Ipv4Addr::LOCALHOST, 0).into()).unwrap();
        let addr = server.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            if let Ok((mut s, mut r)) = conn.accept_bi().await {
                let mut buf = [0u8; 4];
                if r.read_exact(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                    let _ = s.finish();
                }
            }
            conn.closed().await;
        });

        // Client with a keepalive shorter than the server's idle timeout.
        let ep =
            client_endpoint_with(cert, Some(Duration::from_millis(300)), Duration::from_secs(30))
                .unwrap();
        let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();

        // Idle longer than the server's 1s timeout — keepalive must hold it open.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Bounded round-trip: with keepalive it completes fast; without it the
        // connection is dead and this fails within the timeout (never hangs).
        let got = tokio::time::timeout(Duration::from_secs(4), async {
            let (mut s, mut r) = conn.open_bi().await.expect("connection alive after idle gap");
            s.write_all(b"ping").await.unwrap();
            s.finish().unwrap();
            let mut got = [0u8; 4];
            r.read_exact(&mut got).await.unwrap();
            got
        })
        .await
        .expect("round-trip within 4s — keepalive should hold the connection open");
        assert_eq!(&got, b"ping", "keepalive kept the connection past the idle timeout");
        srv.abort();
    }

    #[tokio::test]
    async fn dial_quic_or_blocked_error_reports_udp_blocked() {
        // Nothing listening at this UDP address → the QUIC dial cannot complete;
        // the agent must surface a clear, actionable error (issue #3 / P1.2c-1)
        // instead of a bare TimedOut.
        let (_ep, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("cert");
        let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let start = std::time::Instant::now();
        let r = dial_quic_or_blocked_error(dead_addr, cert, Duration::from_millis(400)).await;
        assert!(r.is_err(), "blocked UDP must error, not hang");
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("UDP") && msg.contains("issue #3"),
            "error must be clear + actionable, got: {msg}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must fail fast, not after a long timeout"
        );
    }

    #[tokio::test]
    async fn agent_dials_edge_over_quic() {
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge server");
        let addr = server.local_addr().expect("edge addr");

        let server_task = tokio::spawn(async move {
            ct_edge::transport::accept_and_echo_one(&server)
                .await
                .expect("edge echo");
        });

        let conn = dial_quic(addr, cert).await.expect("agent dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi");
        send.write_all(b"agent-hello").await.expect("write");
        send.finish().expect("finish");
        let echoed = recv.read_to_end(64 * 1024).await.expect("read echo");
        assert_eq!(&echoed, b"agent-hello", "agent must round-trip via the Edge");

        conn.close(0u32.into(), b"done");
        server_task.await.expect("edge task join");
    }

    // --- P1.4d-ii: credential handshake over QUIC ---

    use crate::identity::AgentIdentity;
    use ct_common::{AgentId, TenantId};
    use ct_control_plane::credential::CredentialIssuer;
    use ct_control_plane::enrollment::Enrollment;
    use ct_control_plane::issuance::mint_for_enrolled;

    fn enrolled_credential(
        expires_at: u64,
    ) -> (ct_common::credential::SignedCredential, [u8; 32]) {
        let issuer = CredentialIssuer::generate();
        let mut enrollment = Enrollment::new();
        let tenant = TenantId("tenant-1".into());
        let token = enrollment.issue_join_token(tenant);
        let identity = AgentIdentity::generate();
        let agent_id = AgentId("agent-1".into());
        enrollment
            .redeem(&token, agent_id.clone(), identity.public_key_bytes())
            .unwrap();
        let signed = mint_for_enrolled(&issuer, &enrollment, &agent_id, expires_at).unwrap();
        (signed, issuer.public_key_bytes())
    }

    #[tokio::test]
    async fn agent_authenticates_to_edge_with_valid_credential() {
        let (signed, issuer_pk) = enrolled_credential(1_000);
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            let conn = ct_edge::auth::accept_and_authenticate(&server, &issuer_pk, 500)
                .await
                .map_err(|e| e.to_string())?;
            conn.closed().await;
            Ok::<(), String>(())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        present_credential(&conn, &signed)
            .await
            .expect("edge accepts valid credential");
        conn.close(0u32.into(), b"done");
        server_task.await.expect("join").expect("edge auth ok");
    }

    #[tokio::test]
    async fn edge_rejects_expired_credential() {
        let (signed, issuer_pk) = enrolled_credential(100); // expires at 100
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let server_task = tokio::spawn(async move {
            // now = 500 >= 100 → expired → Err
            ct_edge::auth::accept_and_authenticate(&server, &issuer_pk, 500)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        let result = present_credential(&conn, &signed).await;
        assert!(result.is_err(), "expired credential must be rejected");
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn agent_registers_tunnel_with_edge() {
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let token = RoutingToken([9u8; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            conn.closed().await;
            Ok::<(), String>(())
        });

        let conn = dial_quic(addr, cert).await.expect("dial");
        register_tunnel(&conn, &token)
            .await
            .expect("agent registers tunnel");
        assert!(state.is_known(&token), "edge now routes the agent's token");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn load_cert_reads_written_der() {
        let (_endpoint, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("cert");
        let path = std::env::temp_dir().join(format!("ct-agent-cert-{}.der", std::process::id()));
        std::fs::write(&path, cert.as_ref()).unwrap();
        let loaded = load_cert(&path).expect("load");
        assert_eq!(loaded, cert, "agent loads the edge cert from the shared file");
        let _ = std::fs::remove_file(&path);
    }

    // #20 TC3: a mock edge that reads one bi-stream request and replies with a
    // fixed ack — lets us drive the reject branches the real edge never takes.
    async fn mock_edge_replying(
        ack: &'static [u8],
    ) -> (SocketAddr, CertificateDer<'static>, tokio::task::JoinHandle<()>) {
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let h = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let _ = recv.read_to_end(8192).await.unwrap();
            send.write_all(ack).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });
        (addr, cert, h)
    }

    #[tokio::test]
    async fn register_tunnel_surfaces_an_edge_rejection() {
        let (addr, cert, edge) = mock_edge_replying(b"NO").await;
        let conn = dial_quic(addr, cert).await.expect("dial");
        let err = register_tunnel(&conn, &RoutingToken([3u8; 32]))
            .await
            .expect_err("non-OK ack must error")
            .to_string();
        assert!(err.contains("rejected tunnel registration"), "{err}");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;
    }

    #[tokio::test]
    async fn advertise_direct_listener_roundtrips_and_surfaces_rejection() {
        let (_ep, dcert) = build_direct_listener().expect("direct listener");
        let dummy: SocketAddr = "10.5.0.4:40001".parse().unwrap();
        let token = RoutingToken([4u8; 32]);

        for (ack, expect_ok) in [(&b"OK"[..], true), (&b"NO"[..], false)] {
            let (addr, cert, edge) = mock_edge_replying(ack).await;
            let conn = dial_quic(addr, cert).await.expect("dial");
            let res = advertise_direct_listener(&conn, &token, dummy, &dcert).await;
            assert_eq!(res.is_ok(), expect_ok, "ack={ack:?}");
            if !expect_ok {
                assert!(res
                    .expect_err("rejected")
                    .to_string()
                    .contains("advertisement rejected"));
            }
            conn.close(0u32.into(), b"done");
            let _ = edge.await;
        }
    }

    // #23 BP3b: bind_hostname writes 'H' | token | len | host and surfaces the ack.
    #[tokio::test]
    async fn bind_hostname_sends_h_and_surfaces_the_ack() {
        let token = RoutingToken([7u8; 32]);

        let (addr, cert, edge) = mock_edge_replying(b"OK").await;
        let conn = dial_quic(addr, cert).await.expect("dial");
        bind_hostname(&conn, &token, "shop.example.test").await.expect("bind ok");
        // An empty hostname is rejected locally, before any network use.
        assert!(bind_hostname(&conn, &token, "").await.is_err(), "empty hostname rejected");
        conn.close(0u32.into(), b"done");
        let _ = edge.await;

        let (addr2, cert2, edge2) = mock_edge_replying(b"NO").await;
        let conn2 = dial_quic(addr2, cert2).await.expect("dial");
        let err = bind_hostname(&conn2, &token, "x.test")
            .await
            .expect_err("non-OK ack must error");
        assert!(err.to_string().contains("rejected hostname"), "{err}");
        conn2.close(0u32.into(), b"done");
        let _ = edge2.await;
    }
}
