//! Agent origin-serving (M5.2b).
//!
//! When the Edge relays a Client stream to this Agent, the Agent dials the local
//! Origin (TCP) and pipes the QUIC stream to it. The Client↔Origin payload is
//! Noise-encrypted end to end (ADR-0013); the Agent forwards opaque bytes to the
//! Origin, which terminates the Noise session (P3). The Agent never inspects
//! them beyond forwarding.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream};

use crate::reconnect::Backoff;
use rustls::pki_types::CertificateDer;
use tokio::io::{copy_bidirectional, join, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::{AgentConfig, OriginProto};
use crate::transport::{
    await_ping_phase_end, bind_hostname, dial_quic, dial_quic_or_blocked_error, register_tunnel,
    register_tunnel_stream, register_tunnel_stream_browser,
    register_tunnel_stream_browser_framed_capable, register_tunnel_stream_browser_ping_capable,
    register_tunnel_stream_ping_capable,
    tcp_tls_connect,
};
// #528: the relay-phase frame codec. Imported as a module, not by item, because
// this file already has its own `read_frame` (the 2-byte Noise framing).
use ct_common::fallback_framing;
use ct_common::metrics::{Metered, TunnelMetrics};
use ct_common::noise::{frame, noise_pump, origin_handshake, origin_handshake_any};
use ct_common::RoutingToken;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Read one length-prefixed frame (2-byte big-endian length + body).
async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<u8>, BoxError> {
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    let mut body = vec![0u8; n];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

/// Serve one relayed QUIC stream: dial the local `origin` (TCP) and relay bytes
/// bidirectionally between the QUIC stream and the Origin connection.
pub async fn serve_stream_to_origin(
    quic_send: SendStream,
    quic_recv: RecvStream,
    origin: SocketAddr,
) -> Result<(), BoxError> {
    serve_duplex_to_origin(join(quic_recv, quic_send), origin).await
}

/// Raw-forward any relayed duplex byte stream to the Origin verbatim (issue #41
/// FB3): the transport-agnostic core of [`serve_stream_to_origin`]. The QUIC
/// path joins its two half-streams; the TLS-TCP fallback hands its whole stream
/// straight in. Either way the browser's TLS terminates AT the Origin — the
/// Edge only ever relays opaque bytes.
///
/// Dials the Origin **lazily**, only once the Client has actually sent its
/// first bytes (#229 follow-up), rather than eagerly the moment this function
/// is entered. The TCP-fallback path in particular can sit parked for an
/// arbitrary amount of time — however long until the Edge delivers a real
/// Client — waiting with an Origin connection already open the whole time.
/// An eagerly-opened connection can idle past the Origin's own read/keep-alive
/// timeout before a Client ever arrives, so the very first real request lands
/// on an already-dead connection and never completes, even though the
/// Client↔Edge TLS layer works perfectly every time. Since this relay only
/// ever carries request/response protocols (HTTP, or the Noise handshake in
/// [`serve_noise_bridge`]), the Client always speaks first, so waiting for
/// its first chunk before dialing costs nothing.
pub async fn serve_duplex_to_origin<T>(mut client: T, origin: SocketAddr) -> Result<(), BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0u8; 4096];
    let n = client.read(&mut first).await?;
    if n == 0 {
        return Ok(()); // Client closed before ever sending anything -- nothing to relay.
    }
    let mut tcp = TcpStream::connect(origin).await?;
    tcp.write_all(&first[..n]).await?;
    copy_bidirectional(&mut client, &mut tcp).await?;
    Ok(())
}

/// How long this side may stay silent on the edge↔agent hop before it injects a
/// [`fallback_framing::FRAME_KEEPALIVE`]. Matches the park phase's PING cadence
/// (`park_and_ping`, 10s) for the same measured reason: on the deployment where
/// this was found a silent fallback connection dies after ~10-15s (5s request
/// spacing → 4/4 OK, 20s spacing → 1/4), so the keepalive has to be comfortably
/// inside that window, and the keepalive is one byte on an already-open TLS
/// connection — the cost of being early is nil.
const FRAMED_KEEPALIVE_IDLE: Duration = Duration::from_secs(10);

/// Chunk size for Origin→Edge [`fallback_framing::FRAME_DATA`] frames. Well under
/// [`fallback_framing::MAX_FRAME_PAYLOAD`] (256 KiB) so a chunk can never be
/// rejected by the far side's cap, and around a max TLS record so a typical
/// response body needs no artificial re-chunking.
const FRAMED_CHUNK: usize = 16 * 1024;

/// Forward a relayed **framed** duplex stream to the Origin (CADS-Tunnel#528) —
/// the `'F'`-registration counterpart to [`serve_duplex_to_origin`].
///
/// Only the edge↔agent hop is framed; the Origin side stays raw, so this
/// unframes on the way in (`FRAME_DATA` → Origin, `FRAME_KEEPALIVE` → discard)
/// and frames on the way out (Origin bytes → `FRAME_DATA`), injecting a
/// `FRAME_KEEPALIVE` whenever *this* side has been silent for
/// [`FRAMED_KEEPALIVE_IDLE`]. That keepalive is the entire point: it is the one
/// thing the raw pump cannot do, because in a raw pump every byte on the wire
/// belongs to the browser↔Origin conversation and there is no way to say
/// "still here" during a silent in-flight request.
///
/// Dials the Origin lazily on the first non-empty `FRAME_DATA`, for exactly the
/// reason spelled out on [`serve_duplex_to_origin`].
///
/// Structure note — why two one-way tasks rather than one `select!` loop over
/// both directions: [`fallback_framing::read_frame`] performs several
/// `read_exact` calls per frame and is therefore **not cancel-safe**; dropping it
/// mid-frame in a `select!` branch would silently desynchronise the relay stream.
/// So the reader half owns the edge read side and is never raced against
/// anything, while the keepalive timer is raced only against the Origin read
/// (`AsyncReadExt::read`, which is cancel-safe) on the writer half.
pub async fn serve_framed_duplex_to_origin<T>(edge: T, origin: SocketAddr) -> Result<(), BoxError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (mut edge_r, mut edge_w) = split(edge);
    // The Origin is dialed by the edge→origin half (it sees the first DATA); its
    // read half is handed to the origin→edge half over this oneshot.
    let (origin_r_tx, mut origin_r_rx) = tokio::sync::oneshot::channel();

    // Edge → Origin: unframe and forward.
    let up = async move {
        let mut origin_w: Option<tokio::net::tcp::OwnedWriteHalf> = None;
        let mut origin_r_tx = Some(origin_r_tx);
        loop {
            let frame = match fallback_framing::read_frame(&mut edge_r).await {
                Ok(f) => f,
                // EOF at (or inside) a frame boundary: the Edge closed this
                // single-use relay. That is the ordinary end of a browser
                // connection, not a failure — the pool worker re-registers.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(BoxError::from(e)),
            };
            let data = match frame {
                fallback_framing::Frame::Keepalive => continue,
                fallback_framing::Frame::Data(d) if d.is_empty() => continue,
                fallback_framing::Frame::Data(d) => d,
            };
            let w = match origin_w.as_mut() {
                Some(w) => w,
                None => {
                    let (r, w) = TcpStream::connect(origin).await?.into_split();
                    // The receiver is only dropped if the writer half already
                    // returned, in which case this relay is over anyway.
                    let _ = origin_r_tx.take().expect("dial happens once").send(r);
                    origin_w.insert(w)
                }
            };
            w.write_all(&data).await?;
        }
        // Half-close the Origin so it sees the request end and can answer/finish
        // — and, crucially, so the origin→edge half below is not left waiting on
        // a response that will never come. Dropping `origin_w` implicitly would
        // not be enough: this future stays alive (pinned in the `select!` below)
        // while the other half is awaited.
        if let Some(mut w) = origin_w.take() {
            let _ = w.shutdown().await;
        }
        Ok::<(), BoxError>(())
    };

    // Origin → Edge: frame, plus keepalive injection during our own silence.
    let down = async move {
        // Keepalive while waiting for the Client's first bytes to arrive and the
        // Origin to be dialed, too: the Edge writes STOP as soon as it splices a
        // Client in, so this gap is normally sub-RTT, but a slow Client must not
        // be able to starve the keepalive.
        let mut origin_r = loop {
            tokio::select! {
                r = &mut origin_r_rx => match r {
                    Ok(r) => break r,
                    // The edge→origin half ended before any Client byte arrived:
                    // nothing was ever relayed, so there is nothing to answer.
                    Err(_) => return Ok(()),
                },
                _ = tokio::time::sleep(FRAMED_KEEPALIVE_IDLE) => {
                    fallback_framing::write_keepalive_frame(&mut edge_w).await?;
                    edge_w.flush().await?;
                }
            }
        };
        let mut buf = vec![0u8; FRAMED_CHUNK];
        loop {
            // Each iteration ends in a write, and the sleep is created fresh
            // here, so it measures exactly "silence since our last frame".
            tokio::select! {
                n = origin_r.read(&mut buf) => {
                    let n = n?;
                    if n == 0 {
                        // Origin closed: half-close the hop so the Edge can end
                        // the browser connection. Under the raw pump this is the
                        // FIN propagating; here it is ours to send.
                        edge_w.shutdown().await?;
                        return Ok(());
                    }
                    fallback_framing::write_data_frame(&mut edge_w, &buf[..n]).await?;
                    edge_w.flush().await?;
                }
                _ = tokio::time::sleep(FRAMED_KEEPALIVE_IDLE) => {
                    fallback_framing::write_keepalive_frame(&mut edge_w).await?;
                    edge_w.flush().await?;
                }
            }
        }
    };

    // Whichever direction ends first, drain the other: an ended edge→origin half
    // has half-closed the Origin (so the response still arrives), and an ended
    // origin→edge half has half-closed the hop (so the Edge closes and the read
    // half sees EOF). An *error* on either side ends the relay immediately —
    // dropping the other future is safe because the stream is unusable anyway.
    tokio::pin!(up, down);
    tokio::select! {
        r = &mut up => { r?; down.await }
        r = &mut down => { r?; up.await }
    }
}

/// Serve one relayed stream as the Origin's Noise responder (M8.3): terminate
/// the `Noise_IK` handshake with the Origin private key, then bridge one
/// request/response to the local `origin` — decrypt the Client's frame, forward
/// the plaintext to the Origin (TCP), read its reply, and return it encrypted.
///
/// Generic over the byte transport so it drives a QUIC stream in the live path
/// (M8.4) and an in-memory duplex in tests. The Edge only ever relays the
/// encrypted frames.
pub async fn serve_noise_bridge<S, R>(
    send: &mut S,
    recv: &mut R,
    origin: SocketAddr,
    origin_private: &[u8; 32],
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hs = origin_handshake(origin_private)?;
    let mut buf = vec![0u8; 65535];
    let mut tmp = vec![0u8; 65535];

    // <- handshake message 1, -> handshake message 2
    let m1 = read_frame(recv).await?;
    hs.read_message(&m1, &mut tmp)?;
    let n = hs.write_message(&[], &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;

    let mut transport = hs.into_transport_mode()?;

    // Decrypt the Client's request and forward the plaintext to the Origin.
    let req_ct = read_frame(recv).await?;
    let n = transport.read_message(&req_ct, &mut tmp)?;
    let request = tmp[..n].to_vec();

    let mut tcp = TcpStream::connect(origin).await?;
    tcp.write_all(&request).await?;
    tcp.shutdown().await?;
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;

    // Encrypt the Origin's response back to the Client.
    let n = transport.write_message(&response, &mut buf)?;
    send.write_all(&frame(&buf[..n])).await?;
    send.flush().await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder with a **full-duplex
/// streaming** bridge (M9.2): terminate the `Noise_IK` handshake, then
/// [`noise_pump`] between the decrypted Client stream and the local Origin TCP
/// socket — arbitrary bidirectional, multi-message traffic, not a single
/// request/response. Generic over the byte transport (QUIC live, duplex in tests).
pub async fn serve_noise_stream<S, R>(
    mut send: S,
    mut recv: R,
    origin: SocketAddr,
    origin_keys: &[[u8; 32]],
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 65535];

    // <- handshake message 1, -> handshake message 2. Time it and count the
    // outcome for observability (M14.1b). During a key rotation (#12) the Agent
    // may hold several Origin keys; `origin_handshake_any` selects whichever one
    // the Client pinned. A completed handshake is an opened tunnel; a failed one
    // increments the failure counter.
    let started = Instant::now();
    let m1 = match read_frame(&mut recv).await {
        Ok(m) => m,
        Err(e) => {
            metrics.tunnels_failed.inc();
            return Err(e);
        }
    };
    let mut hs = match origin_handshake_any(origin_keys, &m1) {
        Some(hs) => hs,
        None => {
            metrics.tunnels_failed.inc();
            return Err("no origin identity matched the client handshake".into());
        }
    };
    let write_msg2 = async {
        let n = hs.write_message(&[], &mut buf)?;
        send.write_all(&frame(&buf[..n])).await?;
        send.flush().await?;
        Ok::<(), BoxError>(())
    }
    .await;
    if let Err(e) = write_msg2 {
        metrics.tunnels_failed.inc();
        return Err(e);
    }
    let transport = match hs.into_transport_mode() {
        Ok(t) => {
            metrics.observe_handshake(started.elapsed());
            metrics.tunnels_opened.inc();
            t
        }
        Err(e) => {
            metrics.tunnels_failed.inc();
            return Err(e.into());
        }
    };

    // Bridge the Noise session <-> the Origin TCP socket, both ways, streaming.
    // Meter the Origin socket: bytes read from it flow back to the Client
    // (bytes_to_client); bytes written to it came from the Client
    // (bytes_to_origin).
    let tcp = TcpStream::connect(origin).await?;
    let tcp = Metered::new(
        tcp,
        Arc::clone(&metrics.bytes_to_client),
        Arc::clone(&metrics.bytes_to_origin),
    );
    let cipher = join(recv, send);
    noise_pump(transport, cipher, tcp).await?;
    Ok(())
}

/// Serve one relayed stream as the Origin's Noise responder bridging to a **UDP**
/// Origin (M10.1). One Noise frame carries exactly one UDP datagram, so the
/// tunnel's framing preserves datagram boundaries: each decrypted frame is `send`
/// as a datagram to the Origin, and each datagram `recv`d from the Origin is
/// encrypted back as one frame. Runs until the Client closes the tunnel.
pub async fn serve_noise_udp<S, R>(
    mut send: S,
    mut recv: R,
    origin: SocketAddr,
    origin_keys: &[[u8; 32]],
) -> Result<(), BoxError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut hbuf = vec![0u8; 65535];
    let m1 = read_frame(&mut recv).await?;
    let mut hs = origin_handshake_any(origin_keys, &m1)
        .ok_or("no origin identity matched the client handshake")?;
    let n = hs.write_message(&[], &mut hbuf)?;
    send.write_all(&frame(&hbuf[..n])).await?;
    send.flush().await?;
    let transport = hs.into_transport_mode()?;

    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    udp.connect(origin).await?;

    let ts = Mutex::new(transport);
    // `e` is inferred as snow::Error from the map_err call sites (naming it would
    // need snow as a direct dep, which ct-agent gets only transitively).
    let noise_err = |e| io::Error::other(format!("{e}"));

    // Client -> decrypt frame -> UDP datagram to Origin.
    let to_origin = async {
        let mut tmp = vec![0u8; 65535];
        loop {
            let fr = match read_frame(&mut recv).await {
                Ok(f) => f,
                Err(_) => break, // tunnel closed
            };
            let len = ts.lock().unwrap().read_message(&fr, &mut tmp).map_err(noise_err)?;
            udp.send(&tmp[..len]).await?;
        }
        Ok::<(), io::Error>(())
    };

    // Origin datagram -> encrypt -> frame to Client.
    let to_client = async {
        let mut dgram = vec![0u8; 65535];
        let mut ct = vec![0u8; 65535 + 256];
        loop {
            let n = udp.recv(&mut dgram).await?;
            let len = ts.lock().unwrap().write_message(&dgram[..n], &mut ct).map_err(noise_err)?;
            send.write_all(&frame(&ct[..len])).await?;
            send.flush().await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };

    // The Client closing the tunnel ends `to_origin`; UDP has no EOF, so
    // `to_client` only ends on error — whichever finishes first tears down.
    tokio::select! {
        r = to_origin => r?,
        r = to_client => r?,
    }
    Ok(())
}

/// Serve the Agent's **direct-path** listener (M11.4b-iii): accept direct Client
/// connections (which bypass the Edge relay) and serve each one as the Origin's
/// Noise responder — streaming for TCP, datagram-preserving for UDP. Loops until
/// the listener closes.
pub async fn serve_direct(
    listener: Endpoint,
    origin: SocketAddr,
    origin_keys: Arc<Vec<[u8; 32]>>,
    proto: OriginProto,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    while let Some(incoming) = listener.accept().await {
        let metrics = Arc::clone(&metrics);
        let keys = Arc::clone(&origin_keys);
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                if let Ok((send, recv)) = conn.accept_bi().await {
                    let _ = match proto {
                        OriginProto::Tcp => {
                            serve_noise_stream(send, recv, origin, &keys, metrics).await
                        }
                        OriginProto::Udp => serve_noise_udp(send, recv, origin, &keys).await,
                    };
                }
                conn.closed().await;
            }
        });
    }
    Ok(())
}

/// Run the Agent: dial the Edge, register the tunnel for `token`, then serve each
/// relayed stream as the Origin's Noise responder, bridging plaintext to the
/// local Origin (M8.4c-i). `origin_private` is the Agent-held Origin static key.
/// Loops until the connection closes.
pub async fn run_agent(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    // Shared tunnel metrics for this Agent (M14.1b), plus optional one-time
    // endpoints — set up once, outside the reconnect loop.
    let metrics = Arc::new(TunnelMetrics::new());
    if let Some(addr) = config.metrics_listen {
        let mmetrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            let _ = crate::observe::serve_metrics(addr, mmetrics).await;
        });
    }
    if let Some(ip) = config.direct_advertise_ip {
        if let Ok((listener, cert)) = crate::transport::build_direct_listener() {
            if let Ok(bound) = listener.local_addr() {
                let advertised = SocketAddr::new(ip, bound.port());
                if let Ok(adv) = dial_quic(config.edge, edge_cert.clone()).await {
                    let _ = crate::transport::advertise_direct_listener(&adv, &token, advertised, &cert)
                        .await;
                    adv.close(0u32.into(), b"advertised");
                }
                let (origin, proto) = (config.origin, config.origin_proto);
                let dmetrics = Arc::clone(&metrics);
                let dkeys = Arc::clone(&origin_keys);
                tokio::spawn(async move {
                    let _ = serve_direct(listener, origin, dkeys, proto, dmetrics).await;
                });
            }
        }
    }

    // Reconnect loop (issue #5 / P1.2b): (re)dial + (re)register + serve until the
    // connection drops, then back off and retry, so a transient edge/network
    // failure doesn't kill the tunnel. ANY dial failure means UDP is (currently)
    // blocked → serve over the TLS-TCP fallback until UDP/QUIC answers again
    // (issue #3, regression re-fixed as #16).
    //
    // #16: this used to fall back only on the *first* dial (`if first { ... }`) —
    // an agent that had ever registered over QUIC retried QUIC-only forever, so a
    // mid-life UDP outage ("UDP flapping") took the whole demo down for exactly as
    // long as the flap lasted, with the working, tested TCP fallback sitting
    // unused. Live-diagnosed 2026-08-13 across four production demos flapping in
    // unison. Now every dial failure enters the fallback, and the fallback itself
    // returns once a QUIC probe succeeds (see
    // [`run_agent_tcp_fallback_until_quic_recovers`]) — so the agent serves over
    // TCP through the flap and upgrades back to QUIC afterwards, instead of
    // choosing between "down until UDP heals" and "TCP forever".
    // #16 escape hatch: CT_AGENT_REGISTER_TCP_ONLY pins the agent to the TLS-TCP
    // fallback permanently — no QUIC dial, no probing, no upgrade. For operators
    // whose UDP path is known-flaky and who prefer the stable transport outright.
    if config.register_tcp_only {
        eprintln!(
            "ct-agent: CT_AGENT_REGISTER_TCP_ONLY set — registering over TLS-TCP exclusively (no QUIC)"
        );
        return run_agent_tcp_fallback(config, edge_cert, token, origin_keys).await;
    }
    let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX, reconnect_max_attempts());
    loop {
        let conn = match dial_quic_or_blocked_error(config.edge, edge_cert.clone(), Duration::from_secs(5))
            .await
        {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!(
                    "ct-agent: edge dial failed ({e}); serving over the TLS-TCP fallback until UDP/QUIC recovers (#16)"
                );
                run_agent_tcp_fallback_until_quic_recovers(
                    config,
                    edge_cert.clone(),
                    token.clone(),
                    Arc::clone(&origin_keys),
                )
                .await?;
                // A QUIC probe answered — start over with a fresh budget and dial it
                // for real.
                backoff.reset();
                continue;
            }
        };
        if let Err(e) = register_tunnel(&conn, &token).await {
            eprintln!("ct-agent: registration failed ({e}); will reconnect");
            match backoff.next_delay_jittered(rand::random::<f64>()) {
                Some(d) => {
                    tokio::time::sleep(d).await;
                    continue;
                }
                None => return Err("ct-agent: gave up re-registering with the edge".into()),
            }
        }
        backoff.reset();
        // Browser Plane (#23 BP3b): bind the public hostname to this token so an
        // SNI-routed browser reaches this tunnel. Re-bound on every reconnect.
        // Retried with backoff (#502): a fresh onboard's authorize-host call can
        // reach the edge a moment after this bind, and a one-shot bind then left
        // the agent serving without its hostname until a process restart.
        if config.browser_forward {
            if let Some(host) = &config.hostname {
                let conn = conn.clone();
                let token = token.clone();
                let host = host.clone();
                tokio::spawn(async move {
                    let backoff = Backoff::new(
                        HOST_BIND_RETRY_BASE,
                        HOST_BIND_RETRY_MAX,
                        HOST_BIND_RETRY_ATTEMPTS,
                    );
                    bind_hostname_with_retry(&conn, &token, &host, backoff).await;
                });
            }
        }
        eprintln!("ct-agent: registered with edge {} (serving)", config.edge);
        serve_quic_connection(
            &conn,
            config.origin,
            config.origin_proto,
            config.browser_forward,
            &origin_keys,
            Arc::clone(&metrics),
        )
        .await;
        eprintln!("ct-agent: edge connection dropped; reconnecting");
        match backoff.next_delay_jittered(rand::random::<f64>()) {
            Some(d) => tokio::time::sleep(d).await,
            None => return Err("ct-agent: gave up reconnecting after the connection dropped".into()),
        }
    }
}

/// Hostname-bind retry parameters (#502). The window they span (~75s) is sized
/// for the race they heal: an agent that onboards at boot binds its hostname
/// within milliseconds of the control plane's authorize-host call reaching the
/// edge, so a lost race resolves in seconds — not minutes.
const HOST_BIND_RETRY_BASE: Duration = Duration::from_secs(1);
const HOST_BIND_RETRY_MAX: Duration = Duration::from_secs(15);
const HOST_BIND_RETRY_ATTEMPTS: u32 = 8;

/// Bind the public hostname, retrying a rejection with backoff (#502).
///
/// The edge answers `NO` both for a *permanent* refusal (hostname bound to a
/// different token, no authorization) and for the *transient* case where this
/// token's authorize-host call from the control plane hasn't landed yet — a
/// freshly onboarded agent loses that race routinely. A one-shot bind turned
/// the transient case into "serving without a hostname until process restart"
/// (help.bunsenbrenner.org, field incident 2026-08-14). Retrying is safe for
/// the permanent case too: the edge's answer is idempotent and the budget is
/// bounded. Gives up early once the connection is gone — the reconnect loop
/// re-binds on the next connection anyway.
async fn bind_hostname_with_retry(
    conn: &Connection,
    token: &RoutingToken,
    host: &str,
    mut backoff: Backoff,
) {
    let mut retries = 0u32;
    loop {
        match bind_hostname(conn, token, host).await {
            Ok(()) => {
                if retries > 0 {
                    eprintln!(
                        "ct-agent: hostname binding for '{host}' established after {retries} retry(s) (#502)"
                    );
                }
                return;
            }
            Err(e) => {
                if conn.close_reason().is_some() {
                    return;
                }
                match backoff.next_delay_jittered(rand::random::<f64>()) {
                    Some(d) => {
                        eprintln!(
                            "ct-agent: hostname binding for '{host}' failed ({e}); retrying in {}ms (#502)",
                            d.as_millis()
                        );
                        tokio::time::sleep(d).await;
                        retries += 1;
                    }
                    None => {
                        eprintln!(
                            "ct-agent: hostname binding for '{host}' failed ({e}); giving up until the next reconnect"
                        );
                        return;
                    }
                }
            }
        }
    }
}

/// Reconnect backoff parameters (issue #5 / P1.2b).
const RECONNECT_BASE: Duration = Duration::from_millis(500);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Reconnect attempts before giving up, when `CT_AGENT_RECONNECT_MAX_ATTEMPTS` is
/// unset. **Unbounded by default** — an onboarded agent IS the tunnel, so exiting
/// takes the service down permanently rather than failing over to anything.
///
/// This was `10` until a real production outage (2026-08-13) traced to exactly
/// that: `sort.bunsenbrenner.org`'s agent burned its 10-attempt budget
/// (0.5s+1+2+4+8+16+30+30+30+30 ≈ **2 minutes** of backoff) during an edge
/// redeploy that took longer than two minutes, exited, and stayed dead for hours
/// — the edge answered `no agent tunnel for token` for every request until a human
/// restarted it by hand. It then died again the same way. A bounded default turns
/// any edge restart, deploy, or network partition longer than ~2 minutes into a
/// permanent, human-only-recoverable outage.
///
/// Exiting also can't self-heal even with a supervisor: the process holds a
/// single-use join token, so a bare `restart:` policy just crash-loops redeeming a
/// spent token (#36). Retrying forever keeps the onboarded credential and simply
/// waits the edge out — the behavior every long-lived deployment actually wants.
///
/// A finite budget remains available via the env var for short-lived or scripted
/// runs where failing fast genuinely is better than hanging.
const RECONNECT_MAX_ATTEMPTS: u32 = u32::MAX;

/// How many reconnect attempts before the agent gives up and exits, from the
/// environment. See [`RECONNECT_MAX_ATTEMPTS`] for why the default is unbounded.
fn reconnect_max_attempts() -> u32 {
    parse_reconnect_max_attempts(std::env::var("CT_AGENT_RECONNECT_MAX_ATTEMPTS").ok())
}

/// Pure core of [`reconnect_max_attempts`]: `Some("0")` → unbounded (`u32::MAX`),
/// a valid count → itself, anything else (unset/garbage) → the default.
fn parse_reconnect_max_attempts(raw: Option<String>) -> u32 {
    match raw.and_then(|s| s.trim().parse::<u32>().ok()) {
        Some(0) => u32::MAX,
        Some(n) => n,
        None => RECONNECT_MAX_ATTEMPTS,
    }
}

/// Serve Client tunnels over a live QUIC `conn` until it drops, then return so
/// the caller can reconnect. Each accepted bi-stream is one Client's Noise tunnel.
async fn serve_quic_connection(
    conn: &Connection,
    origin: SocketAddr,
    proto: OriginProto,
    browser_forward: bool,
    origin_keys: &[[u8; 32]],
    metrics: Arc<TunnelMetrics>,
) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(x) => x,
            Err(_) => return,
        };
        // Browser Plane (#23): forward the relayed stream to the Origin verbatim
        // (raw TLS passthrough); the browser's TLS terminates at the Origin.
        if browser_forward {
            tokio::spawn(async move {
                let _ = serve_stream_to_origin(send, recv, origin).await;
            });
            continue;
        }
        let keys = origin_keys.to_vec();
        let m = Arc::clone(&metrics);
        tokio::spawn(async move {
            let _ = match proto {
                OriginProto::Tcp => serve_noise_stream(send, recv, origin, &keys, m).await,
                OriginProto::Udp => serve_noise_udp(send, recv, origin, &keys).await,
            };
        });
    }
}

/// Serve the Agent over the **TLS-TCP fallback** when UDP/QUIC to the Edge is
/// blocked (issue #3 / P1.2c-4): run [`config.tcp_fallback_pool_size`]
/// independent registration workers concurrently (#229) rather than just
/// one. Each individual registration is still single-use/single-Client (no
/// QUIC-style multiplexing within one TCP connection) -- pooling several of
/// them is what lets more than one simultaneous Client be served at once, the
/// way a real browser's several-parallel-connections-per-origin page load
/// needs. A pool of 1 (`CT_AGENT_TCP_FALLBACK_POOL_SIZE=1`) reproduces the
/// old, implicit one-at-a-time behavior exactly.
///
/// [`config.tcp_fallback_pool_size`]: AgentConfig::tcp_fallback_pool_size
///
/// #16: on a DIAL failure `run_agent` now uses
/// [`run_agent_tcp_fallback_until_quic_recovers`] (serve through the flap, then
/// upgrade back to QUIC); this PERMANENT variant remains the entry point for
/// `CT_AGENT_REGISTER_TCP_ONLY` (an operator pinning a known-flaky-UDP
/// deployment to TCP outright) and for the e2e tests of the pool/worker
/// mechanics (they need "fallback forever", deterministically, without a 30s
/// probe racing the assertion).
async fn run_agent_tcp_fallback(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    let n = config.tcp_fallback_pool_size.max(1);
    let mut workers = Vec::with_capacity(n);
    for _ in 0..n {
        let config = config.clone();
        let edge_cert = edge_cert.clone();
        let token = token.clone();
        let origin_keys = Arc::clone(&origin_keys);
        workers.push(tokio::spawn(async move {
            run_agent_tcp_fallback_worker(&config, edge_cert, token, origin_keys).await
        }));
    }
    // If any one worker gives up (its own backoff exhausted), that's fatal to
    // the whole fallback mode, matching the pre-pool single-worker behavior --
    // a customer running with a pool > 1 should learn about a systemic outage
    // as loudly as they would have with a pool of 1.
    for w in workers {
        w.await??;
    }
    Ok(())
}

/// How often the TCP-fallback mode probes whether UDP/QUIC to the edge has
/// recovered (#16). One cheap dial per interval: rare enough to cost nothing,
/// frequent enough that a healed network upgrades the agent back to QUIC (and
/// its multiplexed, pooled-connection-free serving) within a minute.
const QUIC_REPROBE_INTERVAL: Duration = Duration::from_secs(30);

/// [`run_agent_tcp_fallback`], but temporary (#16): serve over the TLS-TCP
/// fallback pool while probing UDP/QUIC every [`QUIC_REPROBE_INTERVAL`], and
/// return `Ok(())` as soon as a probe dial succeeds — the caller
/// ([`run_agent`]'s reconnect loop) then re-dials QUIC for real. The pool
/// workers are spawned on a [`tokio::task::JoinSet`], whose drop ABORTS them —
/// so returning here (probe success) tears the whole pool down rather than
/// leaking N workers that would keep re-registering over TCP alongside the
/// revived QUIC registration. A worker that gives up (its bounded
/// `CT_AGENT_RECONNECT_MAX_ATTEMPTS` budget exhausted) is fatal to the whole
/// fallback, exactly as in [`run_agent_tcp_fallback`].
async fn run_agent_tcp_fallback_until_quic_recovers(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    let n = config.tcp_fallback_pool_size.max(1);
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..n {
        let config = config.clone();
        let edge_cert = edge_cert.clone();
        let token = token.clone();
        let origin_keys = Arc::clone(&origin_keys);
        workers.spawn(async move {
            run_agent_tcp_fallback_worker(&config, edge_cert, token, origin_keys).await
        });
    }
    loop {
        tokio::select! {
            // A worker only ever ends by giving up (backoff exhausted) — fatal to the
            // whole fallback mode, matching `run_agent_tcp_fallback`'s posture.
            Some(res) = workers.join_next() => {
                return match res {
                    Ok(r) => r,
                    Err(join) => Err(join.into()),
                };
            }
            _ = tokio::time::sleep(QUIC_REPROBE_INTERVAL) => {
                if let Ok(Ok(conn)) = tokio::time::timeout(
                    Duration::from_secs(5),
                    dial_quic(config.edge, edge_cert.clone()),
                )
                .await
                {
                    conn.close(0u32.into(), b"udp recovered - upgrading back to QUIC (#16)");
                    eprintln!(
                        "ct-agent: UDP/QUIC to {} recovered — leaving the TLS-TCP fallback (#16)",
                        config.edge
                    );
                    return Ok(());
                }
            }
        }
    }
}

/// One TCP-fallback pool worker (#229): connect, register, serve one Client,
/// repeat -- the body [`run_agent_tcp_fallback`] runs N of concurrently. Each
/// registration is still single-use/single-Client; see that function's doc
/// for why several of these run at once.
async fn run_agent_tcp_fallback_worker(
    config: &AgentConfig,
    edge_cert: CertificateDer<'static>,
    token: RoutingToken,
    origin_keys: Arc<Vec<[u8; 32]>>,
) -> Result<(), BoxError> {
    let metrics = Arc::new(TunnelMetrics::new());
    // Reconnect loop (issue #5 / P1.2b): re-register and serve again after each
    // single tunnel ends or the connection drops, with backoff on failure.
    let mut backoff = Backoff::new(RECONNECT_BASE, RECONNECT_MAX, reconnect_max_attempts());
    // #46 FB-c: the TCP-fallback rungs to try in order — the configured edge port,
    // then the unified :443 front door when CT_AGENT_FALLBACK_443 is set. The first
    // rung that connects+registers serves the client; if all fail, back off.
    let rungs = crate::ladder::tcp_rungs(config.edge, config.fallback_443);
    loop {
        let mut served = false;
        let mut last_err: Option<BoxError> = None;
        for addr in &rungs {
            match tcp_connect_register_serve(config, *addr, &edge_cert, &token, &origin_keys, &metrics)
                .await
            {
                // A tunnel completed cleanly — re-register (re-walk from the primary).
                Ok(()) => {
                    backoff.reset();
                    served = true;
                    break;
                }
                Err(e) => {
                    eprintln!("ct-agent: TLS-TCP rung {addr} failed: {e}; trying next rung");
                    last_err = Some(e);
                }
            }
        }
        if !served {
            let e = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no TCP rung configured".to_string());
            eprintln!("ct-agent: all TLS-TCP rungs failed ({e}); will reconnect");
            match backoff.next_delay_jittered(rand::random::<f64>()) {
                Some(d) => tokio::time::sleep(d).await,
                None => {
                    return Err("ct-agent: gave up reconnecting over the TLS-TCP fallback".into())
                }
            }
        }
    }
}

/// Connect over TLS-TCP to `target`, register the tunnel over the stream, and
/// serve one Client's Noise tunnel over it — the single-shot body of the
/// TCP-fallback reconnect loop (issue #5 / P1.2b), one rung of the #46 ladder.
async fn tcp_connect_register_serve(
    config: &AgentConfig,
    target: SocketAddr,
    edge_cert: &CertificateDer<'static>,
    token: &RoutingToken,
    origin_keys: &[[u8; 32]],
    metrics: &Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    let mut stream = tcp_tls_connect(target, edge_cert.clone()).await?;
    // Browser Plane over the TCP fallback (#41 FB3): register+bind the public
    // hostname in one 'B' frame, then raw-forward the relayed browser stream to
    // the Origin verbatim — the browser's TLS terminates AT the Origin, so this
    // agent never speaks Noise. Mirrors the QUIC browser path in serve_quic_connection.
    if config.browser_forward {
        if let Some(host) = &config.hostname {
            // Prefer the ping-capable 'L' registration for exactly the reason 'K'
            // exists on the Noise path (see the comment below): a parked fallback
            // connection carrying no payload is silently dropped by middleboxes that
            // ignore ACK-only keepalive segments. Browser-Plane agents were left out
            // of that fix -- 'K' only ever covered the Noise path, so a
            // `CT_AGENT_MODE=browser` agent kept flapping no matter which release it
            // ran. Measured on the live deployment this was found on: a parked
            // connection dies after ~10-15s idle (5s request spacing -> 4/4 OK, 20s
            // spacing -> 1/4), which for sporadic real-user traffic means most
            // requests fail.
            //
            // Same fallback shape as 'K': a pre-'L' Edge treats the unknown role byte
            // as a hard protocol error and drops the connection without an ack, so any
            // failure means redialing and registering plain 'B' on a fresh stream.
            //
            // #528 adds one more rung ABOVE 'L', opt-in via CT_AGENT_FRAMED_FALLBACK:
            // 'F' is 'L' plus a framed relay phase, which is the only way to keep the
            // connection alive during an in-flight request whose Origin is silent (an
            // LLM cold model load) -- 'L' stops framing the moment a request is
            // delivered. The rungs degrade one at a time, each on a fresh connection:
            // 'F' -> 'L' -> 'B'.
            let mut framed = false;
            if config.framed_fallback {
                match register_tunnel_stream_browser_framed_capable(&mut stream, token, host).await {
                    Ok(()) => framed = true,
                    Err(e) => {
                        eprintln!(
                            "ct-agent: framed browser ('F') registration at {target} failed ({e}); \
                             falling back to 'L' on a fresh connection"
                        );
                        stream = tcp_tls_connect(target, edge_cert.clone()).await?;
                    }
                }
            }
            let mut ping_capable = true;
            if !framed {
                if let Err(e) = register_tunnel_stream_browser_ping_capable(&mut stream, token, host).await {
                    eprintln!(
                        "ct-agent: ping-capable browser ('L') registration at {target} failed ({e}); \
                         falling back to a plain 'B' registration on a fresh connection"
                    );
                    stream = tcp_tls_connect(target, edge_cert.clone()).await?;
                    register_tunnel_stream_browser(&mut stream, token, host).await?;
                    ping_capable = false;
                }
            }
            eprintln!(
                "ct-agent: browser-registered '{host}' over the TLS-TCP fallback (UDP blocked){}, \
                 {}-forwarding to {}",
                match (framed, ping_capable) {
                    (true, _) => ", framed ('F')",
                    (false, true) => ", ping-capable ('L')",
                    (false, false) => "",
                },
                if framed { "framed" } else { "raw" },
                config.origin
            );
            if framed || ping_capable {
                // Answer the Edge's PINGs until it writes STOP; the stream is then
                // positioned exactly at the first relayed browser byte. Identical
                // contract to the 'K' path -- `await_ping_phase_end` is shared, and
                // 'F' keeps the park phase byte-for-byte ('F' only changes what
                // comes AFTER the STOP byte).
                await_ping_phase_end(&mut stream).await?;
            }
            return if framed {
                serve_framed_duplex_to_origin(stream, config.origin).await
            } else {
                serve_duplex_to_origin(stream, config.origin).await
            };
        }
    }
    // ct-agent#15: prefer the ping-capable 'K' registration, which has the Edge
    // put real payload on this connection while it sits parked waiting for a
    // Client. A bare TCP keepalive is an ACK-only segment that some enterprise
    // firewall/DPI/SASE gateways don't count as activity, so the parked
    // connection still flapped after the 10s/10s keepalive tightening (9b42d9e).
    //
    // Fallback: a pre-'K' Edge doesn't just refuse 'K', it treats an unknown role
    // byte as a hard protocol error and drops the connection WITHOUT any ack — so
    // the failure surfaces here as an EOF reading the ack, not as a "NO". The
    // stream is unusable either way (a 'K'-aware Edge also shuts down after a
    // "NO"), so the retry has to be a fresh connection rather than a second
    // registration on this one. Any 'K' failure therefore falls back to a plain
    // 'A' on a redial: that keeps us compatible with every Edge without having to
    // tell "didn't understand 'K'" apart from "refused this token", at the cost
    // of one extra dial on a registration that was going to fail anyway.
    let mut ping_capable = true;
    if let Err(e) = register_tunnel_stream_ping_capable(&mut stream, token).await {
        eprintln!(
            "ct-agent: ping-capable ('K') registration at {target} failed ({e}); \
             falling back to a plain 'A' registration on a fresh connection"
        );
        stream = tcp_tls_connect(target, edge_cert.clone()).await?;
        register_tunnel_stream(&mut stream, token).await?;
        ping_capable = false;
    }
    eprintln!(
        "ct-agent: registered over the TLS-TCP fallback (UDP blocked){}, serving one tunnel to {}",
        if ping_capable { ", ping-capable" } else { "" },
        config.origin
    );
    // Answer the Edge's parked-connection PINGs until it signals STOP. Returns
    // with the stream byte-exactly at the first relayed byte, so the Noise
    // handshake below sees an untouched stream.
    if ping_capable {
        await_ping_phase_end(&mut stream).await?;
    }
    let (recv, send) = split(stream);
    serve_noise_stream(send, recv, config.origin, origin_keys, Arc::clone(metrics)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::dial_quic;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn parse_reconnect_max_attempts_maps_zero_to_unbounded() {
        // #36: unset/garbage keeps the default; an explicit 0 means retry forever
        // (so the public-demo agent rejoins a redeployed edge instead of exiting).
        assert_eq!(parse_reconnect_max_attempts(None), RECONNECT_MAX_ATTEMPTS);
        assert_eq!(parse_reconnect_max_attempts(Some("not-a-number".into())), RECONNECT_MAX_ATTEMPTS);
        assert_eq!(parse_reconnect_max_attempts(Some("0".into())), u32::MAX, "0 -> retry forever");
        assert_eq!(parse_reconnect_max_attempts(Some(" 7 ".into())), 7);
    }

    #[test]
    fn the_default_reconnect_budget_is_unbounded_so_an_agent_never_exits_on_a_long_outage() {
        // Real production outage (2026-08-13): with the previous default of 10, an
        // onboarded agent burned its whole budget in ~2 minutes of backoff
        // (0.5+1+2+4+8+16+30+30+30+30 = 151.5s) during an edge redeploy that took
        // longer than that, exited, and stayed dead for hours -- the edge answered
        // `no agent tunnel for token` for every request until a human restarted it.
        // An onboarded agent IS the tunnel: exiting is a permanent outage, not a
        // failover, and it can't even self-heal under a supervisor because the join
        // token is single-use. So the DEFAULT specifically must be unbounded.
        assert_eq!(
            parse_reconnect_max_attempts(None),
            u32::MAX,
            "an agent with no explicit budget must retry forever, never exit"
        );

        // Prove the claim behind the regression: the old default really did cap out
        // in ~2 minutes, i.e. it could not survive an ordinary redeploy.
        let mut b = Backoff::new(RECONNECT_BASE, RECONNECT_MAX, 10);
        let mut total = Duration::ZERO;
        let mut handed_out = 0;
        while let Some(d) = b.next_delay() {
            total += d;
            handed_out += 1;
        }
        assert_eq!(handed_out, 10, "the old default handed out exactly 10 delays");
        assert!(
            total < Duration::from_secs(180),
            "the old 10-attempt default exhausted in {total:?} -- under 3 minutes, \
             which is shorter than a routine edge rebuild+restart"
        );

        // An explicitly-configured finite budget still works, for short-lived or
        // scripted runs that genuinely want to fail fast.
        assert_eq!(parse_reconnect_max_attempts(Some("3".into())), 3);
    }

    /// #502: a mock edge whose 'H' arm answers a fixed sequence of acks over
    /// successive bi-streams — drives the refuse-then-accept race a freshly
    /// onboarded agent loses against the control plane's authorize-host call.
    async fn mock_edge_ack_sequence(
        acks: &'static [&'static [u8]],
    ) -> (SocketAddr, rustls::pki_types::CertificateDer<'static>, tokio::task::JoinHandle<u32>) {
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");
        let h = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let mut served = 0u32;
            for ack in acks {
                let Ok((mut send, mut recv)) = conn.accept_bi().await else { break };
                let _ = recv.read_to_end(8192).await.unwrap();
                send.write_all(ack).await.unwrap();
                send.finish().unwrap();
                served += 1;
            }
            conn.closed().await;
            served
        });
        (addr, cert, h)
    }

    /// #502 acceptance: a bind the edge first refuses (authorize-host not yet
    /// landed) is retried and establishes once the edge accepts — the agent no
    /// longer serves hostname-less until a process restart.
    #[tokio::test]
    async fn hostname_bind_retries_a_transient_rejection_until_it_lands() {
        let (addr, cert, edge) = mock_edge_ack_sequence(&[b"NO", b"OK"]).await;
        let conn = dial_quic(addr, cert).await.expect("dial");
        let backoff = Backoff::new(Duration::from_millis(20), Duration::from_millis(40), 5);
        bind_hostname_with_retry(&conn, &RoutingToken([9u8; 32]), "retry.example.test", backoff)
            .await;
        conn.close(0u32.into(), b"done");
        assert_eq!(edge.await.unwrap(), 2, "exactly one refused bind + one accepted retry");
    }

    /// #502: the retry budget is bounded — a permanently refused bind (hostname
    /// owned by another token) stops after the configured attempts instead of
    /// hammering the edge for the connection's whole life.
    #[tokio::test]
    async fn hostname_bind_gives_up_after_the_retry_budget() {
        let (addr, cert, edge) = mock_edge_ack_sequence(&[b"NO", b"NO", b"NO", b"NO"]).await;
        let conn = dial_quic(addr, cert).await.expect("dial");
        let backoff = Backoff::new(Duration::from_millis(10), Duration::from_millis(20), 2);
        bind_hostname_with_retry(&conn, &RoutingToken([9u8; 32]), "taken.example.test", backoff)
            .await;
        conn.close(0u32.into(), b"done");
        assert_eq!(edge.await.unwrap(), 3, "initial attempt + exactly 2 budgeted retries");
    }

    /// issue #3 acceptance: with UDP blocked, the agent registers over the TLS-TCP
    /// fallback and a Client completes a full Noise round-trip through the edge to
    /// the origin — the cross-host tunnel works without QUIC/UDP.
    #[tokio::test]
    async fn tcp_fallback_agent_serves_a_noise_round_trip_end_to_end() {
        use ct_common::noise::generate_static_keypair;
        use ct_common::pow::Challenge;
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use ct_edge::serve::serve_tcp_connection;
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::net::Ipv4Addr;

        // Real dual edge (TCP + QUIC); we exercise only the TCP fallback side.
        let ca = Ca::new("e2e-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x33; 32]);
        let state = Arc::new(EdgeState::<Connection>::new());
        let challenge = Challenge { nonce: [0u8; 16], difficulty: 0 };

        // Edge: accept each TCP connection and serve it ('A' parks, 'C' delivers).
        //
        // ct-agent#15: this is the REAL pinned ct-edge, which predates role 'K'
        // and rejects an unknown role byte by erroring out and dropping the
        // connection with no ack. That makes this test a genuine end-to-end proof
        // of the legacy-Edge fallback: the Agent's 'K' attempt gets dropped
        // ack-less, it redials and registers with plain 'A', and the tunnel works
        // exactly as before. Accept in an unbounded loop rather than a fixed count
        // so the extra probe dial isn't a brittle magic number.
        let state_e = state.clone();
        let edge = tokio::spawn(async move {
            loop {
                let (tcp, _) = tcp_listener.accept().await.unwrap();
                let (acc, st, ch) = (acceptor.clone(), state_e.clone(), challenge.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acc.accept(tcp).await {
                        // The trailing None is ct-edge's per-connection cap (no cap in this test).
                        let _ = serve_tcp_connection(tls, &st, &ch, None).await;
                    }
                });
            }
        });

        // Origin: a streaming TCP echo (copy) — echoes bytes as they arrive, so
        // the round-trip does not depend on a half-close propagating through the
        // relay chain (matches the known-good TCP-fallback harness).
        let origin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = origin_listener.accept().await.unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        // The agent holds the origin private key; the Capability pins its public.
        let origin_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: tcp_addr.to_string(),
        };

        // Agent: run the TCP fallback (connect + register + serve one tunnel).
        // Pool size 1: the real edge parks one registration per token, and a
        // larger pool would just have the Agent's own workers supersede each
        // other's park slot before the Client arrives.
        let mut cfg = AgentConfig::parse(&tcp_addr.to_string(), &origin_addr.to_string()).unwrap();
        cfg.tcp_fallback_pool_size = 1;
        let ca_root_a = ca_root.clone();
        let a_token = token.clone();
        let agent = tokio::spawn(async move {
            let _ = run_agent_tcp_fallback(&cfg, ca_root_a, a_token, std::sync::Arc::new(vec![origin_kp.private])).await;
        });

        // Wait until the agent has registered (parked) at the edge.
        for _ in 0..200 {
            if state.has_tcp_agent(&token) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(state.has_tcp_agent(&token), "agent parked over TLS-TCP");

        // Client: tunnel over TLS-TCP through the edge to the origin, expect echo.
        let client_kp = generate_static_keypair();
        let client_stream = ct_client::transport::tcp_tls_connect(tcp_addr, ca_root)
            .await
            .unwrap();
        let resp = tokio::time::timeout(
            Duration::from_secs(15),
            ct_client::transport::client_tunnel_noise_tcp(
                client_stream,
                &token,
                &cap,
                &client_kp.private,
                b"hello-tcp-fallback",
            ),
        )
        .await
        .expect("round-trip timed out (relay/serve deadlock)")
        .unwrap();
        assert_eq!(
            resp, b"hello-tcp-fallback",
            "cross-host TCP-fallback Noise round-trip succeeds"
        );

        agent.abort();
        edge.abort();
    }
    use tokio::net::TcpListener;

    async fn echo_origin() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn agent_relays_quic_stream_to_local_origin() {
        // Local TCP echo origin that closes its write side after echoing.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().expect("addr");

        // "Edge": open a relayed stream to the Agent, send "ping", read the echo.
        let edge = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            recv.read_to_end(64).await.unwrap()
        });

        // Agent: dial the edge, accept the relayed stream, serve it to origin.
        let conn = dial_quic(addr, cert).await.expect("agent dial");
        let (a_send, a_recv) = conn.accept_bi().await.unwrap();
        serve_stream_to_origin(a_send, a_recv, origin_addr)
            .await
            .expect("serve to origin");

        let echoed = edge.await.unwrap();
        assert_eq!(echoed, b"ping", "edge gets the origin's echo through the agent");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn noise_bridge_decrypts_to_origin_and_reencrypts() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity, RoutingToken};

        // A real TCP echo Origin — it only ever sees plaintext.
        let (origin_addr, origin) = echo_origin().await;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (client_io, server_io) = tokio::io::duplex(8192);
        let (mut c_read, mut c_write) = tokio::io::split(client_io);

        // Agent-side responder bridge (the code under test).
        let origin_priv = origin_kp.private;
        let bridge = tokio::spawn(async move {
            let (mut s_read, mut s_write) = tokio::io::split(server_io);
            serve_noise_bridge(&mut s_write, &mut s_read, origin_addr, &origin_priv).await
        });

        // Inline Client initiator (mirrors ct-client::noise::client_noise_exchange).
        let mut hs = client_handshake_for(&client_kp.private, &cap).expect("initiator");
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        c_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut c_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();
        let n = transport.write_message(b"secret-request", &mut buf).unwrap();
        c_write.write_all(&frame(&buf[..n])).await.unwrap();
        let resp_ct = read_frame(&mut c_read).await.unwrap();
        let n = transport.read_message(&resp_ct, &mut tmp).unwrap();

        assert_eq!(
            &tmp[..n],
            b"secret-request",
            "agent decrypted to origin, origin echoed, agent re-encrypted"
        );
        bridge.await.unwrap().expect("bridge ok");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn serve_noise_stream_bridges_streaming_to_origin() {
        use ct_common::noise::{
            client_handshake_for, frame, generate_static_keypair, noise_pump, read_frame,
        };
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::net::TcpListener;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // Streaming TCP echo Origin (echoes bytes as they arrive).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);

        // Agent under test: serve_noise_stream over the relayed cipher stream.
        let origin_priv = origin_kp.private;
        let metrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let mcheck = std::sync::Arc::clone(&metrics);
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent = tokio::spawn(async move {
            serve_noise_stream(a_write, a_read, origin_addr, &[origin_priv], metrics).await
        });

        // Initiator: handshake, then pump a 100 KB app stream over the session.
        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let ini_t = hs.into_transport_mode().unwrap();

        let (app_local, app_remote) = tokio::io::duplex(1024 * 1024);
        let cipher = tokio::io::join(i_read, i_write);
        let pump = tokio::spawn(noise_pump(ini_t, cipher, app_local));

        let expected: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let (mut app_r, mut app_w) = tokio::io::split(app_remote);
        let payload = expected.clone();
        let writer = tokio::spawn(async move {
            app_w.write_all(&payload).await.unwrap();
            app_w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        app_r.read_to_end(&mut got).await.unwrap();

        assert_eq!(got, expected, "100 KB streams through serve_noise_stream to the echo Origin");
        writer.await.unwrap();
        pump.await.unwrap().unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();

        // The serve task recorded the handshake and metered both directions.
        assert_eq!(mcheck.tunnels_opened.get(), 1, "one tunnel opened");
        assert_eq!(mcheck.tunnels_failed.get(), 0, "no failures");
        assert_eq!(mcheck.handshakes.get(), 1, "one handshake observed");
        assert_eq!(mcheck.bytes_to_origin.get(), 100_000, "100 KB forwarded to the origin");
        assert_eq!(mcheck.bytes_to_client.get(), 100_000, "100 KB echoed back to the client");
    }

    #[tokio::test]
    async fn serve_noise_stream_selects_the_pinned_key_from_a_rotation_set() {
        // #12 K2: an agent serving a SET of origin keys (a rotation window)
        // terminates the handshake for the identity the client pinned, even when
        // it isn't the first key in the set.
        use ct_common::noise::{
            client_handshake_for, frame, generate_static_keypair, noise_pump, read_frame,
        };
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::net::TcpListener;

        let old_kp = generate_static_keypair();
        let new_kp = generate_static_keypair(); // the client pins THIS one
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(new_kp.public),
            edge_addr: "edge:443".into(),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = listener.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let (mut r, mut w) = sock.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);
        // Rotation window: old key first, the pinned new key second.
        let key_set = vec![old_kp.private, new_kp.private];
        let metrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let mcheck = std::sync::Arc::clone(&metrics);
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent = tokio::spawn(async move {
            serve_noise_stream(a_write, a_read, origin_addr, &key_set, metrics).await
        });

        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let ini_t = hs.into_transport_mode().unwrap();

        let (app_local, app_remote) = tokio::io::duplex(1024 * 1024);
        let cipher = tokio::io::join(i_read, i_write);
        let pump = tokio::spawn(noise_pump(ini_t, cipher, app_local));
        let (mut app_r, mut app_w) = tokio::io::split(app_remote);
        let writer = tokio::spawn(async move {
            app_w.write_all(b"hello-rotation").await.unwrap();
            app_w.shutdown().await.unwrap();
        });
        let mut got = Vec::new();
        app_r.read_to_end(&mut got).await.unwrap();

        assert_eq!(got, b"hello-rotation", "round-trip via the pinned (non-first) key");
        writer.await.unwrap();
        pump.await.unwrap().unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();
        assert_eq!(mcheck.tunnels_opened.get(), 1, "agent selected the pinned key and served");
    }

    #[tokio::test]
    async fn serve_noise_udp_bridges_datagrams_to_origin() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair, read_frame};
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use tokio::io::AsyncWriteExt;
        use tokio::net::UdpSocket;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        // UDP echo Origin.
        let origin_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_sock.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let mut b = vec![0u8; 65535];
            while let Ok((n, peer)) = origin_sock.recv_from(&mut b).await {
                let _ = origin_sock.send_to(&b[..n], peer).await;
            }
        });

        let (ini_cipher, agent_cipher) = tokio::io::duplex(64 * 1024);
        let origin_priv = origin_kp.private;
        let (a_read, a_write) = tokio::io::split(agent_cipher);
        let agent =
            tokio::spawn(async move { serve_noise_udp(a_write, a_read, origin_addr, &[origin_priv]).await });

        // Initiator: handshake, then send discrete datagrams and read echoes.
        let (mut i_read, mut i_write) = tokio::io::split(ini_cipher);
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        i_write.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut i_read).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();

        for msg in [b"one".as_slice(), b"two", b"a-longer-datagram-payload"] {
            let n = transport.write_message(msg, &mut buf).unwrap();
            i_write.write_all(&frame(&buf[..n])).await.unwrap();
            let fr = read_frame(&mut i_read).await.unwrap();
            let n = transport.read_message(&fr, &mut tmp).unwrap();
            assert_eq!(&tmp[..n], msg, "UDP datagram boundary + content preserved through the tunnel");
        }

        // Close the tunnel so serve_noise_udp's reader hits EOF and returns.
        // NOTE: `drop(i_write)` does NOT signal EOF while the split ReadHalf is
        // alive (the DuplexStream stays open) — an explicit shutdown is required.
        i_write.shutdown().await.unwrap();
        agent.await.unwrap().unwrap();
        origin.abort();
    }

    #[tokio::test]
    async fn serve_direct_bridges_a_direct_connection() {
        // M11.4b-iii: serve_direct accepts a direct Client connection and serves
        // it as the Noise responder straight to the Origin (no Edge).
        use crate::transport::build_direct_listener_at;
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair, read_frame};
        use ct_common::{Capability, OriginIdentity, RoutingToken};
        use std::net::Ipv4Addr;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: RoutingToken([0u8; 32]),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let (origin_addr, origin) = echo_origin().await;
        let (listener, cert) =
            build_direct_listener_at((Ipv4Addr::LOCALHOST, 0).into()).expect("listener");
        let laddr = listener.local_addr().expect("laddr");
        let opriv = origin_kp.private;
        let dmetrics = std::sync::Arc::new(ct_common::metrics::TunnelMetrics::new());
        let srv = tokio::spawn(async move {
            let _ = serve_direct(listener, origin_addr, std::sync::Arc::new(vec![opriv]), OriginProto::Tcp, dmetrics).await;
        });

        // Inline Client: connect directly to the listener, handshake, one payload.
        let client = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = client.connect(laddr, "localhost").expect("cfg").await.expect("conn");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let mut hs = client_handshake_for(&client_kp.private, &cap).unwrap();
        let mut buf = vec![0u8; 65535];
        let mut tmp = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).unwrap();
        send.write_all(&frame(&buf[..n])).await.unwrap();
        let m2 = read_frame(&mut recv).await.unwrap();
        hs.read_message(&m2, &mut tmp).unwrap();
        let mut transport = hs.into_transport_mode().unwrap();
        let n = transport.write_message(b"direct-serve", &mut buf).unwrap();
        send.write_all(&frame(&buf[..n])).await.unwrap();
        let resp = read_frame(&mut recv).await.unwrap();
        let n = transport.read_message(&resp, &mut tmp).unwrap();
        assert_eq!(&tmp[..n], b"direct-serve", "serve_direct bridged the direct connection to the origin");

        conn.close(0u32.into(), b"done");
        srv.abort();
        let _ = origin.await;
    }

    #[tokio::test]
    async fn run_agent_reconnects_after_the_edge_connection_drops() {
        // issue #5 / P1.2b: when the registered edge connection closes, the agent
        // re-dials and re-registers instead of dying.
        use ct_edge::serve::register_agent;
        use ct_edge::state::EdgeState;
        use ct_edge::transport::build_server_endpoint_with_cert;
        use quinn::Connection;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;

        let (server, cert) = build_server_endpoint_with_cert().expect("edge");
        let addr = server.local_addr().unwrap();
        let state = Arc::new(EdgeState::<Connection>::new());
        let regs = Arc::new(AtomicUsize::new(0));

        let state_e = state.clone();
        let regs_e = regs.clone();
        let edge = tokio::spawn(async move {
            // First registration, then close the connection to force a reconnect.
            let c1 = server.accept().await.unwrap().await.unwrap();
            register_agent(&c1, &state_e).await.unwrap();
            regs_e.fetch_add(1, SeqCst);
            c1.close(0u32.into(), b"drop");
            // A second registration proves the agent reconnected + re-registered.
            let c2 = server.accept().await.unwrap().await.unwrap();
            register_agent(&c2, &state_e).await.unwrap();
            regs_e.fetch_add(1, SeqCst);
            c2.closed().await;
        });

        let cfg = AgentConfig::parse(&addr.to_string(), "127.0.0.1:9").unwrap();
        let agent = tokio::spawn(async move {
            let _ = run_agent(&cfg, cert, RoutingToken([1u8; 32]), std::sync::Arc::new(vec![[0u8; 32]])).await;
        });

        // Initial registration + one reconnect, within the backoff window.
        for _ in 0..400 {
            if regs.load(SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            regs.load(SeqCst),
            2,
            "agent re-registered after the edge connection dropped"
        );
        agent.abort();
        edge.abort();
    }

    /// ct-agent#15 acceptance for the ping-capable role, end to end through the
    /// real `tcp_connect_register_serve`: a 'K'-aware Edge admits the Agent,
    /// keeps the parked connection busy with real payload PING/PONG round trips,
    /// then writes STOP and splices a Client in — and the Noise tunnel to the
    /// origin still completes on that same stream. This is the whole point of
    /// the change: the ping traffic must keep a middlebox from tearing the
    /// parked connection down WITHOUT disturbing the tunnel that follows.
    #[tokio::test]
    async fn tcp_fallback_ping_capable_role_pings_while_parked_then_serves_noise() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use std::net::Ipv4Addr;

        let (origin_addr, origin) = echo_origin().await;

        let ca = Ca::new("k-e2e-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();

        let token = RoutingToken([0x6b; 32]);
        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: tcp_addr.to_string(),
        };

        // Mock 'K'-aware Edge: admit, ping while parked, STOP, then play the
        // relayed Client by driving the Noise handshake on the same stream.
        let t = token.clone();
        let client_priv = client_kp.private;
        let edge = tokio::spawn(async move {
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut hdr = [0u8; 33];
            tls.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], b'K', "agent registers as ping-capable");
            assert_eq!(&hdr[1..], &t.0, "token echoed");
            tls.write_all(b"OK").await.unwrap();
            tls.flush().await.unwrap();

            // Parked: real payload round trips, each fully awaited before the
            // next, exactly as the Edge's park_and_ping does.
            for c in [0u64, 1] {
                let mut ping = [0u8; 9];
                ping[0] = 0xF9;
                ping[1..].copy_from_slice(&c.to_be_bytes());
                tls.write_all(&ping).await.unwrap();
                tls.flush().await.unwrap();
                let mut pong = [0u8; 9];
                tls.read_exact(&mut pong).await.unwrap();
                assert_eq!(pong[0], 0xFA, "PONG magic");
                assert_eq!(
                    u64::from_be_bytes(pong[1..].try_into().unwrap()),
                    c,
                    "PONG echoes the counter"
                );
            }

            // A Client arrived: STOP, then relayed bytes — written back to back,
            // so this also proves the Agent stops reading ping frames at exactly
            // the right byte rather than eating handshake bytes.
            tls.write_all(&[0xFB]).await.unwrap();
            let (mut recv, mut send) = split(tls);
            let mut hs = client_handshake_for(&client_priv, &cap).unwrap();
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];
            let n = hs.write_message(&[], &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            send.flush().await.unwrap();
            let m2 = read_frame(&mut recv).await.unwrap();
            hs.read_message(&m2, &mut tmp).unwrap();
            let mut transport = hs.into_transport_mode().unwrap();
            let n = transport.write_message(b"ping-role", &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            send.flush().await.unwrap();
            let resp = read_frame(&mut recv).await.unwrap();
            let n = transport.read_message(&resp, &mut tmp).unwrap();
            tmp[..n].to_vec()
        });

        let mut cfg = AgentConfig::parse(&tcp_addr.to_string(), &origin_addr.to_string()).unwrap();
        cfg.tcp_fallback_pool_size = 1;
        let origin_priv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let _ = run_agent_tcp_fallback(&cfg, ca_root, token, Arc::new(vec![origin_priv])).await;
        });

        let echoed = tokio::time::timeout(Duration::from_secs(15), edge)
            .await
            .expect("ping-capable round trip timed out")
            .unwrap();
        assert_eq!(
            echoed, b"ping-role",
            "the Noise tunnel completes on a stream that carried a ping phase first"
        );
        agent.abort();
        let _ = origin.await;
    }

    /// #528: the framed relay's round trip, driven from the Edge side with the very
    /// codec the Edge uses. Everything the Edge writes is a frame; everything the
    /// Origin says comes back as a frame; and the Origin itself never sees framing.
    #[tokio::test]
    async fn the_framed_relay_unframes_to_the_origin_and_reframes_the_response() {
        // The Origin asserts the concatenation itself with a read_exact: the relay
        // forwards each DATA frame as its own write, so a plain single `read` here
        // would race the second one and make the test flaky rather than wrong.
        let ol = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = ol.accept().await.unwrap();
            let mut got = [0u8; 14];
            sock.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"GET / HTTP/1.1", "the Origin sees raw bytes -- no framing reaches it");
            sock.write_all(b"HTTP/1.1 200 OK").await.unwrap();
            sock.shutdown().await.unwrap();
        });
        let (mut edge_side, agent_side) = tokio::io::duplex(1 << 16);
        let relay =
            tokio::spawn(async move { serve_framed_duplex_to_origin(agent_side, origin_addr).await });

        // Two DATA frames: the Origin must receive their concatenation, unframed --
        // relay chunking is not request structure.
        fallback_framing::write_data_frame(&mut edge_side, b"GET / ").await.unwrap();
        fallback_framing::write_data_frame(&mut edge_side, b"HTTP/1.1").await.unwrap();
        edge_side.flush().await.unwrap();

        // The echo origin answers once it has read, then closes; the response comes
        // back framed. It may arrive as one DATA frame or several, so collect until
        // the hop is half-closed (the framed relay's end-of-response signal).
        let mut got = Vec::new();
        loop {
            match fallback_framing::read_frame(&mut edge_side).await {
                Ok(fallback_framing::Frame::Data(d)) => got.extend_from_slice(&d),
                Ok(fallback_framing::Frame::Keepalive) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("relay framing error: {e}"),
            }
        }
        assert_eq!(got, b"HTTP/1.1 200 OK", "the Origin's raw response comes back framed");

        drop(edge_side);
        relay.await.unwrap().expect("the framed relay ends cleanly");
        let _ = origin.await;
    }

    #[tokio::test]
    async fn the_framed_relay_discards_keepalives_instead_of_forwarding_them() {
        // The whole point of KEEPALIVE: it is injectable at ANY frame boundary --
        // before a request, between its chunks, and while a response is in flight --
        // and must never reach the Origin. If a single keepalive byte leaked through,
        // it would corrupt the very request it exists to protect.
        // Same reasoning as above: the Origin itself pins what it received, byte for
        // byte, instead of echoing whatever happened to arrive in one read.
        let ol = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = ol.accept().await.unwrap();
            let mut got = [0u8; 4];
            sock.read_exact(&mut got).await.unwrap();
            assert_eq!(
                &got, b"ABCD",
                "exactly the DATA payloads reached the Origin -- no keepalive leaked into them"
            );
            // Nothing else may follow: a leaked trailing keepalive would show up here.
            let mut extra = [0u8; 1];
            assert_eq!(sock.read(&mut extra).await.unwrap(), 0, "the Origin sees a clean EOF, not a stray byte");
            sock.write_all(b"done").await.unwrap();
            sock.shutdown().await.unwrap();
        });
        let (mut edge_side, agent_side) = tokio::io::duplex(1 << 16);
        let relay =
            tokio::spawn(async move { serve_framed_duplex_to_origin(agent_side, origin_addr).await });

        fallback_framing::write_keepalive_frame(&mut edge_side).await.unwrap();
        fallback_framing::write_data_frame(&mut edge_side, b"AB").await.unwrap();
        fallback_framing::write_keepalive_frame(&mut edge_side).await.unwrap();
        fallback_framing::write_data_frame(&mut edge_side, b"CD").await.unwrap();
        fallback_framing::write_keepalive_frame(&mut edge_side).await.unwrap();
        // Half-close, so the relay half-closes the Origin in turn and the Origin's
        // own "nothing else followed" check can complete.
        edge_side.shutdown().await.unwrap();

        let mut got = Vec::new();
        loop {
            match fallback_framing::read_frame(&mut edge_side).await {
                Ok(fallback_framing::Frame::Data(d)) => got.extend_from_slice(&d),
                Ok(fallback_framing::Frame::Keepalive) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("relay framing error: {e}"),
            }
        }
        assert_eq!(got, b"done", "the Origin answered the un-keepalived request");

        drop(edge_side);
        relay.await.unwrap().expect("the framed relay ends cleanly");
        let _ = origin.await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_framed_relay_keepalives_while_the_origin_is_silent() {
        // The regression this whole feature exists for (#528): an in-flight request
        // whose Origin says nothing for a long time -- an LLM cold model load -- used
        // to leave the hop completely silent, and the middlebox dropped it. Under a
        // paused clock, prove the agent puts real payload on the wire during exactly
        // that silence, at the ~10s cadence, WITHOUT touching the Origin's answer.
        let ol = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let slow_origin = tokio::spawn(async move {
            let (mut sock, _) = ol.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"prompt");
            // "Cold model load": far longer than the ~10-15s middlebox idle timeout.
            tokio::time::sleep(Duration::from_secs(45)).await;
            sock.write_all(b"answer").await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let (mut edge_side, agent_side) = tokio::io::duplex(1 << 16);
        let relay =
            tokio::spawn(async move { serve_framed_duplex_to_origin(agent_side, origin_addr).await });
        fallback_framing::write_data_frame(&mut edge_side, b"prompt").await.unwrap();
        edge_side.flush().await.unwrap();

        let mut keepalives = 0usize;
        let mut answer = Vec::new();
        loop {
            match fallback_framing::read_frame(&mut edge_side).await {
                Ok(fallback_framing::Frame::Keepalive) => keepalives += 1,
                Ok(fallback_framing::Frame::Data(d)) => answer.extend_from_slice(&d),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("relay framing error: {e}"),
            }
        }
        assert_eq!(answer, b"answer", "the response still arrives intact");
        assert!(
            keepalives >= 3,
            "45s of Origin silence must produce keepalives at the {}s cadence, got {keepalives}",
            FRAMED_KEEPALIVE_IDLE.as_secs()
        );

        drop(edge_side);
        relay.await.unwrap().expect("the framed relay ends cleanly");
        let _ = slow_origin.await;
    }

    /// #528 acceptance for the `'F'` rung through the real
    /// `tcp_connect_register_serve`: an Edge that does not know `'F'` drops the
    /// connection without an ack (exactly how a pre-`'F'` Edge treats an unknown
    /// role byte), and the Agent must degrade to `'L'` on a fresh connection and
    /// serve the browser stream RAW — not framed — on that one. Getting this wrong
    /// would make an opted-in agent unusable against every not-yet-upgraded Edge.
    #[tokio::test]
    async fn a_framed_agent_falls_back_to_l_against_an_edge_that_refuses_f() {
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use std::net::Ipv4Addr;

        let (origin_addr, origin) = echo_origin().await;
        let ca = Ca::new("f-fallback-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let token = RoutingToken([0x7f; 32]);

        let edge = tokio::spawn(async move {
            // Connection 1: a pre-'F' Edge reads the unknown role byte and hangs up
            // without an ack.
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut role = [0u8; 1];
            tls.read_exact(&mut role).await.unwrap();
            assert_eq!(role[0], b'F', "the opted-in agent offers 'F' first");
            drop(tls);

            // Connection 2: the same agent must now come back as 'L'.
            let (tcp, _) = tcp_listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut hdr = [0u8; 33];
            tls.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr[0], b'L', "'F' degrades to 'L', not straight to 'B'");
            let mut len = [0u8; 2];
            tls.read_exact(&mut len).await.unwrap();
            let mut host = vec![0u8; u16::from_be_bytes(len) as usize];
            tls.read_exact(&mut host).await.unwrap();
            assert_eq!(host, b"framed.bunsenbrenner.org");
            tls.write_all(b"OK").await.unwrap();
            tls.flush().await.unwrap();

            // Park briefly, STOP, then relay RAW browser bytes — the 'L' contract.
            tls.write_all(&[0xFB]).await.unwrap();
            tls.write_all(b"raw-browser-bytes").await.unwrap();
            tls.flush().await.unwrap();
            let mut echoed = [0u8; 17];
            tls.read_exact(&mut echoed).await.unwrap();
            echoed.to_vec()
        });

        let mut cfg = AgentConfig::parse(&tcp_addr.to_string(), &origin_addr.to_string()).unwrap();
        cfg.browser_forward = true;
        cfg.hostname = Some("framed.bunsenbrenner.org".to_string());
        cfg.framed_fallback = true;
        cfg.tcp_fallback_pool_size = 1;
        let agent = tokio::spawn(async move {
            let _ = run_agent_tcp_fallback(&cfg, ca_root, token, Arc::new(vec![[0u8; 32]])).await;
        });

        let echoed = tokio::time::timeout(Duration::from_secs(15), edge)
            .await
            .expect("'F' -> 'L' fallback timed out")
            .unwrap();
        assert_eq!(
            echoed, b"raw-browser-bytes",
            "after degrading to 'L' the relay is the RAW pump, with no framing applied"
        );
        agent.abort();
        let _ = origin.await;
    }

    #[tokio::test]
    async fn tcp_fallback_reconnects_after_a_tunnel_drops() {
        // issue #5 / P1.2b: the TLS-TCP fallback re-registers after each tunnel.
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::Arc;

        let ca = Ca::new("f53-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let regs = Arc::new(AtomicUsize::new(0));

        // Edge: accept two TLS registrations, ack each, then drop the stream.
        // Models a 'K'-aware Edge (ct-agent#15), so this also pins that the
        // Agent now prefers the ping-capable role -- and that an EOF while it
        // sits in the ping phase waiting for a Client still drives a reconnect.
        let regs_e = regs.clone();
        let edge = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = tcp_listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut hdr = [0u8; 33];
                tls.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], b'K', "agent prefers the ping-capable role");
                tls.write_all(b"OK").await.unwrap();
                tls.flush().await.unwrap();
                regs_e.fetch_add(1, SeqCst);
                // drop `tls` -> the agent's serve sees EOF -> reconnects.
            }
        });

        let cfg = AgentConfig::parse(&tcp_addr.to_string(), "127.0.0.1:9").unwrap();
        let agent = tokio::spawn(async move {
            let _ = run_agent_tcp_fallback(&cfg, ca_root, RoutingToken([2u8; 32]), std::sync::Arc::new(vec![[0u8; 32]])).await;
        });

        for _ in 0..400 {
            if regs.load(SeqCst) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            regs.load(SeqCst),
            2,
            "TLS-TCP fallback re-registered after the tunnel dropped"
        );
        agent.abort();
        edge.abort();
    }

    #[tokio::test]
    async fn tcp_fallback_pool_holds_n_registrations_parked_concurrently() {
        // #229: a real browser page load opens several parallel connections
        // per origin. With the old implicit pool-of-1, only ever one
        // registration was parked at a time -- every simultaneous Client
        // beyond the first got "no agent tunnel for token" even though the
        // Agent process was completely healthy. Proves a pool of N actually
        // holds N registrations parked AT ONCE (not released until this test
        // says so), rather than one-at-a-time.
        use ct_edge::pki::{build_dual_edge_from_ca, Ca};
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

        const POOL: usize = 4;

        let ca = Ca::new("pool-ca").unwrap();
        let (_ep, tcp_listener, acceptor, ca_root) = build_dual_edge_from_ca(
            &ca,
            (Ipv4Addr::LOCALHOST, 0).into(),
            (Ipv4Addr::LOCALHOST, 0).into(),
            vec!["localhost".to_string()],
        )
        .await
        .unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        let registered = Arc::new(AtomicUsize::new(0));

        // Edge: accept POOL registrations, ack each, then hold every stream
        // open (parked, not dropped/relayed) so they stay outstanding at once
        // -- proving the Agent actually opened POOL concurrent connections
        // rather than opening #2 only after #1 finished.
        let registered_e = registered.clone();
        let edge = tokio::spawn(async move {
            let mut held = Vec::with_capacity(POOL);
            for _ in 0..POOL {
                let (tcp, _) = tcp_listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut hdr = [0u8; 33];
                tls.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], b'K', "agent prefers the ping-capable role");
                tls.write_all(b"OK").await.unwrap();
                tls.flush().await.unwrap();
                registered_e.fetch_add(1, SeqCst);
                // Keep it open -- prove it doesn't need to close first. Each
                // worker is now sitting in its ping phase, i.e. genuinely parked.
                held.push(tls);
            }
            // Hold until the test has observed all POOL, then let them drop.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut cfg = AgentConfig::parse(&tcp_addr.to_string(), "127.0.0.1:9").unwrap();
        cfg.tcp_fallback_pool_size = POOL;
        let agent = tokio::spawn(async move {
            let _ =
                run_agent_tcp_fallback(&cfg, ca_root, RoutingToken([0x44u8; 32]), Arc::new(vec![[0u8; 32]])).await;
        });

        // If pooling didn't work (still one-at-a-time), this never reaches
        // POOL within the bound -- the 2nd+ registration would only start
        // once the edge released the 1st, which it deliberately never does
        // here until the sleep above ends.
        let mut reached = 0;
        for _ in 0..300 {
            reached = registered.load(SeqCst);
            if reached >= POOL {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(reached, POOL, "all {POOL} registrations were parked concurrently, not one-at-a-time");

        agent.abort();
        edge.abort();
    }

    #[tokio::test]
    async fn run_agent_registers_and_serves_relayed_streams() {
        use ct_common::noise::{client_handshake_for, frame, generate_static_keypair};
        use ct_common::{Capability, OriginIdentity};
        use ct_edge::state::EdgeState;
        use quinn::Connection;
        use std::sync::Arc;

        let (origin_addr, origin) = echo_origin().await;

        let origin_kp = generate_static_keypair();
        let client_kp = generate_static_keypair();
        let token = RoutingToken([3u8; 32]);
        let cap = Capability {
            token: token.clone(),
            origin: OriginIdentity(origin_kp.public),
            edge_addr: "edge:443".into(),
        };

        let state = Arc::new(EdgeState::<Connection>::new());
        let (server, cert) = ct_edge::transport::build_server_endpoint_with_cert().expect("edge");
        let edge_addr = server.local_addr().expect("addr");

        // Edge: accept the Agent, register it, then act as the Noise initiator
        // over a relayed stream and return the decrypted echo.
        let state_e = state.clone();
        let cap_e = cap.clone();
        let client_priv = client_kp.private;
        let edge = tokio::spawn(async move {
            let agent_conn = server.accept().await.unwrap().await.unwrap();
            ct_edge::serve::register_agent(&agent_conn, &state_e)
                .await
                .map_err(|e| e.to_string())?;
            let (mut send, mut recv) = agent_conn.open_bi().await.unwrap();

            let mut hs = client_handshake_for(&client_priv, &cap_e).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; 65535];
            let mut tmp = vec![0u8; 65535];
            let n = hs.write_message(&[], &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            let m2 = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
            hs.read_message(&m2, &mut tmp).unwrap();
            let mut transport = hs.into_transport_mode().unwrap();
            let n = transport.write_message(b"ping", &mut buf).unwrap();
            send.write_all(&frame(&buf[..n])).await.unwrap();
            let resp_ct = read_frame(&mut recv).await.map_err(|e| e.to_string())?;
            let n = transport.read_message(&resp_ct, &mut tmp).unwrap();
            Ok::<Vec<u8>, String>(tmp[..n].to_vec())
        });

        // Agent: run the full loop (dial → register → accept-and-serve-noise).
        let config = AgentConfig {
            edge: edge_addr,
            origin: origin_addr,
            origin_proto: OriginProto::Tcp,
            direct_advertise_ip: None,
            metrics_listen: None,
            browser_forward: false,
            hostname: None,
            fallback_443: false,
            tcp_fallback_pool_size: 4,
            framed_fallback: false,
            register_tcp_only: false,
        };
        let token_a = token.clone();
        let origin_priv = origin_kp.private;
        let agent = tokio::spawn(async move {
            let _ = run_agent(&config, cert, token_a, std::sync::Arc::new(vec![origin_priv])).await;
        });

        let echoed = edge.await.unwrap().unwrap();
        assert_eq!(echoed, b"ping", "Noise-relayed stream reaches origin and echoes back");
        assert!(state.is_known(&token), "agent registered its tunnel");
        agent.abort();
        let _ = origin.await;
    }

    #[tokio::test]
    async fn serve_stream_to_origin_carries_a_full_tls_session() {
        // #23 BP2: the Agent's browser-forward mode pipes a relayed stream to the
        // Origin verbatim, so a browser's TLS terminates AT the Origin. Prove a
        // full TLS handshake + HTTP exchange survives serve_stream_to_origin.
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let certified =
            rcgen::generate_simple_self_signed(vec!["browser.test".to_string()]).unwrap();
        let origin_cert = certified.cert.der().clone();
        let origin_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let scfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![origin_cert.clone()], origin_key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let ol = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let origin = tokio::spawn(async move {
            let (s, _) = ol.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.expect("origin TLS handshake");
            let mut b = [0u8; 1024];
            let n = tls.read(&mut b).await.unwrap();
            assert!(b[..n].starts_with(b"GET "), "origin got an HTTP request over TLS");
            tls.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });

        // Agent under test: QUIC server; accept a bi-stream, raw-forward to origin.
        let (server, cert) =
            ct_edge::transport::build_server_endpoint_with_cert().expect("agent quic");
        let agent_addr = server.local_addr().unwrap();
        let agent = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (send, recv) = conn.accept_bi().await.unwrap();
            let _ = serve_stream_to_origin(send, recv, origin_addr).await;
            conn.closed().await;
        });

        // "Browser" over a QUIC bi-stream (standing in for the edge relay).
        let ep = ct_edge::transport::build_client_endpoint(cert).expect("client");
        let conn = ep
            .connect(agent_addr, "localhost")
            .expect("cfg")
            .await
            .expect("conn");
        let (send, recv) = conn.open_bi().await.unwrap();
        let stream = tokio::io::join(recv, send);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(origin_cert).unwrap();
        let ccfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(ccfg));
        let sni = rustls::pki_types::ServerName::try_from("browser.test").unwrap();
        let mut tls = connector
            .connect(sni, stream)
            .await
            .expect("browser TLS completes end-to-end through the raw forward");
        tls.write_all(b"GET / HTTP/1.0\r\nHost: browser.test\r\n\r\n").await.unwrap();
        tls.flush().await.unwrap();
        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let page = String::from_utf8_lossy(&resp);
        assert!(
            page.contains("200 OK") && page.contains("hello"),
            "HTTP 200 over TLS survives the agent raw forward: {page}"
        );
        conn.close(0u32.into(), b"done");
        agent.abort();
        origin.abort();
    }

    #[tokio::test]
    async fn serve_duplex_to_origin_dials_the_origin_lazily_after_the_clients_first_bytes() {
        // #229 follow-up: dialing the Origin eagerly (before any Client has
        // actually arrived) leaves an idle connection open for however long
        // this Agent sits parked waiting for a real Client -- long enough, in
        // practice, to outlive the Origin's own idle/keep-alive timeout, so
        // the very first real request lands on an already-dead connection.
        // Prove the Origin is untouched while the Client side is silent, and
        // only dialed once real bytes actually arrive.
        let ol = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = ol.local_addr().unwrap();
        let accepted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let accepted_w = accepted.clone();
        let origin = tokio::spawn(async move {
            let (mut s, _) = ol.accept().await.unwrap();
            accepted_w.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut b = [0u8; 1024];
            let n = s.read(&mut b).await.unwrap();
            assert_eq!(&b[..n], b"hello origin");
            s.write_all(b"hi client").await.unwrap();
        });

        let (mut client_side, agent_side) = tokio::io::duplex(1024);
        let relay = tokio::spawn(async move { serve_duplex_to_origin(agent_side, origin_addr).await });

        // Give the relay every chance to have dialed already, if it were going
        // to dial eagerly -- it must not have.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!accepted.load(std::sync::atomic::Ordering::SeqCst), "must not dial the Origin before the Client sends anything");

        client_side.write_all(b"hello origin").await.unwrap();
        client_side.flush().await.unwrap();
        let mut resp = [0u8; 1024];
        let n = client_side.read(&mut resp).await.unwrap();
        assert_eq!(&resp[..n], b"hi client");
        assert!(accepted.load(std::sync::atomic::Ordering::SeqCst), "dials once the Client actually speaks");

        drop(client_side);
        let _ = relay.await;
        let _ = origin.await;
    }
}
