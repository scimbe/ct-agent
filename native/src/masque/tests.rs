//! ADR-0024 M3's real end-to-end proof: [`dial_quic_via_masque`] against a REAL
//! `quinn::Endpoint` server (standing in for "the Edge's own QUIC listener") and a
//! test-local fake MASQUE proxy (the same h2 Extended-CONNECT + capsule bridging
//! logic as CADS-Tunnel's `masque-proxy`, M2 -- reimplemented here rather than
//! imported, since it lives in a different repo). If this test passes, an ordinary
//! `quinn::Connection` really did get established end-to-end through the tunnel --
//! not just a datagram (M1) or a byte round-trip to a bare UDP echo (M2), but a
//! real QUIC handshake, stream, and application data exchange.

use super::*;
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

/// One self-signed cert valid for both roles `dial_quic_via_masque` trusts it for
/// (the outer TLS-to-proxy layer's SNI, and the inner tunneled QUIC handshake's
/// SNI) -- realistic, not a test shortcut: in every real deployment this ADR
/// anticipates, both roles are the SAME edge process/cert (see `mod.rs`'s own doc
/// on `edge_cert` being reused for both). Returns the cert (cheap to clone, `Arc`-
/// backed DER) plus TWO independent `PrivateKeyDer` values serialized from the
/// SAME underlying keypair -- `ServerConfig::with_single_cert` consumes its key,
/// and the two test servers below (target QUIC server, fake proxy's TLS) each
/// need their own owned copy of the SAME actual key material, not two DIFFERENT
/// generated keys (that was a real bug caught by this test's own first run: two
/// separately-generated self-signed certs produce a `BadSignature` failure when
/// the client, correctly, trusts only ONE of them).
fn test_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>, PrivateKeyDer<'static>) {
    let certified = rcgen::generate_simple_self_signed(vec!["masque.test".to_string(), "localhost".to_string()]).unwrap();
    let cert = certified.cert.der().clone();
    let key_for_target = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let key_for_proxy = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    (cert, key_for_target, key_for_proxy)
}

/// A real quinn QUIC server bound to a loopback UDP port -- stands in for "the
/// Edge's own `CT_EDGE_LISTEN`", the one legitimate CONNECT-UDP target.
fn spawn_quic_target_server(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> (Endpoint, SocketAddr) {
    crate::transport::install_crypto_provider();
    let server_config = ServerConfig::with_single_cert(vec![cert], key).unwrap();
    let endpoint = Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let addr = endpoint.local_addr().unwrap();
    (endpoint, addr)
}

/// The fake MASQUE proxy: TLS+h2, Extended CONNECT with `:protocol=connect-udp`,
/// hard-restricted to `target` exactly like `masque-proxy`'s own by-construction
/// path check (M2) -- bridges capsule-framed datagrams to a real UDP socket
/// connected to `target`. Runs until the underlying TCP connection closes.
async fn spawn_fake_masque_proxy(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>, target: SocketAddr) -> SocketAddr {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let expected_path = connect_udp_path(target);

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let tls = match acceptor.accept(tcp).await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let expected_path = expected_path.clone();
            tokio::spawn(async move {
                let mut conn = h2::server::Builder::new().enable_connect_protocol().handshake::<_, bytes::Bytes>(tls).await.unwrap();
                // The outer accept loop is what drives this h2 Connection's I/O
                // (ADR-0024 M1's own finding: send_data/respond alone only buffer,
                // they don't themselves flush to the socket). Each accepted request
                // is handled on ITS OWN task so this loop returns to `conn.accept()`
                // immediately -- keeping the connection driven continuously for the
                // WHOLE lifetime of the request below, not just up to the point the
                // handler starts, which turned out to matter here (this test hung
                // with the handler inlined directly in this loop instead).
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let is_connect_udp = req.method() == http::Method::CONNECT
                        && req.extensions().get::<h2::ext::Protocol>() == Some(&h2::ext::Protocol::from_static("connect-udp"));
                    if !is_connect_udp || req.uri().path() != expected_path {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        continue;
                    }
                    let response = http::Response::builder().status(200).body(()).unwrap();
                    let mut send_stream = respond.send_response(response, false).unwrap();
                    tokio::spawn(async move {
                        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
                        udp.connect(target).await.unwrap();
                        let mut recv_stream = req.into_body();
                        let mut buf: Vec<u8> = Vec::new();
                        let mut udp_read_buf = vec![0u8; 65_527];
                        loop {
                            tokio::select! {
                                chunk = recv_stream.data() => {
                                    let Some(Ok(chunk)) = chunk else { break };
                                    let _ = recv_stream.flow_control().release_capacity(chunk.len());
                                    buf.extend_from_slice(&chunk);
                                    loop {
                                        match capsule::decode(&buf) {
                                            Ok(Some((0x00, value, consumed))) => {
                                                if let Some(payload) = capsule::udp_datagram_payload::decode(value) {
                                                    let _ = udp.send(payload).await;
                                                }
                                                buf.drain(..consumed);
                                            }
                                            Ok(Some((_, _, consumed))) => buf.drain(..consumed).for_each(drop),
                                            Ok(None) => break,
                                            Err(_) => return,
                                        }
                                    }
                                }
                                recv = udp.recv(&mut udp_read_buf) => {
                                    let Ok(n) = recv else { break };
                                    let framed = capsule::encode_datagram(&capsule::udp_datagram_payload::encode(&udp_read_buf[..n]));
                                    if send_stream.send_data(bytes::Bytes::from(framed), false).is_err() { break; }
                                }
                            }
                        }
                    });
                }
            });
        }
    });
    proxy_addr
}

#[tokio::test(flavor = "multi_thread")]
async fn dial_quic_via_masque_establishes_a_real_quinn_connection_and_exchanges_application_data() {
    let (edge_cert, target_key, proxy_key) = test_cert();
    let (target_server, target_addr) = spawn_quic_target_server(edge_cert.clone(), target_key);
    let proxy_addr = spawn_fake_masque_proxy(edge_cert.clone(), proxy_key, target_addr).await;

    // Accept one connection on the real target server, open a bidirectional
    // stream, and echo whatever the client sends -- proves real QUIC application
    // data flows through the tunnel, not just the handshake.
    //
    // `client_done_rx` matters: quinn implicitly closes a Connection when its last
    // handle is dropped (no explicit `conn.close()` here), which can race with
    // delivery of the stream data `finish()` just queued if `conn` drops before the
    // peer has actually read it. Waiting for the client's explicit confirmation
    // avoids that race deterministically, without an arbitrary sleep.
    let (client_done_tx, client_done_rx) = tokio::sync::oneshot::channel();
    let target_task = tokio::spawn(async move {
        let incoming = target_server.accept().await.expect("a connection arrives");
        let conn = incoming.await.expect("handshake completes");
        let (mut send, mut recv) = conn.accept_bi().await.expect("client opens a bidi stream");
        let data = recv.read_to_end(1024).await.expect("read the client's message");
        send.write_all(&data).await.expect("echo it back");
        send.finish().expect("finish the stream");
        let _ = client_done_rx.await;
    });

    let conn = dial_quic_via_masque(proxy_addr, "masque.test", target_addr, edge_cert)
        .await
        .expect("ADR-0024 M3: a real quinn::Connection over the MASQUE tunnel");

    let (mut send, mut recv) = conn.open_bi().await.expect("open a bidi stream over the tunneled connection");
    send.write_all(b"hello over a real QUIC connection tunneled through MASQUE").await.unwrap();
    send.finish().unwrap();
    let echoed = recv.read_to_end(1024).await.unwrap();
    let _ = client_done_tx.send(());

    assert_eq!(
        echoed, b"hello over a real QUIC connection tunneled through MASQUE",
        "ADR-0024 M3 PROVEN: real QUIC application data round-tripped through a real quinn::Connection \
         established entirely over the MASQUE (RFC 9298 CONNECT-UDP) tunnel"
    );

    target_task.await.unwrap();
}
