//! ADR-0024 M1: the actual feasibility proof. Not a unit test of framing logic
//! (that's in `src/capsule.rs`'s own tests) -- this drives a REAL HTTP/2 Extended
//! CONNECT (RFC 9220) handshake with `:protocol: connect-udp` over a real loopback
//! TCP socket using the mainstream `h2` crate, then exchanges one RFC 9298/9297
//! capsule-framed UDP datagram end to end. If this test does not pass, ADR-0024's
//! Decision 1 (MASQUE tunnel over HTTP/2, not HTTP/3) needs revisiting before any
//! of M2-M4 proceed.
//!
//! `#[tokio::test(flavor = "multi_thread")]`: not incidental. A `current_thread`
//! runtime plus a hand-rolled server accept-loop reproduces a real bug this test
//! found (see the loop below) far less reliably than multi-threaded scheduling does.

use bytes::Bytes;
use h2::ext::Protocol;
use http::{Method, Request, Response};
use spike_masque_h2::capsule;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test(flavor = "multi_thread")]
async fn http2_extended_connect_udp_round_trips_one_datagram_over_real_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let server = tokio::spawn(async move {
        let (io, _peer) = listener.accept().await.expect("accept");

        let mut conn = h2::server::Builder::new()
            .enable_connect_protocol()
            .handshake::<_, Bytes>(io)
            .await
            .expect("server handshake");

        let (req, mut respond) = conn
            .accept()
            .await
            .expect("one request arrives")
            .expect("request is Ok");

        assert_eq!(req.method(), &Method::CONNECT, "must be a CONNECT request");
        assert_eq!(
            req.extensions().get::<Protocol>(),
            Some(&Protocol::from_static("connect-udp")),
            "must carry the RFC 9298 :protocol=connect-udp extended-CONNECT marker"
        );

        let response = Response::builder().status(200).body(()).unwrap();
        let mut send_stream = respond.send_response(response, false).expect("send 200 response");

        // Read the client's one capsule-framed datagram (may arrive as more than one
        // TCP/h2 DATA frame -- buffer until capsule::decode says it's complete, the
        // same "not enough yet" contract this framing is built around).
        let mut recv_stream = req.into_body();
        let mut buf = Vec::new();
        let (cap_type, cap_value, echoed_capsule) = loop {
            let chunk = recv_stream
                .data()
                .await
                .expect("client sends a data frame")
                .expect("data frame is Ok");
            recv_stream
                .flow_control()
                .release_capacity(chunk.len())
                .expect("release flow-control credit");
            buf.extend_from_slice(&chunk);
            if let Some((cap_type, value, consumed)) = capsule::decode(&buf) {
                break (cap_type, value.to_vec(), buf[..consumed].to_vec());
            }
        };
        assert_eq!(cap_type, 0x00, "DATAGRAM capsule type (RFC 9297 section 5.2)");
        let udp_payload =
            capsule::udp_datagram_payload::decode(&cap_value).expect("context ID 0 -- raw UDP payload");
        assert_eq!(udp_payload, b"hello over connect-udp (M1 spike)", "server decodes what the client sent");

        // Echo the exact same capsule bytes back -- proves the tunnel is bidirectional,
        // not just client-to-server.
        send_stream.send_data(Bytes::from(echoed_capsule), true).expect("echo capsule back, end stream");

        // M1 finding: `send_data(..., true)` only BUFFERS the final frame -- it does
        // not by itself flush to the socket. Returning here immediately (dropping
        // `conn`) closed the TCP connection out from under that still-buffered frame
        // in early iterations of this spike, and the client saw a broken-pipe/reset
        // instead of its echoed datagram. `h2::server::Connection` must keep being
        // polled (via `accept()`, same as the initial request wait above) to actually
        // drive buffered writes to the wire -- there is no separate "flush and return"
        // primitive. A real long-lived proxy (M2) naturally does this via its own
        // accept loop; this spike bounds it with the client-side timeout below rather
        // than solving graceful bidirectional teardown, which is out of scope for M1.
        while conn.accept().await.is_some() {}
    });

    let client_io = TcpStream::connect(addr).await.expect("connect to spike server");
    let (send_request, connection) = h2::client::handshake(client_io).await.expect("client handshake");
    tokio::spawn(async move {
        let _ = connection.await; // driven for its side effects; errors surface via the asserts below instead
    });

    let mut send_request = send_request.ready().await.expect("client ready to send");
    // M1 finding: `ready()` resolving does NOT guarantee the server's SETTINGS frame
    // (carrying SETTINGS_ENABLE_CONNECT_PROTOCOL=1) has already been received and
    // processed -- settings acknowledgement races the stream becoming sendable. A
    // real client (M3) needs exactly this kind of bounded wait before attempting
    // Extended CONNECT, not a one-shot check. Bounded so a genuine protocol failure
    // (server never enables it) still fails the test instead of hanging.
    for _ in 0..50 {
        if send_request.is_extended_connect_protocol_enabled() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        send_request.is_extended_connect_protocol_enabled(),
        "server's SETTINGS_ENABLE_CONNECT_PROTOCOL was never observed as enabled within 500ms -- \
         a real protocol failure, not just a race (ADR-0024 M1)"
    );

    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{addr}/.well-known/masque/udp/127.0.0.1/9999/"))
        .body(())
        .unwrap();
    request.extensions_mut().insert(Protocol::from_static("connect-udp"));

    let (response_fut, mut client_send) = send_request.send_request(request, false).expect("send CONNECT request");

    let udp_payload = b"hello over connect-udp (M1 spike)";
    let datagram_payload = capsule::udp_datagram_payload::encode(udp_payload);
    let outgoing_capsule = capsule::encode_datagram(&datagram_payload);
    client_send.send_data(Bytes::from(outgoing_capsule), false).expect("send the capsule-framed datagram");

    let response = response_fut.await.expect("response arrives");
    assert_eq!(response.status(), 200, "extended CONNECT accepted");

    let mut client_recv = response.into_body();
    let mut buf = Vec::new();
    let round_tripped = loop {
        let chunk = client_recv.data().await.expect("server echoes data").expect("data frame is Ok");
        client_recv.flow_control().release_capacity(chunk.len()).expect("release flow-control credit");
        buf.extend_from_slice(&chunk);
        if let Some((cap_type, value, _consumed)) = capsule::decode(&buf) {
            assert_eq!(cap_type, 0x00);
            break capsule::udp_datagram_payload::decode(value).expect("context ID 0").to_vec();
        }
    };

    assert_eq!(
        round_tripped, udp_payload,
        "ADR-0024 M1 PROVEN: a UDP datagram round-tripped, byte-for-byte, through a real HTTP/2 Extended \
         CONNECT (:protocol=connect-udp) tunnel over an actual loopback TCP socket, using only the \
         mainstream `h2` crate plus this spike's own hand-rolled RFC 9297/9298 capsule framing"
    );

    // The core claim (above) is already proven; the server's own accept-loop has no
    // natural termination in this spike (see its comment) -- bound the wait rather
    // than require a fully clean bidirectional teardown, which is real M2/M3 work,
    // not something this feasibility spike needs to solve.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server).await;
}
