//! Unit/integration tests for the channel-run machinery -- split out of the
//! former single-file `channel_run.rs` (consolidation program: module split, slice 1).

use super::*;
use ct_common::noise::generate_static_keypair;
use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Test helper: accept exactly one full QUIC connection on `server` (both stages —
/// `Incoming` then the handshake-completing `Connecting` — matching the pattern
/// `stub_broker_admit` above already establishes) within `timeout`, and report whether
/// one arrived. The accepted `Connection` (and the `Endpoint` itself) is held alive for
/// the caller-supplied `hold` duration afterward, since a dropped `Endpoint` starts
/// tearing down in-flight connections immediately.
async fn accept_one_and_hold(server: Endpoint, timeout: Duration, hold: Duration) -> bool {
    let incoming = match tokio::time::timeout(timeout, server.accept()).await {
        Ok(Some(incoming)) => incoming,
        _ => return false,
    };
    let got = incoming.await.is_ok();
    tokio::time::sleep(hold).await;
    got
}

#[test]
fn reflexive_query_addr_derives_port_4433_by_default_or_honors_an_override() {
    // #248/#238: same host as the relay-gate, this deployment's stable QUIC port,
    // unless an operator overrides it entirely via CT_CHANNEL_REFLEXIVE_EDGE.
    let relay_gate: SocketAddr = "203.0.113.9:443".parse().unwrap();
    assert_eq!(
        reflexive_query_addr(relay_gate, None).unwrap(),
        "203.0.113.9:4433".parse::<SocketAddr>().unwrap(),
        "defaults to the relay-gate's host on the stable QUIC port"
    );
    assert_eq!(
        reflexive_query_addr(relay_gate, Some("")).unwrap(),
        "203.0.113.9:4433".parse::<SocketAddr>().unwrap(),
        "an empty override is treated the same as unset"
    );
    assert_eq!(
        reflexive_query_addr(relay_gate, Some("198.51.100.1:9999")).unwrap(),
        "198.51.100.1:9999".parse::<SocketAddr>().unwrap(),
        "an explicit override wins entirely, including a different host"
    );
    assert!(reflexive_query_addr(relay_gate, Some("not-an-addr")).is_err(), "malformed override is rejected");
}

/// Test-only "edge": accepts one QUIC connection and answers exactly the 'W' whoami
/// wire protocol `discover_udp_reflexive` speaks -- a minimal, from-scratch echo (not
/// a reuse of the real edge's `serve_connection`, which lives in a separate crate/repo)
/// so this test exercises ct-agent's OWN client-side protocol handling in isolation.
async fn serve_one_whoami_echo(server: Endpoint) {
    let incoming = server.accept().await.expect("one connection arrives");
    let conn = incoming.await.expect("handshake completes");
    let remote = conn.remote_address();
    let (mut send, mut recv) = conn.accept_bi().await.expect("client opens a bi stream");
    let mut role = [0u8; 1];
    recv.read_exact(&mut role).await.expect("role byte");
    assert_eq!(role[0], b'W', "discover_udp_reflexive must send the 'W' role byte");
    let addr = remote.to_string();
    let bytes = addr.as_bytes();
    send.write_all(&[bytes.len() as u8]).await.expect("write len");
    send.write_all(bytes).await.expect("write addr");
    send.finish().unwrap();
    // Give the response a moment to actually reach the client before this task (and
    // the `Endpoint`/`Connection` it owns) drops -- dropping immediately after
    // `finish()` can race the client's read with the connection teardown. Not
    // `conn.closed().await`: the client (production `discover_udp_reflexive`) never
    // explicitly closes, it just drops its own endpoint/connection at the end of its
    // async block, so waiting for a graceful close here could hang indefinitely.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn discover_udp_reflexive_queries_the_edges_whoami_echo() {
    use ct_edge::transport::build_server_endpoint_with_cert;

    let (server, _cert) = build_server_endpoint_with_cert().expect("server");
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(serve_one_whoami_echo(server));

    let reported = discover_udp_reflexive(addr, Duration::from_secs(2))
        .await
        .expect("the edge answered with an observed address");
    assert_eq!(
        reported.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "reports the loopback address this in-process test actually dials from"
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn discover_udp_reflexive_returns_none_when_the_edge_is_unreachable() {
    // A bound-then-dropped UDP socket's address: nothing is listening there.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let unreachable = probe.local_addr().unwrap();
    drop(probe);

    assert!(
        discover_udp_reflexive(unreachable, Duration::from_millis(500)).await.is_none(),
        "an unreachable edge yields None, never an error the caller has to handle"
    );
}

#[tokio::test]
async fn discover_udp_reflexive_returns_none_on_timeout_not_a_hang() {
    // A server that accepts the connection but never answers -- discover_udp_reflexive
    // must still return within its own bounded timeout, not hang forever.
    use ct_edge::transport::build_server_endpoint_with_cert;

    let (server, _cert) = build_server_endpoint_with_cert().expect("server");
    let addr = server.local_addr().unwrap();
    let _hold = tokio::spawn(accept_one_and_hold(server, Duration::from_secs(2), Duration::from_secs(2)));

    let started = std::time::Instant::now();
    let result = discover_udp_reflexive(addr, Duration::from_millis(300)).await;
    assert!(result.is_none(), "no reply within the timeout -> None");
    assert!(started.elapsed() < Duration::from_secs(1), "bounded by its own timeout, not the server's hold");
}

#[tokio::test]
async fn dial_relay_preferring_direct_uses_the_direct_address_when_it_is_reachable() {
    // #276: "always look for direct communication; relay is only the last line of
    // defense" -- when a direct address is configured AND reachable, it must be used,
    // never the fallback (e.g. a same-network super-peer relay), even though the
    // fallback is also live and would happily accept the connection.
    use ct_edge::transport::build_server_endpoint_with_cert;

    let (direct_server, _cert) = build_server_endpoint_with_cert().expect("direct server");
    let direct_addr = direct_server.local_addr().unwrap();
    let (fallback_server, _cert2) = build_server_endpoint_with_cert().expect("fallback server");
    let fallback_addr = fallback_server.local_addr().unwrap();

    let direct_hit = tokio::spawn(accept_one_and_hold(direct_server, Duration::from_secs(2), Duration::from_millis(300)));
    // The fallback server is live too, but must never receive a connection in this test.
    let fallback_hit = tokio::spawn(accept_one_and_hold(fallback_server, Duration::from_millis(400), Duration::ZERO));

    let conn = dial_relay_preferring_direct(Some(direct_addr), fallback_addr, Duration::from_secs(2))
        .await
        .expect("dials the direct address");
    assert!(conn.close_reason().is_none(), "connection is live");

    assert!(direct_hit.await.unwrap(), "the direct server received the connection");
    assert!(!fallback_hit.await.unwrap(), "the fallback server never saw a connection attempt");
}

#[tokio::test]
async fn dial_relay_preferring_direct_falls_back_when_the_direct_address_is_unreachable() {
    // A direct address with nothing listening (a closed UDP port) must not hang or
    // error the whole dial -- it falls through to the fallback within a bounded time.
    use ct_edge::transport::build_server_endpoint_with_cert;

    let (fallback_server, _cert) = build_server_endpoint_with_cert().expect("fallback server");
    let fallback_addr = fallback_server.local_addr().unwrap();
    let fallback_hit = tokio::spawn(accept_one_and_hold(fallback_server, Duration::from_secs(3), Duration::from_millis(300)));

    // A bound-then-dropped UDP socket's address: nothing is listening there, so a QUIC
    // handshake attempt to it will not complete.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let unreachable = probe.local_addr().unwrap();
    drop(probe);

    let conn = dial_relay_preferring_direct(Some(unreachable), fallback_addr, Duration::from_millis(500))
        .await
        .expect("falls back to the reachable address");
    assert!(conn.close_reason().is_none(), "connection to the fallback is live");
    assert!(fallback_hit.await.unwrap(), "the fallback server received the connection after the direct attempt failed");
}

#[tokio::test]
async fn dial_relay_preferring_direct_with_no_direct_address_dials_the_fallback_immediately() {
    use ct_edge::transport::build_server_endpoint_with_cert;

    let (fallback_server, _cert) = build_server_endpoint_with_cert().expect("fallback server");
    let fallback_addr = fallback_server.local_addr().unwrap();
    let fallback_hit = tokio::spawn(accept_one_and_hold(fallback_server, Duration::from_secs(2), Duration::from_millis(300)));

    let conn = dial_relay_preferring_direct(None, fallback_addr, Duration::from_secs(2))
        .await
        .expect("dials the fallback directly");
    assert!(conn.close_reason().is_none());
    assert!(fallback_hit.await.unwrap());
}

#[test]
fn dcutr_loop_action_a_persistent_serve_member_always_loops_regardless_of_outcome() {
    // #248: the actual bug -- a completed session (Ok) used to fall through to an
    // unconditional Stop even when serve_loop was true, silently ending the whole
    // process after exactly one session. A persistent serve member must ALWAYS loop
    // back (reset the one-shot counter), whether the session succeeded or errored.
    assert_eq!(dcutr_loop_action(true, true, 0, 2), DcutrLoopAction::RetryReset, "Ok + serve_loop -> keep serving");
    assert_eq!(dcutr_loop_action(false, true, 0, 2), DcutrLoopAction::RetryReset, "Err + serve_loop -> re-admit");
    // Even with the one-shot retry budget already exhausted, serve_loop still wins --
    // that budget is only ever relevant to a ONE-SHOT caller.
    assert_eq!(dcutr_loop_action(false, true, 99, 2), DcutrLoopAction::RetryReset, "serve_loop ignores the one-shot budget entirely");
}

#[test]
fn dcutr_loop_action_a_one_shot_caller_retries_errors_up_to_the_bound_then_stops() {
    assert_eq!(dcutr_loop_action(false, false, 0, 2), DcutrLoopAction::RetryBounded { next_attempt: 1 });
    assert_eq!(dcutr_loop_action(false, false, 1, 2), DcutrLoopAction::RetryBounded { next_attempt: 2 });
    // At the bound, no more retries -- stop and return the (error) result.
    assert_eq!(dcutr_loop_action(false, false, 2, 2), DcutrLoopAction::Stop, "budget exhausted -> stop");
}

#[test]
fn dcutr_loop_action_a_one_shot_callers_success_always_stops_immediately() {
    // A one-shot caller (--call-service, or Accept without --serve) that succeeds must
    // terminate right away -- it never loops just because it COULD have retried.
    assert_eq!(dcutr_loop_action(true, false, 0, 2), DcutrLoopAction::Stop);
    assert_eq!(dcutr_loop_action(true, false, 2, 2), DcutrLoopAction::Stop);
}

fn cfg_from(pairs: &[(&str, &str)]) -> Result<ChannelRunConfig, String> {
    let map: HashMap<String, String> =
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    ChannelRunConfig::from_lookup(|k| map.get(k).cloned())
}

const K64: &str = "aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20aa20";

#[test]
fn agent_card_cli_config_parses_and_writes_a_verifiable_card() {
    // #144 ①-wiring CLI (frozen): the runnable `channel agent-card` path parses
    // CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_* into a signed card and drops it at the RFC-8615
    // well-known path — closing the emit chain with no hand-rolled ed25519. The written file
    // round-trips to a card whose holder signature verifies, bound to the CLI-supplied key.
    use ct_common::channel::AgentCard;

    let dir = std::env::temp_dir().join(format!("ct-agent-card-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let chan = "9b".repeat(32);
    let pairs = [
        ("CT_CHANNEL_HOLDER_KEY", K64),
        ("CT_AGENT_CARD_ROLES", "central, orchestrator"),
        ("CT_AGENT_CARD_SKILLS", "orchestrate_task|coordinate an agent network; fire_transfer"),
        ("CT_AGENT_CARD_CHANNELS", chan.as_str()),
        ("CT_AGENT_CARD_TTL_SECS", "4000"),
        ("CT_AGENT_CARD_OUT", dir.to_str().unwrap()),
    ];
    let map: HashMap<String, String> =
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let cfg = AgentCardCliConfig::from_lookup(|k| map.get(k).cloned()).expect("parses");

    // Claims parsed as expected (CSV roles; `id|desc` and bare-`id` skills; TTL).
    assert_eq!(cfg.role_tags, vec!["central".to_string(), "orchestrator".to_string()]);
    assert_eq!(cfg.skills.len(), 2);
    assert_eq!(cfg.skills[0].id, "orchestrate_task");
    assert_eq!(cfg.skills[0].description, "coordinate an agent network");
    assert_eq!(cfg.skills[1].id, "fire_transfer", "a bare id (no |) is allowed");
    assert_eq!(cfg.skills[1].description, "");
    assert_eq!(cfg.channels.len(), 1);
    assert_eq!(cfg.ttl_secs, 4000);

    // Write + read back: a verifiable card bound to the CLI holder key, at the well-known path.
    let path = cfg.write_card(1_000).expect("writes the card");
    assert!(path.ends_with(".well-known/agent-card.json"), "RFC-8615 path, got {path:?}");
    let back: AgentCard = serde_json::from_slice(&std::fs::read(&path).unwrap()).expect("parses");
    assert!(back.is_valid(1_000), "the written card verifies");
    assert!(!back.is_valid(5_000), "expires at issued+ttl = 5000");
    let holder_pub = SigningKey::from_bytes(&hex32(K64).unwrap()).verifying_key().to_bytes();
    assert_eq!(back.holder_pubkey, holder_pub, "bound to the CLI-supplied holder key");
    assert_eq!(back.role_tags, cfg.role_tags);
    let _ = std::fs::remove_dir_all(&dir);

    // Missing roles → error; a bad holder key → error.
    let no_roles: HashMap<String, String> = [("CT_CHANNEL_HOLDER_KEY", K64)]
        .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    assert!(AgentCardCliConfig::from_lookup(|k| no_roles.get(k).cloned()).is_err(), "roles required");
    let bad_key: HashMap<String, String> = [("CT_CHANNEL_HOLDER_KEY", "zz"), ("CT_AGENT_CARD_ROLES", "central")]
        .iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    assert!(AgentCardCliConfig::from_lookup(|k| bad_key.get(k).cloned()).is_err(), "bad holder key rejected");
}

#[test]
fn agent_card_auto_register_is_opt_in_by_presence_of_all_three_vars() {
    // #214 follow-up: auto-registration only activates when CT_AGENT_CP_URL,
    // CT_AGENT_CARD_URL, AND CT_CP_EDGE_ADMIN_TOKEN are ALL present — any one missing means
    // "unchanged behavior" (card written locally only), never a partial/guessed registration.
    let all: HashMap<String, String> = [
        ("CT_AGENT_CP_URL", "https://bunsenbrenner.org"),
        ("CT_AGENT_CARD_URL", "https://you.example/.well-known/agent-card.json"),
        ("CT_CP_EDGE_ADMIN_TOKEN", "deadbeef"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let reg = AgentCardAutoRegister::from_lookup(|k| all.get(k).cloned()).expect("all three present");
    assert_eq!(reg.cp_url, "https://bunsenbrenner.org");
    assert_eq!(reg.card_url, "https://you.example/.well-known/agent-card.json");
    assert_eq!(reg.admin_token, "deadbeef");

    for missing in ["CT_AGENT_CP_URL", "CT_AGENT_CARD_URL", "CT_CP_EDGE_ADMIN_TOKEN"] {
        let mut partial = all.clone();
        partial.remove(missing);
        assert!(
            AgentCardAutoRegister::from_lookup(|k| partial.get(k).cloned()).is_none(),
            "missing {missing} -> no auto-registration, not a best-effort partial call"
        );
    }
    assert!(AgentCardAutoRegister::from_lookup(|_| None).is_none());
}

#[tokio::test]
async fn serve_local_answers_framed_requests_as_a_persistent_service() {
    // #135 L2.1-cli (frozen): serve-mode local turns the channel's app duplex into a persistent
    // request/response SERVICE — the pump-driven session side accepts framed requests and gets
    // the handler's framed responses back, MANY times over ONE duplex (not one-shot pipe). The
    // handler here upper-cases (a stand-in for the L2.3 MCP dispatch that replaces the echo).
    use ct_common::noise::{frame, read_frame};

    let mut local = serve_local(|req: Vec<u8>| async move { req.to_ascii_uppercase() });
    for msg in [&b"one"[..], b"two", b"three"] {
        local.write_all(&frame(msg)).await.expect("write request frame");
        let resp = read_frame(&mut local).await.expect("read response frame");
        assert_eq!(
            resp,
            msg.to_ascii_uppercase(),
            "each framed request is answered over the one persistent session-side duplex"
        );
    }
}

#[tokio::test]
async fn mcp_call_over_invokes_a_serve_local_peer_and_returns_its_response() {
    // #135 L2.3 (frozen): the --call client (mcp_call_over) invokes a --serve peer's MCP endpoint
    // and gets its answer back — the full call↔serve pair over one duplex (the pump would carry
    // exactly these bytes encrypted). Client sends `tools/call ping`, the peer's registry → pong.
    let registry = std::sync::Arc::new(ct_common::mcp::default_registry());
    let server = serve_local(move |req: Vec<u8>| {
        let registry = registry.clone();
        async move { registry.dispatch(&req) }
    });
    // The server's session side IS a request→response endpoint (write a request, read its reply).
    let (mut r, mut w) = tokio::io::split(server);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        mcp_call_over(&mut w, &mut r, "tools/call", serde_json::json!({ "name": "ping" })),
    )
    .await
    .expect("a response within 2s")
    .expect("got a response");

    let decoded = ct_common::mcp::decode_response(&response).expect("valid JSON-RPC response");
    assert_eq!(
        decoded.result.unwrap(),
        serde_json::json!({ "reply": "pong" }),
        "the peer's ping tool answered the client's call over the pair"
    );
    assert!(decoded.error.is_none());
}

#[test]
fn channel_identity_generates_self_service_keys_the_cli_accepts() {
    // #117-cli-identity (frozen): a participant mints a fresh channel identity
    // LOCALLY, and the emitted hex is exactly what the `ct-agent channel` CLI
    // consumes — so no hand-crafted keys and no central provisioning are needed to
    // get channel crypto material. Round-trip the generated holder + Noise keys
    // through the real `from_lookup` parser.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ed25519_dalek::Signer;

    let id = ChannelIdentity::generate();
    assert_eq!(id.holder_key_hex().len(), 64, "holder private is 64 hex");
    assert_eq!(id.noise_key_hex().len(), 64, "Noise private is 64 hex");
    assert_eq!(id.holder_pubkey_hex().len(), 64, "holder public is 64 hex");
    assert_eq!(id.noise_pubkey_hex().len(), 64, "Noise public is 64 hex");

    // An operator signs a grant over the generated holder public key.
    let op = SigningKey::from_bytes(&[9u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId([0xC7u8; 32]),
        holder: id.holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant_hex =
        hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());

    let pairs: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_ROLE", "initiate".into()),
        ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
        ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
        ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
        ("CT_CHANNEL_GRANT", grant_hex),
        ("CT_CHANNEL_HOLDER_KEY", id.holder_key_hex()),
        ("CT_CHANNEL_NOISE_KEY", id.noise_key_hex()),
    ];
    let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    let cfg = ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
        .expect("the CLI accepts a self-generated channel identity");

    // The parsed keys ARE the generated ones — the generator's output is exactly
    // what the CLI consumes, so self-service key generation needs nothing hand-crafted.
    assert_eq!(cfg.holder.to_bytes(), id.holder.to_bytes(), "holder key round-trips through the CLI");
    assert_eq!(cfg.own_noise_private, id.noise.private, "Noise key round-trips through the CLI");
    assert_eq!(
        cfg.grant.grant.holder,
        id.holder.verifying_key().to_bytes(),
        "the grant binds the generated holder public key"
    );

    // Two mints differ — real randomness, not a fixed/default key.
    let id2 = ChannelIdentity::generate();
    assert_ne!(id.holder.to_bytes(), id2.holder.to_bytes(), "holder keys are unique per mint");
    assert_ne!(id.noise.private, id2.noise.private, "Noise keys are unique per mint");
}

#[test]
fn front_door_only_drops_the_direct_quic_rung_and_requires_a_front_door_16() {
    // #16 ("UDP flapping"): CT_CHANNEL_FRONT_DOOR_ONLY pins the dial ladders to the
    // TLS-TCP `:443` front door — no direct QUIC rung at all — and is refused at
    // parse time without a usable front door (addr + cert), because a ladder with
    // zero rungs would fail every join with an unhelpful error.
    let direct: SocketAddr = "203.0.113.5:9443".parse().unwrap();
    let fd: SocketAddr = "203.0.113.5:443".parse().unwrap();

    // Default order unchanged: direct first, then the two :443 rungs.
    let rungs = ChannelJoinCliConfig::ladder(direct, Some(fd), false);
    assert_eq!(rungs.len(), 3, "default ladder keeps all three rungs");
    assert!(matches!(rungs[0].kind, ChannelDialKind::Direct), "direct QUIC dials first by default");

    // Front-door-only: exactly the two :443 rungs, nothing dials UDP.
    let rungs = ChannelJoinCliConfig::ladder(direct, Some(fd), true);
    assert_eq!(rungs.len(), 2, "front-door-only drops the direct rung");
    assert!(
        rungs.iter().all(|r| r.kind.is_front_door() && r.endpoint == fd),
        "every remaining rung is a :443 front-door dial"
    );

    // Without a configured front door the flag never yields an empty ladder
    // (belt-and-suspenders — the parse guard below refuses the combination first).
    let rungs = ChannelJoinCliConfig::ladder(direct, None, true);
    assert_eq!(rungs.len(), 1, "no front door -> the direct rung survives");

    // Parse guard: FRONT_DOOR_ONLY without FRONT_DOOR(+_CERT) is a clear error.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ed25519_dalek::Signer;
    let id = ChannelIdentity::generate();
    let op = SigningKey::from_bytes(&[9u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId([0x5Du8; 32]),
        holder: id.holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant_hex = hex_encode(
        &SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode(),
    );
    let base: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_ROLE", "initiate".into()),
        ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
        ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
        ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
        ("CT_CHANNEL_GRANT", grant_hex),
        ("CT_CHANNEL_HOLDER_KEY", id.holder_key_hex()),
        ("CT_CHANNEL_NOISE_KEY", id.noise_key_hex()),
        ("CT_CHANNEL_FRONT_DOOR_ONLY", "1".into()),
    ];
    let lookup = |pairs: &[(&str, String)]| {
        let m: HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
    };
    let err = lookup(&base).err().expect("FRONT_DOOR_ONLY without a front door is refused");
    assert!(
        err.contains("CT_CHANNEL_FRONT_DOOR_ONLY"),
        "the error names the flag and what it needs, got: {err}"
    );

    // With both front-door values present the flag parses and the ladders obey it.
    let mut full = base.clone();
    full.push(("CT_CHANNEL_FRONT_DOOR", "203.0.113.5:443".into()));
    full.push(("CT_CHANNEL_FRONT_DOOR_CERT", "aa".into())); // any hex DER parses here
    let cfg = lookup(&full).expect("a usable front door satisfies the guard");
    assert!(cfg.front_door_only);
    assert!(
        cfg.broker_ladder().iter().all(|r| r.kind.is_front_door()),
        "the broker ladder is :443-only under the flag"
    );
    assert!(
        cfg.relay_ladder().iter().all(|r| r.kind.is_front_door()),
        "the relay ladder is :443-only under the flag"
    );
}

#[test]
fn channel_identity_env_block_exports_the_keys_the_cli_reads() {
    // #117-cli-subcommand (frozen): `ct-agent channel init` prints this block; it must
    // `export` exactly the two private-key env vars the CLI consumes, surface the two
    // public keys (for the operator), and be safe to `eval` (only comments + exports).
    let id = ChannelIdentity::generate();
    let block = id.env_block();

    assert!(
        block.contains(&format!("export CT_CHANNEL_HOLDER_KEY={}", id.holder_key_hex())),
        "exports the holder private key the CLI reads"
    );
    assert!(
        block.contains(&format!("export CT_CHANNEL_NOISE_KEY={}", id.noise_key_hex())),
        "exports the Noise private key the CLI reads"
    );
    assert!(block.contains(&id.holder_pubkey_hex()), "surfaces the holder public key for the operator");
    assert!(block.contains(&id.noise_pubkey_hex()), "surfaces the Noise public key for the operator");

    // Safe to `eval`: every non-blank line is a comment or an `export`.
    for line in block.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.starts_with('#') || line.starts_with("export "),
            "every line is a comment or an export, got {line:?}"
        );
    }
}

#[test]
fn operator_issues_a_grant_the_edge_verifies_and_the_member_cli_accepts() {
    // #117-operator-flow (frozen): the create-side crypto. An operator mints a key
    // locally and signs a member's grant over the member's `channel init` holder
    // public key; the edge verifies that grant under the operator's PUBLIC key, and
    // the member CLI accepts it alongside the member's self-generated keys — closing
    // the self-service loop (operator issues -> member joins) with no central step.
    use ct_common::channel::{ChannelId, Direction, SignedChannelGrant};

    let op = OperatorIdentity::generate();
    let member = ChannelIdentity::generate();
    let channel = ChannelId([0x5Eu8; 32]);
    let holder_pub = member.holder.verifying_key().to_bytes();

    let grant_hex = op.issue_member_grant(channel, holder_pub, Direction::Initiate, 1_000);

    // The issued grant decodes + verifies under the operator public key, exactly as
    // the edge's admission gate does, and binds the member's holder + channel.
    let signed = SignedChannelGrant::decode(&hex_bytes(&grant_hex).expect("grant hex")).expect("decode");
    let op_pub = op.key.verifying_key().to_bytes();
    assert!(
        ct_common::channel::verify(&op_pub, &signed, 500).is_ok(),
        "the edge verifies the operator-issued grant under the operator key"
    );
    assert_eq!(signed.grant.holder, holder_pub, "grant binds the member's holder pubkey");
    assert_eq!(signed.grant.channel, channel, "grant is for the intended channel");

    // End-to-end: the member CLI accepts the operator-issued grant + the member's own
    // (`channel init`) keys — nothing hand-crafted, no central provisioning.
    let pairs: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_ROLE", "initiate".into()),
        ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
        ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
        ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
        ("CT_CHANNEL_GRANT", grant_hex),
        ("CT_CHANNEL_HOLDER_KEY", member.holder_key_hex()),
        ("CT_CHANNEL_NOISE_KEY", member.noise_key_hex()),
    ];
    let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    let cfg = ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
        .expect("member CLI accepts the operator-issued grant + self-generated keys");
    assert_eq!(cfg.grant.grant.holder, holder_pub, "the CLI's grant binds the member's holder");

    // Operator key hex round-trips to 64-hex private + public.
    assert_eq!(op.key_hex().len(), 64);
    assert_eq!(op.pubkey_hex().len(), 64);
}

#[test]
fn operator_mints_a_staple_the_cache_accepts_and_only_the_operator_can_mint() {
    // #121 E-fail-static (frozen): the operator — holding the key LOCALLY (invariant #6)
    // — mints a short-lived membership staple that a peer's StapleCache accepts under the
    // operator PUBLIC key, admitting the member offline until the TTL. Central never holds
    // the key, so a foreign key can neither mint nor forge a staple the cache would trust:
    // a central compromise degrades to DoS/metadata, never impersonation.
    use ct_common::channel::{ChannelId, StapleCache};

    let op = OperatorIdentity::generate();
    let member = ChannelIdentity::generate();
    let channel = ChannelId([0x77u8; 32]);
    let holder_pub = member.holder.verifying_key().to_bytes();
    let op_pub = op.key.verifying_key().to_bytes();

    // Operator mints a staple at t=1000 for a 3600s TTL (→ expires 4600).
    let staple = op.issue_membership_staple(channel, holder_pub, 1_000, 3_600);
    assert_eq!(staple.expires_at, 4_600, "expires_at = stapled_at + ttl_secs");

    // A peer caches it under the operator PUBLIC key and admits the member offline...
    let mut cache = StapleCache::new();
    assert!(cache.refresh(&op_pub, staple, 1_000), "the cache accepts the operator's staple");
    assert!(
        cache.is_member(&op_pub, &channel, &holder_pub, 4_000),
        "the member is admitted from cache with no central round-trip (fail-static)"
    );
    // ...and it lapses at the TTL (revocation latency = TTL, invariant #7).
    assert!(
        !cache.is_member(&op_pub, &channel, &holder_pub, 4_600),
        "the cached staple lapses at expires_at"
    );

    // Invariant #6: a FOREIGN operator's staple for the same member is not trusted under
    // this channel's operator key — only the local-key holder can mint an admissible staple.
    let foreign = OperatorIdentity::generate();
    let forged = foreign.issue_membership_staple(channel, holder_pub, 1_000, 3_600);
    let mut cache2 = StapleCache::new();
    assert!(
        !cache2.refresh(&op_pub, forged, 1_000),
        "a staple minted by a different key is rejected — central (keyless) can't forge one (#6)"
    );
}

#[test]
fn operator_compiles_an_overlay_plan_into_verifiable_per_link_grants() {
    // #107-nway (frozen): the controller compiles a topology's overlay links into
    // concrete A2A channels — each link becomes a derived ChannelId plus the two
    // operator-signed grants its members present. The two grants of a link verify under
    // the operator key, bind distinct holders + the same channel, and split
    // Initiate/Accept — exactly what the broker's admission pairing expects. An
    // unmapped node id fails the whole compile (can't wire a link without both keys).
    use ct_common::channel::{channel_id_for_link, verify, Direction};
    use ct_common::overlay::OverlayPlan;

    let op = OperatorIdentity::generate();
    let op_pub = op.key.verifying_key().to_bytes();
    // Three agents a<b<c with distinct holder keys; a line overlay a—b—c.
    let holders = |id: &str| -> Option<[u8; 32]> {
        match id {
            "a" => Some([0xa1u8; 32]),
            "b" => Some([0xb2u8; 32]),
            "c" => Some([0xc3u8; 32]),
            _ => None,
        }
    };
    let plan = OverlayPlan {
        links: vec![("a".into(), "b".into()), ("b".into(), "c".into())],
        total_cost: 0,
        connected: true,
    };

    let compiled = op
        .compile_overlay_grants(&plan, holders, 5_000)
        .expect("every node id maps to a holder");
    assert_eq!(compiled.len(), 2, "one compiled channel per overlay link");

    // Link a—b: the derived channel matches channel_id_for_link, both grants verify
    // under the operator key, bind distinct holders + the SAME channel, and split roles.
    let ab = &compiled[0];
    assert_eq!(
        ab.channel,
        channel_id_for_link(&op_pub, &[0xa1u8; 32], &[0xb2u8; 32]),
        "the link's channel is the deterministic per-link derivation"
    );
    assert!(verify(&op_pub, &ab.initiator_grant, 1_000).is_ok(), "initiator grant verifies");
    assert!(verify(&op_pub, &ab.acceptor_grant, 1_000).is_ok(), "acceptor grant verifies");
    assert_eq!(ab.initiator_grant.grant.channel, ab.channel, "initiator grant is for this channel");
    assert_eq!(ab.acceptor_grant.grant.channel, ab.channel, "acceptor grant is for this channel");
    assert_eq!(ab.initiator_grant.grant.holder, [0xa1u8; 32]);
    assert_eq!(ab.acceptor_grant.grant.holder, [0xb2u8; 32]);
    assert_ne!(
        ab.initiator_grant.grant.holder, ab.acceptor_grant.grant.holder,
        "the two grants bind distinct holders (an agent can't channel to itself)"
    );
    assert!(ab.initiator_grant.grant.direction.permits(Direction::Initiate));
    assert!(ab.acceptor_grant.grant.direction.permits(Direction::Accept));

    // The two links share agent b but are DISTINCT channels (per-link isolation).
    assert_ne!(compiled[0].channel, compiled[1].channel, "distinct links are distinct channels");

    // A plan naming an unmapped agent can't be wired — the whole compile fails, loudly,
    // with the offending node id (no partially-wired overlay).
    let bad = OverlayPlan {
        links: vec![("a".into(), "z".into())],
        total_cost: 0,
        connected: false,
    };
    assert_eq!(
        op.compile_overlay_grants(&bad, holders, 5_000),
        Err("z".to_string()),
        "an unmapped node id fails the compile with that id"
    );
}

#[test]
fn member_material_computes_verifiable_channel_id_and_attestation() {
    // #207 Slice A (frozen): the member-material helper derives the member's channel_id + a
    // holder-signed noise attestation that VERIFY against the canonical primitives — so the block
    // a member posts is exactly what the operator/edge will accept.
    use ct_common::channel::{channel_id_for_link, verify_member_noise_attestation};
    let operator = [0x1eu8; 32];
    let bridge = [0xe1u8; 32];
    let holder_seed = [0x55u8; 32];
    let holder = SigningKey::from_bytes(&holder_seed);
    let noise_pub = [0x77u8; 32];
    let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let env = move |k: &str| match k {
        "CT_CHANNEL_OPERATOR_PUBKEY" => Some(hx(&operator)),
        "CT_CHANNEL_BRIDGE_HOLDER" => Some(hx(&bridge)),
        "CT_CHANNEL_HOLDER_KEY" => Some(hx(&holder_seed)),
        "CT_CHANNEL_NOISE_PUBKEY" => Some(hx(&noise_pub)),
        _ => None,
    };
    let req = MemberMaterialRequest::from_lookup(env).unwrap();
    let (channel, holder_pub, attestation) = req.compute();
    assert_eq!(holder_pub, holder.verifying_key().to_bytes(), "holder pubkey derived from the private key");
    assert_eq!(channel, channel_id_for_link(&operator, &bridge, &holder_pub), "canonical operator-scoped link id");
    assert!(
        verify_member_noise_attestation(&channel, &holder_pub, &noise_pub, &attestation),
        "the emitted attestation verifies against the canonical verifier"
    );
    // the rendered block carries all four values.
    let block = req.render();
    assert!(block.contains(&hx(&channel.0)) && block.contains(&hx(&attestation)) && block.contains(&hx(&noise_pub)));
    // a missing required input errors clearly.
    assert!(MemberMaterialRequest::from_lookup(|_| None).is_err());
}

#[test]
fn pipeline_role_material_computes_verifiable_channel_id_and_attestation_independent_of_counterpart() {
    // #214 follow-up (generic pipeline provisioning): unlike member-material, this needs NO
    // counterpart pubkey — two independent callers (a bridge and a role-serving agent) with
    // the same (operator, pipeline_id, role) must derive the identical channel_id with zero
    // coordination, and each caller's own attestation must verify.
    use ct_common::channel::{channel_id_for_pipeline_role, verify_member_noise_attestation};
    let operator = [0x1eu8; 32];
    let holder_seed = [0x55u8; 32];
    let holder = SigningKey::from_bytes(&holder_seed);
    let noise_pub = [0x77u8; 32];
    let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let env = move |k: &str| match k {
        "CT_CHANNEL_OPERATOR_PUBKEY" => Some(hx(&operator)),
        "CT_PIPELINE_ID" => Some("flappy-demo".to_string()),
        "CT_PIPELINE_ROLE" => Some("physics".to_string()),
        "CT_CHANNEL_HOLDER_KEY" => Some(hx(&holder_seed)),
        "CT_CHANNEL_NOISE_PUBKEY" => Some(hx(&noise_pub)),
        _ => None,
    };
    let req = PipelineRoleMaterialRequest::from_lookup(env).unwrap();
    let (channel, holder_pub, attestation) = req.compute();
    assert_eq!(holder_pub, holder.verifying_key().to_bytes(), "holder pubkey derived from the private key");
    assert_eq!(
        channel,
        channel_id_for_pipeline_role(&operator, "flappy-demo", "physics"),
        "canonical pipeline-role id — no CT_CHANNEL_BRIDGE_HOLDER (counterpart pubkey) needed at all"
    );
    assert!(
        verify_member_noise_attestation(&channel, &holder_pub, &noise_pub, &attestation),
        "the emitted attestation verifies against the canonical verifier"
    );

    // A second, independent caller for the SAME pipeline role (different holder identity)
    // derives the SAME channel_id — the whole point: no round-trip needed to agree.
    let other_holder_seed = [0x99u8; 32];
    let other_env = move |k: &str| match k {
        "CT_CHANNEL_OPERATOR_PUBKEY" => Some(hx(&operator)),
        "CT_PIPELINE_ID" => Some("flappy-demo".to_string()),
        "CT_PIPELINE_ROLE" => Some("physics".to_string()),
        "CT_CHANNEL_HOLDER_KEY" => Some(hx(&other_holder_seed)),
        "CT_CHANNEL_NOISE_PUBKEY" => Some(hx(&noise_pub)),
        _ => None,
    };
    let (other_channel, _, _) = PipelineRoleMaterialRequest::from_lookup(other_env).unwrap().compute();
    assert_eq!(channel, other_channel, "same pipeline+role -> same channel, independent of which holder asks");

    // the rendered block carries pipeline_id, role, and all derived values.
    let block = req.render();
    assert!(block.contains("flappy-demo") && block.contains("physics") && block.contains(&hx(&channel.0)));

    // a missing required input errors clearly.
    assert!(PipelineRoleMaterialRequest::from_lookup(|_| None).is_err());
}

#[test]
fn operator_grant_request_parses_env_and_issues_a_verifiable_grant() {
    // #117-operator-flow (frozen): `ct-agent channel grant` parses the operator key +
    // CT_GRANT_* from env and issues a grant that verifies under the operator key and
    // binds the intended member/channel/direction. Required fields are enforced.
    use ct_common::channel::{ChannelId, Direction, SignedChannelGrant};

    let op = OperatorIdentity::generate();
    let member = ChannelIdentity::generate();
    let member_holder = member.holder.verifying_key().to_bytes();
    let channel = [0x77u8; 32];

    let base: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
        ("CT_GRANT_CHANNEL", hex_encode(&channel)),
        ("CT_GRANT_MEMBER_HOLDER", hex_encode(&member_holder)),
        ("CT_GRANT_DIRECTION", "accept".into()),
        ("CT_GRANT_EXPIRES", "1000".into()),
    ];
    let lookup = |pairs: &[(&str, String)]| {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        OperatorGrantRequest::from_lookup(move |k| m.get(k).cloned())
    };

    let req = lookup(&base).expect("valid operator grant request parses");
    assert_eq!(req.channel, ChannelId(channel));
    assert_eq!(req.member_holder, member_holder);
    assert_eq!(req.direction, Direction::Accept);

    // The issued grant verifies under the operator key and binds the member.
    let signed = SignedChannelGrant::decode(&hex_bytes(&req.issue()).expect("hex")).expect("decode");
    assert!(
        ct_common::channel::verify(&op.key.verifying_key().to_bytes(), &signed, 500).is_ok(),
        "the issued grant verifies under the operator key"
    );
    assert_eq!(signed.grant.holder, member_holder);
    assert_eq!(signed.grant.channel, ChannelId(channel));
    assert_eq!(signed.grant.direction, Direction::Accept);

    // Each required field is enforced.
    for drop_key in [
        "CT_CHANNEL_OPERATOR_KEY",
        "CT_GRANT_CHANNEL",
        "CT_GRANT_MEMBER_HOLDER",
        "CT_GRANT_DIRECTION",
        "CT_GRANT_EXPIRES",
    ] {
        let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
        assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
    }
}

#[test]
fn operator_invite_request_parses_env_and_issues_a_verifiable_invitation() {
    // scimbe/ct-agent#9: `ct-agent channel invite` parses the operator key + CT_INVITE_*
    // from env and issues an invitation that verifies under the operator key and binds the
    // intended invitee identity/channel/direction/rights/delegable/expiry — the cross-
    // account producer `ct_common::channel::verify_invitation`'s consumer side was missing.
    use ct_common::channel::{ChannelId, Direction, Rights, SignedChannelInvitation};

    let op = OperatorIdentity::generate();
    // The invitee is identified by its IDENTITY key here, not a holder key already
    // coordinated with the operator -- generate a bare random "identity" the operator has
    // never otherwise seen, matching the real cross-account use case.
    let invitee_identity: [u8; 32] = {
        use rand::RngCore;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b
    };
    let channel = [0x88u8; 32];

    let base: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
        ("CT_INVITE_CHANNEL", hex_encode(&channel)),
        ("CT_INVITE_IDENTITY", hex_encode(&invitee_identity)),
        ("CT_INVITE_DIRECTION", "initiate".into()),
        ("CT_INVITE_RIGHTS", "read".into()),
        ("CT_INVITE_DELEGABLE", "true".into()),
        ("CT_INVITE_EXPIRES", "1000".into()),
    ];
    let lookup = |pairs: &[(&str, String)]| {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        OperatorInviteRequest::from_lookup(move |k| m.get(k).cloned())
    };

    let req = lookup(&base).expect("valid operator invite request parses");
    assert_eq!(req.channel, ChannelId(channel));
    assert_eq!(req.invitee_identity, invitee_identity);
    assert_eq!(req.direction, Direction::Initiate);
    assert_eq!(req.rights, Rights::Read);
    assert!(req.delegable);

    // The issued invitation verifies under the operator key and binds the invitee identity.
    let signed =
        SignedChannelInvitation::decode(&hex_bytes(&req.issue()).expect("hex")).expect("decode");
    assert!(
        ct_common::channel::verify_invitation(&op.key.verifying_key().to_bytes(), &signed, 500).is_ok(),
        "the issued invitation verifies under the operator key"
    );
    assert_eq!(signed.invitation.invitee_identity, invitee_identity);
    assert_eq!(signed.invitation.channel, ChannelId(channel));
    assert_eq!(signed.invitation.direction, Direction::Initiate);
    assert_eq!(signed.invitation.rights, Rights::Read);
    assert!(signed.invitation.delegable);

    // An invitation must NOT verify as a grant (domain separation) -- decode it as a
    // SignedChannelGrant and confirm `verify` rejects it rather than accepting garbage.
    use ct_common::channel::SignedChannelGrant;
    if let Some(bytes) = hex_bytes(&req.issue()) {
        if let Ok(as_grant) = SignedChannelGrant::decode(&bytes) {
            assert!(
                ct_common::channel::verify(&op.key.verifying_key().to_bytes(), &as_grant, 500).is_err(),
                "an invitation's signature must not verify as a grant's"
            );
        }
    }

    // Default rights (unset) is ReadWrite, matching OperatorGrantRequest's fixed default.
    let no_rights: Vec<(&str, String)> =
        base.iter().filter(|(k, _)| *k != "CT_INVITE_RIGHTS").cloned().collect();
    assert_eq!(lookup(&no_rights).expect("rights optional").rights, Rights::ReadWrite);

    // Default delegable (unset) is false.
    let no_delegable: Vec<(&str, String)> =
        base.iter().filter(|(k, _)| *k != "CT_INVITE_DELEGABLE").cloned().collect();
    assert!(!lookup(&no_delegable).expect("delegable optional").delegable);

    // Each required field is enforced.
    for drop_key in [
        "CT_CHANNEL_OPERATOR_KEY",
        "CT_INVITE_CHANNEL",
        "CT_INVITE_IDENTITY",
        "CT_INVITE_DIRECTION",
        "CT_INVITE_EXPIRES",
    ] {
        let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
        assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
    }
}

#[test]
fn channel_register_request_parses_env_and_derives_the_operator_pubkey() {
    // #117-operator-register (frozen): `ct-agent channel register` parses the CP URL,
    // channel id, OIDC token, and the operator authority from env — deriving the
    // operator PUBLIC key from CT_CHANNEL_OPERATOR_KEY (never sending the private key),
    // canonicalizing the channel hex, and enforcing the required fields.
    let op = OperatorIdentity::generate();
    let channel = [0x91u8; 32];

    let base: Vec<(&str, String)> = vec![
        ("CT_AGENT_CP_URL", "http://cp:8090".into()),
        ("CT_GRANT_CHANNEL", hex_encode(&channel)),
        ("CT_CHANNEL_OPERATOR_KEY", op.key_hex()),
        ("CT_OIDC_TOKEN", "the-bearer-token".into()),
    ];
    let lookup = |pairs: &[(&str, String)]| {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        ChannelRegisterRequest::from_lookup(move |k| m.get(k).cloned())
    };

    let req = lookup(&base).expect("valid register request parses");
    assert_eq!(req.cp_url, "http://cp:8090");
    assert_eq!(req.channel_hex, hex_encode(&channel), "channel id round-trips as canonical hex");
    assert_eq!(req.token, "the-bearer-token");
    // The operator PRIVATE key is never surfaced — only its derived public key is sent.
    assert_eq!(req.operator_pubkey_hex, op.pubkey_hex(), "derives the operator public key");
    assert_ne!(req.operator_pubkey_hex, op.key_hex(), "the private key is not sent to the CP");

    // The public key may also be supplied directly (CT_CHANNEL_OPERATOR_PUBKEY),
    // without the private key present.
    let pubkey_only: Vec<(&str, String)> = vec![
        ("CT_AGENT_CP_URL", "http://cp:8090".into()),
        ("CT_GRANT_CHANNEL", hex_encode(&channel)),
        ("CT_CHANNEL_OPERATOR_PUBKEY", op.pubkey_hex()),
        ("CT_OIDC_TOKEN", "tok".into()),
    ];
    assert_eq!(
        lookup(&pubkey_only).expect("pubkey-only parses").operator_pubkey_hex,
        op.pubkey_hex(),
        "an operator pubkey supplied directly is accepted"
    );

    // Each required field is enforced (the operator key OR pubkey must be present).
    for drop_key in ["CT_AGENT_CP_URL", "CT_GRANT_CHANNEL", "CT_CHANNEL_OPERATOR_KEY", "CT_OIDC_TOKEN"] {
        let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
        assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
    }
}

#[tokio::test]
async fn dial_ladder_falls_through_to_the_front_door_then_errors_when_all_blocked() {
    // #106-client-dial (frozen): the ladder-walk tries rungs in order and returns the
    // first that connects, so a direct rung blocked by a restrictive network falls
    // back to the :443 front-door rung; it errors only when EVERY rung is blocked.
    let direct = ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), kind: ChannelDialKind::Direct };
    let fd = ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoor };

    // Direct blocked -> fall through to the :443 front-door rung.
    let picked: &str = dial_ladder(&[direct, fd], |r: &ChannelDialRung| {
        let via = r.kind.is_front_door();
        async move {
            if via { Ok("front-door") } else { Err(ChannelDialError::Unreachable) }
        }
    })
    .await
    .expect("falls back to the front door when the direct port is blocked");
    assert_eq!(picked, "front-door");

    // First success short-circuits: direct connects -> the front door is never tried.
    let picked: &str = dial_ladder(&[direct, fd], |r: &ChannelDialRung| {
        let via = r.kind.is_front_door();
        async move {
            assert!(!via, "the front-door rung must not be tried once the direct rung connects");
            Ok("direct")
        }
    })
    .await
    .expect("direct connects on the first rung");
    assert_eq!(picked, "direct");

    // Every rung blocked -> error (all paths down).
    let all_blocked: Result<&str, _> =
        dial_ladder(&[direct, fd], |_r: &ChannelDialRung| async move { Err(ChannelDialError::Unreachable) })
            .await;
    assert!(all_blocked.is_err(), "all rungs blocked surfaces an error");
}

#[tokio::test]
async fn dial_ladder_falls_through_to_the_boring_alpn_rung_when_the_front_door_is_fingerprinted() {
    // #106 boring-alpn: the DPI case from the real 2026-08-12 support call -- a network
    // that fingerprints the distinctive `ct-edge-channel` ALPN / `localhost` SNI drops
    // the front-door rung too, so BOTH earlier rungs fail and the walk must reach the
    // third rung, which dials the SAME :443 endpoint with an ordinary-HTTPS ClientHello.
    let fd_addr: SocketAddr = "203.0.113.5:443".parse().unwrap();
    let rungs = ChannelJoinCliConfig::ladder("203.0.113.5:9443".parse().unwrap(), Some(fd_addr), false);

    let tried = std::sync::Arc::new(std::sync::Mutex::new(Vec::<ChannelDialKind>::new()));
    let seen = tried.clone();
    let picked: SocketAddr = dial_ladder(&rungs, |r: &ChannelDialRung| {
        let (kind, endpoint) = (r.kind, r.endpoint);
        let seen = seen.clone();
        async move {
            seen.lock().unwrap().push(kind);
            // Everything but the boring ClientHello is blocked/fingerprinted.
            match kind {
                ChannelDialKind::FrontDoorBoring => Ok(endpoint),
                _ => Err(ChannelDialError::Unreachable),
            }
        }
    })
    .await
    .expect("the boring-ALPN rung carries the join when the other two are blocked");

    assert_eq!(picked, fd_addr, "the boring rung dials the same :443 endpoint");
    assert_eq!(
        *tried.lock().unwrap(),
        vec![ChannelDialKind::Direct, ChannelDialKind::FrontDoor, ChannelDialKind::FrontDoorBoring],
        "rungs are tried in order, boring last"
    );

    // The boring rung must NOT be reached once the ordinary front door works -- it is a
    // fallback, not a behaviour change for networks that are already fine.
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<ChannelDialKind>::new()));
    let log = seen.clone();
    let _: SocketAddr = dial_ladder(&rungs, |r: &ChannelDialRung| {
        let (kind, endpoint) = (r.kind, r.endpoint);
        let log = log.clone();
        async move {
            log.lock().unwrap().push(kind);
            match kind {
                ChannelDialKind::Direct => Err(ChannelDialError::Unreachable),
                _ => Ok(endpoint),
            }
        }
    })
    .await
    .expect("the ordinary front door still wins when it connects");
    assert_eq!(
        *seen.lock().unwrap(),
        vec![ChannelDialKind::Direct, ChannelDialKind::FrontDoor],
        "the boring rung is never dialed once the ct-edge-channel front door connects"
    );
}

#[test]
fn every_dial_rung_has_a_distinct_operator_facing_label() {
    // The dial diagnostics (`ct-agent channel: dialing {label} rung {endpoint}`) are the
    // only way an operator debugging a live case can tell WHICH rung produced a failure
    // -- the two :443 rungs share an endpoint, so a shared label would make the boring
    // fallback indistinguishable from the front-door attempt in the log.
    let labels = [
        ChannelDialKind::Direct.label(),
        ChannelDialKind::FrontDoor.label(),
        ChannelDialKind::FrontDoorBoring.label(),
    ];
    let mut sorted: Vec<&str> = labels.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), labels.len(), "labels must be distinct: {labels:?}");
    assert!(ChannelDialKind::FrontDoorBoring.is_front_door(), "the boring rung goes over :443");
    assert!(!ChannelDialKind::Direct.is_front_door());
}

#[tokio::test]
async fn present_channel_join_via_ladder_falls_back_to_the_443_front_door() {
    // #106 client-dial-443 (frozen): the AGENT actually uses :443. The dial ladder's
    // DIRECT rung points at a dead/closed port (the QUIC dial is Unreachable), so
    // present_channel_join_via_ladder falls through to the FRONT-DOOR rung — a real
    // TLS-TCP `:443`-style edge whose accepted stream is admitted with the production
    // `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — and completes the
    // join (Admitted) over TLS-over-TCP. This is the fallback for a network that blocks
    // the direct channel port.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_edge::channel_broker::admit_channel_join_on_duplex;
    use ct_edge::transport::build_tcp_tls_listener_at;
    use ed25519_dalek::Signer;
    use tokio::io::AsyncWriteExt;

    // Operator-signed grant; the edge `authorize` closure yields this operator's key.
    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let channel = [0x06u8; 32];
    let holder = SigningKey::from_bytes(&[0x11u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId(channel),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
    // The advertised endpoint must be a SAFE (non-loopback) dialable addr for admission.
    let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

    // A real `:443`-style TLS-TCP edge front door.
    let (listener, acceptor, edge_cert) = build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
        .await
        .expect("tls-tcp listener");
    let fd_addr = listener.local_addr().expect("front-door addr");

    // Edge: accept one TLS-TCP connection, admit the channel join over the duplex, then
    // ack `OK <peer_endpoint>` and close the write half so the client reads the ack to EOF.
    let edge = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("accept tcp");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
            tls,
            peer,
            500u64, // now < expires_at (1_000)
            std::time::Duration::from_secs(5),
            &move |c: ChannelId, _h: [u8; 32]| {
                let ok = c.0 == channel;
                async move { ok.then_some((op_pub, None, None)) }
            },
        )
        .await
        .expect("admit over the :443 TLS-TCP duplex");
        stream.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
        stream.shutdown().await.expect("shutdown");
    });

    // The dial ladder: a DEAD direct rung (closed port) then the LIVE :443 front door.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead); // nothing on that UDP port -> the direct QUIC dial is Unreachable
    let rungs = vec![
        ChannelDialRung { endpoint: dead_addr, kind: ChannelDialKind::Direct },
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
    ];

    let outcome = present_channel_join_via_ladder(
        &rungs,
        &request,
        &holder,
        edge_cert,
        std::time::Duration::from_millis(400),
    )
    .await
    .expect("the join completes over the :443 front door after the dead direct rung");

    match outcome {
        ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
            peer_endpoint, "198.51.100.9:8008",
            "the agent learns the peer endpoint over the :443 TLS-TCP fallback rung"
        ),
        other => panic!("a valid join over :443 must be Admitted, got {other:?}"),
    }
    edge.await.expect("edge task");
}

#[tokio::test]
async fn present_channel_join_via_ladder_falls_through_a_refused_rung_to_the_next() {
    // Live-reported gap (ct-agent#15, 2026-08-13): a network that corrupts or
    // fingerprints the request differently per rung can turn a garbled request into a
    // spurious `NO` on one rung while a cleaner rung would legitimately admit the SAME
    // grant/holder -- so `present_channel_join_via_ladder` must not stop at the first
    // `Refused`, it must try the next rung, exactly like it already does for a
    // transport-level `Unreachable`/`Failed`. Two REAL `:443`-style TLS-TCP edges: the
    // first's `authorize` closure always refuses (simulating a corrupted/garbled first
    // rung), the second admits the identical grant.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_edge::channel_broker::admit_channel_join_on_duplex;
    use ct_edge::transport::build_tcp_tls_listener_at;
    use ed25519_dalek::Signer;
    use tokio::io::AsyncWriteExt;

    let op = SigningKey::from_bytes(&[8u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let channel = [0x09u8; 32];
    let holder = SigningKey::from_bytes(&[0x12u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId(channel),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
    let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:7008".to_string() };

    // ONE real edge (one listener, one cert) serving the SAME :443-style endpoint for
    // both rungs -- matching production, where the FrontDoor and FrontDoorBoring rungs
    // dial the identical edge address and only their ClientHello differs. The client
    // connects to this address TWICE (once per rung, fresh TCP connections); the edge
    // refuses the first (simulating a corrupted/garbled first rung) and admits the
    // second (the SAME grant/holder a cleaner rung would have gotten through with).
    let (listener, acceptor, edge_cert) =
        build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls listener");
    let fd_addr = listener.local_addr().expect("front-door addr");
    let edge = tokio::spawn(async move {
        // First connection: refuse unconditionally.
        let (tcp, peer) = listener.accept().await.expect("accept tcp #1");
        let tls = acceptor.accept(tcp).await.expect("tls accept #1");
        let outcome =
            admit_channel_join_on_duplex(tls, peer, 500u64, std::time::Duration::from_secs(5), &|_c, _h| async {
                None
            })
            .await;
        assert!(outcome.is_err(), "the first connection is refused, not admitted");

        // Second connection: admit the same grant.
        let (tcp, peer) = listener.accept().await.expect("accept tcp #2");
        let tls = acceptor.accept(tcp).await.expect("tls accept #2");
        let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
            tls,
            peer,
            500u64,
            std::time::Duration::from_secs(5),
            &move |c: ChannelId, _h: [u8; 32]| {
                let ok = c.0 == channel;
                async move { ok.then_some((op_pub, None, None)) }
            },
        )
        .await
        .expect("admit over the second connection's TLS-TCP duplex");
        stream.write_all(b"OK 198.51.100.10:8009").await.expect("ack");
        stream.shutdown().await.expect("shutdown");
    });

    // Two rungs, same endpoint and kind -- this test is about the reject_refused_outcome
    // wiring, not the boring-ALPN wire format (already covered by its own dedicated tests
    // in transport.rs/pki.rs). Using FrontDoorBoring here would present SNI
    // `edge-cdn.invalid`, which this test's plain `self_signed()` cert (SAN: "localhost"
    // only) can't validate -- an unrelated failure that has nothing to do with what this
    // test proves. If the Refused from the first connection wrongly ended the walk, the
    // second `accept()` above would never be reached and `edge` would hang.
    let rungs = vec![
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
    ];
    let outcome = present_channel_join_via_ladder(
        &rungs,
        &request,
        &holder,
        edge_cert,
        std::time::Duration::from_millis(400),
    )
    .await;

    edge.await.expect("edge task");
    match outcome.expect("the ladder falls through the refused rung to the admitting one") {
        ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
            peer_endpoint, "198.51.100.10:8009",
            "the second rung's admission wins after the first rung's refusal"
        ),
        other => {
            panic!("the ladder must fall through a Refused rung, not terminate on it -- got {other:?}")
        }
    }
}

#[tokio::test]
async fn present_channel_join_via_ladder_stops_on_a_park_expiry_instead_of_advancing_21() {
    // #21: a park expiry (the edge's bare `EX` after a fully successful admission) is NOT a
    // rung failure -- the rung worked, there was simply no partner within the park TTL. The
    // ladder must STOP and surface `ParkExpired` so the caller re-parks on the same
    // transport; falling through to the next rung (like `Refused` deliberately does) is
    // exactly the ladder-advance misclassification measured live as 271 phantom "rung
    // failures" and a 0-40s first-contact roulette. The edge below accepts exactly ONE
    // connection then drops the listener: if the walk wrongly advanced, the second rung's
    // dial would fail and the outcome would be that error instead of a clean ParkExpired.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_edge::channel_broker::admit_channel_join_on_duplex;
    use ct_edge::transport::build_tcp_tls_listener_at;
    use ed25519_dalek::Signer;
    use tokio::io::AsyncWriteExt;

    let op = SigningKey::from_bytes(&[8u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let channel = [0x21u8; 32];
    let holder = SigningKey::from_bytes(&[0x13u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId(channel),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Accept,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
    let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:7009".to_string() };

    let (listener, acceptor, edge_cert) =
        build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls listener");
    let fd_addr = listener.local_addr().expect("front-door addr");
    let edge = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.expect("accept tcp");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
            tls,
            peer,
            500u64,
            std::time::Duration::from_secs(5),
            &move |c: ChannelId, _h: [u8; 32]| {
                let ok = c.0 == channel;
                async move { ok.then_some((op_pub, None, None)) }
            },
        )
        .await
        .expect("admit over the TLS-TCP duplex");
        // The reaper's park-expiry notification: the bare token, then the close.
        stream.write_all(b"EX").await.expect("park-expiry token");
        stream.shutdown().await.expect("shutdown");
        drop(listener); // any second dial (a wrong ladder advance) now fails loudly
    });

    let rungs = vec![
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
    ];
    let outcome = present_channel_join_via_ladder(
        &rungs,
        &request,
        &holder,
        edge_cert,
        std::time::Duration::from_millis(400),
    )
    .await;

    edge.await.expect("edge task");
    match outcome.expect("a park expiry is a clean outcome, not a walk failure") {
        ChannelJoinOutcome::ParkExpired => {}
        other => panic!("the ladder must stop on ParkExpired without advancing (#21), got {other:?}"),
    }
}

#[test]
fn park_expired_is_neither_a_refusal_nor_a_generic_error_21() {
    // #21: the serve loop's routing contract. `reject_refused_outcome` turns the ParkExpired
    // outcome into the TYPED error; `is_park_expired` recognizes it (and the QUIC close
    // reason that arrives flattened inside another error), while the #231 refusal backoff
    // must never see it as refused -- counting park expiries as refusals would back an
    // idle acceptor off exponentially for the crime of having no partner yet.
    let err = reject_refused_outcome(ChannelJoinOutcome::ParkExpired)
        .expect_err("ParkExpired must become the typed error, not pass as admitted");
    assert!(is_park_expired(&err), "the typed ParkExpired is recognized");
    assert!(
        !is_definitive_admission_refusal(&err),
        "a park expiry must NEVER count toward the #231 refusal backoff"
    );
    assert!(
        err.to_string().contains("park expired") && err.to_string().contains("#21"),
        "the field-visible message names the park expiry and the issue: {err}"
    );
    // The QUIC half: a close reason that crossed a stringifying boundary still classifies.
    let flattened: BoxError =
        "connection lost: closed by peer: 0: park-expired: no partner within the park TTL".into();
    assert!(is_park_expired(&flattened), "the wire close reason classifies at any nesting");
    // And plain transport errors never do.
    let transport: BoxError = "connection reset by peer".into();
    assert!(!is_park_expired(&transport));
    // Refusals stay refusals: the two classifiers are disjoint.
    let refused = reject_refused_outcome(ChannelJoinOutcome::Refused).expect_err("refused");
    assert!(is_definitive_admission_refusal(&refused) && !is_park_expired(&refused));
}

#[tokio::test(start_paused = true)]
async fn run_channel_session_times_out_a_stalled_handshake() {
    // #126 (frozen): if the paired peer never sends its Noise_IK handshake message
    // (crash, partition, admit-then-stall), the session must TIME OUT — not block
    // `read_frame` forever. Hold the transport's peer end OPEN but silent; the
    // initiator writes m1 then blocks reading m2, so the #126 handshake timeout must
    // fire (virtual time auto-advances under start_paused, so the test is instant).
    use ct_common::noise::generate_static_keypair;
    use tokio::io::{duplex, split};

    let a = generate_static_keypair();
    let b = generate_static_keypair();
    let (transport, peer_transport) = duplex(16 * 1024);
    let (_local_app, local) = duplex(16 * 1024);
    let session = tokio::spawn(async move {
        let (r, w) = split(transport);
        run_channel_session_on_stream(w, r, ChannelRole::Initiate, &a.private, &b.public, local).await
    });
    let err = session
        .await
        .unwrap()
        .expect_err("a stalled handshake must time out, not hang forever");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::TimedOut,
        "must be the #126 handshake timeout, got: {err}"
    );
    drop(peer_transport);
}

#[tokio::test]
async fn run_channel_session_on_stream_forms_the_noise_tunnel_over_a_plain_duplex() {
    // #106 relay-leg-443 (frozen): the A2A session is transport-agnostic — the
    // Noise_IK handshake + bidirectional pump run over a plain in-memory duplex (the
    // stand-in for a :443/TLS-TCP relay-spliced stream), not just a quinn bi-stream.
    // Two members hand-shake over the transport duplex, then plaintext written to one
    // member's local side arrives DECRYPTED at the other's — proving a :443-only
    // member (relay port also blocked) can relay end-to-end over :443.
    use ct_common::noise::generate_static_keypair;
    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

    let a = generate_static_keypair();
    let b = generate_static_keypair();
    let (a_priv, a_pub) = (a.private, a.public);
    let (b_priv, b_pub) = (b.private, b.public);

    // The relay-spliced transport between the two members.
    let (a_transport, b_transport) = duplex(16 * 1024);
    // Each member's local plaintext side (the CLI's stdio stand-in).
    let (mut a_app, a_local) = duplex(16 * 1024);
    let (mut b_app, b_local) = duplex(16 * 1024);

    let a_task = tokio::spawn(async move {
        let (ar, aw) = split(a_transport);
        run_channel_session_on_stream(aw, ar, ChannelRole::Initiate, &a_priv, &b_pub, a_local).await
    });
    let b_task = tokio::spawn(async move {
        let (br, bw) = split(b_transport);
        run_channel_session_on_stream(bw, br, ChannelRole::Accept, &b_priv, &a_pub, b_local).await
    });

    // A -> B over the encrypted tunnel.
    a_app.write_all(b"ping-A-to-B").await.expect("a writes");
    let mut got = [0u8; 11];
    b_app.read_exact(&mut got).await.expect("b reads A's bytes");
    assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the duplex relay");

    // B -> A.
    b_app.write_all(b"pong-B-to-A").await.expect("b writes");
    let mut got2 = [0u8; 11];
    a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
    assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A");

    // Closing a local side tears the session down cleanly.
    drop(a_app);
    drop(b_app);
    let _ = a_task.await;
    let _ = b_task.await;
}

#[tokio::test]
async fn graceful_stream_drain_returns_when_the_peer_closes() {
    // #150 (frozen): the drain FINs our write half and reads the peer to EOF — so once the peer
    // closes it returns promptly, having kept us alive just long enough to flush our tail (the
    // fix for `:443`/TLS-TCP truncation when `ct-agent` exits as a container's PID 1).
    use std::time::Duration;
    use tokio::io::{duplex, split};
    let (ours, peer) = duplex(64);
    let (mut our_r, mut our_w) = split(ours);
    drop(peer); // the peer closes → our read half EOFs
    let done = tokio::time::timeout(
        Duration::from_secs(2),
        graceful_stream_drain(&mut our_w, &mut our_r, Duration::from_secs(30)),
    )
    .await;
    assert!(done.is_ok(), "drain returns promptly once the peer has closed (well within its bound)");
}

#[tokio::test]
async fn graceful_stream_drain_is_bounded_on_a_silent_peer() {
    // #150 (frozen): a peer that FINs nothing (vanished mid-transfer) must NOT hang teardown —
    // the drain is bounded by its own timeout and returns best-effort, never blocking forever.
    use std::time::Duration;
    use tokio::io::{duplex, split};
    let (ours, peer_kept) = duplex(64);
    let (mut our_r, mut our_w) = split(ours);
    let _peer_kept = peer_kept; // keep the peer open + silent so our read half never EOFs
    let done = tokio::time::timeout(
        Duration::from_secs(3),
        graceful_stream_drain(&mut our_w, &mut our_r, Duration::from_millis(150)),
    )
    .await;
    assert!(done.is_ok(), "a silent peer times out the bounded drain instead of hanging teardown");
}

#[test]
fn agent_offer_cli_config_builds_a_valid_signed_offer_from_env() {
    // #152 (frozen): the --serve offer config parses CT_AGENT_OFFER_* + the shared holder key into
    // a signed CapacityOffer (so channel_local can register auction/offer + auction/bid), bound to
    // the holder, honouring the TTL. Absent required vars → Err (auction tools stay off), exactly
    // like the agent/card path.
    use std::collections::HashMap;
    let key_hex = "11".repeat(32); // 64 hex → [0x11; 32]
    let vars: HashMap<&str, String> = HashMap::from([
        ("CT_CHANNEL_HOLDER_KEY", key_hex.clone()),
        ("CT_AGENT_OFFER_KIND", "cloud".to_string()),
        ("CT_AGENT_OFFER_MODELS", "claude-opus-4-8,local-llama".to_string()),
        ("CT_AGENT_OFFER_UNITS", "1000".to_string()),
        ("CT_AGENT_OFFER_MIN_PRICE", "50".to_string()),
        ("CT_AGENT_OFFER_CURRENCY", "ct-llm-token-chain".to_string()),
        ("CT_AGENT_OFFER_TTL_SECS", "3600".to_string()),
    ]);
    let cfg = AgentOfferCliConfig::from_lookup(|k| vars.get(k).cloned()).expect("parses a full offer config");
    let offer = cfg.build_offer(1_000);
    assert!(offer.is_valid(1_000), "the built offer verifies at issue time");
    assert!(offer.is_valid(4_599), "valid up to issued_at + ttl");
    assert!(!offer.is_valid(4_600), "expires at now + ttl (1000 + 3600)");
    assert_eq!(offer.kind, ct_common::channel::CapacityKind::CloudApiQuota);
    assert_eq!(offer.models, vec!["claude-opus-4-8".to_string(), "local-llama".to_string()]);
    assert_eq!((offer.units_available, offer.min_price), (1000, 50));
    assert_eq!(offer.currency_id, "ct-llm-token-chain");
    assert_eq!(
        offer.holder_pubkey,
        SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes(),
        "the offer is bound to CT_CHANNEL_HOLDER_KEY"
    );
    // Defaults applied when optional vars are absent.
    assert_eq!((cfg.max_bids_per_window, cfg.window_secs), (60, 60), "rate-limit defaults");

    // Absent required vars → Err, so channel_local leaves the auction tools off (card/ping only).
    assert!(AgentOfferCliConfig::from_lookup(|_| None).is_err(), "no CT_AGENT_OFFER_* → no offer");
    // A bad kind is a clear error, not a silent default.
    let mut bad = vars.clone();
    bad.insert("CT_AGENT_OFFER_KIND", "chatbot".to_string());
    assert!(
        AgentOfferCliConfig::from_lookup(|k| bad.get(k).cloned()).is_err(),
        "an unknown CT_AGENT_OFFER_KIND is rejected"
    );
}

#[test]
fn agent_offer_declares_its_service_catalog_for_verifiable_enforcement() {
    // #167 (frozen): CT_AGENT_OFFER_SERVICES is signed INTO the offer, so a buyer can
    // cryptographically verify which services the agent offers and #149-A.1's match_offer
    // service filter has something to enforce (closing the declared-vs-served gap where the
    // offer and the registered service tools were two independent, unvalidated surfaces).
    // #382 follow-up: a slug outside the four fixed variants is no longer a hard config error
    // -- it's a real ServiceType::Custom declaration, signed into the offer exactly like any
    // fixed variant, so an operator can offer a pipeline-designer-declared service (e.g.
    // static_analysis) without a CADS-Tunnel core release. Absent → a generic offer
    // (services: []), unchanged.
    use ct_common::channel::ServiceType::*;
    use std::collections::HashMap;
    let base: HashMap<&str, String> = HashMap::from([
        ("CT_CHANNEL_HOLDER_KEY", "11".repeat(32)),
        ("CT_AGENT_OFFER_KIND", "cloud".to_string()),
        ("CT_AGENT_OFFER_MODELS", "claude-opus-4-8".to_string()),
        ("CT_AGENT_OFFER_UNITS", "1000".to_string()),
        ("CT_AGENT_OFFER_MIN_PRICE", "50".to_string()),
        ("CT_AGENT_OFFER_CURRENCY", "ct-llm-token-chain".to_string()),
    ]);

    // Absent → generic offer with no declared services (unchanged back-compat).
    let generic = AgentOfferCliConfig::from_lookup(|k| base.get(k).cloned()).unwrap();
    assert!(generic.services.is_empty(), "no CT_AGENT_OFFER_SERVICES → generic offer");
    assert!(generic.build_offer(1_000).services.is_empty(), "generic offer declares no services");

    // A declared catalog is parsed and SIGNED into the offer (order + values preserved).
    let mut with = base.clone();
    with.insert("CT_AGENT_OFFER_SERVICES", "code_generation, security_review".to_string());
    let cfg = AgentOfferCliConfig::from_lookup(|k| with.get(k).cloned()).unwrap();
    assert_eq!(cfg.services, vec![CodeGeneration, SecurityReview], "catalog parsed from env");
    let offer = cfg.build_offer(1_000);
    assert_eq!(
        offer.services,
        vec![CodeGeneration, SecurityReview],
        "the declared catalog is signed into the offer (buyer-verifiable ceiling)"
    );
    assert!(offer.is_valid(1_000), "the offer still verifies with a declared catalog");

    // A slug outside the fixed four is a REAL Custom declaration, not an error -- signed into
    // the offer the exact same way, and a real signature still verifies over it.
    let mut custom = base.clone();
    custom.insert("CT_AGENT_OFFER_SERVICES", "code_generation,static_analysis".to_string());
    let cfg = AgentOfferCliConfig::from_lookup(|k| custom.get(k).cloned()).unwrap();
    assert_eq!(
        cfg.services,
        vec![CodeGeneration, Custom("static_analysis".to_string())],
        "an unrecognized slug becomes ServiceType::Custom, not a parse error"
    );
    let offer = cfg.build_offer(1_000);
    assert_eq!(offer.services, vec![CodeGeneration, Custom("static_analysis".to_string())]);
    assert!(offer.is_valid(1_000), "a real signature verifies over a Custom-service offer");

    // A stray empty entry (double comma) is still rejected -- the ONE thing that stays a
    // hard config error, since an empty custom-service name is never a meaningful declaration.
    let mut empty_entry = base.clone();
    empty_entry.insert("CT_AGENT_OFFER_SERVICES", "code_generation,,text_generation".to_string());
    assert!(
        AgentOfferCliConfig::from_lookup(|k| empty_entry.get(k).cloned()).is_ok(),
        "a stray double-comma is just an empty token the split/filter already drops, not an error"
    );
}

#[test]
fn service_type_parsing_and_handler_shell_out_round_trip() {
    // #149-A.1 serve-wiring follow: parse_service_type covers every fixed slug, and (#382
    // follow-up) anything else becomes ServiceType::Custom rather than being dropped -- so a
    // pipeline designer's own service name (e.g. static_analysis) is a real, usable
    // declaration, not silently unavailable. Only an empty token still parses to nothing.
    // run_service_handler actually spawns the configured command, pipes `input` on stdin, and
    // returns trimmed stdout — the shell-out seam a real LLM CLI plugs into.
    use ct_common::channel::ServiceType::*;
    assert_eq!(parse_service_type("code_generation"), Some(CodeGeneration));
    assert_eq!(parse_service_type("security_review"), Some(SecurityReview));
    assert_eq!(parse_service_type("safety_check"), Some(SafetyCheck));
    assert_eq!(parse_service_type("text_generation"), Some(TextGeneration));
    assert_eq!(parse_service_type("not-a-real-service"), Some(Custom("not-a-real-service".to_string())), "unrecognized -> Custom, not dropped");
    assert_eq!(parse_service_type(""), None, "an empty token still parses to nothing");

    // A Custom service round-trips through the SAME shell-out handler: CT_SERVICE_TYPE is
    // set to its slugified name (ct_common::mcp::service_slug), not a fixed built-in slug.
    let out = run_service_handler(
        "echo \"got:$CT_SERVICE_TYPE\"",
        Custom("Static Analysis!".to_string()),
        "ignored",
    )
    .unwrap();
    assert_eq!(out, "got:static_analysis_", "the Custom name is slugified the same way ct_common::mcp registers its tool under");

    // `cat` echoes stdin back — proves input actually reaches the child and stdout is
    // captured + trimmed (a trailing newline from `echo`-style output must not leak through).
    let out = run_service_handler("cat", CodeGeneration, "hello from the caller").unwrap();
    assert_eq!(out, "hello from the caller");

    // CT_SERVICE_TYPE is set in the child's env so a multi-service handler can branch.
    let out = run_service_handler("echo \"got:$CT_SERVICE_TYPE\"", SecurityReview, "ignored").unwrap();
    assert_eq!(out, "got:security_review");

    // A non-zero exit surfaces as a tool error, not a panic or a silently-empty result.
    let err = run_service_handler("exit 7", TextGeneration, "x").unwrap_err();
    assert!(err.contains("exited"), "the exit status is reported: {err}");
}

#[tokio::test]
async fn call_role_service_calls_a_service_tool_over_a_duplex_and_fails_closed() {
    // #171/#173 c2 atom (frozen): the crew bridge dials a role agent's channel and calls its
    // service/<slug> tool, getting the fragment — exercised here against an IN-PROCESS serve
    // peer (a local fake, exactly the parallel dev-testing #173 asks for). A missing service
    // fails closed.
    use ct_common::channel::ServiceType;
    // A stub service that echoes a fragment-shaped output (stands in for a live LLM handler).
    let mut reg = ct_common::mcp::default_registry();
    ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
        Ok(format!("{{\"echoed\":\"{input}\"}}"))
    });
    let reg = std::sync::Arc::new(reg);
    let session = serve_local(move |req: Vec<u8>| {
        let reg = reg.clone();
        async move { reg.dispatch(&req) }
    });
    let (mut recv, mut send) = tokio::io::split(session);
    let out = call_role_service(&mut send, &mut recv, "text_generation", "a matrix theme").await.unwrap();
    assert_eq!(out, "{\"echoed\":\"a matrix theme\"}", "returns the service's output verbatim");

    // Calling a service the peer does NOT offer → JSON-RPC error → Err (fail closed, no fragment).
    let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
    let s2 = serve_local(move |req: Vec<u8>| {
        let bare = bare.clone();
        async move { bare.dispatch(&req) }
    });
    let (mut r2, mut w2) = tokio::io::split(s2);
    assert!(
        call_role_service(&mut w2, &mut r2, "safety_check", "x").await.is_err(),
        "an unoffered service fails closed"
    );
}

#[tokio::test]
async fn call_role_service_propagates_an_oversized_request_as_an_error_211() {
    // #211 (frozen): a service call whose framed request exceeds the u16 wire ceiling
    // (MAX_MESSAGE_BYTES) is rejected by `write_message` BEFORE anything is sent, and that error
    // PROPAGATES up through `call_role_service` as an `Err` (kind InvalidInput) — it is not
    // swallowed. This is exactly the error the one-shot `--call-service`/`--call` wrappers now turn
    // into a NON-ZERO process exit instead of exit-0-with-empty-stdout, so an oversized `input`
    // surfaces as a clear "message too large" rather than a cryptic downstream empty-output failure.
    let (client, _server) = tokio::io::duplex(1 << 16);
    let (mut recv, mut send) = tokio::io::split(client);
    // An `input` past the ceiling → the JSON request is even larger → write_message rejects it.
    let oversized = "x".repeat(ct_common::a2a::MAX_MESSAGE_BYTES + 1);
    let err = call_role_service(&mut send, &mut recv, "text_generation", &oversized)
        .await
        .expect_err("an oversized request must surface as an Err, not be dropped");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "the transport size rejection kind is preserved");
    assert!(
        err.to_string().contains("MAX_MESSAGE_BYTES"),
        "the error names the wire ceiling so the failure is attributable: {err}"
    );
}

#[tokio::test]
async fn channel_call_service_mode_yields_bare_service_output() {
    // #173 distributed (frozen): the initiator CT_CHANNEL_CALL_SERVICE mode's core — invoke the
    // peer's service/<slug> and return the BARE output (result.output), NOT a JSON-RPC envelope
    // (the crew bridge's CREW_*_CMD feeds this straight to ct_common::crew). Against an in-process
    // serve peer. An unoffered service fails closed (→ the bridge 502s → browser local fallback).
    use ct_common::channel::ServiceType;
    let mut reg = ct_common::mcp::default_registry();
    ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
        Ok(format!("{{\"gravity\":2200,\"note\":\"{input}\"}}"))
    });
    let reg = std::sync::Arc::new(reg);
    let peer = serve_local(move |req: Vec<u8>| {
        let reg = reg.clone();
        async move { reg.dispatch(&req) }
    });
    let out = run_service_call(peer, "text_generation", "hard matrix").await.unwrap();
    assert_eq!(out, "{\"gravity\":2200,\"note\":\"hard matrix\"}", "bare service output, no JSON-RPC envelope");

    let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
    let peer2 = serve_local(move |req: Vec<u8>| {
        let bare = bare.clone();
        async move { bare.dispatch(&req) }
    });
    assert!(
        run_service_call(peer2, "safety_check", "x").await.is_err(),
        "an unoffered service fails closed",
    );
}

#[tokio::test]
async fn persistent_call_mode_multiplexes_many_calls_over_one_held_session_19() {
    // #19 (frozen contract): ONE session, many line-framed calls, one NDJSON envelope line per
    // call, clean teardown on source EOF. This is the initiator-side counterpart of --serve:
    // the whole point is that call N+1 reuses the SAME session (no re-pairing, no re-park
    // window on the peer), so all three calls here flow over one serve_local peer.
    use ct_common::channel::ServiceType;
    let mut reg = ct_common::mcp::default_registry();
    ct_common::mcp::register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_svc, input| {
        Ok(format!("echo:{input}"))
    });
    let reg = std::sync::Arc::new(reg);
    let peer = serve_local(move |req: Vec<u8>| {
        let reg = reg.clone();
        async move { reg.dispatch(&req) }
    });

    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    let mut out: Vec<u8> = Vec::new();
    tx.send("first".into()).await.unwrap();
    tx.send("   ".into()).await.unwrap(); // blank line = no-op, must not produce output
    tx.send("second".into()).await.unwrap();
    tx.send("third with spaces".into()).await.unwrap();
    drop(tx); // stdin EOF -> clean end of run

    run_service_calls_persistent(peer, "text_generation", &mut rx, &mut out)
        .await
        .expect("source EOF is the clean end of a run");

    let lines: Vec<serde_json::Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("every response line is one JSON envelope"))
        .collect();
    assert_eq!(lines.len(), 3, "three calls -> three envelopes (blank line produced none)");
    for (envelope, expect) in lines.iter().zip(["echo:first", "echo:second", "echo:third with spaces"]) {
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["output"], expect, "bare service output inside the envelope");
    }
}

#[tokio::test]
async fn persistent_call_mode_fails_closed_with_a_structured_error_envelope_19() {
    // #19 + #211 discipline: a failed call mid-run writes {"ok":false,...} as the LAST line
    // BEFORE the Err return -- the supervising caller can attribute the failure structurally,
    // then sees the non-zero exit and retries at run granularity.
    let bare = std::sync::Arc::new(ct_common::mcp::default_registry()); // no services offered
    let peer = serve_local(move |req: Vec<u8>| {
        let bare = bare.clone();
        async move { bare.dispatch(&req) }
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    let mut out: Vec<u8> = Vec::new();
    tx.send("doomed".into()).await.unwrap();
    drop(tx);

    let err = run_service_calls_persistent(peer, "text_generation", &mut rx, &mut out).await;
    assert!(err.is_err(), "an unoffered service fails the run closed");
    let last: serde_json::Value =
        serde_json::from_str(String::from_utf8(out).unwrap().lines().last().expect("an envelope was written"))
            .expect("the last line is a JSON envelope");
    assert_eq!(last["ok"], false);
    assert!(last["error"].as_str().unwrap().len() > 0, "the error is named, not swallowed");
}

#[test]
fn serve_loop_only_for_accept_in_serve_mode() {
    // #179 (frozen): the persistent re-admit loop engages ONLY for an accept-side serve member
    // (the parking side a pipeline dials repeatedly). Truthy CT_CHANNEL_SERVE in {1,true,yes}.
    assert!(should_serve_loop(ChannelRole::Accept, Some("1")));
    assert!(should_serve_loop(ChannelRole::Accept, Some("true")));
    assert!(should_serve_loop(ChannelRole::Accept, Some(" yes ")));
    // Not the initiator (it does one call/session and exits), regardless of the env.
    assert!(!should_serve_loop(ChannelRole::Initiate, Some("1")));
    // Not a non-serve accept, and not unset/false.
    assert!(!should_serve_loop(ChannelRole::Accept, None));
    assert!(!should_serve_loop(ChannelRole::Accept, Some("0")));
    assert!(!should_serve_loop(ChannelRole::Accept, Some("false")));
}

#[test]
fn required_env_helpers_keep_the_exact_message_format() {
    // #190 (frozen): the shared req_*/opt_hex32 helpers must produce the SAME "KEY required (what)"
    // text the inlined parses used, so consolidating ~a dozen sites changed no error string and no
    // required-vs-optional semantics. A missing var still fails loudly at startup, identically.
    let empty = |_: &str| None::<String>;
    assert_eq!(req_str(&empty, "CT_X", "hint").unwrap_err(), "CT_X required (hint)");
    assert_eq!(req_hex32(&empty, "CT_K", "64 hex").unwrap_err(), "CT_K required (64 hex)");
    assert_eq!(req_key(&empty, "CT_HOLDER", "64 hex").unwrap_err(), "CT_HOLDER required (64 hex)");
    assert_eq!(opt_hex32(&empty, "CT_O"), None);
    // present + valid → the parsed value (req_key accepts any 32-byte seed).
    let full = |k: &str| match k {
        "CT_S" => Some("value".to_string()),
        "CT_H" => Some("11".repeat(32)), // 64 hex chars → [0x11; 32]
        _ => None,
    };
    assert_eq!(req_str(&full, "CT_S", "x").unwrap(), "value");
    assert_eq!(req_hex32(&full, "CT_H", "x").unwrap(), [0x11u8; 32]);
    assert_eq!(opt_hex32(&full, "CT_H"), Some([0x11u8; 32]));
    assert!(req_key(&full, "CT_H", "x").is_ok());
    // a malformed hex value is treated as absent (opt) / a required error (req) — unchanged.
    let bad = |_: &str| Some("nothex".to_string());
    assert_eq!(opt_hex32(&bad, "CT_H"), None);
    assert!(req_hex32(&bad, "CT_H", "64 hex").is_err());
}

#[test]
fn serve_concurrency_parses_the_cap_or_falls_back() {
    // #200 (frozen): a positive integer overrides; absent/blank/zero/garbage → the default.
    assert_eq!(serve_concurrency_from_env(Some("4")), 4);
    assert_eq!(serve_concurrency_from_env(Some(" 16 ")), 16);
    assert_eq!(serve_concurrency_from_env(None), DEFAULT_SERVE_CONCURRENCY);
    assert_eq!(serve_concurrency_from_env(Some("")), DEFAULT_SERVE_CONCURRENCY);
    assert_eq!(serve_concurrency_from_env(Some("0")), DEFAULT_SERVE_CONCURRENCY);
    assert_eq!(serve_concurrency_from_env(Some("lots")), DEFAULT_SERVE_CONCURRENCY);
}

#[tokio::test]
async fn serve_loop_admits_the_next_peer_while_a_slow_session_is_still_running() {
    // #200 (frozen) — THE regression this fixes. The old serve loop served a peer to
    // completion before re-admitting, so a slow handler starved every concurrent Build. Here
    // `serve` never finishes within the window; we assert the loop still admitted and STARTED
    // all five peers concurrently (proving admission no longer waits on the prior session).
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let admits = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));

    let a = admits.clone();
    let admit = move || {
        let a = a.clone();
        async move {
            let n = a.fetch_add(1, Ordering::SeqCst);
            if n < 5 {
                Ok::<usize, BoxError>(n)
            } else {
                // no more peers — park forever so the loop stops admitting
                std::future::pending::<()>().await;
                unreachable!()
            }
        }
    };
    let st = started.clone();
    let fi = finished.clone();
    let serve = move |_w: usize| {
        let st = st.clone();
        let fi = fi.clone();
        async move {
            st.fetch_add(1, Ordering::SeqCst);
            // a session that outlives the observation window (aborted at test end)
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            fi.fetch_add(1, Ordering::SeqCst);
            Ok::<(), BoxError>(())
        }
    };

    // cap high so concurrency (not the cap) is what we're testing.
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        serve_loop_concurrent(100, std::time::Duration::from_millis(10), admit, serve),
    )
    .await;

    assert!(admits.load(Ordering::SeqCst) >= 5, "admitted every peer without waiting for prior sessions");
    assert_eq!(started.load(Ordering::SeqCst), 5, "all five sessions ran concurrently");
    assert_eq!(finished.load(Ordering::SeqCst), 0, "sessions still running — admission did not block on serve");
}

#[tokio::test]
async fn serve_loop_caps_concurrency_so_a_flood_cannot_fork_bomb() {
    // #200 (frozen): the bounded-concurrency guard the issue asks for. With cap=2 and sessions
    // that never finish, only two may start; the permit is taken BEFORE parking, so the loop
    // stops admitting a third peer it has no capacity to serve (backpressure, not a dropped call).
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let admits = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));

    let a = admits.clone();
    let admit = move || {
        let a = a.clone();
        async move {
            a.fetch_add(1, Ordering::SeqCst);
            Ok::<(), BoxError>(())
        }
    };
    let st = started.clone();
    let serve = move |_w: ()| {
        let st = st.clone();
        async move {
            st.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await; // never frees its permit
            Ok::<(), BoxError>(())
        }
    };

    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        serve_loop_concurrent(2, std::time::Duration::from_millis(10), admit, serve),
    )
    .await;

    assert_eq!(started.load(Ordering::SeqCst), 2, "never exceeded the concurrency cap");
    assert_eq!(admits.load(Ordering::SeqCst), 2, "backpressure stopped admitting a peer we couldn't serve");
}

#[test]
fn admission_refusal_classification_is_typed_and_survives_rewording_20() {
    // #20 (consolidation): the classification is a DOWNCAST now, not a substring search --
    // proven by classifying an AdmissionRefused whose text deliberately contains none of the
    // historical wording. Under the old substring-only check this would silently fall back
    // to the fast retry cadence (#231's edge-flood failure mode); typed, it stays a
    // definitive refusal no matter how the operator-facing text evolves.
    let reworded: BoxError = AdmissionRefused::boxed("the peer's broker said no");
    assert!(
        is_definitive_admission_refusal(&reworded),
        "a typed AdmissionRefused classifies regardless of its display text"
    );
    // And the Display contract still emits exactly what was constructed (operators grep it).
    assert_eq!(reworded.to_string(), "the peer's broker said no");

    // The real production values are typed too -- classify + display both hold.
    let real = AdmissionRefused::boxed("edge broker refused the channel join");
    assert!(is_definitive_admission_refusal(&real));
    assert_eq!(real.to_string(), "edge broker refused the channel join");
}

#[test]
fn is_definitive_admission_refusal_matches_only_the_refused_strings() {
    // #231 + #20: the substring FALLBACK (kept one release for errors that crossed a
    // stringifying boundary) still recognizes exactly the historical strings -- everything
    // else, including the #140 stall symptom, is transient and must keep the fast retry.
    assert!(is_definitive_admission_refusal(&"edge broker refused the channel join".into()));
    assert!(is_definitive_admission_refusal(&"edge relay refused the channel join".into()));
    assert!(is_definitive_admission_refusal(
        &"edge relay refused the channel join over the :443 front door".into()
    ));
    assert!(
        !is_definitive_admission_refusal(&"channel join admission exchange stalled (#140)".into()),
        "#140 stalls are transient, not a definitive refusal"
    );
    assert!(!is_definitive_admission_refusal(&"connection reset by peer".into()));
}

#[test]
fn admission_retry_backoff_is_flat_for_transient_and_exponential_for_refused() {
    // #231: a transient error always gets the unchanged fast retry regardless of streak length
    // (a genuine CP/edge blip must keep recovering quickly, per #140's own fix).
    let base = std::time::Duration::from_millis(200);
    assert_eq!(admission_retry_backoff(base, false, 0), base);
    assert_eq!(admission_retry_backoff(base, false, 50), base, "transient errors never back off");

    // A definitive refusal doubles per consecutive occurrence...
    assert_eq!(admission_retry_backoff(base, true, 1), base * 2);
    assert_eq!(admission_retry_backoff(base, true, 2), base * 4);
    assert_eq!(admission_retry_backoff(base, true, 3), base * 8);
    // ...and is clamped at the cap instead of growing (or overflowing) without bound.
    assert_eq!(admission_retry_backoff(base, true, 100), REFUSED_ADMISSION_BACKOFF_CAP);
    assert_eq!(admission_retry_backoff(base, true, u32::MAX), REFUSED_ADMISSION_BACKOFF_CAP);
}

#[test]
fn is_flapping_session_only_flags_a_short_errored_session_250() {
    // #250: the classifier's whole job is telling "pair, then die near-instantly" (flap)
    // apart from every other outcome -- success, a fast-but-real session, or a slow failure.
    let short = FLAPPING_SESSION_THRESHOLD - std::time::Duration::from_millis(1);
    let long = FLAPPING_SESSION_THRESHOLD + std::time::Duration::from_millis(1);
    assert!(is_flapping_session(short, true), "short + errored = a flap");
    assert!(!is_flapping_session(short, false), "short + SUCCEEDED is a fast real session, not a flap");
    assert!(!is_flapping_session(long, true), "a failure that took a while is a real failure, not a flap");
    assert!(!is_flapping_session(long, false), "long + succeeded is obviously not a flap");
    // Exactly-at-threshold is NOT a flap (strict `<`) -- a session that runs the full
    // threshold did real work, it didn't die instantly.
    assert!(!is_flapping_session(FLAPPING_SESSION_THRESHOLD, true));
}

#[test]
fn flapping_session_backoff_is_exponential_and_capped_lower_than_refusal_250() {
    let base = std::time::Duration::from_millis(200);
    assert_eq!(flapping_session_backoff(base, 0), base, "zero flaps -> the unchanged fast retry");
    assert_eq!(flapping_session_backoff(base, 1), base * 2);
    assert_eq!(flapping_session_backoff(base, 2), base * 4);
    assert_eq!(flapping_session_backoff(base, 100), FLAPPING_SESSION_BACKOFF_CAP, "clamped, never overflows");
    assert!(
        FLAPPING_SESSION_BACKOFF_CAP < REFUSED_ADMISSION_BACKOFF_CAP,
        "a flap's cause can clear on its own (unlike a definitive refusal) -- keep checking sooner"
    );
}

#[tokio::test(start_paused = true)]
async fn serve_loop_concurrent_backs_off_after_repeated_flapping_sessions_then_recovers_250() {
    // #250 end-to-end (frozen contract): live-diagnosed 2026-08-13 -- admission succeeded on
    // EVERY attempt (this stub always admits), but the session died near-instantly each
    // time, and the unthrottled loop re-admitted at native speed forever (~98 cycles in 30s
    // against a real edge). This proves the loop now inserts a growing gap between the
    // (n-1)th flap's end and the nth admit, and that a session that finally SUCCEEDS resets
    // the streak so a recovered peer isn't punished by a backoff earned before it recovered.
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    let admits = std::sync::Arc::new(AtomicUsize::new(0));
    let should_succeed = std::sync::Arc::new(AtomicU32::new(0)); // flips to 1 after N flaps
    let admits2 = admits.clone();
    let admit = move || {
        admits2.fetch_add(1, Ordering::SeqCst);
        async { Ok::<(), BoxError>(()) }
    };
    let succeed_flag = should_succeed.clone();
    let serve_calls = std::sync::Arc::new(AtomicUsize::new(0));
    let serve_calls2 = serve_calls.clone();
    let serve = move |_: ()| {
        let succeed_flag = succeed_flag.clone();
        let serve_calls = serve_calls2.clone();
        async move {
            let n = serve_calls.fetch_add(1, Ordering::SeqCst);
            if n < 3 {
                // Instant death -- a flap, exactly the field-observed pattern.
                Err::<(), BoxError>("session died near-instantly".into())
            } else {
                // The 4th session "recovers": runs long enough to be a real session, then
                // succeeds -- must reset the flap streak.
                succeed_flag.store(1, Ordering::SeqCst);
                tokio::time::sleep(FLAPPING_SESSION_THRESHOLD * 2).await;
                Ok(())
            }
        }
    };
    // max=1: forces strictly serial admit -> session -> (backoff) -> next admit, matching
    // the field scenario (one channel, one fixed remote peer) with no concurrency-ordering
    // ambiguity in the test itself.
    let driver = tokio::spawn(serve_loop_concurrent(1, std::time::Duration::from_millis(50), admit, serve));

    // Let the first 3 (flapping) sessions run out and the backoff-then-4th-admit sequence
    // complete, then the 4th (recovering) session's deliberate sleep.
    for _ in 0..20 {
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
    }

    assert!(admits.load(Ordering::SeqCst) >= 4, "the loop kept making progress, not wedged");
    assert_eq!(should_succeed.load(Ordering::SeqCst), 1, "the recovering session was reached and ran");
    driver.abort();
}

#[test]
fn reject_refused_outcome_converts_refused_to_the_err_string_is_definitive_admission_refusal_recognizes() {
    // #248 live-observed bug: `admit_one_peer` used to return `Ok(ChannelJoinOutcome::Refused)`
    // for a broker round-trip whose answer was "no" — indistinguishable, at `serve_loop_concurrent`'s
    // `Ok(work) => spawn(..)` match, from a genuine admission. That spawned the refusal as a full
    // session (through channel_local()'s "--serve mode" setup) which then immediately failed
    // inside run_channel_join_with_admission with the same message — but because the OUTER loop
    // saw `Ok`, not `Err`, `consecutive_refusals` reset to 0 every time and #231's exponential
    // backoff never engaged, hot-looping at near-zero backoff exactly as #231 first fixed for the
    // transport-level case. This proves the translation: a Refused outcome becomes an Err whose
    // string `is_definitive_admission_refusal` recognizes as a definitive refusal.
    let err = reject_refused_outcome(ChannelJoinOutcome::Refused).expect_err("Refused must become an Err");
    assert!(
        is_definitive_admission_refusal(&err),
        "the translated error must be recognized as a definitive refusal so #231's backoff engages, got: {err}"
    );

    // A genuine admission passes through unchanged (not accidentally rejected).
    let admitted = ChannelJoinOutcome::Admitted {
        peer_endpoint: String::new(),
        peer_noise_pubkey: None,
        peer_holder: None,
        peer_attestation: None,
        observed_reflexive: None,
    };
    assert_eq!(
        reject_refused_outcome(admitted.clone()).unwrap(),
        admitted,
        "a real admission must pass through unchanged"
    );
}

#[tokio::test]
async fn serve_loop_never_spawns_a_refused_outcome_as_a_session() {
    // #248: the end-to-end proof that a real `Ok(Refused)` outcome — exactly what
    // `admit_one_peer` used to return before this fix — is rejected before it ever reaches
    // `serve_loop_concurrent`'s spawn path. `admit` here does what `admit_one_peer` now does
    // (call `reject_refused_outcome` on its outcome) rather than injecting a raw `Err` directly,
    // so this covers the actual translation, not just `serve_loop_concurrent`'s own dispatch.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let spawned = Arc::new(AtomicUsize::new(0));
    let admit = move || async move { reject_refused_outcome(ChannelJoinOutcome::Refused) };
    let s = spawned.clone();
    let serve = move |_w: ChannelJoinOutcome| {
        let s = s.clone();
        async move {
            s.fetch_add(1, Ordering::SeqCst);
            Ok::<(), BoxError>(())
        }
    };

    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        serve_loop_concurrent(4, std::time::Duration::from_millis(10), admit, serve),
    )
    .await;

    assert_eq!(spawned.load(Ordering::SeqCst), 0, "a refused outcome must never be spawned as a session");
}

#[tokio::test]
async fn serve_loop_backs_off_a_definitive_refusal_instead_of_hot_looping() {
    // #231 live reproduction: a holder that will never be a member (a stray/orphaned process,
    // observed on the real production edge retrying ~24-47x/second at the OLD flat 200ms
    // backoff) must not keep admitting at the fast transient-error rate — it starves other,
    // genuinely valid joins of the edge's admission capacity. With a 10ms base backoff and a
    // 300ms window, an unfixed flat retry would attempt roughly 30 times; the exponential
    // backoff must land far fewer.
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let attempts = Arc::new(AtomicUsize::new(0));
    let a = attempts.clone();
    let admit = move || {
        let a = a.clone();
        async move {
            a.fetch_add(1, Ordering::SeqCst);
            Err::<(), BoxError>("edge broker refused the channel join".into())
        }
    };
    let serve = move |_w: ()| async move { Ok::<(), BoxError>(()) };

    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        serve_loop_concurrent(4, std::time::Duration::from_millis(10), admit, serve),
    )
    .await;

    let n = attempts.load(Ordering::SeqCst);
    assert!(n >= 1, "attempted admission at least once");
    assert!(n < 10, "exponential backoff kept the refused holder well under the flat-retry rate, got {n} attempts");
}

#[tokio::test]
async fn crew_build_over_runs_the_crew_and_fails_closed() {
    // #171/#173 c2 driver (frozen): safety_check → physics → art over three role channels,
    // assembled by ct_common::crew. Exercised against in-process serve peers (local fakes).
    use ct_common::channel::ServiceType;
    fn peer(services: &[ServiceType], out: &str) -> tokio::io::DuplexStream {
        let mut reg = ct_common::mcp::default_registry();
        let out = out.to_string();
        ct_common::mcp::register_service_tools(&mut reg, services, move |_svc, _input| Ok(out.clone()));
        let reg = std::sync::Arc::new(reg);
        serve_local(move |req: Vec<u8>| {
            let reg = reg.clone();
            async move { reg.dispatch(&req) }
        })
    }
    let auction: Vec<ct_common::crew::RoleAuction> = vec![];

    // Happy path: safety OK → physics + art fragments assemble into a built config.
    let safety = peer(&[ServiceType::SafetyCheck], r#"{"ok":true,"reason":""}"#);
    let physics = peer(&[ServiceType::TextGeneration], r#"{"gravity":2200,"flapPower":420,"pipeGap":115,"pipeSpeed":220}"#);
    let art = peer(&[ServiceType::TextGeneration], r##"{"theme":"night","birdColor":"#00ff41","birdEmoji":"🕶️","title":"Neo"}"##);
    let resp = crew_build_over("matrix theme", safety, physics, art, auction.clone()).await.unwrap();
    assert!(resp.safety.ok, "built when safety passes");
    let cfg = resp.config.as_ref().expect("built carries config");
    assert_eq!((cfg.speed, cfg.jump, cfg.gap), (220, 420, 115), "physics fragment mapped");
    assert_eq!(cfg.bird_emoji, "🕶️", "art fragment carried (emoji intact)");

    // Safety reject → Ok(rejected), no build.
    let safety_r = peer(&[ServiceType::SafetyCheck], r#"{"ok":false,"reason":"anti-prompt"}"#);
    let p2 = peer(&[ServiceType::TextGeneration], "{}");
    let a2 = peer(&[ServiceType::TextGeneration], "{}");
    let rej = crew_build_over("evil", safety_r, p2, a2, auction.clone()).await.unwrap();
    assert!(!rej.safety.ok && rej.config.is_none(), "safety reject carries no build");

    // A role unreachable (bare peer offers no service) → Err → the c3 layer 5xx's → browser falls back.
    let safety3 = peer(&[ServiceType::SafetyCheck], r#"{"ok":true}"#);
    let bare = std::sync::Arc::new(ct_common::mcp::default_registry());
    let physics3 = serve_local(move |req: Vec<u8>| {
        let bare = bare.clone();
        async move { bare.dispatch(&req) }
    });
    let a3 = peer(&[ServiceType::TextGeneration], "{}");
    assert!(crew_build_over("x", safety3, physics3, a3, auction).await.is_err(), "an unreachable role → Err (fail closed)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn dispatching_a_blocking_service_handler_does_not_starve_the_async_runtime_248() {
    // #248-follow: live-reproduced this exact bug against production -- a registered
    // CT_AGENT_SERVICE_HANDLER_CMD (even a near-instant one) made the responder's own
    // reply never reach the initiator ("early eof"), and under different timing a
    // completely unrelated channel's own admission exchange stalled for the full #140
    // window while this one was blocked. Root cause: `registry.dispatch(&req)` is
    // synchronous, and calling it inline inside an `async move { .. }` block (no
    // `spawn_blocking`) blocks whichever Tokio worker thread is running it for the
    // service handler subprocess's whole wall-clock duration.
    //
    // Single worker thread makes this deterministic: with the bug, a slow dispatch
    // occupies the ONLY worker, so a concurrent unrelated task can't run until it's
    // done. With the fix (spawn_blocking), the blocking work moves to Tokio's separate
    // blocking-pool, leaving the one async worker free.
    use ct_common::channel::ServiceType;
    use ct_common::mcp::{register_service_tools, ToolRegistry};

    let mut reg = ToolRegistry::new();
    register_service_tools(&mut reg, &[ServiceType::TextGeneration], |_service, input| {
        std::thread::sleep(std::time::Duration::from_millis(300));
        Ok(input.to_string())
    });
    let registry = std::sync::Arc::new(reg);

    let req = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "service/text_generation", "arguments": {"input": "x"}}
    }))
    .unwrap();

    // The exact pattern this fix applies in `channel_local()`'s --serve construction.
    let dispatch_task = {
        let registry = registry.clone();
        tokio::spawn(async move {
            tokio::task::spawn_blocking(move || registry.dispatch(&req)).await.unwrap_or_default()
        })
    };

    // A cheap, unrelated async task that should complete almost immediately if the
    // single worker thread is actually free to run it concurrently.
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let concurrent_elapsed = start.elapsed();

    let resp = dispatch_task.await.unwrap();
    assert!(!resp.is_empty(), "dispatch still produces a real response");

    assert!(
        concurrent_elapsed < std::time::Duration::from_millis(150),
        "an unrelated concurrent task took {concurrent_elapsed:?} to complete a 10ms sleep \
         -- the blocking dispatch starved the runtime's only worker thread instead of \
         running on the blocking-thread pool"
    );
}

#[test]
fn run_service_handler_does_not_deadlock_on_input_larger_than_the_pipe_buffer() {
    // #149-A.1 serve-wiring (frozen, regression from review): writing stdin inline then calling
    // wait_with_output() is the classic std::process pipe deadlock — an `input` over the OS pipe
    // buffer (~64 KiB) whose handler (`cat`) writes to stdout before it has drained stdin blocks
    // both sides forever. A consumer fully controls `input`'s size, so this was a remote DoS on
    // the provider, not just a footgun. 200 KiB comfortably exceeds every common pipe buffer size.
    // Bounded by the test harness's own timeout — a real deadlock here means the test hangs, not
    // panics, which is exactly the failure mode being guarded against.
    use ct_common::channel::ServiceType::CodeGeneration;
    let big = "x".repeat(200_000);
    let out = run_service_handler("cat", CodeGeneration, &big).unwrap();
    assert_eq!(out, big, "the full oversized input round-trips without hanging");
}

#[test]
fn run_service_handler_kills_and_errors_a_child_that_exceeds_its_timeout() {
    // #149-A.1 serve-wiring (frozen, regression from review): every other blocking step in this
    // file is timed; this closes the one that wasn't. A handler that never exits (simulating a
    // stalled LLM API call / wedged subprocess) must be killed and reported as a timeout, not
    // block the caller forever. Uses the injectable-timeout seam (a real 120s wait would make
    // this test itself the problem it's guarding against).
    use ct_common::channel::ServiceType::CodeGeneration;
    let start = std::time::Instant::now();
    let err = run_service_handler_with_timeout(
        "sleep 30",
        CodeGeneration,
        "x",
        std::time::Duration::from_millis(300),
    )
    .unwrap_err();
    assert!(err.contains("timed out"), "the timeout is reported: {err}");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "the call returns promptly after the timeout, not after the child's own 30s sleep: {:?}",
        start.elapsed()
    );
}

#[test]
fn run_service_handler_errors_instead_of_silently_succeeding_on_empty_stdout() {
    // #206 (frozen): every shipped handler script (ingredients/presentation/art/physics) prints
    // either its real result or a hardcoded fallback on EVERY code path, under `set -uo pipefail`
    // (no `-e`) specifically so an internal failure still reaches one of those prints. So exit-0
    // with empty stdout is never a legitimate handler result — only a process torn down externally
    // between spawn and its final print (this function's own timeout path already returns Err
    // before ever reaching here, so it can't be the source). Before this fix, `Ok("")` flowed on as
    // a "successful" fragment and blew up downstream as a cryptic `serde_json` "EOF while parsing a
    // value" instead of an honest, attributable error at the source.
    use ct_common::channel::ServiceType::CodeGeneration;
    let err = run_service_handler("true", CodeGeneration, "x").unwrap_err();
    assert!(
        err.contains("no output"),
        "empty-but-successful stdout must be reported as an error, got: {err}"
    );
}

#[test]
fn timeout_kills_the_whole_process_group_not_just_the_immediate_child() {
    // #183 Finding 1 (frozen): the handler scripts shell out to a real LLM CLI as a GRANDCHILD of
    // the `sh -c`. Killing only the `sh` pid on timeout leaves a backgrounded grandchild running
    // (costed, unbounded) as an orphan. This handler BACKGROUNDS a grandchild that would create a
    // marker file AFTER a sleep, while the foreground `sh` sleeps so the call times out. With a
    // process-GROUP kill the grandchild dies too and the marker never appears; the pre-fix
    // single-pid kill would let it survive and touch the marker. Distinguishes the fix, not just
    // the current behaviour.
    use ct_common::channel::ServiceType::TextGeneration;
    let marker = std::env::temp_dir().join(format!(
        "ct-183-pgkill-{}-{:?}.marker",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_file(&marker);
    let m = marker.to_string_lossy().replace('\'', "");
    // background grandchild: after 4s, touch the marker; foreground sleeps so the call times out.
    let cmd = format!("(sleep 4; : > '{m}') & sleep 4");
    let err = run_service_handler_with_timeout(
        &cmd,
        TextGeneration,
        "",
        std::time::Duration::from_millis(500),
    )
    .unwrap_err();
    assert!(err.contains("timed out"), "expected a timeout error, got: {err}");
    // Wait past the grandchild's own 4s sleep; if the group kill worked, the marker never appears.
    std::thread::sleep(std::time::Duration::from_secs(6));
    let survived = marker.exists();
    let _ = std::fs::remove_file(&marker);
    assert!(
        !survived,
        "a backgrounded grandchild survived the timeout kill — the process group was not killed (#183)"
    );
}

#[test]
fn resolve_socket_addr_takes_ip_literals_and_resolves_hostnames_214() {
    use std::net::SocketAddr;
    // #214: a literal IP:port is taken as-is (no resolver), so the common case + tests are
    // resolver-free and deterministic.
    assert_eq!(
        resolve_socket_addr("57.131.133.91:4433").unwrap(),
        "57.131.133.91:4433".parse::<SocketAddr>().unwrap(),
        "an IP:port literal parses unchanged"
    );
    // A host:port hostname resolves via DNS. `localhost` always resolves to a loopback address
    // without any network (hermetic), so this exercises the resolution path deterministically —
    // this is exactly what previously failed with "invalid socket address syntax".
    let resolved = resolve_socket_addr("localhost:4433").expect("localhost:port resolves");
    assert!(resolved.ip().is_loopback(), "localhost resolves to loopback, got {resolved}");
    assert_eq!(resolved.port(), 4433, "the port is preserved through resolution");
    // A bare host with NO port is a clear error (fast, no slow DNS), not an opaque parse failure.
    let err = resolve_socket_addr("bunsenbrenner.org").expect_err("a host with no port is rejected");
    assert!(err.contains("no IP:port") || err.contains("host:port"), "the error is descriptive: {err}");
}

#[test]
fn channel_join_cli_config_parses_the_plane_one_liner() {
    // #98 / #103: the plane-brokered one-liner's config contract — broker + relay
    // addrs, the operator-signed grant (hex), the holder + Noise keys, and the
    // advertised endpoint. Round-trips a real grant through decode.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ed25519_dalek::Signer;
    let op = SigningKey::from_bytes(&[7u8; 32]);
    let holder = SigningKey::from_bytes(&[0x11u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId([0xABu8; 32]),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant_hex = hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());
    let hk = "1111111111111111111111111111111111111111111111111111111111111111";
    let nk = "2222222222222222222222222222222222222222222222222222222222222222";
    let base: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_ROLE", "initiate".into()),
        ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
        ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
        ("CT_CHANNEL_LISTEN", "203.0.113.5:7000".into()),
        ("CT_CHANNEL_GRANT", grant_hex),
        ("CT_CHANNEL_HOLDER_KEY", hk.into()),
        ("CT_CHANNEL_NOISE_KEY", nk.into()),
    ];
    let lookup = |pairs: &[(&str, String)]| {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
    };
    let cfg = lookup(&base).expect("plane-brokered config parses");
    assert_eq!(cfg.role, ChannelRole::Initiate);
    assert_eq!(cfg.broker_addr, "203.0.113.5:9443".parse().unwrap());
    assert_eq!(cfg.relay_addr, "203.0.113.5:9444".parse().unwrap());
    assert_eq!(cfg.listen_addr, "203.0.113.5:7000".parse().unwrap());
    assert_eq!(cfg.grant.grant.channel, ChannelId([0xABu8; 32]), "the grant round-trips through decode");

    // Each required field is enforced.
    for drop_key in ["CT_CHANNEL_BROKER", "CT_CHANNEL_RELAY", "CT_CHANNEL_GRANT", "CT_CHANNEL_HOLDER_KEY", "CT_CHANNEL_LISTEN"] {
        let pruned: Vec<(&str, String)> = base.iter().filter(|(k, _)| *k != drop_key).cloned().collect();
        assert!(lookup(&pruned).is_err(), "missing {drop_key} must be rejected");
    }

    // #173 (frozen): a relay-only member has no dialable address, so CT_CHANNEL_LISTEN is
    // OPTIONAL when CT_CHANNEL_RELAY_ONLY=1 — dropping it must NOT error (both source-2 and sink
    // hit the old hard-error and had to supply a dummy). It parses as relay-only with an unbound
    // placeholder listen address that's never used.
    let mut relay_only_no_listen: Vec<(&str, String)> =
        base.iter().filter(|(k, _)| *k != "CT_CHANNEL_LISTEN").cloned().collect();
    relay_only_no_listen.push(("CT_CHANNEL_RELAY_ONLY", "1".into()));
    let ro = lookup(&relay_only_no_listen).expect("relay-only needs no CT_CHANNEL_LISTEN (#173)");
    assert!(ro.relay_only, "explicit CT_CHANNEL_RELAY_ONLY=1 is relay-only");
    assert_eq!(ro.listen_addr, SocketAddr::from(([0, 0, 0, 0], 0)), "unbound placeholder listen");

    // #106: without a front door, the dial ladder is direct-only.
    assert_eq!(cfg.front_door, None);
    assert_eq!(
        cfg.broker_ladder(),
        vec![ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), kind: ChannelDialKind::Direct }]
    );

    // With CT_CHANNEL_FRONT_DOOR set, each ladder tries the direct port then the :443
    // front door (the fallback for networks that block the channel ports).
    let mut with_fd = base.clone();
    with_fd.push(("CT_CHANNEL_FRONT_DOOR", "203.0.113.5:443".into()));
    let cfg = lookup(&with_fd).expect("front-door config parses");
    assert_eq!(cfg.front_door, Some("203.0.113.5:443".parse().unwrap()));
    assert_eq!(
        cfg.broker_ladder(),
        vec![
            ChannelDialRung { endpoint: "203.0.113.5:9443".parse().unwrap(), kind: ChannelDialKind::Direct },
            ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoor },
            ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoorBoring },
        ],
        "broker: direct, then the :443 front door, then the same :443 with a boring ClientHello"
    );
    assert_eq!(
        cfg.relay_ladder(),
        vec![
            ChannelDialRung { endpoint: "203.0.113.5:9444".parse().unwrap(), kind: ChannelDialKind::Direct },
            ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoor },
            ChannelDialRung { endpoint: "203.0.113.5:443".parse().unwrap(), kind: ChannelDialKind::FrontDoorBoring },
        ],
        "relay falls back the same way"
    );

    // #106 boring-alpn: the DPI-resistant rung is strictly LAST -- on any network where
    // the existing rungs work it is never reached, so this is purely additive.
    let boring: Vec<usize> = cfg
        .broker_ladder()
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == ChannelDialKind::FrontDoorBoring)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(boring, vec![2], "exactly one boring rung, and it is the last one tried");
    assert_eq!(
        cfg.broker_ladder()[2].endpoint,
        cfg.broker_ladder()[1].endpoint,
        "the boring rung reuses the SAME :443 endpoint -- only its ClientHello differs"
    );

    // A set-but-malformed front door is a hard error (a typo must not silently drop it).
    let mut bad_fd = base.clone();
    bad_fd.push(("CT_CHANNEL_FRONT_DOOR", "not-an-addr".into()));
    assert!(lookup(&bad_fd).is_err(), "malformed CT_CHANNEL_FRONT_DOOR rejected");

    // A host:port hostname resolves, exactly like CT_CHANNEL_BROKER/CT_CHANNEL_RELAY
    // already do (#214) -- a real regression: this used to be a bare SocketAddr parse
    // with no resolver, so a compose-network service name like "edge:443" failed with
    // "invalid socket address syntax" even though the identical hostname worked fine
    // for CT_CHANNEL_BROKER/CT_CHANNEL_RELAY on the same line.
    let mut hostname_fd = base.clone();
    hostname_fd.push(("CT_CHANNEL_FRONT_DOOR", "localhost:443".into()));
    let cfg = lookup(&hostname_fd).expect("a host:port hostname resolves for the front door too");
    assert!(cfg.front_door.expect("front door set").ip().is_loopback(), "localhost resolves to loopback");

    // CT_CHANNEL_ADVERTISE absent -> advertise_addr defaults to listen_addr, unchanged
    // behavior from before this field existed.
    assert_eq!(cfg.advertise_addr, cfg.listen_addr, "advertise defaults to listen when unset");
}

#[test]
fn channel_advertise_address_splits_bind_from_dial_target() {
    // A containerized accept-side member binds a private/unspecified address
    // (CT_CHANNEL_LISTEN=0.0.0.0:7000, works inside any container) but is reached at
    // a different, real public one (CT_CHANNEL_ADVERTISE, e.g. a Docker port-published
    // <public-ip>:<port>) -- mirrors CT_AGENT_DIRECT_ADVERTISE's existing split for the
    // Browser-Plane tunnel path. Relay-only auto-detection and the peer-facing
    // admission endpoint must both follow the ADVERTISED address, not the bind one.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ed25519_dalek::Signer;
    let op = SigningKey::from_bytes(&[8u8; 32]);
    let holder = SigningKey::from_bytes(&[0x22u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId([0xCDu8; 32]),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Accept,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant_hex = hex_encode(&SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }.encode());
    let hk = "3333333333333333333333333333333333333333333333333333333333333333";
    let nk = "4444444444444444444444444444444444444444444444444444444444444444";
    let base: Vec<(&str, String)> = vec![
        ("CT_CHANNEL_ROLE", "accept".into()),
        ("CT_CHANNEL_BROKER", "203.0.113.5:9443".into()),
        ("CT_CHANNEL_RELAY", "203.0.113.5:9444".into()),
        ("CT_CHANNEL_LISTEN", "0.0.0.0:7000".into()),
        ("CT_CHANNEL_GRANT", grant_hex),
        ("CT_CHANNEL_HOLDER_KEY", hk.into()),
        ("CT_CHANNEL_NOISE_KEY", nk.into()),
    ];
    let lookup = |pairs: &[(&str, String)]| {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        ChannelJoinCliConfig::from_lookup(move |k| m.get(k).cloned())
    };

    // Bind is 0.0.0.0:7000 (not globally routable) and no CT_CHANNEL_ADVERTISE is set ->
    // auto-detected relay-only, exactly as before this field existed.
    let cfg = lookup(&base).expect("binds on 0.0.0.0 without an advertise override");
    assert!(cfg.relay_only, "an unspecified bind with no advertise override is relay-only");

    // With a real public CT_CHANNEL_ADVERTISE, the member is dialable: relay_only is
    // false, the bind address is unchanged (still 0.0.0.0:7000, what the process
    // actually binds), and the admission endpoint sent to the broker is the
    // ADVERTISED address, not the bind address.
    let mut with_adv = base.clone();
    with_adv.push(("CT_CHANNEL_ADVERTISE", "203.0.113.9:7000".into()));
    let cfg = lookup(&with_adv).expect("advertise override parses");
    assert!(!cfg.relay_only, "a globally-routable advertise override is directly dialable");
    assert_eq!(cfg.listen_addr, "0.0.0.0:7000".parse().unwrap(), "bind address is unchanged");
    assert_eq!(cfg.advertise_addr, "203.0.113.9:7000".parse().unwrap());

    // A set-but-malformed advertise override is a hard error (a typo must not
    // silently fall back to the unroutable bind address).
    let mut bad_adv = base.clone();
    bad_adv.push(("CT_CHANNEL_ADVERTISE", "not-an-addr".into()));
    assert!(lookup(&bad_adv).is_err(), "malformed CT_CHANNEL_ADVERTISE rejected");

    // #104: CT_CHANNEL_DIRECT_UPGRADE absent -> off, unchanged behavior from before
    // this option existed.
    assert!(!cfg.direct_upgrade, "direct-upgrade defaults to off");

    let mut with_upgrade = base.clone();
    with_upgrade.push(("CT_CHANNEL_DIRECT_UPGRADE", "1".into()));
    let cfg = lookup(&with_upgrade).expect("direct-upgrade opt-in parses");
    assert!(cfg.direct_upgrade, "CT_CHANNEL_DIRECT_UPGRADE=1 opts in");
}

#[test]
fn channel_config_parses_roles_keys_and_the_initiator_cert_requirement() {
    // #98/#100: the one-liner's config contract. A responder needs no peer cert;
    // an initiator does. Bad role / missing key / bad addr are rejected.
    let acc = cfg_from(&[
        ("CT_CHANNEL_ROLE", "accept"),
        ("CT_CHANNEL_ADDR", "0.0.0.0:9000"),
        ("CT_CHANNEL_NOISE_KEY", K64),
        ("CT_CHANNEL_PEER_NOISE_KEY", K64),
    ])
    .expect("responder config is valid without a peer cert");
    assert_eq!(acc.role, ChannelRole::Accept);
    assert_eq!(acc.addr, "0.0.0.0:9000".parse().unwrap());
    assert!(acc.peer_cert_der.is_none());

    // Initiator without a cert is valid (dials accept-any; Noise authenticates);
    // a hex cert, if given, is parsed and pinned.
    let base = [
        ("CT_CHANNEL_ROLE", "initiate"),
        ("CT_CHANNEL_ADDR", "203.0.113.9:9000"),
        ("CT_CHANNEL_NOISE_KEY", K64),
        ("CT_CHANNEL_PEER_NOISE_KEY", K64),
    ];
    let no_cert = cfg_from(&base).expect("initiator without a cert is valid (accept-any dial)");
    assert!(no_cert.peer_cert_der.is_none());
    let mut with_cert = base.to_vec();
    with_cert.push(("CT_CHANNEL_PEER_CERT", "deadbeef"));
    let init = cfg_from(&with_cert).expect("initiator with a cert is valid");
    assert_eq!(init.peer_cert_der.as_deref(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));

    // Rejections.
    assert!(cfg_from(&[("CT_CHANNEL_ROLE", "bogus"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad role");
    assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "not-an-addr"), ("CT_CHANNEL_NOISE_KEY", K64), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad addr");
    assert!(cfg_from(&[("CT_CHANNEL_ROLE", "accept"), ("CT_CHANNEL_ADDR", "0.0.0.0:1"), ("CT_CHANNEL_NOISE_KEY", "tooshort"), ("CT_CHANNEL_PEER_NOISE_KEY", K64)]).is_err(), "bad key");
}

#[tokio::test]
async fn runner_pipes_local_data_over_the_a2a_tunnel() {
    // #72 AF4-session-wire / #98: the runnable path. Two agents each call
    // run_channel_session with their role over a REAL QUIC connection, each
    // handing it a LOCAL duplex. Bytes written to the initiator's local side come
    // out of the responder's local side — plaintext in, plaintext out, encrypted
    // A2A tunnel in between. This is exactly what the CLI wires to stdin/stdout.
    let initiator = generate_static_keypair();
    let responder = generate_static_keypair();
    let resp_priv = responder.private;
    let init_priv = initiator.private;
    let resp_pub = responder.public;

    let (server, cert) = build_server_endpoint_with_cert().expect("server");
    let addr = server.local_addr().expect("addr");

    // Responder: accept the connection, run the Accept side, pump its local end.
    let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
    let resp_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
            .await
            .expect("responder session");
    });

    // Initiator: dial, run the Initiate side (pinning the responder key), pump local.
    let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
    let client = build_client_endpoint(cert).expect("client");
    let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
    let init_task = tokio::spawn(async move {
        run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
            .await
            .expect("initiator session");
        // hold the connection until the pump finishes
    });

    // Drive it: write a payload into the initiator's local side; the pump
    // forwards it, so exactly those bytes come out of the responder's local side.
    // (Read the exact length rather than to-EOF: both pumps stay open for the
    // reverse direction, so there is no EOF to wait on here.)
    let payload = b"data flowing agent A -> agent B over the channel";
    init_local_test.write_all(payload).await.expect("write local");
    init_local_test.flush().await.expect("flush local");

    let mut got = vec![0u8; payload.len()];
    resp_local_test.read_exact(&mut got).await.expect("read peer local");
    assert_eq!(got, payload, "the responder's local side receives exactly what A sent");

    init_task.abort();
    resp_task.abort();
}

// A minimal edge-broker stand-in that admits one join and acks a fixed peer
// endpoint + Noise key. It replicates the broker wire protocol (length-framed
// request, possession challenge, `OK <endpoint> <noise_hex>`) but omits the
// `safe_endpoint` SSRF gate — which is tested in `ct_edge::channel_broker` and
// would (correctly) reject the loopback address a hermetic test must use.
async fn stub_broker_admit(
    server: &Endpoint,
    peer_addr: std::net::SocketAddr,
    peer_noise: [u8; 32],
    peer_holder: [u8; 32],
    peer_attestation: [u8; 64],
) {
    let conn = server.accept().await.expect("incoming").await.expect("conn");
    let (mut send, mut recv) = conn.accept_bi().await.expect("accept_bi");
    let mut len = [0u8; 2];
    recv.read_exact(&mut len).await.expect("len");
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    recv.read_exact(&mut buf).await.expect("req");
    send.write_all(&[0u8; 32]).await.expect("challenge"); // possession challenge
    let mut sig = [0u8; 64];
    let _ = recv.read_exact(&mut sig).await; // (signature not checked by the stub)
    // Ack the attested-key triple the real broker relays (#101).
    let ack = format!(
        "OK {} {} {} {}",
        peer_addr,
        hex_encode(&peer_noise),
        hex_encode(&peer_holder),
        hex_encode(&peer_attestation)
    );
    send.write_all(ack.as_bytes()).await.expect("ack");
    send.finish().expect("finish");
    conn.closed().await;
}

#[tokio::test]
async fn channel_join_initiator_uses_the_rendezvous_peer_and_pipes_data() {
    // #72 AF4 / #100 hands-off capstone: run_channel_join presents to the broker,
    // takes the peer endpoint AND Noise key from the ack (no out-of-band value),
    // dials the peer (accept-any), and pipes data. Here the peer is a real
    // responder listener; the stub broker supplies its addr+key.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    // Responder: a real direct listener running the Accept side of the session.
    let responder_noise = generate_static_keypair();
    let (resp_listener, _c) = crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
    let resp_addr = resp_listener.local_addr().expect("resp addr");
    let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
    let rnp = responder_noise.private;
    let resp_task = tokio::spawn(async move {
        let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
        run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
            .await
            .expect("responder session");
    });

    // Stub broker: admits the initiator and relays the responder's addr + key.
    let (broker_ep, broker_cert) = build_server_endpoint_with_cert().expect("broker");
    let broker_addr = broker_ep.local_addr().expect("broker addr");
    let rnpub = responder_noise.public;
    // The stub relays the responder's attested-key triple (#101): a holder that
    // signs the responder's Noise key for the initiator's channel.
    let resp_holder = SigningKey::from_bytes(&[0x44u8; 32]);
    let resp_hpub = resp_holder.verifying_key().to_bytes();
    let resp_att = resp_holder
        .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId([0xD0u8; 32]), &resp_hpub, &rnpub))
        .to_bytes();
    let broker_task = tokio::spawn(async move {
        stub_broker_admit(&broker_ep, resp_addr, rnpub, resp_hpub, resp_att).await
    });

    // Initiator: run_channel_join over a connection to the (stub) broker.
    let initiator_noise = generate_static_keypair();
    let op = SigningKey::from_bytes(&[7u8; 32]);
    let holder = SigningKey::from_bytes(&[0x11u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId([0xD0u8; 32]),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
    let req = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };
    let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
    let inp = initiator_noise.private;
    let a_task = tokio::spawn(async move {
        let c = build_client_endpoint(broker_cert).expect("client");
        let conn = c.connect(broker_addr, "localhost").expect("cfg").await.expect("conn");
        // Direct dial succeeds here (the stub broker gives a real responder addr),
        // so relay_conn is unused — reuse the broker conn; timeouts don't fire.
        run_channel_join(
            &conn,
            &conn,
            &req,
            &holder,
            ChannelRole::Initiate,
            &inp,
            None,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            a_local_run,
        )
        .await
    });

    // Data flows initiator -> responder with zero out-of-band key/cert exchange.
    let payload = b"hands-off: peer addr + Noise key came from the rendezvous ack";
    a_local_test.write_all(payload).await.expect("write");
    a_local_test.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    resp_local_test.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "the responder receives the initiator's data, keyed only via rendezvous");

    a_task.abort();
    resp_task.abort();
    broker_task.abort();
}

#[tokio::test]
async fn run_channel_join_with_admission_runs_the_direct_session_from_a_443_ladder_admission() {
    // #106 client-dial-wire (frozen): the seam the plane CLI now uses. The AGENT
    // admits over the broker LADDER — a DEAD direct rung (blocked channel port) then a
    // real `:443` TLS-TCP front door driven by the production
    // `ct_edge::channel_broker::admit_channel_join_on_duplex` gate — and the resulting
    // ChannelJoinOutcome drives run_channel_join_with_admission's DIRECT data path to a
    // real responder. Broker admission is thereby decoupled from (and reachable over
    // `:443` independently of) the direct/relay data legs; data flows with zero
    // out-of-band key/cert exchange. (The QUIC relay handle is present but unused — the
    // direct dial succeeds — since the relay-leg-over-`:443` is the ⏳ follow slice.)
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::admit_channel_join_on_duplex;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert, build_tcp_tls_listener_at};
    use ed25519_dalek::Signer;
    use tokio::io::AsyncWriteExt;

    let channel = [0x6Au8; 32];

    // Responder: a real direct listener running the Accept side of the session.
    let responder_noise = generate_static_keypair();
    let (resp_listener, _c) =
        crate::transport::build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
    let resp_addr = resp_listener.local_addr().expect("resp addr");
    let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
    let rnp = responder_noise.private;
    let resp_task = tokio::spawn(async move {
        let conn = resp_listener.accept().await.expect("incoming").await.expect("conn");
        run_channel_session(&conn, ChannelRole::Accept, &rnp, &[0u8; 32], resp_local_run)
            .await
            .expect("responder session");
    });

    // The responder's attested-key triple (#101) the front door relays in its ack, so
    // the initiator pins the responder's Noise key with nothing conveyed out-of-band.
    let resp_holder = SigningKey::from_bytes(&[0x44u8; 32]);
    let resp_hpub = resp_holder.verifying_key().to_bytes();
    let resp_npub = responder_noise.public;
    let resp_att = resp_holder
        .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &resp_hpub, &resp_npub))
        .to_bytes();

    // Operator-signed initiator grant; the front door authorizes it under op_pub.
    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder = SigningKey::from_bytes(&[0x11u8; 32]);
    let g = ChannelGrant {
        channel: ChannelId(channel),
        holder: holder.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let grant = SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() };
    // The advertised endpoint must be a SAFE (non-loopback) dialable addr for admission.
    let request = ChannelJoinRequest { grant, endpoint: "203.0.113.1:7001".to_string() };

    // A real `:443`-style TLS-TCP edge front door: admit the join over the duplex, then
    // ack the responder's addr + attested Noise triple (as the rendezvous broker would).
    let (fd_listener, acceptor, edge_cert) =
        build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap()).await.expect("tls-tcp listener");
    let fd_addr = fd_listener.local_addr().expect("front-door addr");
    let edge = tokio::spawn(async move {
        let (tcp, peer) = fd_listener.accept().await.expect("accept tcp");
        let tls = acceptor.accept(tcp).await.expect("tls accept");
        let (mut stream, _req, _op, _noise, _attest, _observed) = admit_channel_join_on_duplex(
            tls,
            peer,
            500u64, // now < expires_at (1_000)
            std::time::Duration::from_secs(5),
            &move |c: ChannelId, _h: [u8; 32]| {
                let ok = c.0 == channel;
                async move { ok.then_some((op_pub, None, None)) }
            },
        )
        .await
        .expect("admit over the :443 TLS-TCP duplex");
        let ack = format!(
            "OK {} {} {} {}",
            resp_addr,
            hex_encode(&resp_npub),
            hex_encode(&resp_hpub),
            hex_encode(&resp_att)
        );
        stream.write_all(ack.as_bytes()).await.expect("ack");
        stream.shutdown().await.expect("shutdown");
    });

    // The broker ladder: a DEAD direct rung (closed UDP port → the QUIC dial is
    // Unreachable) then the LIVE `:443` front door.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let rungs = vec![
        ChannelDialRung { endpoint: dead_addr, kind: ChannelDialKind::Direct },
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
    ];

    // Admit over the ladder: direct is Unreachable → the `:443` front door completes it.
    let admission = present_channel_join_via_ladder(
        &rungs,
        &request,
        &holder,
        edge_cert,
        std::time::Duration::from_millis(400),
    )
    .await
    .expect("admitted over the :443 front door after the dead direct rung");

    // A scratch (unused) QUIC relay handle — the direct dial succeeds, so it is never
    // touched; the outcome-driven data path still requires a `&Connection` for the leg.
    let (scratch_ep, scratch_cert) = build_server_endpoint_with_cert().expect("scratch relay ep");
    let scratch_addr = scratch_ep.local_addr().expect("scratch addr");
    tokio::spawn(async move {
        if let Some(inc) = scratch_ep.accept().await {
            let _ = inc.await;
        }
    });
    let sc = build_client_endpoint(scratch_cert).expect("scratch client");
    let unused_relay = sc.connect(scratch_addr, "localhost").expect("cfg").await.expect("scratch conn");

    // The outcome-driven data path dials the responder directly and pumps bytes.
    let initiator_noise = generate_static_keypair();
    let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
    let inp = initiator_noise.private;
    let a_task = tokio::spawn(async move {
        run_channel_join_with_admission(
            admission,
            RelayFallback::Quic(&unused_relay),
            &request,
            &holder,
            ChannelRole::Initiate,
            &inp,
            None,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            a_local_run,
            false,
        )
        .await
    });

    // Data flows initiator -> responder: `:443` broker admission + direct data leg.
    let payload = b"admitted over :443, then piped over the direct A2A session";
    a_local_test.write_all(payload).await.expect("write");
    a_local_test.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    resp_local_test.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "the responder receives the initiator's data (admitted over :443, direct data leg)");

    edge.await.expect("edge task");
    a_task.abort();
    resp_task.abort();
}

#[tokio::test]
async fn agents_tunnel_a_noise_session_over_the_edge_relay() {
    // #72 AF4-session-resilience CAPSTONE — the connection-difficulty case that
    // matters: two agents that can't reach each other directly both fall back to
    // the edge RELAY endpoint, run a real Noise_IK session over the relayed stream,
    // and application data flows THROUGH the edge (the edge only sees ciphertext).
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::broker_channel_relay;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
    let channel = [0xE1u8; 32];
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
    let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

    // Edge relay endpoint pairs + splices the two members.
    let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
    let relay_addr = relay_ep.local_addr().expect("addr");
    let relay_task = tokio::spawn(async move {
        broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
            (c.0 == channel).then_some((op_pub, None, None))
        })
        .await
        .map(|_| ())
    });

    // Both agents fall back to the relay (they never reach each other directly).
    let cert_b = cert.clone();
    let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
    let (na, nbpub) = (noise_a.private, noise_b.public);
    let a = tokio::spawn(async move {
        let c = build_client_endpoint(cert).expect("client");
        let conn = c.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
        join_via_relay(&conn, &req_a, &holder_a, ChannelRole::Initiate, &na, &nbpub, a_local_run, None).await
    });
    let (nb, napub) = (noise_b.private, noise_a.public);
    let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
    let b = tokio::spawn(async move {
        let c = build_client_endpoint(cert_b).expect("client");
        let conn = c.connect(relay_addr, "localhost").expect("cfg").await.expect("conn");
        join_via_relay(&conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &napub, b_local_run, None).await
    });

    // Application data flows A -> B over the relayed, encrypted A2A tunnel.
    let payload = b"tunnel carried over the edge relay when direct was blocked";
    a_local_test.write_all(payload).await.expect("write");
    a_local_test.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    b_local_test.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "B receives A's data via the edge relay (Noise stays E2E)");

    a.abort();
    b.abort();
    relay_task.abort();
}

#[tokio::test]
async fn join_via_relay_ladder_falls_back_to_the_443_front_door_and_forms_the_noise_tunnel() {
    // #106 relay-leg-443 (frozen): the relay-leg analog of the `:443` broker fallback,
    // and the capstone for a fully `:443`-only member. BOTH members' relay ladders have
    // a DEAD direct rung (the relay port is FILTERED → the QUIC dial is Unreachable) then
    // a LIVE `:443` TLS-TCP front door driven by the PRODUCTION edge relay path
    // (`admit_and_pair_on_stream` → `finish_relay_pair_over_streams`). Each member walks
    // `join_via_relay_ladder`, falls through the dead direct rung, presents its join over
    // `:443` WITHOUT consuming the stream, and runs the Noise_IK session over that SAME
    // relay-spliced stream. A real payload round-trips BOTH directions — proving a member
    // whose relay port is also blocked relays end-to-end over `:443` (the #103 sink),
    // Noise staying end-to-end (the edge splices ciphertext only).
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::{
        admit_and_pair_on_stream, finish_relay_pair_over_streams, ChannelPairer,
    };
    use ct_edge::transport::build_tcp_tls_listener_at;
    use ed25519_dalek::Signer;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
    let channel = [0xE4u8; 32];
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    // Advertised endpoints must be SAFE (non-loopback) to pass the admission gate, even
    // though the relay leg never dials them (the members can't be dialed — that's why
    // they relay).
    let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
    let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

    // A real `:443`-style TLS-TCP edge front door: admit two independently-arriving
    // members, correlate them by channel, and relay-splice the two `:443` duplexes —
    // the production front-door relay path (#106).
    let (listener, acceptor, edge_cert) = build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
        .await
        .expect("tls-tcp listener");
    let fd_addr = listener.local_addr().expect("front-door addr");
    let edge = tokio::spawn(async move {
        let pairer: Mutex<ChannelPairer<_>> = Mutex::new(ChannelPairer::new());
        let authorize =
            move |c: ChannelId, _h: [u8; 32]| async move { (c.0 == channel).then_some((op_pub, None, None)) };
        let mut paired = None;
        for _ in 0..2 {
            let (tcp, peer) = listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            if let Some((x, y)) = admit_and_pair_on_stream(
                tls,
                peer,
                500u64, // now < expires_at (1_000)
                Duration::from_secs(5),
                &authorize,
                10_000u64, // parked-member deadline (never reached in this test)
                &pairer,
            )
            .await
            .expect("admit + pair the :443 member")
            {
                paired = Some((x, y));
            }
        }
        let (x, y) = paired.expect("two same-channel members paired over :443");
        finish_relay_pair_over_streams(x, y, 500u64).await.expect("relay-splice the two :443 duplexes");
    });

    // Each member's relay ladder: a DEAD direct rung (closed UDP port → the QUIC relay
    // dial is Unreachable) then the LIVE `:443` front door.
    let dead = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead); // nothing on that UDP port -> the direct QUIC relay dial is Unreachable
    let rungs = vec![
        ChannelDialRung { endpoint: dead_addr, kind: ChannelDialKind::Direct },
        ChannelDialRung { endpoint: fd_addr, kind: ChannelDialKind::FrontDoor },
    ];

    // Two members drive `join_via_relay_ladder`: A initiates, B accepts. Each pins the
    // peer's Noise key directly (the relay leg conveys no peer material).
    let (mut a_app, a_local) = duplex(16 * 1024);
    let (mut b_app, b_local) = duplex(16 * 1024);
    let (na, nbpub) = (noise_a.private, noise_b.public);
    let rungs_a = rungs.clone();
    let cert_a = edge_cert.clone();
    let a = tokio::spawn(async move {
        join_via_relay_ladder(
            &rungs_a,
            cert_a,
            Duration::from_millis(400),
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &na,
            &nbpub,
            a_local,
            None,
        )
        .await
    });
    let (nb, napub) = (noise_b.private, noise_a.public);
    let b = tokio::spawn(async move {
        join_via_relay_ladder(
            &rungs,
            edge_cert,
            Duration::from_millis(400),
            &req_b,
            &holder_b,
            ChannelRole::Accept,
            &nb,
            &napub,
            b_local,
            None,
        )
        .await
    });

    // A -> B over the `:443`-relayed, encrypted A2A tunnel.
    a_app.write_all(b"ping-A-to-B").await.expect("a writes");
    let mut got = [0u8; 11];
    b_app.read_exact(&mut got).await.expect("b reads A's bytes");
    assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B over the :443 relay");

    // B -> A (reverse direction proves the splice is full-duplex).
    b_app.write_all(b"pong-B-to-A").await.expect("b writes");
    let mut got2 = [0u8; 11];
    a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
    assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A over the :443 relay");

    // Closing both local sides tears the sessions down cleanly (noise_pump shuts down
    // each transport write half → graceful TLS close_notify → the relay sees EOF).
    drop(a_app);
    drop(b_app);
    let _ = a.await.expect("initiator task joins");
    let _ = b.await.expect("acceptor task joins");
    edge.await.expect("edge relay task joins");
}

#[tokio::test]
async fn two_443_only_members_learn_each_others_noise_key_and_form_the_tunnel() {
    // #122 (frozen): the bug that broke EVERY `:443`-only two-party join. Two members
    // FORCED onto the public `:443` front door (relay/broker ports unreachable), each with
    // FRESHLY + independently generated channel keys and grants — NO pre-shared peer Noise
    // key, no reliance on any prior broker-admission step. Each drives the join over the
    // PRODUCTION relay-splice path (`admit_and_pair_on_stream` → `finish_relay_pair_over_
    // streams`) and MUST learn the OTHER's attested Noise key FROM THE ACK itself
    // (`Admitted.peer_noise_pubkey == Some(peer key)`), verify the #101 attestation, pin it,
    // and form the Noise_IK tunnel — a real payload crossing BOTH directions. Before the
    // fix the relay acked a bare `OK` conveying no key, so `peer_noise_pubkey` was `None`
    // and the join failed at the pin step (channel_run.rs). So this test FAILS against the
    // bare-`OK` code and PASSES once the ack carries the peer's attested key.
    use ct_common::channel::{
        member_noise_attest_bytes, verify_member_noise_attestation, ChannelGrant, ChannelId,
        Direction, Rights, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY,
    };
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::{
        admit_and_pair_on_stream, finish_relay_pair_over_streams, ChannelPairer,
    };
    use ct_edge::transport::build_tcp_tls_listener_at;
    use ed25519_dalek::Signer;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};

    let op = SigningKey::from_bytes(&[0x5Au8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let channel = [0xC2u8; 32];
    // Fresh, independent identities per member — nothing pre-shared between them.
    let holder_a = SigningKey::from_bytes(&[0x2au8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x2bu8; 32]);
    let ha_pub = holder_a.verifying_key().to_bytes();
    let hb_pub = holder_b.verifying_key().to_bytes();
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let (na, na_pub) = (noise_a.private, noise_a.public);
    let (nb, nb_pub) = (noise_b.private, noise_b.public);
    // Each member attests its OWN Noise key under its holder key (#101).
    let attest_a = holder_a
        .sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &na_pub))
        .to_bytes();
    let attest_b = holder_b
        .sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &nb_pub))
        .to_bytes();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    // Both are `:443`-only — they advertise the relay-only sentinel (they can't be dialed).
    let req_a = ChannelJoinRequest {
        grant: signed(&holder_a, Direction::Initiate),
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };
    let req_b = ChannelJoinRequest {
        grant: signed(&holder_b, Direction::Accept),
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };

    // The PRODUCTION `:443` front door: admit two independently-arriving members, correlate
    // them by channel, and relay-splice the two duplexes. The `authorize` closure resolves
    // each member to its OWN (operator, Noise key, attestation) — exactly as the CP-backed
    // registry does — so the relay finisher has the material to relay each side the OTHER's
    // attested key.
    let (listener, acceptor, edge_cert) =
        build_tcp_tls_listener_at("127.0.0.1:0".parse().unwrap())
            .await
            .expect("tls-tcp listener");
    let fd_addr = listener.local_addr().expect("front-door addr");
    let edge = tokio::spawn(async move {
        let pairer: Mutex<ChannelPairer<_>> = Mutex::new(ChannelPairer::new());
        let authorize = move |c: ChannelId, h: [u8; 32]| async move {
            if c.0 != channel {
                return None;
            }
            let (noise, attest) =
                if h == ha_pub { (na_pub, attest_a) } else { (nb_pub, attest_b) };
            Some((op_pub, Some(noise), Some(attest)))
        };
        let mut paired = None;
        for _ in 0..2 {
            let (tcp, peer) = listener.accept().await.expect("accept tcp");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            if let Some((x, y)) = admit_and_pair_on_stream(
                tls,
                peer,
                500u64,
                Duration::from_secs(5),
                &authorize,
                10_000u64,
                &pairer,
            )
            .await
            .expect("admit + pair the :443 member")
            {
                paired = Some((x, y));
            }
        }
        let (x, y) = paired.expect("two same-channel members paired over :443");
        finish_relay_pair_over_streams(x, y, 500u64)
            .await
            .expect("relay-splice the two :443 duplexes");
    });

    let (mut a_app, a_local) = duplex(16 * 1024);
    let (mut b_app, b_local) = duplex(16 * 1024);
    let cert_a = edge_cert.clone();
    // A: connect over `:443`, present the join WITHOUT consuming the stream, LEARN B's
    // attested Noise key from the ack, verify #101, pin it, run the session on the SAME
    // relay-spliced stream.
    let a = tokio::spawn(async move {
        let stream = crate::transport::tcp_tls_connect_channel(fd_addr, cert_a)
            .await
            .expect("A tls-tcp connect");
        let (mut recv, mut send) = split(stream);
        let outcome = present_channel_relay_join_on_stream(&mut send, &mut recv, &req_a, &holder_a, None)
            .await
            .expect("A relay join");
        let peer_noise = match outcome {
            ChannelJoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation, .. } => {
                let n = peer_noise_pubkey.expect("A learns B's Noise key from the ack (#122)");
                assert_eq!(n, nb_pub, "A learns B's REAL Noise key from the ack");
                let ph = peer_holder.expect("A learns B's holder from the ack");
                let att = peer_attestation.expect("A learns B's attestation from the ack");
                assert!(
                    verify_member_noise_attestation(&ChannelId(channel), &ph, &n, &att),
                    "B's #101 attestation verifies against its grant-authenticated holder"
                );
                n
            }
            other => panic!("A's :443 join must be Admitted, got {other:?}"),
        };
        run_channel_session_on_stream(send, recv, ChannelRole::Initiate, &na, &peer_noise, a_local).await
    });
    // B: the mirror (Accept role), learning A's key from its ack.
    let b = tokio::spawn(async move {
        let stream = crate::transport::tcp_tls_connect_channel(fd_addr, edge_cert)
            .await
            .expect("B tls-tcp connect");
        let (mut recv, mut send) = split(stream);
        let outcome = present_channel_relay_join_on_stream(&mut send, &mut recv, &req_b, &holder_b, None)
            .await
            .expect("B relay join");
        let peer_noise = match outcome {
            ChannelJoinOutcome::Admitted { peer_noise_pubkey, peer_holder, peer_attestation, .. } => {
                let n = peer_noise_pubkey.expect("B learns A's Noise key from the ack (#122)");
                assert_eq!(n, na_pub, "B learns A's REAL Noise key from the ack");
                let ph = peer_holder.expect("B learns A's holder from the ack");
                let att = peer_attestation.expect("B learns A's attestation from the ack");
                assert!(
                    verify_member_noise_attestation(&ChannelId(channel), &ph, &n, &att),
                    "A's #101 attestation verifies against its grant-authenticated holder"
                );
                n
            }
            other => panic!("B's :443 join must be Admitted, got {other:?}"),
        };
        run_channel_session_on_stream(send, recv, ChannelRole::Accept, &nb, &peer_noise, b_local).await
    });

    // A -> B over the `:443`-relayed, encrypted A2A tunnel keyed on the ACK-LEARNED keys.
    a_app.write_all(b"ping-A-to-B").await.expect("a writes");
    let mut got = [0u8; 11];
    b_app.read_exact(&mut got).await.expect("b reads A's bytes");
    assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B (key learned from the ack)");

    // B -> A (reverse direction proves the splice is full-duplex).
    b_app.write_all(b"pong-B-to-A").await.expect("b writes");
    let mut got2 = [0u8; 11];
    a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
    assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A over the :443 relay");

    drop(a_app);
    drop(b_app);
    a.await.expect("A task joins").expect("A session ok");
    b.await.expect("B task joins").expect("B session ok");
    edge.await.expect("edge relay task joins");
}

#[tokio::test]
async fn run_channel_join_auto_falls_back_to_the_relay_when_direct_is_blocked() {
    // #72 AF4-relay-orchestrate: the auto-recovery. The rendezvous hands the
    // initiator a peer endpoint that BLACKHOLES (bound-but-silent), so the direct
    // dial times out (Unreachable) and run_channel_join transparently falls back to
    // the edge relay where the responder waits — the tunnel carries data with NO
    // caller intervention.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::broker_channel_relay;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
    let channel = [0xE2u8; 32];
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
    let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

    // A bound-but-silent UDP socket: the direct dial to it blackholes -> times out.
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").expect("blackhole");
    let blackhole_addr = blackhole.local_addr().expect("bh addr");

    // Stub rendezvous: hands the initiator the blackhole addr + B's Noise key.
    let (rdv_ep, rdv_cert) = build_server_endpoint_with_cert().expect("rdv");
    let rdv_addr = rdv_ep.local_addr().expect("rdv addr");
    let nb_pub = noise_b.public;
    // B's attested-key triple, verified by run_channel_join before it falls back.
    let hb_pub = holder_b.verifying_key().to_bytes();
    let b_att = holder_b
        .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &nb_pub))
        .to_bytes();
    let rdv_task = tokio::spawn(async move {
        stub_broker_admit(&rdv_ep, blackhole_addr, nb_pub, hb_pub, b_att).await
    });

    // Real relay endpoint.
    let (relay_ep, relay_cert) = build_server_endpoint_with_cert().expect("relay");
    let relay_addr = relay_ep.local_addr().expect("relay addr");
    let relay_task = tokio::spawn(async move {
        broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
            (c.0 == channel).then_some((op_pub, None, None))
        })
        .await
        .map(|_| ())
    });

    // Initiator via run_channel_join: direct -> blackhole -> Unreachable -> relay.
    let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
    let na = noise_a.private;
    let relay_cert_a = relay_cert.clone();
    let a = tokio::spawn(async move {
        let bc = build_client_endpoint(rdv_cert).expect("bc");
        let broker_conn = bc.connect(rdv_addr, "localhost").expect("cfg").await.expect("bconn");
        let rc = build_client_endpoint(relay_cert_a).expect("rc");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn");
        run_channel_join(
            &broker_conn,
            &relay_conn,
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &na,
            None,
            std::time::Duration::from_millis(400), // short dial timeout -> fast fallback
            std::time::Duration::from_secs(2),
            a_local_run,
        )
        .await
    });

    // Responder joins the relay directly (its own listen-timeout fallback is covered
    // by run_channel_join's Accept branch; here it goes straight to the relay).
    let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
    let nb = noise_b.private;
    let nap = noise_a.public;
    let b = tokio::spawn(async move {
        let rc = build_client_endpoint(relay_cert).expect("rc b");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
        join_via_relay(&relay_conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &nap, b_local_run, None).await
    });

    let payload = b"auto-recovered onto the relay after the direct path was blocked";
    a_local_test.write_all(payload).await.expect("write");
    a_local_test.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    b_local_test.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "the tunnel auto-recovered via the relay with no caller intervention");

    a.abort();
    b.abort();
    rdv_task.abort();
    relay_task.abort();
    drop(blackhole);
}

#[tokio::test]
async fn quic_lazy_relay_dials_only_on_fallback_and_forms_the_tunnel() {
    // #103 fix (frozen): RelayFallback::QuicLazy holds NO idle relay connection during
    // admission/direct-dial — it dials the relay only when the direct path fails. Prove
    // the lazily-dialed relay still forms the tunnel end to end. (The eager Quic variant
    // held an idle connection the edge reaped as a spurious pre-admission close.)
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::broker_channel_relay;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
    let channel = [0xE4u8; 32];
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    let req_a = ChannelJoinRequest { grant: signed(&holder_a, Direction::Initiate), endpoint: "203.0.113.1:7001".to_string() };
    let req_b = ChannelJoinRequest { grant: signed(&holder_b, Direction::Accept), endpoint: "203.0.113.2:7002".to_string() };

    // Blackhole direct peer -> the Initiate direct dial times out (Unreachable) -> relay.
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").expect("blackhole");
    let blackhole_addr = blackhole.local_addr().expect("bh addr");
    let hb_pub = holder_b.verifying_key().to_bytes();
    let b_att = holder_b
        .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public))
        .to_bytes();
    // Pre-computed admission (blackhole peer + B's attested Noise key) — no rendezvous stub.
    let admission = ChannelJoinOutcome::Admitted {
        peer_endpoint: blackhole_addr.to_string(),
        peer_noise_pubkey: Some(noise_b.public),
        peer_holder: Some(hb_pub),
        peer_attestation: Some(b_att),
        observed_reflexive: None,
    };

    // Real relay endpoint.
    let (relay_ep, relay_cert) = build_server_endpoint_with_cert().expect("relay");
    let relay_addr = relay_ep.local_addr().expect("relay addr");
    let relay_task = tokio::spawn(async move {
        broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
            (c.0 == channel).then_some((op_pub, None, None))
        })
        .await
        .map(|_| ())
    });

    // Initiator: run_channel_join_with_admission with the LAZY relay — direct blackhole
    // -> Unreachable -> QuicLazy dials relay_addr on demand.
    let (mut a_local_test, a_local_run) = tokio::io::duplex(8192);
    let na = noise_a.private;
    let a = tokio::spawn(async move {
        run_channel_join_with_admission(
            admission,
            RelayFallback::QuicLazy(relay_addr),
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &na,
            None,
            std::time::Duration::from_millis(400),
            std::time::Duration::from_secs(2),
            a_local_run,
            false,
        )
        .await
    });

    // Responder waits on the relay.
    let (mut b_local_test, b_local_run) = tokio::io::duplex(8192);
    let nb = noise_b.private;
    let nap = noise_a.public;
    let b = tokio::spawn(async move {
        let rc = build_client_endpoint(relay_cert).expect("rc b");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
        join_via_relay(&relay_conn, &req_b, &holder_b, ChannelRole::Accept, &nb, &nap, b_local_run, None).await
    });

    let payload = b"lazily-dialed relay carries the tunnel (#103)";
    a_local_test.write_all(payload).await.expect("write");
    a_local_test.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    b_local_test.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "the lazily-dialed relay formed the tunnel");

    a.abort();
    b.abort();
    relay_task.abort();
    drop(blackhole);
}

#[tokio::test]
async fn run_channel_join_rejects_a_peer_key_with_a_bad_attestation() {
    // #101 SEC101c-ii: if the relayed peer Noise key's attestation doesn't verify
    // against the peer's holder (a DB-substituted key), run_channel_join REFUSES to
    // pin it — it errors before establishing any session.
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_common::noise::generate_static_keypair;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    let op = SigningKey::from_bytes(&[7u8; 32]);
    let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
    let channel = [0xE3u8; 32];
    let g = ChannelGrant {
        channel: ChannelId(channel),
        holder: holder_a.verifying_key().to_bytes(),
        direction: Direction::Initiate,
        rights: Rights::ReadWrite,
        delegable: false,
        expires_at: 1_000,
    };
    let req_a = ChannelJoinRequest {
        grant: SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() },
        endpoint: "203.0.113.1:7001".to_string(),
    };

    // The stub relays a peer key + holder, but an attestation over a DIFFERENT key
    // (as a tampered DB would produce) — it must not verify.
    let peer_holder = SigningKey::from_bytes(&[0x55u8; 32]);
    let peer_hpub = peer_holder.verifying_key().to_bytes();
    let peer_noise = generate_static_keypair().public;
    let bad_attest = peer_holder
        .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &peer_hpub, &[0u8; 32]))
        .to_bytes();

    let (rdv_ep, rdv_cert) = build_server_endpoint_with_cert().expect("rdv");
    let rdv_addr = rdv_ep.local_addr().expect("addr");
    let rdv_task = tokio::spawn(async move {
        stub_broker_admit(&rdv_ep, "203.0.113.9:9000".parse().unwrap(), peer_noise, peer_hpub, bad_attest).await
    });

    let bc = build_client_endpoint(rdv_cert).expect("bc");
    let broker_conn = bc.connect(rdv_addr, "localhost").expect("cfg").await.expect("conn");
    let noise_a = generate_static_keypair();
    let (_t, local) = tokio::io::duplex(64);
    let result = run_channel_join(
        &broker_conn,
        &broker_conn,
        &req_a,
        &holder_a,
        ChannelRole::Initiate,
        &noise_a.private,
        None,
        std::time::Duration::from_millis(200),
        std::time::Duration::from_secs(1),
        local,
    )
    .await;
    assert!(result.is_err(), "a peer key with a bad attestation is rejected before pinning (#101)");
    rdv_task.abort();
}

#[tokio::test]
async fn direct_dial_to_an_unreachable_peer_fails_fast_as_unreachable() {
    // #72 AF4-session-resilience — THE case that matters: a peer that can't be
    // reached on the direct path (NAT/firewall/blackhole). The dial must classify
    // as `Unreachable` (the relay-fallback signal) and fail FAST, not hang on the
    // QUIC handshake's retransmits. A bound-but-silent UDP socket blackholes the
    // handshake (the port is "open", so no ICMP reject short-circuits it).
    use std::time::{Duration, Instant};
    let sink = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sink");
    let addr = sink.local_addr().expect("sink addr"); // occupied, never answers QUIC

    let start = Instant::now();
    let result = dial_peer_direct(addr, Duration::from_millis(400)).await;
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(ChannelDialError::Unreachable)),
        "an unreachable peer classifies as Unreachable (relay-fallback signal), got {result:?}"
    );
    assert!(elapsed < Duration::from_secs(2), "failed fast in {elapsed:?}, did not hang");
    drop(sink);
}

#[tokio::test]
async fn initiator_dials_without_a_pre_shared_cert_noise_authenticates() {
    // #100 self-containment: the initiator uses the accept-any channel dialer, so
    // NO transport cert is conveyed — only the peer's Noise key. The responder
    // self-signs (a cert the initiator has never seen); the A2A session still
    // forms and data flows, because Noise_IK is the real mutual auth.
    use crate::transport::{build_channel_dialer, build_direct_listener_at};
    let initiator = generate_static_keypair();
    let responder = generate_static_keypair();
    let resp_priv = responder.private;
    let init_priv = initiator.private;
    let resp_pub = responder.public;

    let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
    let addr = server.local_addr().expect("addr");

    let (mut resp_local_test, resp_local_run) = tokio::io::duplex(8192);
    let resp_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_local_run)
            .await
            .expect("responder session");
    });

    let (mut init_local_test, init_local_run) = tokio::io::duplex(8192);
    let endpoint = build_channel_dialer().expect("dialer");
    // Dial with NO peer cert — the accept-any verifier trusts the transport.
    let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
    let init_task = tokio::spawn(async move {
        run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_local_run)
            .await
            .expect("initiator session");
    });

    let payload = b"self-contained: no transport cert was conveyed";
    init_local_test.write_all(payload).await.expect("write");
    init_local_test.flush().await.expect("flush");
    let mut got = vec![0u8; payload.len()];
    resp_local_test.read_exact(&mut got).await.expect("read");
    assert_eq!(got, payload, "data flows without a pre-shared transport cert");

    init_task.abort();
    resp_task.abort();
}

#[tokio::test]
async fn large_transfer_is_not_truncated_when_the_sender_tears_down_after_the_session(
) {
    // #134 (frozen): a large A2A transfer must be delivered in FULL even when the sending
    // agent drops the connection the instant its session returns (the real bug: the process
    // exits right after the pump FINs). quinn `finish()` only queues the FIN; without waiting
    // for the peer's acknowledgement, the userspace QUIC driver dies on connection-drop and
    // the unacked tail is silently lost (the sink saw clean 144/224 KiB prefixes of a 588 KB
    // payload). `run_channel_session`'s send-drain (`stopped()`) is what closes that hole —
    // it returns only once the peer has acknowledged every byte, so the drop below is safe.
    use crate::transport::{build_channel_dialer, build_direct_listener_at};
    use ct_common::noise::generate_static_keypair;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let initiator = generate_static_keypair();
    let responder = generate_static_keypair();
    let (init_priv, resp_priv, resp_pub) = (initiator.private, responder.private, responder.public);

    // ~1 MiB — well past the ~144 KiB first-flight/window where the truncation was observed.
    let payload: Vec<u8> = (0..(1024u32 * 1024)).map(|i| (i % 251) as u8).collect();
    let len = payload.len();

    let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
    let addr = server.local_addr().expect("addr");

    // Responder: accept, run the Accept session, and collect exactly `len` delivered bytes.
    // Its local read half is closed at once (no responder→initiator app data), so its own
    // send direction FINs immediately; we read the payload out concurrently to open flow
    // control. We do NOT await the responder session (its own drain would wait on the
    // now-gone initiator) — read_exact of the full length is the delivery assertion.
    let resp_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        let (resp_run, resp_test) = tokio::io::duplex(64 * 1024);
        let (mut resp_test_r, resp_test_w) = tokio::io::split(resp_test);
        drop(resp_test_w); // responder→initiator app source EOF
        let _sess = tokio::spawn(async move {
            let _ = run_channel_session(&conn, ChannelRole::Accept, &resp_priv, &[0u8; 32], resp_run).await;
            // keep `conn` alive for the session's lifetime, then drop
            drop(conn);
        });
        let mut got = vec![0u8; len];
        let r = resp_test_r.read_exact(&mut got).await;
        (r.is_ok(), got)
    });

    // Initiator: dial, feed the whole payload then EOF the source, run the session to
    // completion (which now blocks on the delivery ack), THEN drop the connection+endpoint
    // — simulating the process exiting the moment the transfer "finished".
    let endpoint = build_channel_dialer().expect("dialer");
    let conn = endpoint.connect(addr, "localhost").expect("cfg").await.expect("conn");
    let (init_run, init_test) = tokio::io::duplex(64 * 1024);
    let (init_test_r, mut init_test_w) = tokio::io::split(init_test);
    drop(init_test_r); // no initiator←responder app data
    let feeder = tokio::spawn(async move {
        init_test_w.write_all(&payload).await.expect("feed payload");
        init_test_w.flush().await.expect("flush");
        drop(init_test_w); // source EOF → initiator outbound FINs
        payload
    });

    run_channel_session(&conn, ChannelRole::Initiate, &init_priv, &resp_pub, init_run)
        .await
        .expect("initiator session");
    // The drain has returned → the peer acknowledged every byte. Now tear the sender down
    // as abruptly as a process exit would.
    drop(conn);
    drop(endpoint);

    let expected = feeder.await.expect("feeder");
    let (ok, got) = tokio::time::timeout(std::time::Duration::from_secs(20), resp_task)
        .await
        .expect("responder collected within 20s")
        .expect("responder task");
    assert!(ok, "the full {len}-byte payload was delivered (no truncation) despite the abrupt sender teardown (#134)");
    assert_eq!(got, expected, "delivered bytes are byte-exact and complete");
}

#[tokio::test]
async fn open_channel_streams_bounds_a_stalled_setup_instead_of_hanging() {
    // #139 (frozen): after dial_peer_direct connects, open_bi/accept_bi were unbounded — a QUIC
    // conn that handshaked then went dead hung the direct-session setup forever with no relay
    // fallback. `open_channel_streams` bounds it. Here the client connects but NEVER opens the
    // channel bi-stream, so the server's accept_bi would hang; the bound turns that into a fast
    // `TimedOut`, which lets the direct path fall back to the relay instead of wedging.
    use crate::transport::{build_channel_dialer, build_direct_listener_at};
    let (server, _cert) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("listener");
    let addr = server.local_addr().expect("addr");

    let srv = tokio::spawn(async move {
        let conn = server.accept().await.expect("incoming").await.expect("conn");
        let start = std::time::Instant::now();
        let r = open_channel_streams(&conn, ChannelRole::Accept, std::time::Duration::from_millis(300)).await;
        (r.as_ref().err().map(|e| e.kind()), r.is_ok(), start.elapsed())
    });

    // Connect and hold the connection open, but NEVER open a bi-stream.
    let dialer = build_channel_dialer().expect("dialer");
    let _conn = dialer.connect(addr, "localhost").expect("cfg").await.expect("conn");

    let (kind, ok, elapsed) = tokio::time::timeout(std::time::Duration::from_secs(5), srv)
        .await
        .expect("the bounded setup returns within 5s (a hang here is the #139 regression)")
        .expect("join");
    assert!(!ok, "a stalled stream setup errors, it does not hang or succeed");
    assert_eq!(kind, Some(std::io::ErrorKind::TimedOut), "the stall is reported as TimedOut (#139)");
    assert!(elapsed < std::time::Duration::from_secs(2), "the bound fires fast (~300ms), not after a long wait");
}

#[tokio::test]
async fn upgradable_session_refuses_a_private_direct_target_and_stays_byte_exact_on_relay() {
    // #104 wire-in + #137 SSRF guard (frozen): two agents run an UPGRADABLE A2A session over a
    // relay quinn conn. The initiator advertises a direct listener bound on LOOPBACK
    // (`127.0.0.1`), so the #137 guard (`upgrade_safe_endpoint` = the edge's `is_global_unicast`
    // filter) correctly REFUSES the responder's dial of that peer-conveyed internal endpoint —
    // the session stays on the relay and the payload still arrives byte-exact. This proves the
    // SSRF guard (a) blocks a private/internal upgrade target and (b) does not break delivery.
    // (The full relay→direct upgrade over a *global-unicast* target can't run on loopback — that
    // is H4's live cross-NAT proof; the pure upgrade mechanics are covered by the ct-common
    // orchestration + DCUtR tests.)
    use crate::transport::{build_channel_dialer, build_direct_listener_at};
    use ct_common::noise::generate_static_keypair;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let a = generate_static_keypair(); // channel initiator
    let b = generate_static_keypair(); // channel responder
    let (a_priv, a_pub, b_priv, b_pub) = (a.private, a.public, b.private, b.public);
    let dt = std::time::Duration::from_secs(5);

    // Relay leg: the responder is the quinn server, the initiator connects to it.
    let (relay_server, _rc) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("relay listener");
    let relay_addr = relay_server.local_addr().expect("relay addr");
    // The initiator's direct listener (the responder dials this to upgrade).
    let (direct_listener, _dc) = build_direct_listener_at("127.0.0.1:0".parse().unwrap()).expect("direct listener");
    let direct_addr = direct_listener.local_addr().expect("direct addr").to_string();

    // Responder: accept the relay conn, run the upgradable Accept session, collect the payload.
    let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
    let len = payload.len();
    let resp = tokio::spawn(async move {
        let relay_conn = relay_server.accept().await.expect("incoming").await.expect("relay conn");
        let (resp_app, resp_test) = tokio::io::duplex(1 << 16);
        let (mut resp_out, _w) = tokio::io::split(resp_test);
        let sess = tokio::spawn(async move {
            let _ = run_channel_session_upgradable(
                &relay_conn, ChannelRole::Accept, &b_priv, &a_pub, resp_app, None, None, dt,
            )
            .await;
            drop(relay_conn);
        });
        let mut got = vec![0u8; len];
        let ok = resp_out.read_exact(&mut got).await.is_ok();
        sess.abort();
        (ok, got)
    });

    // Initiator: dial the relay, run the upgradable Initiate session with its direct listener.
    let dialer = build_channel_dialer().expect("dialer");
    let relay_conn = dialer.connect(relay_addr, "localhost").expect("cfg").await.expect("relay conn");
    let (init_app, init_test) = tokio::io::duplex(1 << 16);
    let (_r, mut init_feed) = tokio::io::split(init_test);
    let init = tokio::spawn(async move {
        run_channel_session_upgradable(
            &relay_conn,
            ChannelRole::Initiate,
            &a_priv,
            &b_pub,
            init_app,
            Some(direct_listener),
            Some(direct_addr),
            dt,
        )
        .await
    });

    init_feed.write_all(&payload).await.unwrap();
    init_feed.flush().await.unwrap();
    init_feed.shutdown().await.unwrap();

    let (ok, got) = tokio::time::timeout(std::time::Duration::from_secs(20), resp)
        .await
        .expect("responder within 20s")
        .expect("responder task");
    assert!(ok, "the full {len}-byte payload was delivered across the upgradable session");
    assert_eq!(got, payload, "relay→direct upgrade over real quinn delivered a byte-exact stream (#104)");
    init.abort();
}

#[test]
fn relay_only_mode_forces_on_explicitly_and_auto_detects_a_non_routable_listen_addr() {
    // #121 (frozen): the pure relay-only decision. The explicit CT_CHANNEL_RELAY_ONLY flag
    // always forces relay-only (even with a routable address); otherwise a member
    // auto-detects relay-only when its advertised listen address is not globally routable
    // (a NAT-only / private-address-only host the edge would refuse to advertise, #94), and
    // stays direct-capable only with a real global-unicast address. It decides from the
    // address alone — no network interfaces touched — so it is deterministically testable.
    assert!(
        relay_only_mode(true, "203.0.113.10:7000".parse().unwrap()),
        "the explicit flag forces relay-only even for a routable address"
    );
    // Auto-detect: private / loopback / unspecified / CGNAT / link-local / ULA => relay-only.
    for private in [
        "10.0.0.5:7000",
        "192.168.1.9:7000",
        "172.16.0.1:7000",
        "127.0.0.1:7000",
        "0.0.0.0:7000",
        "100.64.0.1:7000",
        "169.254.1.1:7000",
        "[fc00::1]:7000",
        "[fe80::1]:7000",
    ] {
        assert!(relay_only_mode(false, private.parse().unwrap()), "{private} auto-detects relay-only");
    }
    // A real global-unicast address stays direct-capable (not forced relay-only).
    for routable in ["203.0.113.10:7000", "8.8.8.8:7000", "[2001:4860:4860::8888]:7000"] {
        assert!(!relay_only_mode(false, routable.parse().unwrap()), "{routable} stays direct-capable");
    }
}

#[test]
fn parse_circuit_relay_is_optional_and_rejects_a_malformed_multiaddr() {
    // #136 N-wire (frozen): CT_CHANNEL_CIRCUIT_RELAY is the libp2p circuit-relay for the DCUtR
    // punch. Absent/blank => None (plain relay session, no punch); a valid multiaddr parses;
    // a malformed value is an error (a typo must not silently disable the hole-punch).
    assert_eq!(parse_circuit_relay(None), Ok(None));
    assert_eq!(parse_circuit_relay(Some("   ".to_string())), Ok(None));

    // A valid Circuit-Relay v2 multiaddr (relay TCP addr + /p2p-circuit) parses + round-trips.
    let ma = "/ip4/203.0.113.1/tcp/4001/p2p-circuit";
    let parsed = parse_circuit_relay(Some(ma.to_string())).expect("valid multiaddr parses");
    assert_eq!(parsed.map(|m| m.to_string()), Some(ma.to_string()));

    // A malformed value fails config load (not silently dropped).
    assert!(parse_circuit_relay(Some("not-a-multiaddr".to_string())).is_err());
}

#[tokio::test]
async fn build_upgrade_candidate_binds_an_ephemeral_listener_only_when_reflexive_is_known() {
    // #104: no observed_reflexive (e.g. the edge reported none for this admission) ->
    // no candidate, no listener bound -- direct_upgrade being on is a no-op for this
    // session, exactly the same as before the option existed.
    assert!(build_upgrade_candidate(None).await.is_none(), "no reflexive -> no candidate");

    // A real reflexive address -> a real, freshly-bound ephemeral listener, and the
    // offered string's reflexive half is exactly the edge-observed address, never
    // anything self-selected (#276 piece 1 may additionally append a NUL-separated
    // local candidate -- see `split_offered_candidates` -- when this host has a real
    // local egress IP, which the test environment may or may not have).
    let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    let (listener, offered) = build_upgrade_candidate(Some(addr)).await.expect("candidate built");
    let (reflexive, local) = split_offered_candidates(&offered);
    assert_eq!(reflexive, "203.0.113.7:4433", "offers exactly the edge-observed address");
    if let Some(local) = local {
        let local_addr: SocketAddr = local.parse().expect("appended local candidate is a valid SocketAddr");
        assert!(
            is_lan_candidate(local_addr.ip()),
            "an appended local candidate is always a real private/ULA address, never anything else"
        );
    }
    let bound = listener.local_addr().expect("listener is actually bound");
    assert_eq!(bound.ip(), std::net::Ipv4Addr::UNSPECIFIED, "binds 0.0.0.0, not the offered address");
    assert_ne!(bound.port(), 0, "the ephemeral port was actually assigned by the OS");
}

#[test]
fn split_offered_candidates_recovers_the_optional_local_half() {
    // #276 piece 1: the reflexive-only (pre-#276) format still round-trips unchanged.
    assert_eq!(split_offered_candidates("203.0.113.7:4433"), ("203.0.113.7:4433", None));
    // The new compound format recovers both halves.
    assert_eq!(
        split_offered_candidates("203.0.113.7:4433\0192.168.1.42:5000"),
        ("203.0.113.7:4433", Some("192.168.1.42:5000"))
    );
    // A malformed (empty) local segment degrades to "no local candidate", not a parse
    // error -- the reflexive candidate alone is always a complete, valid offer.
    assert_eq!(split_offered_candidates("203.0.113.7:4433\0"), ("203.0.113.7:4433", None));
}

#[test]
fn select_upgrade_candidate_prefers_a_genuinely_same_subnet_local_candidate() {
    // #276 piece 1's core behavior: when the peer-offered local candidate lands in
    // OUR OWN local subnet, prefer it over the reflexive one.
    let Some(my_local) = local_egress_ip() else {
        return; // no route in this sandbox -- nothing to assert against
    };
    // Construct a same-subnet candidate at a different last octet (v4) or suffix (v6),
    // matching same_local_subnet's own /24 (v4) / /64 (v6) heuristic.
    let same_subnet = match my_local {
        std::net::IpAddr::V4(v4) => {
            let mut o = v4.octets();
            o[3] = o[3].wrapping_add(1).max(1);
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]))
        }
        std::net::IpAddr::V6(_) => return, // v6 egress is environment-dependent; v4 case covers the seam
    };
    if !is_lan_candidate(my_local) {
        return; // this sandbox's egress isn't a private address at all -- nothing to assert
    }
    let ep = format!("203.0.113.7:4433\0{same_subnet}:5000");
    let chosen = select_upgrade_candidate(&ep).expect("a same-subnet local candidate is chosen");
    assert_eq!(chosen.ip(), same_subnet, "the local candidate was preferred over the reflexive one");
}

#[test]
fn select_upgrade_candidate_refuses_an_off_subnet_local_candidate_and_falls_back() {
    // #276 piece 1's safety property, exercised end-to-end through select_upgrade_candidate:
    // a local candidate that is NOT in our own subnet must never be dialed, regardless of
    // how plausible-looking it is -- the reflexive candidate is used instead.
    let ep = "203.0.113.7:4433\0192.168.250.250:5000";
    let chosen = select_upgrade_candidate(ep).expect("falls back to the reflexive candidate");
    assert_eq!(chosen, "203.0.113.7:4433".parse::<SocketAddr>().unwrap(), "off-subnet local candidate refused, reflexive used instead");
}

#[test]
fn select_upgrade_candidate_never_dials_an_unsafe_reflexive_fallback_either() {
    // The pre-#276 #137 guard still applies to the reflexive half when there is no
    // (or an unusable) local candidate.
    assert!(select_upgrade_candidate("192.168.1.1:4433").is_none(), "private reflexive with no local candidate -> refused, not silently dialed");
    assert!(select_upgrade_candidate("203.0.113.7:4433").is_some(), "a plain global-unicast reflexive with no local half still works");
}

#[tokio::test]
async fn build_upgrade_candidate_refuses_a_non_global_unicast_reflexive_248() {
    // #248 (found live, 2026-08-01): a member co-located with the edge on the same
    // Docker host gets an edge-observed reflexive address on the Docker bridge
    // network (RFC1918) -- real, but never reachable by a genuinely external peer.
    // Offering it anyway left the initiator hanging for the full session timeout
    // instead of degrading to relay-only immediately, since the peer's own SSRF
    // guard (#137) silently refuses to dial it. Symmetric with `upgrade_safe_endpoint`'s
    // existing filter on the *peer's* offered endpoint -- applied here to our own.
    for bad in [
        "172.18.0.19:4433",  // RFC1918 (the exact address found live, #248)
        "10.0.0.5:4433",     // RFC1918
        "192.168.1.9:4433",  // RFC1918
        "127.0.0.1:4433",    // loopback
        "169.254.1.1:4433",  // link-local
    ] {
        let addr: SocketAddr = bad.parse().unwrap();
        assert!(
            build_upgrade_candidate(Some(addr)).await.is_none(),
            "{bad} is not global-unicast -- must not be offered as a direct candidate"
        );
    }
    // A genuinely global-unicast reflexive still works (unchanged from the test above).
    let addr: SocketAddr = "203.0.113.7:4433".parse().unwrap();
    assert!(build_upgrade_candidate(Some(addr)).await.is_some());
}

#[test]
fn upgrade_safe_endpoint_refuses_ssrf_ranges_and_admits_only_global_unicast() {
    // #137 (frozen): the responder's SSRF guard for the peer-conveyed #104 Offer.direct_endpoint.
    // Because the in-band upgrade bypasses the edge broker's `safe_endpoint` gate (#94), the
    // guard must apply the SAME range filter — an internal / private / metadata / link-local /
    // CGNAT / ULA / unspecified target (and anything unparseable) is refused; only a
    // global-unicast address is dialable. Matches the edge's `safe_endpoint` semantics exactly
    // (both are `parse + ct_common::channel::is_global_unicast`).
    for bad in [
        "127.0.0.1:7000",       // loopback
        "10.0.0.5:7000",        // RFC1918
        "192.168.1.9:7000",     // RFC1918
        "172.16.0.1:7000",      // RFC1918
        "169.254.169.254:80",   // cloud metadata / link-local
        "100.64.0.1:7000",      // CGNAT
        "0.0.0.0:7000",         // unspecified
        "[::1]:7000",           // IPv6 loopback
        "[fe80::1]:7000",       // IPv6 link-local
        "[fc00::1]:7000",       // IPv6 ULA
        "not-an-addr",          // unparseable
        "example.com:443",      // hostname, not an IP:port
    ] {
        assert!(upgrade_safe_endpoint(bad).is_none(), "{bad} must be refused (SSRF / unparseable) — #137");
    }
    for ok in ["203.0.113.10:7000", "8.8.8.8:7000", "[2001:4860:4860::8888]:7000"] {
        assert!(upgrade_safe_endpoint(ok).is_some(), "{ok} must be admitted (global-unicast)");
    }
}

#[tokio::test]
async fn two_relay_only_members_join_without_a_dialable_address_and_relay_splice() {
    // #121 (frozen): the reachability floor. TWO relay-only members — each advertising the
    // relay-only SENTINEL (no dialable address), each with NO bound listener — join and are
    // relay-spliced by the PRODUCTION edge relay path (`broker_channel_relay`). Presenting
    // the sentinel to the real relay proves the edge admits it in production. The initiator's
    // paired peer_endpoint is the sentinel, so `run_channel_join_with_admission` SKIPS the
    // wasted direct dial and relays straight away; the acceptor has no listener, so it relays
    // directly too. A real payload round-trips BOTH directions, the Noise_IK session staying
    // end-to-end (the edge splices ciphertext only) — so a NAT-only member with only a
    // private address participates purely via the relay + the #106 :443 fallback.
    use ct_common::channel::{
        member_noise_attest_bytes, ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant,
        CHANNEL_ENDPOINT_RELAY_ONLY,
    };
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::broker_channel_relay;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    let op = SigningKey::from_bytes(&[7u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
    let channel = [0xE5u8; 32];
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    // BOTH members advertise the relay-only sentinel — neither has a dialable address.
    let req_a = ChannelJoinRequest {
        grant: signed(&holder_a, Direction::Initiate),
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };
    let req_b = ChannelJoinRequest {
        grant: signed(&holder_b, Direction::Accept),
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };

    // Each member's attested-key triple (#101): its holder signs its Noise key for the
    // channel so the peer verifies + pins it with nothing conveyed out-of-band.
    let ha_pub = holder_a.verifying_key().to_bytes();
    let hb_pub = holder_b.verifying_key().to_bytes();
    let a_att = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &noise_a.public)).to_bytes();
    let b_att = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public)).to_bytes();

    // The PRODUCTION edge relay: admits both sentinel-advertising members (proving the edge
    // admits the relay-only sentinel over the real relay path), pairs, and splices them.
    let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
    let relay_addr = relay_ep.local_addr().expect("addr");
    let relay_task = tokio::spawn(async move {
        broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
            (c.0 == channel).then_some((op_pub, None, None))
        })
        .await
        .map(|_| ())
    });

    // Member A (initiator): its paired peer_endpoint is the SENTINEL → skip the direct dial,
    // relay straight away. The admission is constructed directly (a real rendezvous would
    // swap the two sentinel endpoints); the relay leg is the production edge.
    let cert_a = cert.clone();
    let (mut a_app, a_local) = tokio::io::duplex(8192);
    let (na, nbpub) = (noise_a.private, noise_b.public);
    let a = tokio::spawn(async move {
        let rc = build_client_endpoint(cert_a).expect("rc a");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn a");
        let admission = ChannelJoinOutcome::Admitted {
            peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            peer_noise_pubkey: Some(nbpub),
            peer_holder: Some(hb_pub),
            peer_attestation: Some(b_att),
            observed_reflexive: None,
        };
        run_channel_join_with_admission(
            admission,
            RelayFallback::Quic(&relay_conn),
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &na,
            None, // relay-only: no bound listener
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            a_local,
            false,
        )
        .await
    });

    // Member B (acceptor): NO bound listener (relay-only) → relay straight away.
    let cert_b = cert.clone();
    let (mut b_app, b_local) = tokio::io::duplex(8192);
    let (nb, napub) = (noise_b.private, noise_a.public);
    let b = tokio::spawn(async move {
        let rc = build_client_endpoint(cert_b).expect("rc b");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
        let admission = ChannelJoinOutcome::Admitted {
            peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            peer_noise_pubkey: Some(napub),
            peer_holder: Some(ha_pub),
            peer_attestation: Some(a_att),
            observed_reflexive: None,
        };
        run_channel_join_with_admission(
            admission,
            RelayFallback::Quic(&relay_conn),
            &req_b,
            &holder_b,
            ChannelRole::Accept,
            &nb,
            None, // relay-only: no bound listener
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            b_local,
            false,
        )
        .await
    });

    // A -> B over the relay-only, edge-spliced, encrypted A2A tunnel.
    a_app.write_all(b"ping-A-to-B").await.expect("a writes");
    let mut got = [0u8; 11];
    b_app.read_exact(&mut got).await.expect("b reads A's bytes");
    assert_eq!(&got, b"ping-A-to-B", "A's plaintext arrives decrypted at B via the relay (both relay-only)");

    // B -> A (reverse proves the splice is full-duplex).
    b_app.write_all(b"pong-B-to-A").await.expect("b writes");
    let mut got2 = [0u8; 11];
    a_app.read_exact(&mut got2).await.expect("a reads B's bytes");
    assert_eq!(&got2, b"pong-B-to-A", "B's plaintext arrives decrypted at A via the relay");

    // Both payloads are confirmed received BEFORE any teardown, so there is no last-byte
    // race to lose; abort the tasks to end the still-open sessions.
    a.abort();
    b.abort();
    relay_task.abort();
}

#[tokio::test]
async fn direct_upgrade_opt_in_still_completes_over_the_relay_when_the_candidate_is_unsafe() {
    // #104 wiring, real proof: with CT_CHANNEL_DIRECT_UPGRADE on and a real
    // edge-observed reflexive address baked into the admission (exactly what a live
    // admission delivers), the session still round-trips a real payload byte-exact —
    // it does NOT hang, error, or silently drop data. On loopback the "reflexive"
    // address is necessarily non-global-unicast, so the responder's #137 SSRF guard
    // (upgrade_safe_endpoint) correctly refuses the in-band upgrade candidate and the
    // session gracefully stays on the relay -- the same behavior this project's own
    // single-host demos get in production, and exactly what "on: but nothing routable
    // to offer" must do: never break the session, never silently accept an unsafe
    // target.
    use ct_common::channel::{
        member_noise_attest_bytes, ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant,
        CHANNEL_ENDPOINT_RELAY_ONLY,
    };
    use ct_common::noise::generate_static_keypair;
    use ct_edge::channel_broker::broker_channel_relay;
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};
    use ed25519_dalek::Signer;

    let op = SigningKey::from_bytes(&[9u8; 32]);
    let op_pub = op.verifying_key().to_bytes();
    let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
    let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
    let channel = [0xE6u8; 32];
    let noise_a = generate_static_keypair();
    let noise_b = generate_static_keypair();
    let signed = |h: &SigningKey, dir| {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: SigningKey::verifying_key(h).to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        SignedChannelGrant { grant: g.clone(), signature: op.sign(&g.signing_bytes()).to_bytes() }
    };
    let req_a = ChannelJoinRequest {
        grant: signed(&holder_a, Direction::Initiate),
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };
    let req_b = ChannelJoinRequest {
        grant: signed(&holder_b, Direction::Accept),
        endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
    };
    let ha_pub = holder_a.verifying_key().to_bytes();
    let hb_pub = holder_b.verifying_key().to_bytes();
    let a_att = holder_a.sign(&member_noise_attest_bytes(&ChannelId(channel), &ha_pub, &noise_a.public)).to_bytes();
    let b_att = holder_b.sign(&member_noise_attest_bytes(&ChannelId(channel), &hb_pub, &noise_b.public)).to_bytes();

    let (relay_ep, cert) = build_server_endpoint_with_cert().expect("relay ep");
    let relay_addr = relay_ep.local_addr().expect("addr");
    let relay_task = tokio::spawn(async move {
        broker_channel_relay(&relay_ep, 500, move |c, _h| async move {
            (c.0 == channel).then_some((op_pub, None, None))
        })
        .await
        .map(|_| ())
    });

    // Member A: direct_upgrade ON, with a real (loopback) observed_reflexive -- exactly
    // the shape a live edge admission delivers, just not a globally-routable address.
    let cert_a = cert.clone();
    let (mut a_app, a_local) = tokio::io::duplex(8192);
    let (na, nbpub) = (noise_a.private, noise_b.public);
    let a = tokio::spawn(async move {
        let rc = build_client_endpoint(cert_a).expect("rc a");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn a");
        let admission = ChannelJoinOutcome::Admitted {
            peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            peer_noise_pubkey: Some(nbpub),
            peer_holder: Some(hb_pub),
            peer_attestation: Some(b_att),
            observed_reflexive: Some("127.0.0.1:7001".parse().unwrap()),
        };
        run_channel_join_with_admission(
            admission,
            RelayFallback::Quic(&relay_conn),
            &req_a,
            &holder_a,
            ChannelRole::Initiate,
            &na,
            None,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            a_local,
            true, // #104 direct_upgrade opt-in
        )
        .await
    });

    let cert_b = cert.clone();
    let (mut b_app, b_local) = tokio::io::duplex(8192);
    let (nb, napub) = (noise_b.private, noise_a.public);
    let b = tokio::spawn(async move {
        let rc = build_client_endpoint(cert_b).expect("rc b");
        let relay_conn = rc.connect(relay_addr, "localhost").expect("cfg").await.expect("rconn b");
        let admission = ChannelJoinOutcome::Admitted {
            peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            peer_noise_pubkey: Some(napub),
            peer_holder: Some(ha_pub),
            peer_attestation: Some(a_att),
            observed_reflexive: Some("127.0.0.1:7002".parse().unwrap()),
        };
        run_channel_join_with_admission(
            admission,
            RelayFallback::Quic(&relay_conn),
            &req_b,
            &holder_b,
            ChannelRole::Accept,
            &nb,
            None,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
            b_local,
            true, // #104 direct_upgrade opt-in
        )
        .await
    });

    a_app.write_all(b"ping-A-to-B").await.expect("a writes");
    let mut got = [0u8; 11];
    b_app.read_exact(&mut got).await.expect("b reads A's bytes despite the upgrade attempt");
    assert_eq!(&got, b"ping-A-to-B", "direct_upgrade=on still delivers real plaintext via the relay");

    b_app.write_all(b"pong-B-to-A").await.expect("b writes");
    let mut got2 = [0u8; 11];
    a_app.read_exact(&mut got2).await.expect("a reads B's bytes despite the upgrade attempt");
    assert_eq!(&got2, b"pong-B-to-A", "full-duplex still works with direct_upgrade on both sides");

    a.abort();
    b.abort();
    relay_task.abort();
}
