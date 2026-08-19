//! Local service-call plumbing -- the MCP/JSON-RPC client machinery a channel session
//! drives against its LOCAL side (consolidation program: module split, slice 3 -- moved
//! verbatim out of channel_run/mod.rs; visibilities widened to pub(crate) only where the
//! parent still calls in).
//!
//! Covers: [`ChannelLocal`] (the local stream the session pumps), the one-shot and
//! PERSISTENT (#19 envelope) service-call clients, the crew/role helpers, and the
//! service-handler subprocess runner with its #200 timeout.

use super::*;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

/// The channel session's local application duplex (#135 L2.1-cli). **Pipe** mode (default) is the
/// CLI's stdin/stdout — the historical one-shot behaviour (stdin-EOF tears the session down).
/// **Serve** mode (`CT_CHANNEL_SERVE=1`) makes the channel a persistent request/response *service*:
/// the session side of an in-process duplex whose other half runs
/// [`serve_request_loop`](ct_common::a2a::serve_request_loop), so the peer can call it many times
/// over one Noise tunnel. A single enum keeps the two shapes one concrete type for the generic pump.
pub(crate) enum ChannelLocal {
    Pipe(tokio::io::Join<tokio::io::Stdin, tokio::io::Stdout>),
    Serve(tokio::io::DuplexStream),
}

impl AsyncRead for ChannelLocal {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_read(cx, buf),
            ChannelLocal::Serve(d) => Pin::new(d).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ChannelLocal {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_write(cx, buf),
            ChannelLocal::Serve(d) => Pin::new(d).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_flush(cx),
            ChannelLocal::Serve(d) => Pin::new(d).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ChannelLocal::Pipe(p) => Pin::new(p).poll_shutdown(cx),
            ChannelLocal::Serve(d) => Pin::new(d).poll_shutdown(cx),
        }
    }
}

/// Serve-mode local (#135 L2.1-cli): spawn [`serve_request_loop`](ct_common::a2a::serve_request_loop)
/// with `handle` on one half of an in-process duplex and return the *session* half — the pump drives
/// it, so the peer's framed requests are answered by `handle` over the one persistent Noise tunnel.
pub(crate) fn serve_local<H, F>(handle: H) -> tokio::io::DuplexStream
where
    H: FnMut(Vec<u8>) -> F + Send + 'static,
    F: std::future::Future<Output = Vec<u8>> + Send,
{
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        let _ = ct_common::a2a::serve_request_loop(&mut send, &mut recv, handle).await;
    });
    session_side
}

/// Call-mode local (#135 L2.3, client side): spawn a one-shot MCP client on one half of an in-process
/// duplex — write ONE JSON-RPC request, print the peer's response body, then close — and return the
/// session half for the pump. So `ct-agent channel --call <method>` = connect, invoke a peer's tool
/// once, print the JSON-RPC reply, exit.
/// One MCP request/response over a duplex's split halves (#135 L2.3 client core): frame + write the
/// request, then read + return the peer's response body. Testable in isolation; `call_local` prints
/// what it returns.
pub(crate) async fn mcp_call_over<W, R>(
    send: &mut W,
    recv: &mut R,
    method: &str,
    params: serde_json::Value,
) -> io::Result<Vec<u8>>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let request = ct_common::mcp::encode_request(1, method, params);
    ct_common::a2a::write_message(send, &request).await?;
    ct_common::noise::read_frame(recv).await
}

/// Crew-bridge c2 atom (#171/#173): call a peer's `service/<slug>` tool over an already-established
/// channel duplex and return the service's `output` string. Frames the fixed
/// `service/<slug>({input}) -> {output}` shape (#149-A.1), reads the reply, and extracts
/// `result.output`. **Fails closed:** a transport error, a JSON-RPC `error` (the service
/// rejected/failed), or a reply missing `result.output` all return `Err` — never a bogus fragment.
/// The crew bridge calls this once per role (safety_check, physics, art) over each dialed channel
/// and feeds the returned JSON into [`ct_common::crew`].
pub async fn call_role_service<W, R>(
    send: &mut W,
    recv: &mut R,
    slug: &str,
    input: &str,
) -> io::Result<String>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let params = serde_json::json!({ "name": format!("service/{slug}"), "arguments": { "input": input } });
    let body = mcp_call_over(send, recv, "tools/call", params).await?;
    let v: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if let Some(err) = v.get("error") {
        return Err(io::Error::other(format!("service/{slug} returned an error: {err}")));
    }
    v.get("result")
        .and_then(|r| r.get("output"))
        .and_then(|o| o.as_str())
        .map(String::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("service/{slug} reply missing result.output")))
}

/// Crew-bridge c2 driver (#171/#173): given already-connected channel duplexes to the three role
/// agents, run the crew end to end and return the browser's `{safety, auction, config}` — the
/// orchestration the `/crew/build` server (c3) wraps.
///
/// Order + fail-closed semantics:
/// 1. **safety_check** runs FIRST over the safety agent's channel; its output is `{ok, reason}`. A
///    `false` verdict short-circuits to a **rejection** (no fragment calls, no build) — the
///    authoritative live guard.
/// 2. **physics** then **art** run over their agents' channels (`service/text_generation`), and the
///    fragments are assembled by [`ct_common::crew`].
///
/// A transport/parse failure at any step returns `Err(reason)` — the c3 HTTP layer maps that to a
/// 5xx so the **browser fails closed to its local stand-in**. A clean policy rejection is
/// `Ok(rejected)`; a clean build is `Ok(built)`. `auction` (who won each role) is supplied by the
/// caller — the bridge derives it from a real `match_offer`/`convene`; a demo may pass the fixed crew.
pub async fn crew_build_over<S, P, A>(
    prompt: &str,
    safety_conn: S,
    physics_conn: P,
    art_conn: A,
    auction: Vec<ct_common::crew::RoleAuction>,
) -> Result<ct_common::crew::CrewBuildResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
    A: AsyncRead + AsyncWrite + Unpin,
{
    // 1. safety_check — the authoritative live guard.
    let (mut sr, mut sw) = tokio::io::split(safety_conn);
    let safety_out = call_role_service(&mut sw, &mut sr, "safety_check", prompt)
        .await
        .map_err(|e| format!("safety_check service unreachable: {e}"))?;
    let verdict: serde_json::Value =
        serde_json::from_str(&safety_out).map_err(|e| format!("safety_check reply not JSON: {e}"))?;
    if verdict.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let reason = verdict.get("reason").and_then(|r| r.as_str()).unwrap_or("rejected by the safety agent");
        return Ok(ct_common::crew::CrewBuildResponse::rejected(reason.to_string()));
    }
    // 2. physics + art fragments — run CONCURRENTLY. They are independent (each only depends on
    //    safety_check having passed) and use separate channels, so their wall-clock is max(physics,
    //    art), not the sum. Measured (#173): each role's real `claude -p` is ~14s and the tunnel
    //    overhead is negligible, so sequential was safety+physics+art ≈ 40–55s; joining the two
    //    independent roles cuts it to ≈ safety + max(physics, art) ≈ ~28s.
    let physics = async {
        let (mut pr, mut pw) = tokio::io::split(physics_conn);
        call_role_service(&mut pw, &mut pr, "text_generation", prompt)
            .await
            .map_err(|e| format!("physics role unreachable: {e}"))
    };
    let art = async {
        let (mut ar, mut aw) = tokio::io::split(art_conn);
        call_role_service(&mut aw, &mut ar, "text_generation", prompt)
            .await
            .map_err(|e| format!("art role unreachable: {e}"))
    };
    let (physics_json, art_json) = tokio::join!(physics, art);
    let (physics_json, art_json) = (physics_json?, art_json?);
    // 3. assemble the real config from the fragments (fail-closed on a malformed fragment).
    let cfg = ct_common::crew::CrewConfig::from_fragment_json(&physics_json, &art_json)
        .map_err(|e| format!("crew fragments malformed: {e}"))?;
    Ok(ct_common::crew::CrewBuildResponse::built(cfg, auction))
}

pub(crate) fn call_local(method: String, params: serde_json::Value) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        match mcp_call_over(&mut send, &mut recv, &method, params).await {
            Ok(response) => println!("{}", String::from_utf8_lossy(&response)),
            // #211: a failed one-shot call (e.g. `write_message` rejecting an oversized request past
            // MAX_MESSAGE_BYTES) must exit NON-ZERO, not exit-0-with-empty-stdout — otherwise the
            // caller can't tell "the call failed" from "the call produced nothing", and a size
            // rejection surfaces downstream as a cryptic empty-output/JSON-parse failure. stderr is
            // unbuffered, so the message is out before we exit.
            Err(e) => {
                eprintln!("ct-agent channel --call: no response ({e})");
                std::process::exit(1);
            }
        }
        // Dropping serve_side EOFs the session side → the channel session ends → the process exits.
    });
    session_side
}

/// Invoke the peer's `service/<slug>` tool with `input` over the channel's `local` duplex and return
/// the **bare** service output (`result.output`) — reusing the tested [`call_role_service`]. Unlike
/// [`call_local`]'s raw-method mode (which prints the whole JSON-RPC envelope for a caller-supplied
/// method + static params), this is the crew-native contract: one `service/<slug>` call, plain
/// output. Split out so it can be frozen-tested against an in-process serve peer.
pub(crate) async fn run_service_call<S>(local: S, slug: &str, input: &str) -> std::io::Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut recv, mut send) = tokio::io::split(local);
    let result = call_role_service(&mut send, &mut recv, slug, input).await;
    // #248: a one-shot call used to drop `local` (tearing the whole session down) the
    // INSTANT the reply arrived -- structurally too fast for any concurrent relay->direct
    // upgrade (#104's in-band candidate exchange, or the relay-gate DCUtR hole-punch,
    // both of which need real network round-trips: address exchange, then a simultaneous
    // connect attempt) to ever land, even when the upgrade is actively in flight and
    // would otherwise have succeeded. Live-reproduced: dozens of real relay-gate DCUtR
    // sessions, admission+circuit genuinely established, none ever showed a completed
    // hole-punch -- every one raced the reply against a sub-200ms teardown and lost.
    // Give a real upgrade attempt a fair window before tearing down, but ONLY when one
    // could plausibly be in flight (either upgrade mechanism configured) -- unconditional
    // added latency on every call would be a real regression for latency-sensitive
    // production use (the crew bridge also drives this same one-shot path).
    if result.is_ok() {
        let upgrade_configured = std::env::var_os("CT_CHANNEL_RELAY_GATE").is_some()
            || std::env::var_os("CT_CHANNEL_CIRCUIT_RELAY").is_some()
            || std::env::var_os("CT_CHANNEL_DIRECT_UPGRADE").is_some();
        if upgrade_configured {
            // #248: 2s (the original fb5a799 value, tuned against local-loopback tests where a
            // hole-punch is near-instant) turned out too short for a REAL cross-NAT relay-gate
            // DCUtR attempt over genuine WAN paths -- live-reproduced on the bob-1<->bob-2
            // pairing after aad49fb finally got both sides' real reflexive addresses into
            // DCUtR's candidate pool: the swarm logged `Dialing` toward the peer's real address,
            // then the one-shot process exited (reply already received over the relay leg,
            // concurrently) before any `ConnectionEstablished`/`OutgoingConnectionError` for that
            // dial appeared, even with CT_DEBUG_A2A_TIMING on. A real hole-punch involves actual
            // network round-trips over the internet (address exchange, then a simultaneous
            // connect attempt, possibly retried) -- meaningfully slower than anything on
            // loopback. This is still a blind fixed sleep, not "wait for the actual upgrade
            // outcome" -- a real fix would have the channel session signal completion
            // (success/failure/timeout) instead of guessing a window, which remains open.
            const UPGRADE_GRACE: std::time::Duration = std::time::Duration::from_secs(6);
            tokio::time::sleep(UPGRADE_GRACE).await;
        }
    }
    result
}

/// #19: the initiator-side PERSISTENT service-call driver — the calling-side counterpart of the
/// accept side's `--serve` (#200). ONE channel session is established and then held for the
/// process's whole life; each line arriving on `lines` becomes one `service/<slug>` call over that
/// same session, answered as one NDJSON envelope line on `out`:
///
/// - success: `{"ok":true,"output":"<bare service output>"}`
/// - failure: `{"ok":false,"error":"<message>"}` — written BEFORE the `Err` return, so the
///   supervising caller always gets a structured last line to attribute, then sees the non-zero
///   exit and can re-spawn + retry the in-flight request.
///
/// Why this exists (measured, 2026-08-13): a caller making many calls to the same peer (the sort
/// arena bridge: ~1 call/second for ~95 rounds) previously paid a full join+pair+Noise handshake
/// per call via the one-shot `--call-service` — and rolled the accept side's re-park gap every
/// time, a structural 15-22% per-round transport-fault rate (#18). Holding the session makes it
/// ONE pairing per run: the gap is practically never rolled, and the per-round handshake overhead
/// disappears. The envelope (rather than raw output lines) is what keeps the stream parseable:
/// service outputs may legitimately contain anything, including newlines, so raw framing cannot
/// delimit responses — JSON-string escaping can.
///
/// The line source is an injected channel (not `stdin` directly) so the loop is testable without a
/// real process; production feeds it from a dedicated stdin-reader thread
/// ([`call_service_persistent_local`]). Returns `Ok(())` on source EOF (clean end-of-run teardown:
/// the caller closed stdin), `Err` after the first failed call — a persistent session that broke
/// mid-run is NOT silently re-dialed in-process: the process-supervision model (the bridge spawns
/// one process per RUN and can retry a round) stays the recovery layer, exactly as before, just at
/// run granularity instead of round granularity.
pub(crate) async fn run_service_calls_persistent<S, W>(
    local: S,
    slug: &str,
    lines: &mut tokio::sync::mpsc::Receiver<String>,
    out: &mut W,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let (mut recv, mut send) = tokio::io::split(local);
    while let Some(line) = lines.recv().await {
        let input = line.trim();
        if input.is_empty() {
            continue; // a blank line is a keep-alive/no-op, not a call
        }
        match call_role_service(&mut send, &mut recv, slug, input).await {
            Ok(output) => {
                let envelope = serde_json::json!({ "ok": true, "output": output });
                out.write_all(format!("{envelope}\n").as_bytes()).await?;
                out.flush().await?;
            }
            Err(e) => {
                let envelope = serde_json::json!({ "ok": false, "error": e.to_string() });
                let _ = out.write_all(format!("{envelope}\n").as_bytes()).await;
                let _ = out.flush().await;
                return Err(std::io::Error::other(format!(
                    "persistent service call failed mid-run: {e}"
                )));
            }
        }
    }
    Ok(()) // stdin EOF -> drop the halves -> the session ends cleanly
}

/// #19 production glue for [`run_service_calls_persistent`]: bridge the real process stdin into
/// the injected line channel via a dedicated blocking reader thread (tokio's async stdin is a
/// thread pool anyway, and a plain `BufRead::lines` thread is the simplest EOF-correct feed), run
/// the persistent loop against real stdout, and translate its outcome into the process contract:
/// clean source EOF ends the session (normal exit through the session driver), a mid-run call
/// failure exits non-zero AFTER the structured error envelope is out (same #211 fail-closed
/// discipline as the one-shot mode).
pub(crate) fn call_service_persistent_local(slug: String) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    std::thread::spawn(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.blocking_send(l).is_err() {
                        break; // consumer gone (session over) -- stop reading
                    }
                }
                Err(_) => break,
            }
        }
        // Thread end drops `tx` -> the loop sees source EOF -> clean teardown.
    });
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        if let Err(e) = run_service_calls_persistent(serve_side, &slug, &mut rx, &mut stdout).await {
            eprintln!("ct-agent channel --call-service {slug} (persistent): {e}");
            std::process::exit(1);
        }
        // Ok: serve_side was moved+dropped -> session EOF -> the process exits through the
        // normal session teardown (drain + exit 0), same as the one-shot mode's happy path.
    });
    session_side
}

/// The initiator-side one-shot **service** call (#173 distributed crew topology): dial done by the
/// channel session, this drives the local side — call the peer's `service/<slug>` with `input`, print
/// the bare service output, then EOF the session so the process exits. This is exactly the
/// stdin→stdout contract the crew bridge's `CREW_*_CMD` expects, so `CREW_PHYSICS_CMD="ct-agent
/// channel"` (with `CT_CHANNEL_CALL_SERVICE=text_generation` + the source-2 channel-join env) dials
/// source-2 over the real Agent-Fabric tunnel and yields its fragment JSON — no jq/wrapper needed.
pub(crate) fn call_service_local(slug: String, input: String) -> tokio::io::DuplexStream {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        match run_service_call(serve_side, &slug, &input).await {
            Ok(output) => println!("{output}"),
            // #211: fail closed AND exit NON-ZERO. Previously this only `eprintln!`'d and let the
            // process exit 0 with empty stdout — indistinguishable from "the role produced no output"
            // (the empty-stdout bugs #206/a3412fc). An oversized `input` is correctly rejected by
            // `write_message` (MAX_MESSAGE_BYTES, u16 wire ceiling) as an `Err` that propagates up
            // here; turning it into a non-zero exit lets the bridge surface the clear "message too
            // large" stderr instead of a cryptic downstream JSON-parse failure. stderr is unbuffered.
            Err(e) => {
                eprintln!("ct-agent channel --call-service {slug}: {e}");
                std::process::exit(1);
            }
        }
        // Dropping serve_side (moved into run_service_call) EOFs the session → the session ends.
    });
    session_side
}

/// Parse a `CT_AGENT_SERVICES` entry (the same slugs `ct_common::mcp`'s `service/<slug>` tool
/// names use) into a [`ct_common::channel::ServiceType`]. The four fixed slugs above map to their
/// matching built-in variant; anything else becomes `ServiceType::Custom(s)` (#382 follow-up:
/// CADS-Tunnel core generalized `RequiredRole`/`convene()` beyond a closed service catalog, so a
/// pipeline designer can declare e.g. `static_analysis`/`android_instrumented_test` without a
/// CADS-Tunnel core release per new pipeline-stage type) — never silently dropped anymore. An
/// empty string still parses to nothing useful downstream but isn't specially rejected here; the
/// caller's own offer/catalog matching is still the real gate on what actually gets served.
pub(crate) fn parse_service_type(s: &str) -> Option<ct_common::channel::ServiceType> {
    use ct_common::channel::ServiceType::*;
    if s.is_empty() {
        // e.g. a stray double-comma in CT_AGENT_SERVICES -- still filtered out, same as before
        // Custom existed (an empty custom-service name is never a meaningful declaration).
        return None;
    }
    Some(match s {
        "code_generation" => CodeGeneration,
        "security_review" => SecurityReview,
        "safety_check" => SafetyCheck,
        "text_generation" => TextGeneration,
        other => Custom(other.to_string()),
    })
}

/// Bound how long a `CT_AGENT_SERVICE_HANDLER_CMD` child may run before it's killed (#149-A.1
/// serve-wiring: every other blocking step in this file is timed — `A2A_HANDSHAKE_TIMEOUT`,
/// `DIRECT_STREAM_SETUP_TIMEOUT`, `*_DRAIN_TIMEOUT` — this was the one unbounded exception, flagged
/// in review). Generous: a real LLM-backed handler can legitimately take tens of seconds.
pub(crate) const SERVICE_HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Run the configured `CT_AGENT_SERVICE_HANDLER_CMD` for one `service/<slug>` call (#149-A.1
/// serve-wiring follow): spawn it via `sh -c`, write `input` to its stdin, and return its trimmed
/// stdout as the result. `CT_SERVICE_TYPE` is set in the child's environment so one handler script
/// can branch on which of several registered services was actually invoked. A non-zero exit, a
/// spawn/IO failure, or exceeding `timeout` becomes the tool error (surfaced to the caller as a
/// JSON-RPC error, never a panic). `timeout` is a parameter (the real call site below always passes
/// [`SERVICE_HANDLER_TIMEOUT`]) so the kill-on-timeout path is unit-testable without an actual
/// 120-second wait.
///
/// Two fixes from review, both real (caught reading `#149`'s wiring, not hypothetical):
/// - **stdin is written on its own thread**, concurrently with the wait/output-read below — writing
///   it inline, then calling `wait_with_output()`, is the textbook `std::process` pipe deadlock: an
///   `input` over the OS pipe buffer (~64 KiB) whose handler writes to stdout *before* finishing its
///   stdin read blocks both sides forever, and a consumer fully controls `input`'s size (`register_service_tools`
///   reads `args["input"]` with no cap) — a remote DoS on the provider, not just a footgun.
/// - **the child is bounded by `timeout` and killed if it's exceeded**, closing the one unbounded
///   blocking step in this file.
pub(crate) fn run_service_handler_with_timeout(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use std::process::{Command, Stdio};
    // Reuse ct_common's own slug derivation (now `pub`, #382 follow-up) rather than a second,
    // driftable copy of this match here -- this is the SAME name the `service/<slug>` MCP tool
    // this call is answering was registered under, including the Custom(name) case.
    let slug = ct_common::mcp::service_slug(&service);
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg(cmd)
        .env("CT_SERVICE_TYPE", slug.as_ref())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // #183: put the child in its OWN process group (pgid == its pid) on Unix so the timeout
    // kill below can signal the WHOLE subtree, not just the immediate `sh -c`. The handler
    // scripts shell out to a real LLM CLI as a GRANDCHILD; killing only the `sh` pid leaves an
    // orphaned (costed, running) LLM subprocess whenever the script pipes/backgrounds,
    // defeating SERVICE_HANDLER_TIMEOUT. `std::process::Command` has no process-group concept
    // on Windows, so the timeout kill there (below) only ever reaches the immediate child --
    // a narrower, documented guarantee than Unix's whole-group kill.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|e| format!("service handler spawn failed: {e}"))?;
    let pid = child.id();

    // Write stdin on its own thread so it can proceed concurrently with the wait/output-read
    // below (the deadlock fix). Best-effort: a handler that never reads stdin (or exits before
    // fully consuming it) makes this fail with a broken-pipe error, which we deliberately ignore
    // here — the child's own exit status/output is the actual verdict, not whether every stdin
    // byte landed.
    let mut stdin = child.stdin.take().ok_or("service handler: no stdin pipe")?;
    let input_owned = input.to_string();
    let _stdin_writer = std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(input_owned.as_bytes());
    });

    // Run wait_with_output() (which itself reads stdout/stderr concurrently on its own threads —
    // std's own implementation, not reproduced here) on a background thread so this call can be
    // bounded: recv_timeout enforces SERVICE_HANDLER_TIMEOUT, and on timeout we kill the child by
    // pid (captured above, before ownership moved into the thread) so the still-running background
    // wait unblocks on its own rather than leaking a wedged process.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let output = match rx.recv_timeout(timeout) {
        Ok(result) => result.map_err(|e| format!("service handler wait failed: {e}"))?,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // #183: kill the whole process GROUP so a grandchild (the LLM CLI) can't survive the
            // timeout as an orphan. `process_group(0)` above made pgid == pid, and a NEGATIVE pid to
            // kill(2) signals every process in that group. Done via libc, not `Command::new("kill")`:
            // minimal images ship no `kill` binary, so the old spawn silently no-op'd there.
            #[cfg(unix)]
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
            // Windows: no raw kill-by-pid in std and no process-group equivalent (see the
            // process_group comment above) -- shell out to the always-present taskkill,
            // which only reaches the immediate child, not any grandchild the handler
            // script spawned.
            #[cfg(not(unix))]
            {
                let _ = std::process::Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .status();
            }
            return Err(format!(
                "service handler timed out after {}s (pid {pid} killed)",
                timeout.as_secs()
            ));
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            return Err("service handler: wait thread disconnected unexpectedly".to_string())
        }
    };
    if !output.status.success() {
        return Err(format!(
            "service handler exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        // #206: every shipped handler script unconditionally prints either its real result or a
        // fallback on every code path — an exit-0-with-empty-stdout result is never a legitimate
        // success, only a process torn down externally (e.g. OOM) between spawn and its final print,
        // after this function's own timeout-kill path (which returns Err before reaching here). Left
        // untreated, the empty string flows on as a "successful" fragment and produces a cryptic
        // downstream `serde_json` "EOF while parsing a value" instead of an honest, attributable error.
        return Err(format!(
            "service handler exited {} but produced no output (killed mid-run?)",
            output.status
        ));
    }
    Ok(stdout)
}

/// [`run_service_handler_with_timeout`] bound to the real [`SERVICE_HANDLER_TIMEOUT`] — the seam
/// every non-test call site uses.
pub(crate) fn run_service_handler(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
) -> Result<String, String> {
    run_service_handler_with_timeout(cmd, service, input, SERVICE_HANDLER_TIMEOUT)
}

/// #19 (v0.5.0 default flip): whether `--call-service` holds ONE session and multiplexes
/// NDJSON-framed calls over it (`true`, the default) or runs the legacy one-shot
/// bare-output call (`false`). Only an explicit `0`/`false`/`no` opts out — unset,
/// empty, or anything else keeps the session mode, so a typo can never silently
/// reintroduce the one-pairing-per-call cost this flip removes.
pub(crate) fn call_persistent_enabled_from(v: Option<&str>) -> bool {
    !matches!(
        v.map(str::trim),
        Some(s) if s == "0" || s.eq_ignore_ascii_case("false") || s.eq_ignore_ascii_case("no")
    )
}

/// Build the channel session's local app duplex from the environment (#135 L2.x). `CT_CHANNEL_CALL=<method>`
/// → one-shot MCP **client** (invoke a peer's tool, print the reply, exit). `CT_CHANNEL_SERVE=1` → the
/// persistent MCP **service** (JSON-RPC `tools/list`/`tools/call` via the tool registry). Neither → the
/// historical stdin/stdout pipe.
pub(crate) fn channel_local() -> ChannelLocal {
    // #173 distributed crew: one-shot `service/<slug>` client. Reads the prompt on stdin, calls the
    // peer's service, prints the BARE output — the crew-bridge `CREW_*_CMD` contract. Checked before
    // the raw CT_CHANNEL_CALL below because it's the service-specific (and jq-free) path.
    if let Ok(slug) = std::env::var("CT_CHANNEL_CALL_SERVICE") {
        let slug = slug.trim().to_string();
        // #19: persistent call mode -- hold ONE session and multiplex line-framed calls over it
        // until stdin EOF, instead of one pairing per call. THE DEFAULT since v0.5.0 (the
        // operator-staged flip: opt-in through v0.4.x, default once the reference bridges
        // migrated to the NDJSON envelope -- sort runs it in the field at 85-92 ms/round,
        // faults 0). `CT_CHANNEL_CALL_PERSISTENT=0` opts a deliberate one-shot caller back
        // into the old contract (ONE bare-output call, then exit); only an explicit off
        // value disables, so a typo can never silently drop the session mode (same posture
        // as `phase_marker_enabled_from`). Deliberately NOT combined with the DCUtR retry
        // modes (their per-attempt channel_local() re-entry would contend for the single
        // stdin feed -- the #248 trap class below); the arena/front-door path this exists
        // for calls channel_local() exactly once.
        if call_persistent_enabled_from(std::env::var("CT_CHANNEL_CALL_PERSISTENT").ok().as_deref()) {
            eprintln!(
                "ct-agent channel: --call-service {slug} (persistent: one held session, NDJSON calls over stdio until EOF, #19)"
            );
            return ChannelLocal::Serve(call_service_persistent_local(slug));
        }
        // #248: cache the stdin read -- this function is called fresh on every
        // relay-gate/circuit-relay DCUtR retry attempt (each attempt needs its own owned
        // ChannelLocal), and stdin is only readable to EOF once. A naive re-read on retry
        // doesn't error, it silently returns empty ("" is a valid, if useless, read) --
        // the real message only ever reached the FIRST attempt; every retry silently sent
        // nothing, which the peer can reasonably react to by closing early. Live-reproduced
        // on bob2's retried rounds: no input-related error anywhere, just an unexplained
        // "early eof" a step later than expected.
        static INPUT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let input = INPUT
            .get_or_init(|| {
                let mut input = String::new();
                use std::io::Read;
                let _ = std::io::stdin().read_to_string(&mut input);
                input.trim().to_string()
            })
            .clone();
        eprintln!("ct-agent channel: --call-service {slug} (one service call over the channel, then exit)");
        return ChannelLocal::Serve(call_service_local(slug, input));
    }
    // #135 L2.3 client: one MCP request/response over the channel, then exit.
    if let Ok(method) = std::env::var("CT_CHANNEL_CALL") {
        let method = method.trim().to_string();
        let params = std::env::var("CT_CHANNEL_CALL_PARAMS")
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .unwrap_or(serde_json::Value::Null);
        eprintln!("ct-agent channel: --call {method} (one MCP request over the channel, then exit)");
        return ChannelLocal::Serve(call_local(method, params));
    }
    let serve = std::env::var("CT_CHANNEL_SERVE")
        .map(|v| {
            let v = v.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false);
    if serve {
        // #135 L2.3: each framed request body is a JSON-RPC 2.0 message dispatched against the agent's
        // MCP tool registry; the response body is the JSON-RPC reply. Arc so the registry is shared
        // across the persistent session's calls. #144×#135: if the agent has AgentCard config
        // (CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_*), also expose `agent/card` — its signed identity
        // over the authenticated channel; otherwise just the default `ping` tool.
        fn now_secs() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }
        let mut reg = match AgentCardCliConfig::from_env() {
            Ok(cfg) => {
                let card_json = serde_json::to_value(cfg.build_card(now_secs()))
                    .unwrap_or(serde_json::Value::Null);
                eprintln!("ct-agent channel: --serve mode (MCP-over-channel; tools: ping, agent/card)");
                ct_common::mcp::registry_with_card(card_json)
            }
            Err(_) => {
                eprintln!(
                    "ct-agent channel: --serve mode (MCP-over-channel; tool: ping — set CT_AGENT_CARD_* to also expose agent/card)"
                );
                ct_common::mcp::default_registry()
            }
        };
        // #152: if an offer is configured (CT_AGENT_OFFER_*), also expose the #147 auction tools
        // (`auction/offer` + `auction/bid`) over the same authenticated channel — the CLI parity that
        // lets the marketplace be demoed live the way `agent/card` is. The seller stamps time itself
        // (`now_secs`), never the caller.
        // #152/#167: build the offer config ONCE — the signed offer drives both the auction tools
        // and the ceiling on which `service/<slug>` tools may be registered, so the two can't drift.
        let offer_cfg = AgentOfferCliConfig::from_env().ok();
        if let Some(cfg) = &offer_cfg {
            let offer = cfg.build_offer(now_secs());
            ct_common::mcp::register_auction_tools(
                &mut reg,
                offer,
                now_secs,
                cfg.max_bids_per_window,
                cfg.window_secs,
            );
            // ct-agent#17: ONCE per process, and worded as the config report it is --
            // channel_local() is rebuilt on every (re-)admission attempt, and the old
            // per-attempt print was misread as "handler is live" during a 49-cycle
            // admission hot-loop that never admitted once.
            static AUCTION_LINE: std::sync::Once = std::sync::Once::new();
            AUCTION_LINE.call_once(|| {
                eprintln!(
                    "ct-agent channel: --serve configured to expose auction/offer + auction/bid (CT_AGENT_OFFER_*) -- served to peers only after a confirmed admission"
                );
            });
        }
        // #149-A.1 serve-wiring + #167 declared-vs-served: expose one schema-typed `service/<slug>`
        // tool per service, backed by shelling out to `CT_AGENT_SERVICE_HANDLER_CMD` (`input` on
        // stdin, trimmed stdout is the result, `CT_SERVICE_TYPE` names the slug; runs synchronously —
        // fine for a low-concurrency demo, a multi-tenant host would want `spawn_blocking`).
        //
        // #167: the signed offer's **declared** service catalog is the ceiling. A service is
        // registered only if the offer declares it, so what a buyer can cryptographically verify the
        // agent offers is exactly what it will serve. `CT_AGENT_SERVICES`, when set, is an explicit
        // override *filtered to* the declared catalog (undeclared entries are refused loudly, never
        // registered); when unset with an offer, the declared catalog itself is the list (one knob).
        // With no offer configured there is no cryptographic ceiling and `CT_AGENT_SERVICES` stands
        // alone — the unchanged self-asserted regime.
        if let Ok(handler_cmd) = std::env::var("CT_AGENT_SERVICE_HANDLER_CMD") {
            let requested: Vec<ct_common::channel::ServiceType> = match std::env::var("CT_AGENT_SERVICES") {
                Ok(s) => s.split(',').filter_map(|t| parse_service_type(t.trim())).collect(),
                Err(_) => offer_cfg.as_ref().map(|c| c.services.clone()).unwrap_or_default(),
            };
            let services: Vec<ct_common::channel::ServiceType> = match &offer_cfg {
                Some(cfg) => {
                    let (allowed, refused): (Vec<_>, Vec<_>) =
                        requested.into_iter().partition(|s| cfg.services.contains(s));
                    if !refused.is_empty() {
                        eprintln!(
                            "ct-agent channel: REFUSING {} service tool(s) not in the signed offer's declared catalog (#167): {:?}",
                            refused.len(),
                            refused
                        );
                    }
                    allowed
                }
                None => requested,
            };
            if !services.is_empty() {
                let n = services.len();
                ct_common::mcp::register_service_tools(&mut reg, &services, move |service, input| {
                    run_service_handler(&handler_cmd, service, input)
                });
                // ct-agent#17: same Once + honest wording as the auction line above.
                static SERVICE_LINE: std::sync::Once = std::sync::Once::new();
                SERVICE_LINE.call_once(|| {
                    eprintln!(
                        "ct-agent channel: --serve configured to expose {n} service tool(s) via CT_AGENT_SERVICE_HANDLER_CMD -- served to peers only after a confirmed admission"
                    );
                });
            }
        }
        let registry = std::sync::Arc::new(reg);
        ChannelLocal::Serve(serve_local(move |req: Vec<u8>| {
            let registry = registry.clone();
            // #248-follow: `ToolRegistry::dispatch` is synchronous, and when a
            // `CT_AGENT_SERVICE_HANDLER_CMD` service tool is registered it can block this
            // call for real wall-clock time (`run_service_handler`'s
            // `std::process::Command::wait`, up to `SERVICE_HANDLER_TIMEOUT`). Calling it
            // inline inside this async block used to block whichever Tokio worker thread
            // was running this connection's task for that whole duration -- starving the
            // SAME connection's own read/write pump (no bytes flow while the handler runs)
            // and, on a runtime with few worker threads (this host: 2 CPUs), starving
            // *other* connections' admission/keepalive handling too. Live-reproduced: a
            // registered service handler -- even a near-instant one -- made the responder's
            // reply never reach the initiator (seen as a clean, fast "early eof"), and under
            // slightly different timing a completely unrelated fresh channel's own admission
            // exchange stalled for the full #140 window while this one was blocked. Moving
            // the actual dispatch onto Tokio's dedicated blocking-thread pool fixes both:
            // the async worker stays free to keep pumping bytes and servicing other
            // connections while the handler subprocess runs.
            async move {
                tokio::task::spawn_blocking(move || registry.dispatch(&req))
                    .await
                    .unwrap_or_default()
            }
        }))
    } else {
        ChannelLocal::Pipe(tokio::io::join(tokio::io::stdin(), tokio::io::stdout()))
    }
}
