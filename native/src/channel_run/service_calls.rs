//! Local service-call plumbing -- the MCP/JSON-RPC client machinery a channel session
//! drives against its LOCAL side (consolidation program: module split, slice 3 -- moved
//! verbatim out of channel_run/mod.rs; visibilities widened to pub(crate) only where the
//! parent still calls in).
//!
//! Covers: [`ChannelLocal`] (the local stream the session pumps), the one-shot and
//! PERSISTENT (#19 envelope) service-call clients, the crew/role helpers, and the
//! service-handler subprocess runner with its #200 timeout.

use super::*;
use crate::task_guard::TaskGuard;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

/// The session side of an in-process duplex plus, when one exists, the guard of the task pumping
/// the OTHER side (ct-agent#180). The four `*_local` constructors below each spawn such a pump;
/// tying its guard to the stream means the pump is aborted the moment the session drops its local
/// -- the call's lifetime IS the pump's lifetime -- instead of running on until it happens to
/// notice the duplex EOF (a serve-mode handler mid-`CT_AGENT_SERVICE_HANDLER_CMD` never would,
/// for up to [`SERVICE_HANDLER_TIMEOUT`]). `From<DuplexStream>` is for a caller that drives the
/// other half itself, inline, and has no task to own.
pub(crate) struct LocalDuplex {
    stream: tokio::io::DuplexStream,
    _pump: Option<TaskGuard<()>>,
}

impl From<tokio::io::DuplexStream> for LocalDuplex {
    fn from(stream: tokio::io::DuplexStream) -> Self {
        Self { stream, _pump: None }
    }
}

impl LocalDuplex {
    fn with_pump(stream: tokio::io::DuplexStream, pump: TaskGuard<()>) -> Self {
        Self { stream, _pump: Some(pump) }
    }
}

impl AsyncRead for LocalDuplex {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for LocalDuplex {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// The channel session's local application duplex (#135 L2.1-cli). **Pipe** mode (default) is the
/// CLI's stdin/stdout — the historical one-shot behaviour (stdin-EOF tears the session down).
/// **Serve** mode (`CT_CHANNEL_SERVE=1`) makes the channel a persistent request/response *service*:
/// the session side of an in-process duplex whose other half runs
/// [`serve_request_loop`](ct_common::a2a::serve_request_loop), so the peer can call it many times
/// over one Noise tunnel. A single enum keeps the two shapes one concrete type for the generic pump.
pub(crate) enum ChannelLocal {
    Pipe(tokio::io::Join<tokio::io::Stdin, tokio::io::Stdout>),
    Serve(LocalDuplex),
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
pub(crate) fn serve_local<H, F>(handle: H) -> LocalDuplex
where
    H: FnMut(Vec<u8>) -> F + Send + 'static,
    F: std::future::Future<Output = Vec<u8>> + Send,
{
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    // ct-agent#180: guarded -- the serve loop (and a handler it is awaiting) ends with the
    // session that owns the returned local, not whenever its next write happens to fail.
    let pump = TaskGuard::spawn(async move {
        let (mut recv, mut send) = tokio::io::split(serve_side);
        // ct-agent#115: `serve_request_loop`'s `Err` used to be silently discarded here (`let _ =`)
        // -- including `write_message`'s pre-wire rejection of an oversize response
        // (`ct_common::a2a::MAX_MESSAGE_BYTES`, 65535 bytes). That left a peer seeing a bare "early
        // eof" with zero diagnostic on this side, even under `CT_DEBUG_A2A_TIMING`. A clean peer
        // close still returns `Ok`, so this only ever fires on a genuine session-ending error.
        if let Err(e) = ct_common::a2a::serve_request_loop(&mut send, &mut recv, handle).await {
            eprintln!("ct-agent channel: serve session ended: {e}");
        }
    });
    LocalDuplex::with_pump(session_side, pump)
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

pub(crate) fn call_local(method: String, params: serde_json::Value) -> LocalDuplex {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    // ct-agent#180: the pump's guard rides on the returned local, so a session that drops it
    // before the reply arrives aborts the pump. Its own `exit(1)` below still covers the case
    // that matters for #211 -- a failure the pump itself observes while the session is up.
    let pump = TaskGuard::spawn(async move {
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
    LocalDuplex::with_pump(session_side, pump)
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
pub(crate) fn call_service_persistent_local(slug: String) -> LocalDuplex {
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
    // ct-agent#180: guarded. Without it a session that died left this pump parked on
    // `rx.recv()` -- the NEXT stdin line, however much later -- before it could notice.
    let pump = TaskGuard::spawn(async move {
        let mut stdout = tokio::io::stdout();
        if let Err(e) = run_service_calls_persistent(serve_side, &slug, &mut rx, &mut stdout).await {
            eprintln!("ct-agent channel --call-service {slug} (persistent): {e}");
            std::process::exit(1);
        }
        // Ok: serve_side was moved+dropped -> session EOF -> the process exits through the
        // normal session teardown (drain + exit 0), same as the one-shot mode's happy path.
    });
    LocalDuplex::with_pump(session_side, pump)
}

/// ct-agent#47: the internal-reconnect counterpart to [`call_service_persistent_local`] --
/// entry point for persistent `--call-service` when `CT_CHANNEL_CALL_RECONNECT` is on (the
/// default). Where that function spawns ONE admission+session attempt and exits(1) on failure,
/// this one owns a whole redial loop: the stdin-reading thread and its `mpsc` receiver are set
/// up exactly ONCE (the already-documented #248 trap -- re-entering `channel_local()`'s stdin
/// setup on every retry silently drops everything after the first attempt, since stdin is only
/// readable to EOF once), then each loop iteration builds a FRESH duplex, admits a FRESH session
/// over it via [`crate::channel_run::serving::run_one_admission_session_with_local`] (the exact
/// ladder/relay/admission logic every other caller uses, untouched), and races that admission's
/// session pump against [`run_service_calls_persistent`] driving the SAME shared receiver. A
/// stdin line that arrives mid-reconnect simply waits in the channel and is answered once the
/// next session is up, instead of being lost with the whole process the way it used to be.
///
/// Failure classification reuses #250's own `is_flapping_session`/`flapping_session_backoff`
/// (see `channel_run::errors`) rather than inventing a new backoff policy -- a session that dies
/// near-instantly repeatedly backs off exponentially (capped), exactly like the SERVE-side loop
/// already does for the same symptom class. Only a clean stdin EOF ends the process (exit 0).
pub(crate) async fn run_persistent_call_reconnect_loop(
    slug: String,
    cfg: &ChannelJoinCliConfig,
    request: &ChannelJoinRequest,
    broker_ladder: &[ChannelDialRung],
    relay_ladder: &[ChannelDialRung],
    front_door_cert: &Option<CertificateDer<'static>>,
) -> Result<(), BoxError> {
    let admit = |local: ChannelLocal| {
        run_one_admission_session_with_local(cfg, request, broker_ladder, relay_ladder, front_door_cert, local)
    };
    run_persistent_call_reconnect_loop_with(slug, cfg.call_reconnect, admit).await
}

/// [`run_persistent_call_reconnect_loop`]'s actual loop, parameterized over the admission step
/// (`admit`) so it's unit-testable without a real broker/edge -- mirrors `dial_ladder`'s own
/// injected-closure pattern (`channel_run::dialing`). See that function's doc comment for the
/// full rationale (the #248 stdin-reuse trap, the #250 backoff reuse, the select!-races-pump-
/// against-calls shape).
pub(crate) async fn run_persistent_call_reconnect_loop_with<A, Fut>(
    slug: String,
    call_reconnect: bool,
    admit: A,
) -> Result<(), BoxError>
where
    A: Fn(ChannelLocal) -> Fut,
    Fut: std::future::Future<Output = Result<(), BoxError>>,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    std::thread::spawn(move || {
        use std::io::BufRead;
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.blocking_send(l).is_err() {
                        break; // consumer gone (process exiting) -- stop reading
                    }
                }
                Err(_) => break,
            }
        }
        // Thread end drops `tx` -> the loop below sees source EOF -> clean teardown.
    });
    run_persistent_call_reconnect_loop_over(slug, call_reconnect, admit, &mut rx, tokio::io::stdout()).await
}

/// The reconnect loop's core, split out one layer further so a test can feed it lines through an
/// `mpsc::Sender` it controls directly (no real stdin/process involved) and capture output via an
/// in-memory `out` instead of real stdout.
pub(crate) async fn run_persistent_call_reconnect_loop_over<A, Fut, W>(
    slug: String,
    call_reconnect: bool,
    admit: A,
    rx: &mut tokio::sync::mpsc::Receiver<String>,
    mut out: W,
) -> Result<(), BoxError>
where
    A: Fn(ChannelLocal) -> Fut,
    Fut: std::future::Future<Output = Result<(), BoxError>>,
    W: AsyncWrite + Unpin,
{
    let retry_backoff = std::time::Duration::from_millis(200);
    let mut consecutive_flaps: u32 = 0;

    loop {
        let (session_side, serve_side) = tokio::io::duplex(1 << 16);
        let attempt_started = std::time::Instant::now();

        // No task to guard here: `calls` drives the other half inline (ct-agent#180).
        let pump = admit(ChannelLocal::Serve(session_side.into()));
        let calls = run_service_calls_persistent(serve_side, &slug, rx, &mut out);
        tokio::pin!(pump);
        tokio::pin!(calls);

        let clean_eof = tokio::select! {
            _ = &mut pump => false,
            r = &mut calls => matches!(r, Ok(())),
        };
        // Whichever future didn't finish is dropped here, cancelling it -- the same
        // shutdown-by-drop idiom this codebase already relies on elsewhere (e.g. the
        // shutdown-signal races in ct-edge's channel broker).

        if clean_eof {
            return Ok(());
        }

        if !call_reconnect {
            // Return, don't `std::process::exit` directly: the error envelope
            // `run_service_calls_persistent` already wrote (and flushed) for a mid-run call
            // failure happened before this point, so the process-contract from the pre-#47
            // behavior (envelope out, THEN nonzero exit) still holds once this Err propagates
            // through the normal one-shot session error path all the way to `main`'s own
            // `#[tokio::main]`-generated nonzero exit -- same observable outcome, but testable
            // without killing the test binary the way a direct `process::exit` call would.
            return Err(format!(
                "ct-agent channel --call-service {slug} (persistent): session ended, \
                 CT_CHANNEL_CALL_RECONNECT=0 -- not reconnecting (#47)"
            )
            .into());
        }

        if is_flapping_session(attempt_started.elapsed(), true) {
            consecutive_flaps += 1;
        } else {
            consecutive_flaps = 0;
        }
        let delay = equal_jitter(flapping_session_backoff(retry_backoff, consecutive_flaps), rand::random::<f64>());
        eprintln!(
            "ct-agent channel --call-service {slug} (persistent): session ended after {:?}, \
             reconnecting in {delay:?} (streak {consecutive_flaps}, #47)",
            attempt_started.elapsed()
        );
        tokio::time::sleep(delay).await;
    }
}

/// The initiator-side one-shot **service** call (#173 distributed crew topology): dial done by the
/// channel session, this drives the local side — call the peer's `service/<slug>` with `input`, print
/// the bare service output, then EOF the session so the process exits. This is exactly the
/// stdin→stdout contract the crew bridge's `CREW_*_CMD` expects, so `CREW_PHYSICS_CMD="ct-agent
/// channel"` (with `CT_CHANNEL_CALL_SERVICE=text_generation` + the source-2 channel-join env) dials
/// source-2 over the real Agent-Fabric tunnel and yields its fragment JSON — no jq/wrapper needed.
pub(crate) fn call_service_local(slug: String, input: String) -> LocalDuplex {
    let (session_side, serve_side) = tokio::io::duplex(1 << 16);
    // ct-agent#180: guarded, same reasoning as `call_local`.
    let pump = TaskGuard::spawn(async move {
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
    LocalDuplex::with_pump(session_side, pump)
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
    run_service_handler_with_timeout_to(cmd, service, input, timeout, &mut std::io::stderr())
}

/// Upper bound on how much of one handler run's stderr is forwarded into this process's own
/// stderr (ct-agent#105 diagnosability): the TAIL of the child's stderr up to this many bytes.
/// Real handlers log heavily (an LLM CLI's whole progress chatter); the tail is what carries the
/// verdict-adjacent lines, and a runaway handler must not be able to flood `docker logs` through
/// this path.
pub(crate) const HANDLER_STDERR_PASSTHROUGH_MAX: usize = 64 * 1024;

/// [`run_service_handler_with_timeout`] with the diagnostic sink made explicit (ct-agent#105):
/// everything the handler child wrote to its stderr is forwarded to `diag`, line by line,
/// prefixed `service handler[<slug>] stderr: `, on BOTH the success and the non-zero-exit path.
///
/// Why: the child's stderr was only ever captured into the error string of a failed run. A
/// handler that succeeded (exit 0) had its stderr silently discarded, so `docker logs` on a
/// `--serve` container never showed a single handler-level log line -- which is exactly what made
/// ct-agent#105 (a caller-side envelope mismatch that LOOKED like a serve-side corruption) so
/// hard to localize. Production passes `std::io::stderr()` (unbuffered, so it interleaves
/// correctly with this process's own `eprintln!` lines); tests pass a `Vec<u8>`.
///
/// Not forwarded: a run killed by `timeout` (the child never finished, so `wait_with_output`
/// never returned its buffers -- the timeout error is the record of that run).
pub(crate) fn run_service_handler_with_timeout_to(
    cmd: &str,
    service: ct_common::channel::ServiceType,
    input: &str,
    timeout: std::time::Duration,
    diag: &mut dyn std::io::Write,
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
    forward_handler_stderr(diag, slug.as_ref(), &output.stderr);
    if !output.status.success() {
        // ct-agent#169: this error string is what the REMOTE peer receives as the JSON-RPC
        // error. The full stderr already went to the local diagnostic sink above (the
        // operator's own log); the peer gets the exit status plus a bounded, secret-redacted
        // tail -- never an unbounded crash trace that may quote the handler's API keys.
        return Err(format!(
            "service handler exited {}: {}",
            output.status,
            peer_facing_stderr_tail(&output.stderr)
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

/// ct-agent#105: forward a finished handler child's stderr into `diag`, one prefixed line per
/// stderr line, keeping only the last [`HANDLER_STDERR_PASSTHROUGH_MAX`] bytes (a cut is
/// announced so a reader never mistakes the tail for the whole). Empty stderr writes nothing --
/// a quiet handler must not add a blank line per call. Write errors on `diag` are ignored: the
/// diagnostic must never fail the call it describes.
pub(crate) fn forward_handler_stderr(diag: &mut dyn std::io::Write, slug: &str, stderr: &[u8]) {
    if stderr.is_empty() {
        return;
    }
    let (tail, cut) = if stderr.len() > HANDLER_STDERR_PASSTHROUGH_MAX {
        (&stderr[stderr.len() - HANDLER_STDERR_PASSTHROUGH_MAX..], true)
    } else {
        (stderr, false)
    };
    if cut {
        let _ = writeln!(
            diag,
            "service handler[{slug}] stderr: [... {} bytes cut, last {HANDLER_STDERR_PASSTHROUGH_MAX} shown]",
            stderr.len() - HANDLER_STDERR_PASSTHROUGH_MAX
        );
    }
    for line in String::from_utf8_lossy(tail).lines() {
        let _ = writeln!(diag, "service handler[{slug}] stderr: {line}");
    }
    let _ = diag.flush();
}

/// ct-agent#169: how much of a FAILED handler's stderr may travel to the remote peer inside the
/// tool error -- the tail, at most this many bytes, after [`redact_secrets`]. Deliberately far
/// below [`HANDLER_STDERR_PASSTHROUGH_MAX`] (the local sink's cap): the peer needs a hint of
/// what went wrong, the operator's own log keeps the record.
pub(crate) const HANDLER_STDERR_PEER_TAIL_MAX: usize = 2 * 1024;

/// ct-agent#169: the peer-facing rendering of a failed handler's stderr -- the last
/// [`HANDLER_STDERR_PEER_TAIL_MAX`] bytes (a cut is announced), trailing whitespace trimmed,
/// every secret-shaped span masked by [`redact_secrets`]. Empty stderr renders empty.
pub(crate) fn peer_facing_stderr_tail(stderr: &[u8]) -> String {
    if stderr.is_empty() {
        return String::new();
    }
    let (tail, cut) = if stderr.len() > HANDLER_STDERR_PEER_TAIL_MAX {
        (&stderr[stderr.len() - HANDLER_STDERR_PEER_TAIL_MAX..], true)
    } else {
        (stderr, false)
    };
    let text = redact_secrets(String::from_utf8_lossy(tail).trim_end());
    if cut {
        format!(
            "[... {} bytes cut, last {HANDLER_STDERR_PEER_TAIL_MAX} shown] {text}",
            stderr.len() - HANDLER_STDERR_PEER_TAIL_MAX
        )
    } else {
        text
    }
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

/// ct-agent#94: the warning to print (if any) when `CT_CHANNEL_CALL_SERVICE` is in effect and
/// `CT_CHANNEL_CALL_PARAMS` is also set -- the latter is silently ignored by this mode (it only
/// belongs to the separate `CT_CHANNEL_CALL=<method>` client). Pure and unit-testable, same
/// shape as [`call_persistent_enabled_from`] above.
pub(crate) fn call_service_params_ignored_warning(params_env_is_set: bool) -> Option<String> {
    params_env_is_set.then(|| {
        "ct-agent channel: warning: CT_CHANNEL_CALL_PARAMS is set but CT_CHANNEL_CALL_SERVICE \
         does not read it -- this mode takes its call input from stdin, not this variable \
         (ct-agent#94). For a single params-driven call instead, use CT_CHANNEL_CALL=tools/call \
         with CT_CHANNEL_CALL_PARAMS='{\"name\":\"service/<slug>\",\"arguments\":<params>}'."
            .to_string()
    })
}

/// Register the `channel/grant` tool on `reg`, backed by `operator` (2026-09-01). Split out
/// from [`channel_local`]'s --serve construction so it's directly unit-testable against a
/// bare [`ct_common::mcp::ToolRegistry`] -- no env vars, no duplex streams, no async runtime
/// needed to prove the JSON-RPC wiring (argument parsing, error propagation, response shape)
/// is correct. See [`channel_local`]'s own comment at the call site for the design rationale
/// (replaces the removed local REST-server listener; no new network listener anywhere).
pub(crate) fn register_grant_tool(reg: &mut ct_common::mcp::ToolRegistry, operator: SigningKey, scope: GrantScope) {
    if scope.any {
        // ct-agent#174: the pre-#174 cross-channel behaviour, kept for one release behind an
        // explicit flag. Said once per process, at registration.
        static GRANT_ANY_LINE: std::sync::Once = std::sync::Once::new();
        GRANT_ANY_LINE.call_once(|| {
            eprintln!(
                "ct-agent channel: DEPRECATED: {GRANT_ANY_ENV}=1 lets channel/grant mint grants for ANY \
                 channel under this operator key -- any admitted member of this channel can then obtain \
                 a grant for every other channel this operator signs for; this override will be removed \
                 in a later release (ct-agent#174)"
            );
        });
    }
    reg.register(
        "channel/grant",
        "Issue a channel grant FOR THIS AGENT'S OWN CHANNEL. Arguments: {channel, holder, \
         direction, expires_in} (64-hex channel id, 64-hex member holder pubkey, \
         \"initiate\"|\"accept\", a relative duration like \"30d\" -- the same fields `channel \
         grant --interactive` prompts for). Returns {grant: <hex>}. One channel per serving \
         process (ct-agent#174): `channel` must equal the channel this process serves \
         (CT_CHANNEL_ID, CT_GRANT_CHANNEL, or the channel inside its own CT_CHANNEL_GRANT); any \
         other channel id is refused, so an admitted \
         member of this channel can never mint grants for another channel the same operator key \
         signs for.",
        move |args: &serde_json::Value| {
            let field = |name: &str| -> Result<&str, String> {
                args.get(name)
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("missing string field `{name}`"))
            };
            let channel = field("channel")?;
            scope.check(channel)?;
            let grant = issue_grant_from_fields(
                operator.clone(),
                channel,
                field("holder")?,
                field("direction")?,
                field("expires_in")?,
            )?;
            Ok(serde_json::json!({ "grant": grant }))
        },
    );
}

/// ct-agent#174: env var restoring `channel/grant`'s pre-#174 cross-channel issuance for one
/// release (`1`/`true`/`yes`). Logged as deprecated once per process when in effect.
pub(crate) const GRANT_ANY_ENV: &str = "CT_CHANNEL_GRANT_ANY";

/// ct-agent#174: which channel(s) this process's `channel/grant` tool may issue grants for.
/// The audit finding: `CallContext` carries no channel id and the tool had no scoping check,
/// so any admitted member of ANY channel served under one operator key could mint
/// operator-signed grants for a DIFFERENT channel. The model is one channel per serving
/// process, so the fix is the simplest possible: the caller's `channel` must equal this
/// process's own configured channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantScope {
    /// This process's own channel -- `CT_CHANNEL_ID`, else `CT_GRANT_CHANNEL` (the same alias
    /// order every other channel-scoped request in this crate uses), else the channel named
    /// inside this member's own `CT_CHANNEL_GRANT` (what a `--serve` session is admitted with,
    /// so it is exactly "the channel this process serves" -- and the only one of the three a
    /// typical serve deployment has set at all). `None` when none of them yields a channel: the
    /// tool then refuses every call, naming what is missing.
    pub(crate) own_channel: Option<[u8; 32]>,
    /// `CT_CHANNEL_GRANT_ANY=1`: skip the check (deprecated, one release).
    pub(crate) any: bool,
}

impl GrantScope {
    pub(crate) fn from_env() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Read from a variable lookup (the testable seam). A malformed channel id is treated as
    /// unset rather than silently accepted: the tool will refuse and say what it needs.
    pub(crate) fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Self {
        let own_channel = ["CT_CHANNEL_ID", "CT_GRANT_CHANNEL"]
            .into_iter()
            .find_map(&f)
            .and_then(|v| decode_hex_32_bridge_peer(v.trim()))
            .or_else(|| {
                let bytes = hex_bytes(&f("CT_CHANNEL_GRANT")?)?;
                let grant = ct_common::channel::SignedChannelGrant::decode(&bytes).ok()?;
                Some(grant.grant.channel.0)
            });
        let any = matches!(
            f(GRANT_ANY_ENV).as_deref().map(str::trim),
            Some(s) if s == "1" || s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("yes")
        );
        Self { own_channel, any }
    }

    /// Only this channel, no override -- what a test or an explicit caller constructs.
    #[cfg(test)]
    pub(crate) fn own(channel: [u8; 32]) -> Self {
        Self { own_channel: Some(channel), any: false }
    }

    /// Refuse unless `requested_channel_hex` is this process's own channel (or the deprecated
    /// override is on). Both refusals name what the caller can do about it.
    pub(crate) fn check(&self, requested_channel_hex: &str) -> Result<(), String> {
        if self.any {
            return Ok(());
        }
        let own = self.own_channel.ok_or_else(|| {
            "channel/grant: grant issuance needs CT_CHANNEL_ID (or CT_GRANT_CHANNEL, or this member's \
             own CT_CHANNEL_GRANT) set on this agent -- it only issues grants for its own channel \
             (ct-agent#174)"
                .to_string()
        })?;
        let requested = decode_hex_32_bridge_peer(requested_channel_hex.trim())
            .ok_or_else(|| "channel/grant: `channel` must be exactly 64 hex characters".to_string())?;
        if requested != own {
            return Err(format!(
                "channel/grant: this agent only issues grants for its own channel {}... (requested {}...) \
                 (ct-agent#174)",
                hex_prefix(&own),
                hex_prefix(&requested)
            ));
        }
        Ok(())
    }
}

/// The first four bytes of an id as 8 lowercase hex chars -- enough to tell channels apart in
/// an error line without echoing a whole id back.
fn hex_prefix(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode `CT_CHANNEL_BRIDGE_PEER`'s 64 lowercase-hex chars into the raw pubkey, or `None`.
/// Chunks raw BYTES and `from_utf8`s each 2-byte chunk rather than slicing the `&str` by byte
/// offset -- the established fix for the char-boundary panic family this codebase has hit
/// repeatedly on malformed hex input (a naive `s[i..i+2]` slice panics if a multi-byte UTF-8
/// char straddles the boundary; chunking bytes first can't ever split one).
pub(crate) fn decode_hex_32_bridge_peer(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// ct-agent#178: every bridge tool is wrapped so ONE `bridge_call {tool, ok}` event is emitted
/// per invocation (a refused caller is `ok=false` like any other error).
fn bridge_traced(
    tool: &'static str,
    handler: impl Fn(&ct_common::mcp::CallContext, &serde_json::Value) -> Result<serde_json::Value, String>
        + Send
        + Sync
        + 'static,
) -> impl Fn(&ct_common::mcp::CallContext, &serde_json::Value) -> Result<serde_json::Value, String>
       + Send
       + Sync
       + 'static {
    move |ctx: &ct_common::mcp::CallContext, args: &serde_json::Value| {
        let out = handler(ctx, args);
        crate::events::emit(crate::events::BRIDGE_CALL, serde_json::json!({ "tool": tool, "ok": out.is_ok() }));
        out
    }
}

/// Register the "Agent bridges" tool tranche (2026-09-01, CADS-Tunnel portal remote-control
/// design) on `reg`, each gated to `bridge_peer` — the ONE Noise pubkey this agent trusts as
/// its bridge (`CT_CHANNEL_BRIDGE_PEER`; today, the deployment's single shared bridge identity,
/// scimbe's explicit "simple, if secure" call over a per-account one). Every handler below is
/// `register_ctx`, not `register`: it MUST check `ctx.peer == Some(bridge_peer)` and refuse
/// otherwise, because `ChannelGrant`/`Direction`/`Rights` (crates/common/src/channel.rs) only
/// gate the transport session, not which tool a caller may invoke -- ANY channel member
/// admitted with a valid grant can otherwise call ANY registered tool (see `channel/grant`'s own
/// tool above, deliberately open to every member; these tools must NOT be). Refusing a
/// non-bridge caller is the entire security boundary "nur der richtig eingeloggte Nutzer darf
/// den Agent steuern" rests on at the agent's own admission point, independent of whatever the
/// portal itself checks. `bridge/status`, `bridge/config`, `bridge/channel-members`,
/// `bridge/allowlist-list`, `bridge/allowlist-add`, `bridge/allowlist-remove`,
/// `bridge/manifest-list`, `bridge/manifest-install` ship in this pass; `bridge/manifest-plan`
/// (scimbe/ct-agent#183, the dry run the portal shows before an install) joins them. The mutating
/// allowlist-add/remove tools ARE gated (bridge-peer-only, same as everything else here) but
/// the portal's own confirmation-before-calling UX is separate, not-yet-built work -- this
/// tool existing safely does not mean the portal should call it without one yet. Only
/// `bridge/cert-status` (needs cross-process state -- the `channel --serve` process and the
/// `certificate` renewal daemon are separate processes, not yet wired to share tier state) and
/// `bridge/channel-revoke` remain, same list this feature's plan already scoped.
///
/// What the read-only tools return (CADS-Tunnel#763, the portal renders these directly):
/// `bridge/config` is the non-secret summary from [`bridge_config_summary`] -- role/broker/relay
/// plus `*_configured` readiness booleans and the `oidc_credential` kind, so the portal can show
/// a readiness table and grey out the tools whose prerequisites are missing BEFORE the owner
/// clicks them into an error. `bridge/manifest-list` is `{registry_url, manifests: [...]}` from
/// [`enrich_manifest_list`], each registry entry carrying an added `manifest_url` the portal can
/// hand straight back to `bridge/manifest-install` as `manifest_location`.
pub(crate) fn register_bridge_tools(reg: &mut ct_common::mcp::ToolRegistry, bridge_peer: [u8; 32]) {
    reg.register_ctx(
        "bridge/status",
        "Agent bridge status: this agent's version and that the bridge gate is active. Callable \
         only by this agent's configured bridge peer (CT_CHANNEL_BRIDGE_PEER) -- refused for any \
         other channel member, even an otherwise-admitted one.",
        bridge_traced("bridge/status", move |ctx: &ct_common::mcp::CallContext, _args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/status: caller is not this agent's configured bridge peer".to_string());
            }
            Ok(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "bridge_gated": true,
            }))
        }),
    );
    reg.register_ctx(
        "bridge/config",
        "This agent's own non-secret configuration summary: role, broker/relay addresses, \
         whether MASQUE fallback and channel/grant issuance are configured, plus readiness flags \
         saying which bridge tools can work from here: channel-members and allowlist-* need \
         cp_url_configured + channel_id_configured + an oidc_credential (\"env\", \"stored\" or \
         \"stored-expired-refreshable\" -- \"stored-expired\" means the login on disk can no longer be \
         refreshed and \"none\" that there is no credential at all); manifest-list needs \
         manifest_registry_configured; manifest-install additionally \
         needs manifest_trust_allowlist_configured + manifest_work_dir_configured, and \
         docker_available for compose-kind manifests. Never returns actual key/token/secret VALUES, \
         only which optional features are turned on. No arguments.",
        bridge_traced("bridge/config", move |ctx: &ct_common::mcp::CallContext, _args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/config: caller is not this agent's configured bridge peer".to_string());
            }
            Ok(bridge_config_summary(
                |k| std::env::var(k).ok(),
                crate::login::oidc_credential_state(),
                docker_on_path(),
            ))
        }),
    );
    // ct-agent#181: the four CP-backed tools below resolve the bearer through
    // `resolve_oidc_token_with_retry`, so an IdP that is briefly unreachable while the
    // stored login is being refreshed costs a retry, not a "run ct-agent login" error
    // surfaced to an unattended sidecar's operator.
    reg.register_ctx(
        "bridge/channel-members",
        "List this agent's own channel's members (holder + Noise pubkey per member). Needs \
         CT_AGENT_CP_URL and CT_CHANNEL_ID (or CT_GRANT_CHANNEL) configured, plus a usable OIDC \
         credential -- CT_OIDC_TOKEN, a CT_OIDC_TOKEN_FILE, or a prior `ct-agent login` (same \
         resolution `channel register`/`channel allowlist` already use). The channel is always THIS agent's \
         own -- never caller-supplied, so a bridge peer can't use this to enumerate an unrelated \
         channel's membership. No arguments.",
        bridge_traced("bridge/channel-members", move |ctx: &ct_common::mcp::CallContext, _args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/channel-members: caller is not this agent's configured bridge peer".to_string());
            }
            let env = |k: &str| std::env::var(k).ok();
            let cp_url = env("CT_AGENT_CP_URL")
                .ok_or_else(|| "bridge/channel-members: this agent has no CT_AGENT_CP_URL configured".to_string())?
                .trim_end_matches('/')
                .to_string();
            let channel_hex = hex_encode(&req_hex32_aliased(&env, "CT_CHANNEL_ID", "CT_GRANT_CHANNEL", "64 hex channel id")?);
            let body = tokio::runtime::Handle::current().block_on(async {
                let token = crate::login::resolve_oidc_token_with_retry(
                    crate::login::OIDC_REFRESH_RETRY_ATTEMPTS,
                    crate::login::OIDC_REFRESH_RETRY_BASE,
                )
                .await?;
                reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .map_err(|e| format!("building HTTP client: {e}"))?
                    .get(format!("{cp_url}/me/channels/{channel_hex}/members"))
                    .header("authorization", format!("Bearer {token}"))
                    .send()
                    .await
                    .map_err(|e| format!("GET .../channels/{channel_hex}/members: {e}"))?
                    .error_for_status()
                    .map_err(|e| format!("GET .../channels/{channel_hex}/members: {e}"))?
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|e| format!("GET .../channels/{channel_hex}/members: invalid JSON response: {e}"))
            })?;
            Ok(body)
        }),
    );
    reg.register_ctx(
        "bridge/allowlist-list",
        "List the e-mails allow-listed for self-service claim on this agent's own channel \
         (ChannelAllowlistRequest/ControlPlaneClient::channel_allowlist_list -- the exact \
         already-shipped call `ct-agent channel allowlist list` itself makes). No arguments.",
        bridge_traced("bridge/allowlist-list", move |ctx: &ct_common::mcp::CallContext, _args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/allowlist-list: caller is not this agent's configured bridge peer".to_string());
            }
            let env = |k: &str| std::env::var(k).ok();
            let emails = tokio::runtime::Handle::current().block_on(async {
                let token = crate::login::resolve_oidc_token_with_retry(
                    crate::login::OIDC_REFRESH_RETRY_ATTEMPTS,
                    crate::login::OIDC_REFRESH_RETRY_BASE,
                )
                .await?;
                let req = ChannelAllowlistRequest::from_lookup_with_token(env, token)?;
                ct_control_plane::client::ControlPlaneClient::new(req.cp_url.clone())
                    .channel_allowlist_list(&req.channel_hex, &req.token)
                    .await
                    .map_err(|e| e.to_string())
            })?;
            Ok(serde_json::json!({ "emails": emails }))
        }),
    );
    reg.register_ctx(
        "bridge/allowlist-add",
        "Allow-list an e-mail for self-service claim on this agent's own channel. Arguments: \
         {email}. Same call `ct-agent channel allowlist add <email>` already makes \
         (ControlPlaneClient::channel_allowlist_add) -- owner-scoped by the resolved OIDC \
         bearer token, not by anything the caller supplies.",
        bridge_traced("bridge/allowlist-add", move |ctx: &ct_common::mcp::CallContext, args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/allowlist-add: caller is not this agent's configured bridge peer".to_string());
            }
            let email = args
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "bridge/allowlist-add: missing string field `email`".to_string())?
                .to_string();
            let env = |k: &str| std::env::var(k).ok();
            tokio::runtime::Handle::current().block_on(async {
                let token = crate::login::resolve_oidc_token_with_retry(
                    crate::login::OIDC_REFRESH_RETRY_ATTEMPTS,
                    crate::login::OIDC_REFRESH_RETRY_BASE,
                )
                .await?;
                let req = ChannelAllowlistRequest::from_lookup_with_token(env, token)?;
                ct_control_plane::client::ControlPlaneClient::new(req.cp_url.clone())
                    .channel_allowlist_add(&req.channel_hex, &email, &req.token)
                    .await
                    .map_err(|e| e.to_string())
            })?;
            Ok(serde_json::json!({ "allow_listed": email }))
        }),
    );
    reg.register_ctx(
        "bridge/allowlist-remove",
        "Remove an e-mail from this agent's own channel's self-service allow-list. Arguments: \
         {email}. Same call `ct-agent channel allowlist remove <email>` already makes \
         (ControlPlaneClient::channel_allowlist_remove) -- owner-scoped by the resolved OIDC \
         bearer token, not by anything the caller supplies. Does NOT revoke an already-claimed \
         membership -- only stops a NEW claim of that e-mail going forward.",
        bridge_traced("bridge/allowlist-remove", move |ctx: &ct_common::mcp::CallContext, args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/allowlist-remove: caller is not this agent's configured bridge peer".to_string());
            }
            let email = args
                .get("email")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "bridge/allowlist-remove: missing string field `email`".to_string())?
                .to_string();
            let env = |k: &str| std::env::var(k).ok();
            tokio::runtime::Handle::current().block_on(async {
                let token = crate::login::resolve_oidc_token_with_retry(
                    crate::login::OIDC_REFRESH_RETRY_ATTEMPTS,
                    crate::login::OIDC_REFRESH_RETRY_BASE,
                )
                .await?;
                let req = ChannelAllowlistRequest::from_lookup_with_token(env, token)?;
                ct_control_plane::client::ControlPlaneClient::new(req.cp_url.clone())
                    .channel_allowlist_remove(&req.channel_hex, &email, &req.token)
                    .await
                    .map_err(|e| e.to_string())
            })?;
            Ok(serde_json::json!({ "removed": email }))
        }),
    );
    reg.register_ctx(
        "bridge/manifest-list",
        "List manifests available from this agent's configured registry (CT_MANIFEST_REGISTRY_URL). \
         Returns {registry_url, manifests: [...]}: the registry's own entries (manifest_id, \
         publisher_pubkey, name, version, guardrail_verdict, published_at) each with an added \
         `manifest_url` ({registry_url}/manifests/{manifest_id}) that bridge/manifest-install accepts \
         as `manifest_location` verbatim. An entry's `installer_kind`, where the registry reports one, \
         is \"compose\" (sandboxed, Docker) or \"binary\" (raw, bare executable) -- the portal's picker \
         surfaces this directly, no separate flag. No arguments.",
        bridge_traced("bridge/manifest-list", move |ctx: &ct_common::mcp::CallContext, _args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/manifest-list: caller is not this agent's configured bridge peer".to_string());
            }
            let registry_url = std::env::var("CT_MANIFEST_REGISTRY_URL")
                .map_err(|_| "bridge/manifest-list: this agent has no CT_MANIFEST_REGISTRY_URL configured".to_string())?
                .trim_end_matches('/')
                .to_string();
            let body = tokio::runtime::Handle::current()
                .block_on(async {
                    reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .map_err(|e| format!("building HTTP client: {e}"))?
                        .get(format!("{registry_url}/manifests"))
                        .send()
                        .await
                        .map_err(|e| format!("GET {registry_url}/manifests: {e}"))?
                        .error_for_status()
                        .map_err(|e| format!("GET {registry_url}/manifests: {e}"))?
                        .json::<serde_json::Value>()
                        .await
                        .map_err(|e| format!("GET {registry_url}/manifests: invalid JSON response: {e}"))
                })?;
            Ok(enrich_manifest_list(&registry_url, body))
        }),
    );
    reg.register_ctx(
        "bridge/manifest-install",
        "Install a manifest from this agent's configured registry. Arguments: {manifest_location, \
         project_name} (a URL/id from bridge/manifest-list's output, and an isolated project name \
         for THIS install -- the same explicit, no-default choice `ct-agent manifest activate` \
         itself always requires). The project name isolates the docker compose project AND selects \
         the per-activation directory <CT_MANIFEST_WORK_DIR>/<project_name> the bundle is unpacked \
         into, which is refused unless it is absent or empty (#165) -- so a second install can never \
         overwrite the first's files; reuse of a project name is an error, not a silent replace. \
         Trust allowlist, work directory, and registry-ledger config all come from this agent's OWN \
         configuration (CT_MANIFEST_TRUST_ALLOWLIST[_FILE]/CT_MANIFEST_WORK_DIR/CT_MANIFEST_*), \
         never from the caller -- the portal picks WHICH manifest, never WHO is trusted to publish \
         one. Returns the same structured InstallReport `ct-agent manifest activate` prints, plus \
         `install_dir`. Refused unconditionally, for every caller including the bridge peer, when \
         this agent's own CT_CHANNEL_BRIDGE_DISABLE_MANIFEST_INSTALL is set -- the owner's own \
         opt-out, independent of who the bridge peer or trust allowlist otherwise trust. A binary \
         manifest is installed FAIL CLOSED (#183): refused when no sandbox backend is usable on \
         this host, unless the agent's OWN process environment carries CT_ALLOW_UNSANDBOXED=1 -- \
         that opt-out is inherited from the agent's environment and is never caller-controlled. \
         Call bridge/manifest-plan first to see the verdict without installing.",
        bridge_traced("bridge/manifest-install", move |ctx: &ct_common::mcp::CallContext, args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/manifest-install: caller is not this agent's configured bridge peer".to_string());
            }
            if std::env::var("CT_CHANNEL_BRIDGE_DISABLE_MANIFEST_INSTALL").is_ok() {
                return Err(
                    "bridge/manifest-install: disabled on this agent (CT_CHANNEL_BRIDGE_DISABLE_MANIFEST_INSTALL \
                     is set) -- unset it locally to allow remote manifest installs again"
                        .to_string(),
                );
            }
            let manifest_location = args
                .get("manifest_location")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "bridge/manifest-install: missing string field `manifest_location`".to_string())?
                .to_string();
            let project_name = args
                .get("project_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "bridge/manifest-install: missing string field `project_name`".to_string())?
                .to_string();
            // Every OTHER field (trust allowlist, work dir, registry ledger config) still comes
            // from this agent's own process environment, exactly like `ct-agent manifest activate`
            // -- only which manifest and what to isolate it as are caller-supplied. That includes
            // `CT_MANIFEST_ALLOW_LOCAL_PATH` (ct-agent#170): the `other` arm below is what makes
            // the https://-only policy in `ActivateCliConfig::from_lookup` read the local-path
            // opt-in from THIS process, so a caller-supplied `manifest_location` can never be a
            // filesystem probe unless the agent's owner allowed local paths.
            let cfg = crate::manifest_run::ActivateCliConfig::from_lookup(move |k| match k {
                "CT_MANIFEST_URL" => Some(manifest_location.clone()),
                "CT_MANIFEST_PROJECT_NAME" => Some(project_name.clone()),
                other => std::env::var(other).ok(),
            })?;
            let activation = tokio::runtime::Handle::current().block_on(crate::manifest_run::run_activate(cfg))?;
            Ok(crate::manifest_run::report_json_with_install_dir(&activation))
        }),
    );
    register_bridge_manifest_plan_tool(reg, bridge_peer, |k| std::env::var(k).ok());
}

/// `bridge/manifest-plan` (scimbe/ct-agent#183): the dry run of `bridge/manifest-install`, so the
/// portal can show what an install WOULD do -- and every reason it would be refused -- before
/// the owner clicks install. Split out of [`register_bridge_tools`] (which registers it with
/// the real process environment) so the env lookup is injectable: the plan's whole config
/// (trust allowlist, work dir, sandbox opt-out) comes from `env`, and a test can supply one
/// without touching process-global state. The handler runs the blocking plan inline: the
/// registry's `dispatch_ctx` already executes on Tokio's blocking pool (see `channel_local`),
/// and a plan does nothing async -- no ledger POST, no docker -- so there is nothing to await.
/// Never accepts a compose-file path from the caller: a local path would let the bridge peer
/// point the static scan at any file this agent can read.
pub(crate) fn register_bridge_manifest_plan_tool(
    reg: &mut ct_common::mcp::ToolRegistry,
    bridge_peer: [u8; 32],
    env: impl Fn(&str) -> Option<String> + Send + Sync + 'static,
) {
    reg.register_ctx(
        "bridge/manifest-plan",
        "Dry-run a manifest install (#183): what bridge/manifest-install WOULD do on this agent's \
         host, computed without fetching a bundle, creating a directory, or running anything (a \
         binary manifest probes the sandbox backend, nothing more). Arguments: {manifest_location, \
         project_name}, exactly as bridge/manifest-install takes them. Returns the plan JSON: \
         `backend` (the sandbox backend a binary run would use; null for compose or an unsandboxed \
         opt-out run), `argv_preview` (secret values redacted), `compose_overrides` (the hardening \
         every compose service must carry), `refusals` (EVERY reason the install would be rejected, \
         in the order the checks run: signature/expiry and trust allowlist first, then the \
         environment contract, the sandbox requirement, and the compose guardrails when the compose \
         text is available), plus `would_refuse`, `install_dir` and `manifest_id`. The static \
         compose scan is skipped here (the bundle is not fetched and no caller-supplied file is ever \
         read); the real install scans the unpacked bundle. Trust allowlist, work directory and the \
         CT_ALLOW_UNSANDBOXED opt-out come from this agent's OWN environment, never from the caller. \
         Not gated by CT_CHANNEL_BRIDGE_DISABLE_MANIFEST_INSTALL: a plan installs nothing.",
        bridge_traced("bridge/manifest-plan", move |ctx: &ct_common::mcp::CallContext, args: &serde_json::Value| {
            if ctx.peer != Some(bridge_peer) {
                return Err("bridge/manifest-plan: caller is not this agent's configured bridge peer".to_string());
            }
            let manifest_location = args
                .get("manifest_location")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "bridge/manifest-plan: missing string field `manifest_location`".to_string())?
                .to_string();
            let project_name = args
                .get("project_name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "bridge/manifest-plan: missing string field `project_name`".to_string())?
                .to_string();
            let cfg = crate::manifest_run::PlanCliConfig::from_lookup(|k| match k {
                "CT_MANIFEST_URL" => Some(manifest_location.clone()),
                "CT_MANIFEST_PROJECT_NAME" => Some(project_name.clone()),
                // Never a caller path (see the doc above); `create`'s meaning of this variable
                // in the agent's environment is a path INSIDE a bundle and must not be scanned.
                "CT_MANIFEST_COMPOSE_FILE" => None,
                other => env(other),
            })?;
            let planned = crate::manifest_run::run_plan_blocking(cfg)?;
            Ok(crate::manifest_run::plan_json_with_install_dir(&planned))
        }),
    );
}

/// The `bridge/config` tool's whole answer, built purely from `env` (a `CT_*` lookup), the
/// OIDC credential's state (`crate::login::oidc_credential_state`, judged without refreshing),
/// and whether `docker` is on PATH -- so the readiness logic is unit-testable without touching
/// the process environment (CADS-Tunnel#763). Only ever reports non-secret values: addresses/role
/// as-is, everything else as a presence boolean or, for the OIDC credential, WHICH kind and
/// state (ct-agent#181): `"env"` = `CT_OIDC_TOKEN` or a `CT_OIDC_TOKEN_FILE`, `"stored"` = a usable
/// login on disk, `"stored-expired-refreshable"` = one the next call will refresh,
/// `"stored-expired"` = one that can no longer be refreshed (re-login or `CT_OIDC_TOKEN_FILE`
/// needed), `"none"` -- the same precedence `crate::login::resolve_oidc_token` applies, and the
/// three pre-#181 spellings unchanged. The `*_configured` flags mirror exactly what each bridge
/// tool checks before it can work: `bridge/channel-members` and `bridge/allowlist-*` need
/// `cp_url_configured` + `channel_id_configured` + a credential; `bridge/manifest-list` needs
/// `manifest_registry_configured`; `bridge/manifest-install` (and `bridge/manifest-plan`) also needs
/// `manifest_trust_allowlist_configured` + `manifest_work_dir_configured`, and `docker_available`
/// for compose-kind manifests. A `bool` can't leak a secret, so the portal may render this table
/// freely.
pub(crate) fn bridge_config_summary(
    env: impl Fn(&str) -> Option<String>,
    oidc: crate::login::OidcCredentialState,
    docker_on_path: bool,
) -> serde_json::Value {
    let set = |k: &str| env(k).is_some_and(|v| !v.trim().is_empty());
    let masque_configured = [
        "CT_AGENT_MASQUE_PROXY",
        "CT_AGENT_MASQUE_SNI_HOST",
        "CT_AGENT_MASQUE_TARGET",
        "CT_AGENT_MASQUE_TOKEN",
    ]
    .iter()
    .all(|&k| env(k).is_some());
    let oidc_credential = oidc.as_str();
    serde_json::json!({
        "role": env("CT_CHANNEL_ROLE"),
        "broker": env("CT_CHANNEL_BROKER"),
        "relay": env("CT_CHANNEL_RELAY"),
        "direct_upgrade": env("CT_CHANNEL_DIRECT_UPGRADE").is_some(),
        "masque_fallback_configured": masque_configured,
        "grant_issuance_configured": env("CT_CHANNEL_OPERATOR_KEY").is_some(),
        "manifest_registry_configured": env("CT_MANIFEST_REGISTRY_URL").is_some(),
        "manifest_install_disabled": env("CT_CHANNEL_BRIDGE_DISABLE_MANIFEST_INSTALL").is_some(),
        "cp_url_configured": set("CT_AGENT_CP_URL"),
        "channel_id_configured": env("CT_CHANNEL_ID").is_some() || env("CT_GRANT_CHANNEL").is_some(),
        "oidc_credential": oidc_credential,
        "manifest_trust_allowlist_configured": env("CT_MANIFEST_TRUST_ALLOWLIST").is_some()
            || env("CT_MANIFEST_TRUST_ALLOWLIST_FILE").is_some(),
        "manifest_work_dir_configured": env("CT_MANIFEST_WORK_DIR").is_some(),
        "docker_available": docker_on_path,
    })
}

/// Whether a `docker` executable sits in one of this process's `PATH` directories -- i.e. whether
/// a compose-kind manifest could be installed from here at all (CADS-Tunnel#763). A pure
/// filesystem probe, deliberately NOT a `docker version` subprocess: `bridge/config` is a cheap
/// read-only status call and must not spawn anything (or hang on a wedged daemon socket).
fn docker_on_path() -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|dir| dir.join("docker").is_file()))
        .unwrap_or(false)
}

/// Shape the registry's `GET {registry_url}/manifests` answer into `bridge/manifest-list`'s
/// result (CADS-Tunnel#763): `{registry_url, manifests}`. When `body` is the registry's JSON
/// array, every object entry with a string `manifest_id` gains a `manifest_url` of
/// `{registry_url}/manifests/{manifest_id}` -- the exact `manifest_location`
/// `bridge/manifest-install` (and `ct-agent manifest activate`) accept -- unless the registry
/// already supplied one, which is then left untouched; non-object elements pass through as-is. A
/// non-array `body` (an older/other registry shape) is wrapped under `manifests` unchanged
/// rather than dropped, so the portal always sees the same envelope.
pub(crate) fn enrich_manifest_list(registry_url: &str, body: serde_json::Value) -> serde_json::Value {
    let manifests = match body {
        serde_json::Value::Array(entries) => serde_json::Value::Array(
            entries
                .into_iter()
                .map(|entry| match entry {
                    serde_json::Value::Object(mut obj) => {
                        let id = obj.get("manifest_id").and_then(|v| v.as_str()).map(str::to_string);
                        if let Some(id) = id.filter(|_| !obj.contains_key("manifest_url")) {
                            obj.insert(
                                "manifest_url".to_string(),
                                serde_json::Value::String(format!("{registry_url}/manifests/{id}")),
                            );
                        }
                        serde_json::Value::Object(obj)
                    }
                    other => other,
                })
                .collect(),
        ),
        other => other,
    };
    serde_json::json!({
        "registry_url": registry_url,
        "manifests": manifests,
    })
}

/// Build the channel session's local app duplex from the environment (#135 L2.x). `CT_CHANNEL_CALL=<method>`
/// → one-shot MCP **client** (invoke a peer's tool, print the reply, exit). `CT_CHANNEL_SERVE=1` → the
/// persistent MCP **service** (JSON-RPC `tools/list`/`tools/call` via the tool registry). Neither → the
/// historical stdin/stdout pipe.
/// `peer`: the channel-authenticated remote's Noise static public key, when already known at
/// the call site (e.g. a resolved broker admission, or a direct-mode config's configured peer
/// key) — threaded into the `--serve` registry's dispatch as a [`ct_common::mcp::CallContext`]
/// so identity-aware tools (bridge tools, gated to one specific configured caller — see
/// `register_bridge_tools`) can refuse anyone else. `None` when not yet known at this call site
/// (pre-admission paths) or not applicable (`Pipe`/one-shot `--call` mode never dispatches
/// through a registry at all) — identical to today's always-anonymous `dispatch()` behaviour.
pub(crate) fn channel_local(peer: Option<[u8; 32]>) -> ChannelLocal {
    // #173 distributed crew: one-shot `service/<slug>` client. Reads the prompt on stdin, calls the
    // peer's service, prints the BARE output — the crew-bridge `CREW_*_CMD` contract. Checked before
    // the raw CT_CHANNEL_CALL below because it's the service-specific (and jq-free) path.
    if let Ok(slug) = std::env::var("CT_CHANNEL_CALL_SERVICE") {
        let slug = slug.trim().to_string();
        // ct-agent#94: CT_CHANNEL_CALL_PARAMS is a real, working env var -- just for the OTHER
        // client mode below (CT_CHANNEL_CALL=<method>). It is never read on this branch (input
        // comes from stdin instead), and silently ignoring it is exactly the "worst failure
        // mode" #94 reported: no join/call/error, just a silent success-shaped exit, because
        // nothing ever told the caller their params never reached anything. Diagnostic-only --
        // does not change what CT_CHANNEL_CALL_SERVICE does, only makes the misconfiguration
        // visible.
        if let Some(warning) = call_service_params_ignored_warning(std::env::var("CT_CHANNEL_CALL_PARAMS").is_ok())
        {
            eprintln!("{warning}");
        }
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
        // Grant issuance over the already-authenticated channel (2026-09-01). Replaces
        // the removed local REST-server listener (`rest_server.rs`, deleted after it
        // caused a real crash on one operator's install and, more fundamentally, was
        // architecturally unnecessary): an agent that holds the channel operator's own
        // key can expose a `channel/grant` tool right here, on the SAME session already
        // open for --serve mode -- no new network listener anywhere, on either side.
        // Only a peer this operator already admitted to the channel (the channel's own
        // grant-based admission, unrelated to this tool) can ever reach it at all.
        // Silently absent (not registered) when CT_CHANNEL_OPERATOR_KEY isn't set, same
        // "only exists if configured" posture as agent/card and the auction tools above.
        if let Ok(operator) = operator_key_from_env() {
            // ct-agent#174: scoped to this process's own channel (CT_CHANNEL_ID, else
            // CT_GRANT_CHANNEL, else the channel inside this member's own CT_CHANNEL_GRANT);
            // with none of them the tool is still registered but refuses every call naming
            // what it needs, so the misconfiguration is visible to the caller rather than
            // silently widening to every channel.
            let scope = GrantScope::from_env();
            let scope_line = match (&scope.own_channel, scope.any) {
                (_, true) => "for ANY channel (CT_CHANNEL_GRANT_ANY=1, deprecated)".to_string(),
                (Some(own), false) => format!("for its own channel {}... only", hex_prefix(own)),
                (None, false) => "-- but none of CT_CHANNEL_ID/CT_GRANT_CHANNEL/CT_CHANNEL_GRANT names a channel, so every call will be refused (ct-agent#174)".to_string(),
            };
            register_grant_tool(&mut reg, operator, scope);
            static GRANT_TOOL_LINE: std::sync::Once = std::sync::Once::new();
            GRANT_TOOL_LINE.call_once(|| {
                eprintln!(
                    "ct-agent channel: --serve configured to expose channel/grant \
                     (CT_CHANNEL_OPERATOR_KEY set) {scope_line} -- served to admitted peers only, \
                     no new network listener"
                );
            });
        }
        // Agent bridges (2026-09-01): a curated, explicitly peer-gated tool tranche for the
        // CADS-Tunnel portal's remote-control feature -- see `register_bridge_tools`'s own doc
        // for why every handler there re-checks the caller's identity even though the channel
        // itself already authenticated them. Silently absent unless CT_CHANNEL_BRIDGE_PEER is
        // set to a valid 64-hex Noise pubkey, same "only exists if configured" posture as
        // channel/grant and the auction tools above.
        if let Ok(raw) = std::env::var("CT_CHANNEL_BRIDGE_PEER") {
            match decode_hex_32_bridge_peer(raw.trim()) {
                Some(bridge_peer) => {
                    register_bridge_tools(&mut reg, bridge_peer);
                    static BRIDGE_TOOLS_LINE: std::sync::Once = std::sync::Once::new();
                    BRIDGE_TOOLS_LINE.call_once(|| {
                        eprintln!(
                            "ct-agent channel: --serve configured to expose Agent-bridge tools \
                             (CT_CHANNEL_BRIDGE_PEER set) -- served only to that one configured \
                             peer, refused for every other admitted channel member"
                        );
                    });
                }
                None => {
                    eprintln!(
                        "ct-agent channel: CT_CHANNEL_BRIDGE_PEER is set but not valid 64-hex -- \
                         Agent-bridge tools NOT registered"
                    );
                }
            }
        }
        let registry = std::sync::Arc::new(reg);
        let ctx = ct_common::mcp::CallContext { peer };
        ChannelLocal::Serve(serve_local(move |req: Vec<u8>| {
            let registry = registry.clone();
            let ctx = ctx;
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
                tokio::task::spawn_blocking(move || registry.dispatch_ctx(&ctx, &req))
                    .await
                    .unwrap_or_default()
            }
        }))
    } else {
        ChannelLocal::Pipe(tokio::io::join(tokio::io::stdin(), tokio::io::stdout()))
    }
}
