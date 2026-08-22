//! The persistent "serve" admission cluster (#200): how an accept-side member with
//! `CT_CHANNEL_SERVE` set stays parked and handles many successive peers concurrently.
//!
//! Herausgeloest aus `channel_run/mod.rs` (Konsolidierungsprogramm, Modulsplit Schnitt 5,
//! #38): admit -> serve, the shared per-member context, and the concurrency-bounding loop
//! that drives them. `run_channel_join_command` (still in `mod.rs`) builds the
//! [`ServeSessionCtx`] once and hands `admit_one_peer`/`serve_admitted_session` to
//! [`serve_loop_concurrent`] as closures.
//!
//! Reiner Verschiebeschnitt: kein Verhalten geaendert. Sichtbarkeiten wurden nur so weit
//! geoeffnet, wie der Umzug es verlangt (`ServeSessionCtx`'s Felder eingeschlossen -- seine
//! Konstruktion bleibt in `mod.rs`'s `run_channel_join_command`).

use super::*;

/// #200: the owned, `Send + Sync` context a persistent serve member needs to run each of its
/// concurrent sessions independently of the parking loop. Built ONCE (cloning the config's
/// request/holder/ladders + cert, and binding the shared direct listener) so each spawned session
/// borrows only from an `Arc<ServeSessionCtx>` and never from the loop's stack.
pub(crate) struct ServeSessionCtx {
    pub(crate) request: ChannelJoinRequest,
    pub(crate) holder: SigningKey,
    pub(crate) role: ChannelRole,
    pub(crate) own_noise_private: [u8; 32],
    pub(crate) broker_addr: SocketAddr,
    pub(crate) relay_addr: SocketAddr,
    pub(crate) broker_ladder: Vec<ChannelDialRung>,
    pub(crate) relay_ladder: Vec<ChannelDialRung>,
    pub(crate) front_door_cert: Option<CertificateDer<'static>>,
    /// Bound once (Accept + not relay-only) and cloned per session; `None` for relay-only members
    /// (they can't be dialed directly) — those serve purely over the edge relay.
    pub(crate) listener: Option<Endpoint>,
    /// #104, mirrors [`ChannelJoinCliConfig::direct_upgrade`] (`CT_CHANNEL_DIRECT_UPGRADE`).
    pub(crate) direct_upgrade: bool,
}

/// #200: present the grant to the broker and park until the edge pairs the NEXT peer, returning that
/// peer's admission. This is the sequential part of the serve loop — only one admission is ever
/// parked, so the pairer is never asked to hold two accepts for one channel. Mirrors the admission
/// half of [`run_one_admission_session`], reading from the shared `Arc` instead of borrowed config.
///
/// A **refused** outcome (a clean broker round-trip whose answer is "no") is turned into an `Err`
/// here — not returned as `Ok(ChannelJoinOutcome::Refused)` — so [`serve_loop_concurrent`] routes it
/// through its existing error/backoff path instead of its `Ok(work) => spawn(..)` path. Before this,
/// a refusal-as-a-value was indistinguishable from a real admission at that match: it got spawned as
/// a full session (through `channel_local()`'s "--serve mode" setup and the rest of
/// [`run_channel_join_with_admission`]) only to immediately fail there with the very same "refused
/// the channel join" message — resetting `consecutive_refusals` to 0 on every attempt (since the
/// outer loop saw `Ok`, not `Err`) and so **never** engaging #231's exponential backoff for this
/// failure mode. Live-observed via #248: a channel's outer loop hammering `admit_one_peer` at a near-
/// zero-backoff rate whenever every admission attempt came back refused-as-a-value, spawning (and
/// immediately discarding) hundreds of sessions an hour instead of backing off between attempts.
pub(crate) async fn admit_one_peer(ctx: &ServeSessionCtx) -> Result<ChannelJoinOutcome, BoxError> {
    let outcome = match &ctx.front_door_cert {
        Some(edge_cert) => {
            present_channel_join_via_ladder(&ctx.broker_ladder, &ctx.request, &ctx.holder, edge_cert.clone(), DIRECT_DIAL_TIMEOUT).await?
        }
        None => {
            // #25: name the path -- rung log lines exist only on the ladder above, and
            // their absence here has been misread as a failure during live debugging.
            eprintln!("ct-agent channel: direct-QUIC broker admission (no front-door cert configured -- no ladder)");
            let broker_conn = crate::transport::build_channel_dialer()?
                .connect(ctx.broker_addr, "localhost")?
                .await?;
            // CADS-Tunnel#495 U2 (a'): broker_conn is admission-only -- PHASE_MARKER_RENDEZVOUS.
            present_channel_join_marked(&broker_conn, &ctx.request, &ctx.holder, PHASE_MARKER_RENDEZVOUS).await?
        }
    };
    reject_refused_outcome(outcome)
}

/// Pure translation step for [`admit_one_peer`], pulled out so it's unit-testable without a real
/// broker: turn a **refused** outcome into the same `Err` string [`is_definitive_admission_refusal`]
/// already recognizes, so [`serve_loop_concurrent`] routes it through its error/backoff path instead
/// of spawning it as if it were a real session. See [`admit_one_peer`]'s doc comment for why this
/// matters (#248).
pub(crate) fn reject_refused_outcome(outcome: ChannelJoinOutcome) -> Result<ChannelJoinOutcome, BoxError> {
    match outcome {
        ChannelJoinOutcome::Refused { ref category } => {
            // #524: base string frozen, category appended when present.
            Err(AdmissionRefused::boxed_with_category(
                "edge broker refused the channel join",
                category.as_deref(),
            ))
        }
        // #21: a park expiry becomes the DISTINCT typed error so [`serve_loop_concurrent`]
        // routes it through its immediate-re-park path (no refusal backoff, no ladder advance)
        // instead of spawning it as a session or backing off as if refused.
        ChannelJoinOutcome::ParkExpired => Err(ParkExpired::boxed(
            "channel park expired with no partner within the edge park window (#21) -- re-parking",
        )),
        admitted => Ok(admitted),
    }
}

/// #200: run one already-admitted peer's session to completion — the SPAWNED part of the serve loop.
/// Rebuilds the relay fallback + a fresh local app stream and clones the shared direct listener, then
/// runs the session exactly as [`run_one_admission_session`] does. A fresh `channel_local()` per
/// session matches the pre-existing per-session behaviour (the #179 loop rebuilt it each peer too).
pub(crate) async fn serve_admitted_session(
    ctx: std::sync::Arc<ServeSessionCtx>,
    admission: ChannelJoinOutcome,
) -> Result<(), BoxError> {
    let relay = match &ctx.front_door_cert {
        Some(edge_cert) => RelayFallback::Ladder {
            rungs: &ctx.relay_ladder,
            edge_cert: edge_cert.clone(),
            direct_timeout: DIRECT_DIAL_TIMEOUT,
        },
        None => RelayFallback::QuicLazy(ctx.relay_addr),
    };
    let listener = ctx.listener.clone(); // cheap quinn handle; shared across concurrent sessions
    let local = channel_local();
    run_channel_join_with_admission(
        admission,
        relay,
        &ctx.request,
        &ctx.holder,
        ctx.role,
        &ctx.own_noise_private,
        listener,
        DIRECT_DIAL_TIMEOUT,
        CHANNEL_ACCEPT_TIMEOUT,
        local,
        ctx.direct_upgrade,
    )
    .await
}

/// #200: default number of concurrent serve sessions when `CT_CHANNEL_SERVE_CONCURRENCY` is unset —
/// comfortably covers realistic demo concurrency (central's 5/10-at-once test) while bounding the
/// fan-out of handler subprocesses (`claude -p`) a flood of Builds can trigger.
pub(crate) const DEFAULT_SERVE_CONCURRENCY: usize = 8;

/// Parse `CT_CHANNEL_SERVE_CONCURRENCY` into a concurrency cap: a positive integer overrides the
/// default; anything absent/blank/zero/malformed falls back to [`DEFAULT_SERVE_CONCURRENCY`]. Pure.
pub(crate) fn serve_concurrency_from_env(value: Option<&str>) -> usize {
    value
        .and_then(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(DEFAULT_SERVE_CONCURRENCY)
}

/// #250: atomically record one just-ended session's flap outcome on the shared streak counter.
/// A single [`AtomicU32::fetch_add`]/[`AtomicU32::store`] — never a separate load followed by a
/// store — because [`serve_loop_concurrent`] runs up to `max` sessions concurrently and their
/// completions (and therefore their calls here) can race: a `load`-then-`store` sequence lets two
/// concurrently-completing flapping sessions both read the same pre-increment value and one
/// increment is then silently lost on write-back, undercounting the very streak #250's backoff
/// escalates on (and, symmetrically, a `store(0)` from a session that raced in between a
/// concurrent flap's load and store could itself be clobbered by that flap's stale write).
pub(crate) fn record_flap_outcome(counter: &std::sync::atomic::AtomicU32, flapped: bool) {
    if flapped {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else {
        counter.store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// #200: drive a persistent serve member as CONCURRENT sessions. `admit` parks at the broker and
/// returns the next paired peer's session work `W` (called sequentially — only one admission is ever
/// in flight); `serve` runs a session to completion and is SPAWNED, so the loop returns to `admit`
/// the next peer immediately instead of blocking on the whole session. `max` bounds in-flight
/// sessions via a semaphore whose permit is taken BEFORE parking (backpressure: we never admit a peer
/// we have no capacity to serve) and released when the session ends. A transient `admit` error is
/// logged and retried after `retry_backoff`; a **refused** (definitive, not-a-member) admission
/// backs off exponentially instead — see [`admission_retry_backoff`]. A `serve` error is a single
/// peer's problem, logged and dropped. Never returns under normal operation. Injectable so the
/// concurrency contract is unit-testable without a real broker/relay.
pub(crate) async fn serve_loop_concurrent<A, Fa, S, Fs, W>(
    max: usize,
    retry_backoff: std::time::Duration,
    mut admit: A,
    serve: S,
) -> Result<(), BoxError>
where
    A: FnMut() -> Fa,
    Fa: std::future::Future<Output = Result<W, BoxError>>,
    S: Fn(W) -> Fs,
    Fs: std::future::Future<Output = Result<(), BoxError>> + Send + 'static,
    W: Send + 'static,
{
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max.max(1)));
    let mut consecutive_refusals: u32 = 0;
    // #40 (CADS-Tunnel#335): independent from `consecutive_refusals` -- a TLS-handshake-EOF
    // admission failure (a saturated edge connection cap shedding pre-handshake) has a
    // different cause and a different natural resolution time than a definitive refusal, so
    // its own streak must not affect, or be affected by, the refusal streak.
    let mut consecutive_handshake_eofs: u32 = 0;
    // #250: shared across spawned sessions (all admissions on this loop are for the SAME
    // channel/holder -- an accept-side member has exactly one fixed remote grant, so there is
    // no "other peer" a global backoff could unfairly delay). Incremented by a session that
    // dies within FLAPPING_SESSION_THRESHOLD of being admitted; reset by any session that
    // either succeeds or simply lives long enough to not look like a flap.
    let consecutive_flaps = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    loop {
        let permit = sem
            .clone()
            .acquire_owned()
            .await
            .expect("serve concurrency semaphore is never closed");
        // #250: back off BEFORE the next admit if the last several sessions all died
        // near-instantly -- otherwise a flapping peer re-pairs and dies again at native RTT
        // speed forever, with no gap for the underlying interference (if transient) to clear
        // and no relief for the edge (every pairing round-trips a full admission + relay
        // splice for nothing).
        let flaps = consecutive_flaps.load(std::sync::atomic::Ordering::Relaxed);
        if flaps > 0 {
            let backoff = flapping_session_backoff(retry_backoff, flaps);
            eprintln!(
                "ct-agent channel: {flaps} consecutive session(s) died within {}ms of pairing (#250) -- \
                 backing off {backoff:?} before the next admit (peer may be experiencing network \
                 interference: AV/firewall DPI killing the connection post-handshake is the leading \
                 cause seen in the field)",
                FLAPPING_SESSION_THRESHOLD.as_millis()
            );
            tokio::time::sleep(backoff).await;
        }
        match admit().await {
            Ok(work) => {
                consecutive_refusals = 0;
                consecutive_handshake_eofs = 0;
                let fut = serve(work);
                let flap_counter = consecutive_flaps.clone();
                tokio::spawn(async move {
                    let _permit = permit; // held for the whole session; frees a slot on drop
                    let started = std::time::Instant::now();
                    let result = fut.await;
                    let flapped = is_flapping_session(started.elapsed(), result.is_err());
                    record_flap_outcome(&flap_counter, flapped);
                    if let Err(e) = result {
                        eprintln!("ct-agent channel: serve session ended with error (#200): {e}");
                    }
                });
            }
            Err(e) => {
                drop(permit);
                // #21: a park expiry re-parks IMMEDIATELY on the same transport -- it is neither
                // a refusal (never counts toward the #231 backoff) nor a failure worth the
                // generic "admission error" log line (the named line below is the field-visible
                // contract the #21 measurement greps for). The single fast `retry_backoff` sleep
                // (200ms in production) is only a tight-loop guard against a misbehaving edge
                // that reaps instantly; a healthy edge parks for the full TTL between expiries.
                if is_park_expired(&e) {
                    consecutive_refusals = 0;
                    consecutive_handshake_eofs = 0;
                    eprintln!("ct-agent channel: {e}");
                    tokio::time::sleep(retry_backoff).await;
                    continue;
                }
                // #40 (CADS-Tunnel#335): checked before refusal classification -- a
                // TLS-handshake-EOF is not a refusal (nothing about the grant or holder was
                // even reached), so it must not feed or reset `consecutive_refusals` either.
                // Escalates on its own streak instead of retrying at native speed against a
                // saturated cap (CADS-Tunnel#335's field-observed failure mode).
                if is_transport_handshake_eof(&e) {
                    consecutive_refusals = 0;
                    consecutive_handshake_eofs = consecutive_handshake_eofs.saturating_add(1);
                    let backoff = handshake_eof_backoff(retry_backoff, consecutive_handshake_eofs);
                    eprintln!(
                        "ct-agent channel: {consecutive_handshake_eofs} consecutive TLS-handshake-EOF \
                         admission attempt(s) (#40/CADS-Tunnel#335) -- backing off {backoff:?} before \
                         the next admit (a saturated edge connection cap is the leading known cause; \
                         it clears on its own once load drops)"
                    );
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                consecutive_handshake_eofs = 0;
                let refused = is_definitive_admission_refusal(&e);
                consecutive_refusals = if refused { consecutive_refusals.saturating_add(1) } else { 0 };
                let backoff = admission_retry_backoff(retry_backoff, refused, consecutive_refusals);
                eprintln!("ct-agent channel: admission error, re-admitting (#200): {e}");
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// #179: should `ct-agent channel` stay parked and re-admit successive peers? Only the **accept**
/// side in **serve** mode (`CT_CHANNEL_SERVE` truthy) — the parking side of a role a pipeline dials
/// repeatedly. An initiator (or a non-serve accept) does exactly one session and exits. Pure.
pub(crate) fn should_serve_loop(role: ChannelRole, serve_env: Option<&str>) -> bool {
    role == ChannelRole::Accept
        && serve_env
            .map(|v| {
                let t = v.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
}

/// One admit→serve cycle of the plane-brokered flow: re-present the grant to the broker (a fresh
/// admission per peer), build the relay fallback + optional direct listener, and run the session
/// with a fresh local app stream. Factored out so [`run_channel_join_command`]'s #179 serve loop can
/// repeat it for each successive peer without re-parsing config.
///
/// Thin wrapper over [`run_one_admission_session_with_local`] that builds the local app stream via
/// [`channel_local`] itself — the shape every existing caller (this one-shot CALL path, the #179
/// serve loop) wants. ct-agent#47's persistent-CALL reconnect loop needs the OTHER split: it must
/// call `channel_local()` itself ONCE (setting up the stdin-reading thread), then reuse the shared
/// `mpsc` feed across many redials — calling `channel_local()` again per attempt would re-enter the
/// already-documented #248 trap (stdin is only readable to EOF once). See
/// [`run_one_admission_session_with_local`].
pub(crate) async fn run_one_admission_session(
    cfg: &ChannelJoinCliConfig,
    request: &ChannelJoinRequest,
    broker_ladder: &[ChannelDialRung],
    relay_ladder: &[ChannelDialRung],
    front_door_cert: &Option<CertificateDer<'static>>,
) -> Result<(), BoxError> {
    let local = channel_local();
    run_one_admission_session_with_local(cfg, request, broker_ladder, relay_ladder, front_door_cert, local).await
}

/// [`run_one_admission_session`]'s body, minus its own `channel_local()` call — `local` is supplied
/// by the caller instead. Exists so a caller that must control the local app stream's lifecycle
/// itself (ct-agent#47: redialing this admission cycle repeatedly while reusing ONE stdin feed
/// across attempts) can drive the identical admission/relay/session logic without re-entering
/// `channel_local()`.
pub(crate) async fn run_one_admission_session_with_local<L>(
    cfg: &ChannelJoinCliConfig,
    request: &ChannelJoinRequest,
    broker_ladder: &[ChannelDialRung],
    relay_ladder: &[ChannelDialRung],
    front_door_cert: &Option<CertificateDer<'static>>,
    local: L,
) -> Result<(), BoxError>
where
    L: AsyncRead + AsyncWrite + Unpin,
{
    let admission = match front_door_cert {
        Some(edge_cert) => {
            present_channel_join_via_ladder(broker_ladder, request, &cfg.holder, edge_cert.clone(), DIRECT_DIAL_TIMEOUT).await?
        }
        None => {
            let broker_conn = crate::transport::build_channel_dialer()?
                .connect(cfg.broker_addr, "localhost")?
                .await?;
            // CADS-Tunnel#495 U2 (a'): broker_conn is admission-only -- PHASE_MARKER_RENDEZVOUS.
            present_channel_join_marked(&broker_conn, request, &cfg.holder, PHASE_MARKER_RENDEZVOUS).await?
        }
    };
    // The relay data leg mirrors the broker leg (#106 relay-leg-443): with a `:443` front-door cert
    // the relay fallback walks its own ladder — direct QUIC to the relay port, then the `:443` front
    // door — so a member whose relay port is ALSO filtered can still relay. Without a cert, the eager
    // direct-QUIC relay dial is unchanged.
    let relay = match front_door_cert {
        Some(edge_cert) => RelayFallback::Ladder {
            rungs: relay_ladder,
            edge_cert: edge_cert.clone(),
            direct_timeout: DIRECT_DIAL_TIMEOUT,
        },
        // #103: dial the relay LAZILY (only on direct-dial failure).
        None => RelayFallback::QuicLazy(cfg.relay_addr),
    };
    // #121: a relay-only member skips binding the direct listener even in Accept — it can't be dialed.
    let listener = match cfg.role {
        ChannelRole::Accept if !cfg.relay_only => Some(crate::transport::build_direct_listener_at(cfg.listen_addr)?.0),
        _ => None,
    };
    run_channel_join_with_admission(
        admission,
        relay,
        request,
        &cfg.holder,
        cfg.role,
        &cfg.own_noise_private,
        listener,
        DIRECT_DIAL_TIMEOUT,
        CHANNEL_ACCEPT_TIMEOUT,
        local,
        cfg.direct_upgrade,
    )
    .await
}
