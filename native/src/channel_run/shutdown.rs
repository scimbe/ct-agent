//! SIGTERM and SIGINT for a running `ct-agent channel` process: stop taking new peers and
//! connections, give the work in flight a bounded drain, then exit -- with status 0, "stopped on
//! request", unless the stop cut a one-shot transfer.
//!
//! Before this a channel process installed no signal handler. As a container's PID 1 it therefore
//! ignored SIGTERM -- the kernel drops a signal that PID 1 does not handle -- so every pod
//! termination waited out the whole grace period (30 s by default) and ended in SIGKILL, and a
//! persistent serve member's parked admission died with the process instead of closing first.
//! Outside a container SIGTERM killed the process on the spot, cutting whatever was in flight.
//!
//! On the first SIGTERM or SIGINT:
//!
//! 1. `/readyz` answers 503 ([`super::health`]) and the process-wide stop ([`process_stop`]) is
//!    cancelled. A persistent serve member drops the admission it has parked at the edge -- the
//!    leg closes, so the edge drops the park (a keepalive leg at once) instead of pairing a peer
//!    with a process that is going away -- and parks no more ([`admit_next_peer`]). A forward
//!    initiator's engine closes every new local connection at once, instead of leaving it in the
//!    listen backlog until the exit resets it: the client gets a failure it can retry elsewhere
//!    right away. Sessions already running go on.
//! 2. The drain: the process waits until nothing is in flight -- a forward member's streams, any
//!    other member's sessions, a QUIC session's wait for the peer to acknowledge its tail included
//!    ([`super::health::ChannelHealth::in_flight`]) -- for at most [`SHUTDOWN_DRAIN_ENV`] (default
//!    [`DEFAULT_SHUTDOWN_DRAIN`], `0`: no wait). An idle forward session (no stream on it) is
//!    nothing to wait for.
//! 3. The exit ([`exit_status`]): status 0 when nothing was cut, and always for a member that runs
//!    for good (a forward, a persistent serve member) -- it did what it was asked to. A one-shot
//!    member (a pipe, a call) whose transfer the stop cut exits with the status the signal itself
//!    gave before there was a handler (143 for SIGTERM, 130 for SIGINT), so a caller that checks
//!    the status does not take a cut transfer for a complete one.
//!
//! Another stop signal ends the drain at once -- but only one that comes [`REPEAT_DEBOUNCE`] or
//! more after the first. A copy of the same stop comes sooner: systemd's default
//! `KillMode=control-group` signals every process of the unit at once, so a wrapper script or
//! `ct-agent-supervisor` that passes SIGTERM on delivers a second one milliseconds after the
//! first, and that copy must not cut the drain short.
//!
//! The reconnect loops (a forward initiator's, the relay-only DCUtR serve loop's, a persistent
//! `--call`'s) are not stopped on their own: a session that ends during the drain leaves nothing
//! in flight, so the process exits within about 100 ms -- before a forward initiator's next
//! admission (1 s at the earliest); an admission one of the other loops starts in that window
//! ends with the process.
//!
//! This is a different contract from a member that stops ON ITS OWN because its grant ended
//! (ct-agent#308): that status says "a restart with this configuration cannot help", these say
//! "stopped on request" or "stopped on request, transfer incomplete".

use std::future::Future;
use std::sync::OnceLock;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::health::{health_listen_from, ChannelHealth, HEALTH, HEALTH_LISTEN_ENV};

/// `CT_CHANNEL_SHUTDOWN_DRAIN_SECS`: how long a stopped channel process waits for its work in
/// flight before it exits. Keep it below what the orchestrator allows between SIGTERM and SIGKILL
/// (Kubernetes' `terminationGracePeriodSeconds`, 30 s by default; `ct-agent-supervisor` 10 s).
pub const SHUTDOWN_DRAIN_ENV: &str = "CT_CHANNEL_SHUTDOWN_DRAIN_SECS";

/// The drain when [`SHUTDOWN_DRAIN_ENV`] is unset: long enough for a request in flight, well inside
/// every grace period above.
pub const DEFAULT_SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// The longest drain [`SHUTDOWN_DRAIN_ENV`] takes. More is a typo, not a plan -- and an unbounded
/// value would overflow the deadline arithmetic on the stop path itself.
const MAX_SHUTDOWN_DRAIN: Duration = Duration::from_secs(3600);

/// How often the drain looks at what is still in flight.
const DRAIN_POLL: Duration = Duration::from_millis(50);

/// A stop signal sooner than this after the first is a copy of the same stop (see the module doc)
/// and does not end the drain; a later one does. A person who presses Ctrl-C twice in a hurry
/// waits for one more press, or for the drain, which is short by default.
pub(crate) const REPEAT_DEBOUNCE: Duration = Duration::from_secs(1);

/// The process-wide stop: cancelled once, by the first stop signal. Production code watches this
/// one; a test builds its own token instead, because cancelling this one would stop every other
/// test's serve loop in the same process.
pub(crate) fn process_stop() -> &'static CancellationToken {
    static STOP: OnceLock<CancellationToken> = OnceLock::new();
    STOP.get_or_init(CancellationToken::new)
}

/// `work`, unless `stop` is cancelled first or meanwhile: then `work` is dropped at once -- an
/// admission's leg closes with it -- and this never resolves, so a loop that awaits it starts
/// nothing new. The process ends by the drain, not by this loop returning.
pub(crate) async fn unless_stopped<F: Future>(stop: &CancellationToken, work: F) -> F::Output {
    tokio::select! {
        biased;
        // `select!` drops the other branch before it runs this one, so `work` is gone here.
        () = stop.cancelled() => std::future::pending().await,
        out = work => out,
    }
}

/// The persistent serve loop's admission step (`run_channel_join_command` hands the loop a closure
/// that is this one call): park until the edge pairs the next peer ([`super::admit_one_peer`]) --
/// unless `stop` is cancelled first or meanwhile. Then the park in flight closes and no new one
/// opens ([`unless_stopped`]); production passes [`process_stop`], a test its own token.
pub(crate) async fn admit_next_peer(
    ctx: &super::ServeSessionCtx,
    stop: &CancellationToken,
) -> Result<crate::channel::ChannelJoinOutcome, super::BoxError> {
    unless_stopped(stop, super::admit_one_peer(ctx)).await
}

/// [`SHUTDOWN_DRAIN_ENV`] parsed: unset or empty is the default, a whole number of seconds up to
/// [`MAX_SHUTDOWN_DRAIN`] (`0` included) is taken, anything else fails the start.
pub(crate) fn shutdown_drain_from(raw: Option<&str>) -> Result<Duration, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_SHUTDOWN_DRAIN);
    };
    let drain = s
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("{SHUTDOWN_DRAIN_ENV}={s:?} is not a whole number of seconds"))?;
    if drain > MAX_SHUTDOWN_DRAIN {
        return Err(format!(
            "{SHUTDOWN_DRAIN_ENV}={s} is over the limit of {} seconds",
            MAX_SHUTDOWN_DRAIN.as_secs()
        ));
    }
    Ok(drain)
}

/// One line on stderr that cannot panic. `eprintln!` panics when stderr is gone (a closed pipe),
/// and the stop path has to reach its exit however the log fares.
fn say(line: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// How a drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainEnd {
    /// Nothing was, or remained, in flight.
    Idle,
    /// The drain time ran out with this much still in flight.
    TimedOut(usize),
    /// Another stop signal, [`REPEAT_DEBOUNCE`] or more after the first: exit without waiting for
    /// this much in flight.
    Interrupted(usize),
}

/// What a stopped member waits for, and what its exit status says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Member {
    /// A forward on either side: the work in flight is its forwarded streams, not its sessions.
    pub(crate) forward: bool,
    /// It runs for good -- a forward, a persistent serve member -- rather than for one transfer.
    pub(crate) persistent: bool,
}

/// Whether a member runs for good rather than for one transfer: a forward on either side, or a
/// persistent serve member -- the accept role with `CT_CHANNEL_SERVE` on the edge-brokered path
/// (`CT_CHANNEL_BROKER` set), the only path with a serve loop (`should_serve_loop`). A
/// direct-address member, a pipe and a call (persistent `--call` included) run one transfer at a
/// time for a caller that may check the status.
pub(crate) fn persistent_member(forward: bool, accept: bool, serve: Option<&str>, broker: Option<&str>) -> bool {
    let brokered = broker.is_some_and(|b| !b.is_empty());
    forward || (accept && brokered && crate::envflag::flag(serve, false))
}

/// The exit status after a stop that `signal` started and that ended as `end` (see the module
/// doc): 0, unless the drain cut a one-shot member's work -- then what the signal itself gave
/// before there was a handler, 128 + its number, as a shell reports a process the signal ended.
pub(crate) fn exit_status(end: DrainEnd, persistent: bool, signal: &str) -> i32 {
    let cut = match end {
        DrainEnd::Idle => 0,
        DrainEnd::TimedOut(n) | DrainEnd::Interrupted(n) => n,
    };
    if persistent || cut == 0 {
        0
    } else if signal == "SIGTERM" {
        128 + 15
    } else {
        // SIGINT, and Ctrl-C on a platform without signal numbers.
        128 + 2
    }
}

/// Wait until `in_flight()` reports nothing on two looks in a row (one [`DRAIN_POLL`] apart: a
/// pairing that completed just before the stop gets its session counted), `drain` passes, or
/// `again` resolves.
pub(crate) async fn drain_in_flight<N, A>(in_flight: N, drain: Duration, again: A) -> DrainEnd
where
    N: Fn() -> usize,
    A: Future<Output = ()>,
{
    // `None` only for a drain beyond any clock (the start refuses more than an hour): no deadline.
    let deadline = tokio::time::Instant::now().checked_add(drain);
    tokio::pin!(again);
    let mut idle_looks = 0;
    loop {
        let n = in_flight();
        idle_looks = if n == 0 { idle_looks + 1 } else { 0 };
        if idle_looks >= 2 {
            return DrainEnd::Idle;
        }
        let now = tokio::time::Instant::now();
        let left = match deadline {
            Some(deadline) if now >= deadline => {
                return if n == 0 { DrainEnd::Idle } else { DrainEnd::TimedOut(n) };
            }
            Some(deadline) => deadline - now,
            None => DRAIN_POLL,
        };
        tokio::select! {
            biased;
            () = &mut again => return DrainEnd::Interrupted(in_flight()),
            () = tokio::time::sleep(DRAIN_POLL.min(left)) => {}
        }
    }
}

/// What one unit in flight is called in the log lines.
fn unit(forward: bool) -> &'static str {
    if forward {
        "forwarded stream(s)"
    } else {
        "session(s)"
    }
}

/// Everything after the first stop signal `name`: mark the member unready, cancel `stop`, drain,
/// and say how it ended. Returns that end and the exit status ([`exit_status`]) the caller exits
/// with.
pub(crate) async fn drain_after_signal<A>(
    name: &str,
    stop: &CancellationToken,
    health: &'static ChannelHealth,
    member: Member,
    drain: Duration,
    again: A,
) -> (DrainEnd, i32)
where
    A: Future<Output = ()>,
{
    health.set_stopping();
    stop.cancel();
    let unit = unit(member.forward);
    say(format_args!(
        "ct-agent channel: {name} -- shutting down: no new peers or connections; waiting up to {drain:?} \
         for {} {unit} in flight (another stop signal {REPEAT_DEBOUNCE:?} or more after this one exits at once)",
        health.in_flight(member.forward)
    ));
    let end = drain_in_flight(|| health.in_flight(member.forward), drain, again).await;
    let status = exit_status(end, member.persistent, name);
    match end {
        DrainEnd::Idle => say(format_args!("ct-agent channel: nothing in flight -- exiting with status {status}")),
        DrainEnd::TimedOut(n) => say(format_args!(
            "ct-agent channel: drain time {drain:?} over with {n} {unit} still in flight -- exiting with status {status}"
        )),
        DrainEnd::Interrupted(n) => say(format_args!(
            "ct-agent channel: second stop signal -- exiting with status {status} without waiting for {n} {unit}"
        )),
    }
    (end, status)
}

/// Where stop signals come from: the platform ([`StopSignals`]), or a test's script.
trait StopSource {
    /// The name of the next stop signal.
    fn next(&mut self) -> impl Future<Output = &'static str> + Send;
}

/// The stop signals of this platform: SIGTERM and SIGINT on Unix, Ctrl-C elsewhere. Registered
/// when constructed, so a signal that arrives before anything awaits it is not lost.
struct StopSignals {
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
}

impl StopSignals {
    fn install() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self { term: signal(SignalKind::terminate())?, int: signal(SignalKind::interrupt())? })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }
}

impl StopSource for StopSignals {
    // The trait's `Send` bound holds the future of this `async fn` to it.
    async fn next(&mut self) -> &'static str {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = self.term.recv() => "SIGTERM",
                _ = self.int.recv() => "SIGINT",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            "Ctrl-C"
        }
    }
}

/// Resolves at the first stop signal from `signals` that comes [`REPEAT_DEBOUNCE`] or more after
/// `first`, the moment the first one arrived. A sooner one is a copy of the same stop (see the
/// module doc): logged and ignored.
async fn second_stop<S: StopSource>(mut signals: S, first: tokio::time::Instant) {
    loop {
        let name = signals.next().await;
        if first.elapsed() >= REPEAT_DEBOUNCE {
            return;
        }
        say(format_args!(
            "ct-agent channel: {name} again within {REPEAT_DEBOUNCE:?} of the first -- taken as a copy of the same \
             stop, the drain goes on"
        ));
    }
}

/// Set up what a running `ct-agent channel` process needs around its sessions, before the first
/// network call: check the lifecycle settings ([`SHUTDOWN_DRAIN_ENV`], [`HEALTH_LISTEN_ENV`], and
/// [`super::forward_stream::FORWARD_SESSION_WINDOW_ENV`] -- an error here fails the start), bind
/// and serve the health listener when one is configured, and install the SIGTERM/SIGINT handler
/// that drains and exits (see the module doc).
pub async fn start_channel_lifecycle() -> Result<(), String> {
    let env = |k: &str| std::env::var(k).ok();
    let drain = shutdown_drain_from(env(SHUTDOWN_DRAIN_ENV).as_deref())?;
    let listen = health_listen_from(env(HEALTH_LISTEN_ENV).as_deref())?;
    let window = super::forward_stream::session_window_from(
        env(super::forward_stream::FORWARD_SESSION_WINDOW_ENV).as_deref(),
    )?;
    let forward = super::forward_session_configured();
    let accept = super::health::accept_role(env("CT_CHANNEL_ROLE").as_deref());
    let member = Member {
        forward,
        persistent: persistent_member(
            forward,
            accept,
            env("CT_CHANNEL_SERVE").as_deref(),
            env("CT_CHANNEL_BROKER").as_deref(),
        ),
    };
    if forward && window != super::forward_stream::SESSION_WINDOW {
        eprintln!(
            "ct-agent channel: forward session window granted to the peer: {} KiB ({})",
            window / 1024,
            super::forward_stream::FORWARD_SESSION_WINDOW_ENV
        );
    }
    if let Some(addr) = listen {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("{HEALTH_LISTEN_ENV}={addr}: cannot listen: {e}"))?;
        let bound = listener.local_addr().map_err(|e| format!("{HEALTH_LISTEN_ENV}={addr}: {e}"))?;
        eprintln!("ct-agent channel: health endpoint on {bound} (GET /healthz, /readyz; {HEALTH_LISTEN_ENV})");
        // Lives as long as the process: detached on purpose (task_guard's rule for that case).
        crate::task_guard::TaskGuard::spawn(async move {
            if let Err(e) = super::health::serve_health(listener, &HEALTH, accept).await {
                eprintln!("ct-agent channel: health endpoint on {bound} failed: {e}");
            }
        })
        .detach();
    }
    match StopSignals::install() {
        Ok(mut signals) => {
            // Same lifetime: it is what ends the process on a stop signal.
            crate::task_guard::TaskGuard::spawn(async move {
                let name = signals.next().await;
                let again = second_stop(signals, tokio::time::Instant::now());
                let (_, status) = drain_after_signal(name, process_stop(), &HEALTH, member, drain, again).await;
                std::process::exit(status);
            })
            .detach();
        }
        Err(e) => eprintln!(
            "ct-agent channel: WARNING: cannot handle SIGTERM/SIGINT ({e}) -- a stop signal ends this process \
             without a drain"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    fn private() -> &'static ChannelHealth {
        Box::leak(Box::new(ChannelHealth::new()))
    }

    /// A pipe or a call: one transfer, its sessions are the work in flight.
    const ONE_SHOT: Member = Member { forward: false, persistent: false };

    /// Stop signals at these gaps, each after the one before (the first gap counts from the first
    /// signal, which the caller already took), then none.
    struct Scripted(std::collections::VecDeque<Duration>);

    impl StopSource for Scripted {
        fn next(&mut self) -> impl Future<Output = &'static str> + Send {
            let gap = self.0.pop_front();
            async move {
                match gap {
                    Some(gap) => tokio::time::sleep(gap).await,
                    None => std::future::pending().await,
                }
                "SIGTERM"
            }
        }
    }

    #[test]
    fn the_drain_is_whole_seconds_and_empty_is_the_default() {
        assert_eq!(shutdown_drain_from(None), Ok(DEFAULT_SHUTDOWN_DRAIN));
        assert_eq!(shutdown_drain_from(Some("")), Ok(DEFAULT_SHUTDOWN_DRAIN), "compose passes unset as empty");
        assert_eq!(shutdown_drain_from(Some(" 12 ")), Ok(Duration::from_secs(12)));
        assert_eq!(shutdown_drain_from(Some("0")), Ok(Duration::ZERO), "0: exit without waiting");
        assert_eq!(shutdown_drain_from(Some("3600")), Ok(MAX_SHUTDOWN_DRAIN));
        for bad in ["5s", "-1", "1.5", "five", "3601", "18446744073709551615"] {
            let err = shutdown_drain_from(Some(bad)).unwrap_err();
            assert!(err.contains(SHUTDOWN_DRAIN_ENV), "{bad}: {err}");
        }
    }

    /// A park as `admit_one_peer` holds it: pending until it is dropped, which closes its leg.
    struct Park(Arc<AtomicBool>);
    impl Drop for Park {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_stop_drops_the_parked_admission_and_no_new_one_starts() {
        let stop = CancellationToken::new();
        let closed = Arc::new(AtomicBool::new(false));
        let park = Park(closed.clone());
        let parked = tokio::spawn({
            let stop = stop.clone();
            async move {
                unless_stopped(&stop, async move {
                    let _park = park;
                    std::future::pending::<()>().await
                })
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!closed.load(Ordering::SeqCst), "parked until the stop");
        stop.cancel();
        for _ in 0..100 {
            if closed.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(closed.load(Ordering::SeqCst), "the stop closed the park");
        assert!(!parked.is_finished(), "and the caller waits for good instead of parking again");
        // After the stop the work is never even started.
        let started = Arc::new(AtomicBool::new(false));
        let s = started.clone();
        let late = tokio::time::timeout(
            Duration::from_millis(50),
            unless_stopped(&stop, async move { s.store(true, Ordering::SeqCst) }),
        )
        .await;
        assert!(late.is_err(), "never resolves");
        assert!(!started.load(Ordering::SeqCst), "a new admission never starts");
        parked.abort();
    }

    #[tokio::test]
    async fn work_that_finishes_before_any_stop_is_unchanged() {
        let stop = CancellationToken::new();
        assert_eq!(unless_stopped(&stop, async { 7 }).await, 7);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_waits_for_the_sessions_in_flight_then_ends_idle() {
        let h = private();
        let stop = CancellationToken::new();
        let session = h.session_established();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(session);
        });
        let started = tokio::time::Instant::now();
        let end = drain_after_signal("SIGTERM", &stop, h, ONE_SHOT, Duration::from_secs(5), std::future::pending()).await;
        assert_eq!(end, (DrainEnd::Idle, 0), "nothing was cut: status 0");
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(2) && took < Duration::from_secs(3), "waited for the session: {took:?}");
        assert!(stop.is_cancelled(), "the stop reached the admission paths");
        assert_eq!(h.readiness_at(crate::codec::now_unix(), true).unwrap_err(), "shutting down");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stop_with_nothing_in_flight_ends_at_once() {
        let h = private();
        let stop = CancellationToken::new();
        let started = tokio::time::Instant::now();
        let end = drain_after_signal("SIGTERM", &stop, h, ONE_SHOT, Duration::from_secs(5), std::future::pending()).await;
        assert_eq!(end, (DrainEnd::Idle, 0));
        assert!(started.elapsed() <= DRAIN_POLL * 2, "{:?}", started.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn the_drain_time_bounds_the_wait() {
        let h = private();
        let stop = CancellationToken::new();
        let _stuck = h.session_established();
        let started = tokio::time::Instant::now();
        let end = drain_after_signal("SIGTERM", &stop, h, ONE_SHOT, Duration::from_secs(5), std::future::pending()).await;
        assert_eq!(end, (DrainEnd::TimedOut(1), 143), "a cut one-shot session: SIGTERM's own status");
        assert_eq!(started.elapsed(), Duration::from_secs(5));
        // 0: no wait at all.
        let started = tokio::time::Instant::now();
        let end = drain_after_signal("SIGINT", &stop, h, ONE_SHOT, Duration::ZERO, std::future::pending()).await;
        assert_eq!(end, (DrainEnd::TimedOut(1), 130));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_signal_ends_the_drain_at_once() {
        let h = private();
        let stop = CancellationToken::new();
        let _stuck = h.session_established();
        let again = tokio::time::sleep(Duration::from_millis(300));
        let started = tokio::time::Instant::now();
        let end = drain_after_signal("SIGINT", &stop, h, ONE_SHOT, Duration::from_secs(60), again).await;
        assert_eq!(end, (DrainEnd::Interrupted(1), 130));
        assert!(started.elapsed() < Duration::from_millis(400), "{:?}", started.elapsed());
    }

    // systemd's default KillMode=control-group signals the agent and the wrapper that started it
    // at once; the wrapper passes its copy on a few milliseconds later. That copy is the same
    // stop, not a request to skip the drain.
    #[tokio::test(start_paused = true)]
    async fn a_copy_of_the_first_signal_does_not_cut_the_drain_short() {
        let h = private();
        let stop = CancellationToken::new();
        let _stuck = h.session_established();
        let first = tokio::time::Instant::now();
        let again = second_stop(Scripted([Duration::from_millis(10)].into()), first);
        let end = drain_after_signal("SIGTERM", &stop, h, ONE_SHOT, Duration::from_secs(5), again).await;
        assert_eq!(end, (DrainEnd::TimedOut(1), 143), "the copy 10 ms later left the drain running");
        assert_eq!(first.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn a_signal_well_after_the_first_still_ends_the_drain_at_once() {
        let h = private();
        let stop = CancellationToken::new();
        let _stuck = h.session_established();
        let first = tokio::time::Instant::now();
        // The copy at 10 ms, then a real second request two seconds later.
        let gaps = [Duration::from_millis(10), Duration::from_secs(2)];
        let again = second_stop(Scripted(gaps.into()), first);
        let end = drain_after_signal("SIGTERM", &stop, h, ONE_SHOT, Duration::from_secs(60), again).await;
        assert_eq!(end, (DrainEnd::Interrupted(1), 143));
        let took = first.elapsed();
        assert!(took >= Duration::from_millis(2010) && took < Duration::from_millis(2060), "{took:?}");
    }

    #[test]
    fn the_status_is_0_unless_the_stop_cut_a_one_shot_members_work() {
        for end in [DrainEnd::Idle, DrainEnd::TimedOut(3), DrainEnd::Interrupted(1), DrainEnd::Interrupted(0)] {
            for signal in ["SIGTERM", "SIGINT", "Ctrl-C"] {
                assert_eq!(exit_status(end, true, signal), 0, "a member that runs for good: {end:?} {signal}");
            }
        }
        assert_eq!(exit_status(DrainEnd::Idle, false, "SIGTERM"), 0, "nothing cut");
        assert_eq!(exit_status(DrainEnd::Interrupted(0), false, "SIGINT"), 0, "nothing cut");
        assert_eq!(exit_status(DrainEnd::TimedOut(1), false, "SIGTERM"), 143);
        assert_eq!(exit_status(DrainEnd::Interrupted(2), false, "SIGINT"), 130);
        assert_eq!(exit_status(DrainEnd::TimedOut(1), false, "Ctrl-C"), 130);
    }

    #[test]
    fn a_forward_and_a_brokered_serve_member_run_for_good_and_the_rest_is_one_shot() {
        let edge = Some("203.0.113.9:4433");
        assert!(persistent_member(true, false, None, None), "a forward initiator");
        assert!(persistent_member(true, true, None, edge), "a forward acceptor");
        assert!(persistent_member(false, true, Some("1"), edge), "a persistent serve member");
        assert!(persistent_member(false, true, Some(" yes "), edge));
        assert!(!persistent_member(false, true, Some("1"), None), "direct address: no serve loop");
        assert!(!persistent_member(false, true, Some("1"), Some("")), "an empty broker is unset");
        assert!(!persistent_member(false, true, None, edge), "a one-shot acceptor");
        assert!(!persistent_member(false, true, Some("0"), edge));
        assert!(!persistent_member(false, false, Some("1"), edge), "an initiator never serves");
    }

    #[tokio::test(start_paused = true)]
    async fn a_forward_member_waits_for_its_streams_not_for_its_idle_session() {
        let h = private();
        let stop = CancellationToken::new();
        let _idle_session = h.session_established();
        let stream = tokio::spawn(h.forward_stream(tokio::time::sleep(Duration::from_secs(1))));
        let started = tokio::time::Instant::now();
        let forward = Member { forward: true, persistent: true };
        let end = drain_after_signal("SIGTERM", &stop, h, forward, Duration::from_secs(5), std::future::pending()).await;
        assert_eq!(end, (DrainEnd::Idle, 0), "the idle session is not waited for");
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(2), "the stream was: {took:?}");
        stream.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_forward_member_exits_0_also_when_the_drain_cut_its_streams() {
        let h = private();
        let stop = CancellationToken::new();
        let _stream = h.forward_stream(std::future::pending::<()>());
        let forward = Member { forward: true, persistent: true };
        let end = drain_after_signal("SIGTERM", &stop, h, forward, Duration::from_secs(2), std::future::pending()).await;
        assert_eq!(end, (DrainEnd::TimedOut(1), 0), "stopped on request");
    }
}
