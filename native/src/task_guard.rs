//! Task lifetime discipline (ct-agent#180): an abort-on-drop guard for spawned
//! tasks plus a process-wide live-task gauge.
//!
//! `tokio::task::JoinHandle`'s own `Drop` only DETACHES a task -- it keeps running
//! in the background regardless -- so a bare `tokio::spawn(...)` with no handle
//! kept is a task whose lifetime nobody owns. The 2026-09-06 survey found eight
//! such spawns on the data plane (the direct-connect listener surviving every
//! transport switch, the service-call pumps, the MASQUE socket pumps, the
//! super-peer return paths). Every one of them now hands its handle to a
//! [`TaskGuard`] (aborted when the owner drops it) or to a `JoinSet` (aborted when
//! the set drops, the pattern the TLS-TCP fallback pool already used), and every
//! spawned body is wrapped by [`tracked`] so `/metrics` can show how many are alive
//! as `ct_agent_tasks_live`.
//!
//! The guard replaces the private `AbortOnDrop` that `masque/mod.rs` grew for the
//! same reason (a leaked h2 connection driver per failed MASQUE dial exhausted the
//! process's file descriptors on a flaky network); that call site now uses this
//! one.

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use tokio::task::{JoinError, JoinHandle};

/// A count of tasks that were spawned through this module and have not ended yet.
/// The process-wide instance is [`TASKS_LIVE`]; tests build their own so they can
/// assert exact values without other tests' tasks interfering.
#[derive(Debug)]
pub struct LiveGauge(AtomicU64);

/// The process-wide live-task gauge, rendered on `/metrics` as `ct_agent_tasks_live`.
pub static TASKS_LIVE: LiveGauge = LiveGauge::new();

impl LiveGauge {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Tasks counted by this gauge that have not ended (or been aborted) yet.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    /// Wrap `future` so this gauge counts it from now until it completes or is
    /// dropped (an aborted task drops its future, so an abort decrements too). The
    /// increment happens HERE, synchronously, not on first poll -- so a caller that
    /// wraps and then spawns sees the gauge move before `spawn` returns.
    pub fn track<F: Future>(&'static self, future: F) -> impl Future<Output = F::Output> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let ticket = LiveTicket(self);
        async move {
            let _ticket = ticket;
            future.await
        }
    }

    /// `tokio::spawn` a task counted by this gauge and return its abort-on-drop guard.
    pub fn spawn<F>(&'static self, future: F) -> TaskGuard<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        TaskGuard::from_handle(tokio::spawn(self.track(future)))
    }
}

impl Default for LiveGauge {
    fn default() -> Self {
        Self::new()
    }
}

/// Decrements its gauge when dropped -- lives inside the tracked future's state.
struct LiveTicket(&'static LiveGauge);

impl Drop for LiveTicket {
    fn drop(&mut self) {
        self.0 .0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// [`LiveGauge::track`] on the process-wide gauge: wrap a future that is about to be
/// spawned somewhere this module does not control (a `JoinSet`, a hand-held
/// `JoinHandle`) so it still shows up in `ct_agent_tasks_live`.
pub fn tracked<F: Future>(future: F) -> impl Future<Output = F::Output> {
    TASKS_LIVE.track(future)
}

/// The process-wide gauge's current value.
pub fn tasks_live() -> u64 {
    TASKS_LIVE.get()
}

/// `ct_agent_tasks_live` in the Prometheus text exposition format, appended to the
/// `/metrics` body by `observe::render_text` after the MASQUE drop counters.
pub fn render_prometheus() -> String {
    format!(
        "# HELP ct_agent_tasks_live Spawned tokio tasks owned by a task guard or task set that have \
         not ended yet (ct-agent#180).\n\
         # TYPE ct_agent_tasks_live gauge\n\
         ct_agent_tasks_live {}\n",
        tasks_live()
    )
}

/// Owns a spawned task: dropping the guard ABORTS the task, unless
/// [`TaskGuard::detach`] was called first. Derefs to the `JoinHandle` (so
/// `is_finished()`/`abort()` are available) and is itself a `Future` yielding the
/// task's join result, so an owner can also await it.
///
/// Prefer [`TaskGuard::spawn`] (which also counts the task in [`TASKS_LIVE`]) over
/// wrapping a handle by hand.
#[derive(Debug)]
pub struct TaskGuard<T> {
    handle: JoinHandle<T>,
    /// `false` after `detach()`: the drop no longer aborts.
    armed: bool,
}

impl<T> TaskGuard<T> {
    /// Spawn `future` on the current runtime, counted in [`TASKS_LIVE`], and own it.
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        TASKS_LIVE.spawn(future)
    }

    /// Own an already-spawned task. The task is only counted in the gauge if its
    /// body was wrapped with [`tracked`] before spawning.
    pub fn from_handle(handle: JoinHandle<T>) -> Self {
        Self { handle, armed: true }
    }

    /// Opt out explicitly: the task keeps running after this guard is gone. The one
    /// legitimate use is a task whose lifetime is genuinely the process's (or is
    /// owned by something the guard cannot be stored in) -- say so at the call site.
    pub fn detach(mut self) {
        self.armed = false;
    }
}

impl<T> Deref for TaskGuard<T> {
    type Target = JoinHandle<T>;

    fn deref(&self) -> &JoinHandle<T> {
        &self.handle
    }
}

impl<T> Drop for TaskGuard<T> {
    fn drop(&mut self) {
        if self.armed {
            self.handle.abort();
        }
    }
}

impl<T> Future for TaskGuard<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // `JoinHandle<T>: Unpin`, so projecting through `&mut self` is sound.
        Pin::new(&mut self.handle).poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    /// Waits until the runtime has actually dropped an aborted task's future --
    /// `abort()` only schedules the cancellation, so a test that asserts on the
    /// gauge right after `drop(guard)` would race the scheduler.
    async fn settle<F: Fn() -> bool>(done: F) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached within 1s");
    }

    #[tokio::test]
    async fn guard_aborts_the_task_on_drop() {
        static GAUGE: LiveGauge = LiveGauge::new();
        let started = Arc::new(Notify::new());
        let s = Arc::clone(&started);
        let guard = GAUGE.spawn(async move {
            s.notify_one();
            // Would loop forever: only an abort ends it.
            std::future::pending::<()>().await;
        });
        started.notified().await;
        assert_eq!(GAUGE.get(), 1);
        assert!(!guard.is_finished());

        drop(guard);
        settle(|| GAUGE.get() == 0).await;
        assert_eq!(GAUGE.get(), 0, "the aborted task's future was dropped");
    }

    #[tokio::test]
    async fn detach_keeps_the_task_alive() {
        static GAUGE: LiveGauge = LiveGauge::new();
        let release = Arc::new(Notify::new());
        let r = Arc::clone(&release);
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = Arc::clone(&finished);
        let guard = GAUGE.spawn(async move {
            r.notified().await;
            f.store(true, Ordering::SeqCst);
        });
        guard.detach();
        // Still alive after the guard is gone: the gauge did not move ...
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(GAUGE.get(), 1, "a detached task is not aborted");
        assert!(!finished.load(Ordering::SeqCst));
        // ... and the task can still run to completion.
        release.notify_one();
        settle(|| finished.load(Ordering::SeqCst)).await;
        settle(|| GAUGE.get() == 0).await;
    }

    #[tokio::test]
    async fn live_gauge_returns_to_its_baseline_after_a_guarded_task_is_dropped() {
        static GAUGE: LiveGauge = LiveGauge::new();
        let baseline = GAUGE.get();
        let a = GAUGE.spawn(std::future::pending::<()>());
        let b = GAUGE.spawn(std::future::pending::<()>());
        assert_eq!(GAUGE.get(), baseline + 2, "the increment is synchronous with spawn");
        drop(a);
        settle(|| GAUGE.get() == baseline + 1).await;
        drop(b);
        settle(|| GAUGE.get() == baseline).await;
        assert_eq!(GAUGE.get(), baseline);
    }

    #[tokio::test]
    async fn tracked_counts_a_task_spawned_into_a_join_set() {
        static GAUGE: LiveGauge = LiveGauge::new();
        let mut set = tokio::task::JoinSet::new();
        set.spawn(GAUGE.track(std::future::pending::<()>()));
        set.spawn(GAUGE.track(async {}));
        assert_eq!(GAUGE.get(), 2);
        // The finished one is reaped; the pending one only ends when the set drops.
        let _ = set.join_next().await;
        settle(|| GAUGE.get() == 1).await;
        drop(set);
        settle(|| GAUGE.get() == 0).await;
    }

    #[tokio::test]
    async fn guard_is_awaitable_and_reports_the_join_result() {
        let guard = TaskGuard::spawn(async { 7u8 });
        assert_eq!(guard.await.unwrap(), 7);

        let guard = TaskGuard::spawn(std::future::pending::<()>());
        guard.abort();
        assert!(guard.await.unwrap_err().is_cancelled());
    }

    #[test]
    fn render_prometheus_exposes_the_gauge_series() {
        let text = render_prometheus();
        assert!(text.contains("# TYPE ct_agent_tasks_live gauge"));
        assert!(text.lines().last().unwrap().starts_with("ct_agent_tasks_live "));
        assert!(text.ends_with('\n'));
    }
}
