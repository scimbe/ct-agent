//! Soak harness (ct-agent#179): the agent's long-running state machines driven
//! through simulated WEEKS in seconds.
//!
//! The time-driven tests run under tokio's paused clock
//! (`#[tokio::test(start_paused = true)]`): every `sleep` completes as soon as
//! the runtime is otherwise idle, so a 14-day run costs only its bookkeeping.
//! The walks over an injected clock (`healthz_at(now)`, `renewal_due(_, now)`,
//! `oidc_credential_state_from(_, now)`) need no runtime and are plain
//! `#[test]`s. Every test is self-contained -- its own gauge, ring, status,
//! socket and temp dir -- and asserts bounded resources and no permanent exit,
//! never wall-clock timings.
//!
//! CI runs this module on its own (`soak` job: `-- soak:: --test-threads=1`),
//! so the sampled invariants are never skewed by another test's tasks; the
//! module also runs as part of the ordinary `cargo test`, where each test keeps
//! to its own instances for the same reason.

use std::time::Duration;

const HOUR: Duration = Duration::from_secs(60 * 60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const DAY_SECS: u64 = 24 * 60 * 60;

/// Deterministic uniform samples in `[0, 1)` for the jittered backoffs -- a
/// 64-bit LCG (Knuth's MMIX constants), so a failing run reproduces exactly.
struct Lcg(u64);

impl Lcg {
    fn next01(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// 1. Six hours of a dead edge under the production defaults (500 ms base, 30 s
///    cap, unbounded attempts -- `CT_AGENT_RECONNECT_*` unset): the loop never gives
///    up, every sleep stays within the jittered cap, and one success re-arms the
///    budget from the base. A configured finite budget ends exactly at the budget.
#[tokio::test(start_paused = true)]
async fn reconnect_loop_survives_a_multi_hour_edge_outage_and_recovers() {
    use crate::reconnect::{ReconnectPolicy, Retry};
    use crate::serve::{parse_reconnect_backoff_bounds, parse_reconnect_max_attempts};

    let (base, max) = parse_reconnect_backoff_bounds(None, None);
    let attempts = parse_reconnect_max_attempts(None);
    assert_eq!(attempts, u32::MAX, "the production default never gives up");
    assert_eq!(max, Duration::from_secs(30), "the production cap is 30 s");
    let mut policy = ReconnectPolicy::new(base, max, attempts);
    let mut rng = Lcg(179);

    let outage = 6 * HOUR;
    let start = tokio::time::Instant::now();
    let mut failures = 0u32;
    let mut at_cap = 0u32;
    while start.elapsed() < outage {
        match policy.after_failure(rng.next01()) {
            Retry::After(d) => {
                assert!(d <= max, "attempt {failures}: {d:?} exceeds the cap {max:?}");
                assert!(d >= base / 2, "attempt {failures}: {d:?} is below half the base");
                if failures >= 6 {
                    // 500 ms * 2^6 = 32 s > 30 s: from the seventh delay on the cap
                    // applies, and equal jitter keeps every delay in [15 s, 30 s].
                    assert!(d >= max / 2, "attempt {failures}: {d:?} is below half the cap");
                    at_cap += 1;
                }
                tokio::time::sleep(d).await;
            }
            Retry::GiveUp => panic!(
                "gave up after {failures} failures, {:?} into a 6 h outage",
                start.elapsed()
            ),
        }
        failures += 1;
    }
    assert!(start.elapsed() >= outage);
    // Bounded on both sides: at the cap each round waits between 15 s and 30 s.
    let rounds_at_the_cap = (outage.as_secs() / max.as_secs()) as u32;
    assert!(
        failures >= rounds_at_the_cap,
        "{failures} attempts over 6 h: some sleep exceeded the cap"
    );
    assert!(
        failures <= 2 * rounds_at_the_cap + 8,
        "{failures} attempts over 6 h: some sleep was shorter than half the cap"
    );
    assert_eq!(policy.failures_since_success(), failures);
    assert!(at_cap > 0);

    // The edge is back: one success re-arms the policy from the base.
    policy.after_success();
    assert_eq!(policy.failures_since_success(), 0);
    match policy.after_failure(rng.next01()) {
        Retry::After(d) => assert!(d <= base, "after a success the delay restarts at the base, got {d:?}"),
        Retry::GiveUp => panic!("a success must re-arm the budget"),
    }

    // A configured finite budget (CT_AGENT_RECONNECT_MAX_ATTEMPTS=3) ends exactly there ...
    let budget = parse_reconnect_max_attempts(Some("3".into()));
    assert_eq!(budget, 3);
    let mut finite = ReconnectPolicy::new(base, max, budget);
    for i in 0..budget {
        assert!(
            matches!(finite.after_failure(rng.next01()), Retry::After(_)),
            "attempt {i} is within the budget"
        );
    }
    assert_eq!(finite.after_failure(rng.next01()), Retry::GiveUp);
    assert_eq!(finite.after_failure(rng.next01()), Retry::GiveUp, "and stays given up");
    // ... unless a success re-arms it.
    finite.after_success();
    for _ in 0..budget {
        assert!(matches!(finite.after_failure(rng.next01()), Retry::After(_)));
    }
    assert_eq!(finite.after_failure(rng.next01()), Retry::GiveUp);
}

/// 2. Fourteen days of TLS-TCP fallback worker churn against an edge that drops
///    every connection before TLS: each worker burns a finite budget, the pool
///    reports them all gone, a fresh pool is spawned (what
///    `run_agent_tcp_fallback_with_revocation` does between pools), and so on.
///    The pool's own task gauge, sampled every simulated hour, never exceeds the
///    worker count, and the pool's task count returns to zero once it is dropped.
#[tokio::test(start_paused = true)]
async fn fallback_pool_survives_weeks_of_worker_churn_without_leaking_tasks() {
    use crate::config::AgentConfig;
    use crate::serve::{run_tcp_fallback_pool_on, FallbackBudget, FallbackExit, RevocationView};
    use crate::task_guard::LiveGauge;
    use ct_common::RoutingToken;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    static GAUGE: LiveGauge = LiveGauge::new();
    const WORKERS: usize = 2;

    // The edge: accepts and immediately drops, so every rung fails before TLS.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = listener.local_addr().unwrap();
    let refused = Arc::new(AtomicU64::new(0));
    let refused_e = Arc::clone(&refused);
    let edge = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            refused_e.fetch_add(1, Ordering::SeqCst);
            drop(tcp);
        }
    });

    let mut config = AgentConfig::parse(&edge_addr.to_string(), "127.0.0.1:9").unwrap();
    config.tcp_fallback_pool_size = WORKERS;
    // A finite budget so pools actually churn: 1 s, 2 s, ..., capped at 2 min, 40
    // delays (about an hour per worker life), then the pool is gone and the next
    // one spawns.
    let budget = FallbackBudget {
        base: Duration::from_secs(1),
        max: Duration::from_secs(120),
        attempts: 40,
    };
    // Never presented to anything (the edge drops before TLS), but the pool needs one.
    let edge_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .unwrap()
        .cert
        .der()
        .clone();
    let pools = Arc::new(AtomicU64::new(0));
    let unexpected_exits = Arc::new(AtomicU64::new(0));
    let pools_l = Arc::clone(&pools);
    let unexpected_l = Arc::clone(&unexpected_exits);
    let pool_loop = tokio::spawn(async move {
        let (gate, _) = crate::local_auth::LocalAuthGate::from_env(None, |_| None).unwrap();
        let gate = Arc::new(gate);
        loop {
            let exit = run_tcp_fallback_pool_on(
                &GAUGE,
                &config,
                edge_cert.clone(),
                RoutingToken([0x79u8; 32]),
                Arc::new(vec![[0u8; 32]]),
                Arc::clone(&gate),
                Arc::new(RevocationView::default()),
                None,
                budget,
                None,
            )
            .await;
            if !matches!(exit, FallbackExit::AllWorkersGaveUp) {
                unexpected_l.fetch_add(1, Ordering::SeqCst);
            }
            pools_l.fetch_add(1, Ordering::SeqCst);
            // Between pools the pool's set is dropped: nothing of it may survive.
            if GAUGE.get() != 0 {
                unexpected_l.fetch_add(1_000, Ordering::SeqCst);
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    let hours = 14 * 24;
    let mut samples = Vec::with_capacity(hours);
    for _ in 0..hours {
        tokio::time::sleep(HOUR).await;
        samples.push(GAUGE.get());
    }
    let max = *samples.iter().max().unwrap();
    let min = *samples.iter().min().unwrap();
    assert!(
        max <= WORKERS as u64,
        "the pool's task gauge reached {max} with {WORKERS} workers: a task leaked"
    );
    assert!(max - min <= WORKERS as u64, "samples span {min}..={max}");
    assert!(
        samples.contains(&(WORKERS as u64)),
        "a full pool was running at some hourly sample: {samples:?}"
    );
    assert_eq!(
        unexpected_exits.load(Ordering::SeqCst),
        0,
        "every pool ended with AllWorkersGaveUp and an empty gauge"
    );
    // One pool lives 2043 s (every delay jittered to its floor) to 4087 s (none
    // jittered) plus the 30 s gap: 294 to 583 pools in 14 days.
    let pools = pools.load(Ordering::SeqCst);
    assert!(pools >= 250, "only {pools} pools in 14 days: the churn did not happen");
    assert!(pools <= 650, "{pools} pools in 14 days: workers gave up faster than their budget");
    let refused = refused.load(Ordering::SeqCst);
    assert!(
        refused >= pools * (WORKERS as u64) * u64::from(budget.attempts),
        "{refused} refused connections for {pools} pools: workers stopped short of their budget"
    );

    // Tearing the loop down aborts the live pool: its workers go with it.
    pool_loop.abort();
    edge.abort();
    for _ in 0..1_000 {
        if GAUGE.get() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(GAUGE.get(), 0, "the aborted pool's workers were dropped");
}

/// 3. 200k events through a 64 KiB ring: the on-disk footprint (current file
///    plus the one rotated predecessor) never exceeds twice the cap, no append
///    fails, `recent(100)` is the newest hundred in order, and the per-kind
///    counters add up.
#[test]
fn event_ring_and_counters_stay_bounded_over_a_month_of_events() {
    use crate::events::{EventCounters, Ring, KINDS};

    fn file_len(path: &std::path::Path) -> u64 {
        std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
    }

    let dir = tempfile::tempdir().unwrap();
    let cap = 64 * 1024;
    let ring = Ring::with_cap(dir.path(), cap);
    let counters = EventCounters::new();
    let total = 200_000u64;
    let t0 = 1_800_000_000u64;
    // 200k events spread over 30 days: one every ~13 s.
    let spacing = 30 * DAY_SECS / total;
    let mut footprint_max = 0u64;
    for seq in 0..total {
        let kind = KINDS[(seq % KINDS.len() as u64) as usize];
        counters.bump(kind);
        ring.append(&format!(
            "{{\"ts\":{},\"session\":\"0123456789abcdef\",\"conn\":{},\"kind\":\"{kind}\",\"seq\":{seq}}}",
            t0 + seq * spacing,
            seq / 7
        ));
        if seq % 997 == 0 || seq + 1 == total {
            let footprint = file_len(ring.path()) + file_len(&ring.rotated_path());
            assert!(
                footprint <= 2 * cap,
                "after {} events the ring holds {footprint} bytes on disk (cap {cap})",
                seq + 1
            );
            footprint_max = footprint_max.max(footprint);
        }
    }
    assert_eq!(ring.write_errors(), 0);
    assert!(footprint_max > cap, "the ring rotated at least once ({footprint_max} bytes at most)");
    assert!(
        file_len(ring.path()) <= cap && file_len(&ring.rotated_path()) <= cap,
        "each file stays within the cap"
    );
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        2,
        "exactly the current file and one rotated predecessor"
    );

    let recent = ring.recent(100);
    assert_eq!(recent.len(), 100);
    for (i, line) in recent.iter().enumerate() {
        let expected = total - 100 + i as u64;
        assert!(
            line.ends_with(&format!("\"seq\":{expected}}}")),
            "recent()[{i}] is not event {expected}: {line}"
        );
    }
    assert!(ring.recent(1)[0].ends_with(&format!("\"seq\":{}}}", total - 1)));

    let per_kind = total / KINDS.len() as u64;
    let extra = total % KINDS.len() as u64;
    for (i, kind) in KINDS.iter().enumerate() {
        let expected = per_kind + u64::from((i as u64) < extra);
        assert_eq!(counters.get(kind), expected, "counter for {kind}");
    }
    assert_eq!(counters.get("not-a-kind"), 0);
}

/// 4. Thirty days of a keepalive every 25 s with three five-minute silences:
///    `/healthz` is `Err` exactly from 90 s after the last keepalive before a
///    silence until the first keepalive after it, and `Ok` at every other second.
#[test]
fn status_healthz_flips_only_on_silence_and_recovers() {
    use crate::status::{AgentStatus, ProcessFacts, HEALTHZ_MAX_SILENCE_SECS};

    const KEEPALIVE: u64 = 25;
    const SILENCE: u64 = 5 * 60;
    let t0 = 1_800_000_000u64;
    let end = t0 + 30 * DAY_SECS;
    // Each silence starts on the keepalive grid (a multiple of 25 s from t0).
    let silences = [
        t0 + 3 * DAY_SECS + 100 * KEEPALIVE,
        t0 + 17 * DAY_SECS + 4_000 * KEEPALIVE,
        t0 + 29 * DAY_SECS + 7 * KEEPALIVE,
    ];
    for s in silences {
        assert_eq!((s - t0) % KEEPALIVE, 0);
    }
    let facts = ProcessFacts {
        uptime_secs: 0,
        session: "0123456789abcdef".to_string(),
        conn: Some(1),
        tasks_live: 3,
        oidc_credential: "stored",
        masque_dropped_datagrams: (0, 0),
        events_ring_write_errors: 0,
    };

    let status = AgentStatus::new();
    status.set_transport("quic");
    status.set_registered(Some(t0));
    let mut healthy = false;
    let mut flips = 0u32;
    let mut err_seconds = 0u64;
    for now in t0..=end {
        let silent = silences.iter().any(|&s| now >= s && now < s + SILENCE);
        if (now - t0) % KEEPALIVE == 0 && !silent {
            status.note_keepalive_at(now);
        }
        let ok = status.healthz_at(now).is_ok();
        // The last keepalive before silence `s` is at `s - 25`, the first after it at
        // `s + 300`: unhealthy on [s - 25 + 90, s + 300), healthy everywhere else.
        let expected_ok = !silences
            .iter()
            .any(|&s| now >= s - KEEPALIVE + HEALTHZ_MAX_SILENCE_SECS && now < s + SILENCE);
        assert_eq!(ok, expected_ok, "healthz at t0 + {} s", now - t0);
        if ok != healthy {
            flips += 1;
            healthy = ok;
        }
        if !ok {
            err_seconds += 1;
        }
        if (now - t0) % DAY_SECS == 0 {
            let snapshot = status.snapshot_at(now, &facts);
            assert_eq!(snapshot["healthy"], serde_json::json!(ok));
            assert_eq!(snapshot["registered"], serde_json::json!(true));
            assert_eq!(snapshot["reconnects"], serde_json::json!(0));
        }
    }
    // Ok at t0 (the first keepalive lands at t0), then Err/Ok once per silence.
    assert_eq!(flips, 1 + 2 * silences.len() as u32);
    assert!(healthy, "healthy again at the end of the month");
    assert_eq!(
        err_seconds,
        silences.len() as u64 * (SILENCE - (HEALTHZ_MAX_SILENCE_SECS - KEEPALIVE)),
        "unhealthy for exactly (300 - 65) s per silence"
    );
}

/// 5. A stored login walked day by day over ninety days, no network: fresh until
///    the access token's expiry, expired-but-refreshable at expiry, fresh again
///    after a refresh rewrote the file; expired for good at expiry without a refresh
///    token, or once the refresh token's own expiry has passed.
#[test]
fn oidc_state_machine_over_ninety_days() {
    use crate::login::{oidc_credential_state_from, OidcCredentialState as S};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oidc-token.json");
    let path_str = path.to_str().unwrap().to_string();
    let env = |k: &str| (k == "CT_AGENT_LOGIN_TOKEN_FILE").then(|| path_str.clone());
    let state = |now: u64| oidc_credential_state_from(env, now);
    // The exact shape `login.rs`'s `StoredToken` serializes.
    let write = |access_expires_at: u64, refresh: Option<(&str, Option<u64>)>| {
        let (refresh_token, refresh_expires_at) = match refresh {
            Some((t, exp)) => (Some(t.to_string()), exp),
            None => (None, None),
        };
        let doc = serde_json::json!({
            "access_token": format!("at-{access_expires_at}"),
            "refresh_token": refresh_token,
            "access_expires_at": access_expires_at,
            "refresh_expires_at": refresh_expires_at,
            "issuer": "https://kc.example/realms/ct",
            "client_id": "ct-agent-cli",
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    };
    let t0 = 1_800_000_000u64;
    let day = |d: u64| t0 + d * DAY_SECS;

    // A: a login with a refresh token, refreshed whenever the walk finds it due
    // (what `resolve_oidc_token` does on the next bridge call).
    write(day(30), Some(("rt-0", Some(day(90)))));
    let mut refreshed_on = Vec::new();
    for d in 0..=90 {
        match state(day(d)) {
            S::StoredFresh => {}
            S::StoredExpiredRefreshable => {
                refreshed_on.push(d);
                write(day(d + 30), Some(("rt", Some(day(d + 90)))));
                assert_eq!(state(day(d)), S::StoredFresh, "day {d}: fresh again after the refresh");
            }
            other => panic!("day {d}: {other:?}"),
        }
    }
    assert_eq!(refreshed_on, vec![30, 60, 90], "due exactly at each expiry, never before");
    assert_eq!(state(day(29) + DAY_SECS - 60), S::StoredFresh, "a minute before expiry");
    assert_eq!(state(day(120)), S::StoredExpiredRefreshable);

    // B: no refresh token -- fresh until expiry, then expired for the rest of the walk.
    write(day(30), None);
    for d in 0..=90 {
        let expected = if d < 30 { S::StoredFresh } else { S::StoredExpiredNoRefresh };
        assert_eq!(state(day(d)), expected, "B day {d}");
    }

    // C: a refresh token that outlives the access token by 15 days, never used
    // (the IdP unreachable): refreshable until its own expiry, then expired.
    write(day(30), Some(("rt", Some(day(45)))));
    for d in 0..=90 {
        let expected = match d {
            0..=29 => S::StoredFresh,
            30..=44 => S::StoredExpiredRefreshable,
            _ => S::StoredExpiredNoRefresh,
        };
        assert_eq!(state(day(d)), expected, "C day {d}");
    }

    // D: a refresh token with no recorded expiry stays usable for the whole walk.
    write(day(30), Some(("rt", None)));
    assert_eq!(state(day(90)), S::StoredExpiredRefreshable);
    // E: the file gone (logout) -> none, whatever the day.
    std::fs::remove_file(&path).unwrap();
    assert_eq!(state(day(1)), S::None);
}

/// 6. A million datagrams offered to a MASQUE socket's outbound pump over four
///    simulated days while the consumer takes at most two per six minutes: the
///    pump never holds more than its capacity, `try_send` never fails, and every
///    datagram is either queued, delivered, or counted as dropped.
#[tokio::test(start_paused = true)]
async fn masque_pumps_never_grow_under_a_slow_consumer_for_days() {
    use crate::masque::socket::{DropCounters, MasqueUdpSocket, PUMP_CAPACITY};
    use quinn::AsyncUdpSocket;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    let (to_send_tx, mut to_send_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PUMP_CAPACITY);
    let (_recv_tx, recv_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(PUMP_CAPACITY);
    // A second handle on the pump, to read how many datagrams it holds.
    let probe = to_send_tx.clone();
    let peer = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 4433);
    let sock = MasqueUdpSocket::from_parts(
        to_send_tx,
        recv_rx,
        Arc::new(DropCounters::default()),
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
        peer,
    );
    let held = || (PUMP_CAPACITY - probe.capacity()) as u64;
    let payload = [0xAAu8; 1200];
    let transmit = quinn::udp::Transmit {
        destination: peer,
        ecn: None,
        contents: &payload,
        segment_size: None,
        src_ip: None,
    };

    const TOTAL: u64 = 1_000_000;
    const BATCH: u64 = 1_000;
    let start = tokio::time::Instant::now();
    let mut offered = 0u64;
    let mut drained = 0u64;
    let mut held_max = 0u64;
    for batch in 0..(TOTAL / BATCH) {
        for _ in 0..BATCH {
            sock.try_send(&transmit).expect("a full pump drops the datagram, it never fails the sender");
            offered += 1;
        }
        // The slow consumer: every six minutes it takes 0, 1 or 2 datagrams.
        tokio::time::sleep(Duration::from_secs(6 * 60)).await;
        for _ in 0..(batch % 3) {
            if to_send_rx.try_recv().is_ok() {
                drained += 1;
            }
        }
        let in_pump = held();
        held_max = held_max.max(in_pump);
        let (dropped, inbound_dropped) = sock.dropped_datagrams();
        assert!(in_pump <= PUMP_CAPACITY as u64, "batch {batch}: the pump holds {in_pump}");
        assert_eq!(inbound_dropped, 0, "nothing was offered inbound");
        assert_eq!(
            offered,
            drained + in_pump + dropped,
            "batch {batch}: every datagram is queued, delivered, or counted as dropped"
        );
    }
    assert!(start.elapsed() >= 4 * DAY, "the run spans four simulated days");
    assert_eq!(offered, TOTAL);
    assert_eq!(held_max, PUMP_CAPACITY as u64, "the pump filled up exactly to its capacity");
    assert_eq!(held(), PUMP_CAPACITY as u64, "and is full at the end: the consumer never caught up");
    let (dropped, _) = sock.dropped_datagrams();
    assert_eq!(dropped, TOTAL - drained - PUMP_CAPACITY as u64);
    assert!(dropped > TOTAL * 9 / 10, "almost everything was dropped, not buffered: {dropped}");

    // The pump is intact: draining it hands over exactly its capacity, and a fresh
    // datagram is queued again without a further drop.
    let mut left = 0u64;
    while to_send_rx.try_recv().is_ok() {
        left += 1;
    }
    assert_eq!(left, PUMP_CAPACITY as u64);
    sock.try_send(&transmit).unwrap();
    assert_eq!(held(), 1);
    assert_eq!(sock.dropped_datagrams().0, dropped, "no drop once there is room");
}

/// 7. The renewal loop's decision, ticked every `CHECK_INTERVAL` (6 h) over 95
///    days of a 90-day certificate: renewal is decided exactly once, at the first
///    check on or after day `RENEW_AFTER_DAYS` (60), never before, and not again
///    within the horizon (the renewed cert is not due until day 120).
#[test]
fn acme_renewal_cadence_over_a_certificate_lifetime() {
    use crate::acme_orchestrate::{renewal_due, CHECK_INTERVAL, RENEW_AFTER_DAYS};
    use std::time::UNIX_EPOCH;

    assert_eq!(CHECK_INTERVAL, 6 * HOUR);
    let due_after = Duration::from_secs(RENEW_AFTER_DAYS * DAY_SECS);
    let issued = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let horizon = 95 * DAY;

    // The loop's first check lands `offset` after issuance: on the day boundary,
    // and at two arbitrary phases within a check interval.
    for offset in [Duration::ZERO, HOUR, 5 * HOUR + Duration::from_secs(59 * 60)] {
        let mut cert_issued_at = issued;
        let mut renewals: Vec<Duration> = Vec::new();
        let mut ticks = 0u32;
        let mut now = issued + offset;
        while now.duration_since(issued).unwrap() <= horizon {
            if renewal_due(cert_issued_at, now) {
                renewals.push(now.duration_since(issued).unwrap());
                cert_issued_at = now;
            }
            now += CHECK_INTERVAL;
            ticks += 1;
        }
        assert!(ticks >= 380, "{ticks} checks over 95 days");
        assert_eq!(renewals.len(), 1, "offset {offset:?}: renewed at {renewals:?}");
        let at = renewals[0];
        assert!(at >= due_after, "offset {offset:?}: renewed at {at:?}, before day {RENEW_AFTER_DAYS}");
        assert!(
            at < due_after + CHECK_INTERVAL,
            "offset {offset:?}: renewed at {at:?}, more than one check after day {RENEW_AFTER_DAYS}"
        );
        if offset.is_zero() {
            assert_eq!(at, due_after, "on the grid the renewal lands exactly on day 60");
        }
    }

    // The decision itself: due at exactly 60 days, not a second earlier; a cert
    // from the future (clock stepped back) is due, as `needs_renewal` always did.
    assert!(!renewal_due(issued, issued + due_after - Duration::from_secs(1)));
    assert!(renewal_due(issued, issued + due_after));
    assert!(renewal_due(issued + Duration::from_secs(1), issued));
}
