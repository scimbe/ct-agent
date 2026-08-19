//! Typed admission errors and the retry/backoff policy around them (consolidation
//! program: module split, slice 2 -- moved verbatim out of the former single-file
//! `channel_run.rs`; only visibilities changed to `pub(crate)`).
//!
//! The two typed markers ([`AdmissionRefused`], [`ParkExpired`]) and their classifiers
//! are the wire-outcome vocabulary the serve loop routes on; the backoff constants and
//! pure functions are the policy for HOW each class retries. Keeping them in one module
//! makes the contract reviewable at a glance: refusals back off exponentially, park
//! expiries re-park immediately, flaps back off on a shorter cap, transients retry fast.

use super::BoxError;

/// #231: ceiling on the exponential backoff a persistent serve loop applies after consecutive
/// **refused** (not transient) admission attempts — see [`serve_loop_concurrent`].
pub(crate) const REFUSED_ADMISSION_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(30);

/// #250 ("flapping peer"): a session that dies within this long of being admitted is treated as
/// a FAILED pairing, not a completed one — live-diagnosed 2026-08-13 (a Windows accept-side
/// member and a front-door-only bridge): admission succeeded every single time (grant verified,
/// both sides acked), but the underlying TLS-TCP connection then died before/during the Noise
/// handshake, near-instantly, on essentially every attempt — ~98 pair-then-die cycles in 30s
/// (~300ms apart), matching this loop's UNTHROTTLED re-admit cadence exactly (there was no
/// backoff at all between a failed session and the next admit). Root cause (Windows-side
/// AV/firewall DPI killing the connection post-handshake, or a platform-specific transport bug)
/// is still open -- but regardless of cause, hammering the edge at native RTT speed while it
/// persists serves nobody: it floods the edge's admission/relay path for no gain (the failure
/// recurs every time) and produces a wall of noise that hides every other signal. A genuine
/// session (even a very short, single-call one) legitimately completes well under this: the
/// sort arena's own measured per-round session lifetime is ~85ms end-to-end including the Noise
/// handshake -- this threshold is 6x that, so a real, working session is never mistaken for a
/// flap.
pub(crate) const FLAPPING_SESSION_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(500);

/// #250: ceiling on the exponential backoff applied after consecutive flapping (pair-then-
/// near-instant-death) sessions — same shape as [`REFUSED_ADMISSION_BACKOFF_CAP`], deliberately
/// shorter: unlike a definitive refusal (which literally cannot resolve without operator
/// action), a flap's underlying cause (a transient AV heuristic, a flaky corporate firewall
/// rule) can clear on its own, so this loop should keep checking meaningfully sooner.
pub(crate) const FLAPPING_SESSION_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(10);

/// #250: pure classifier -- did a just-ended session look like a "flap" (pair, then die near-
/// instantly)? Only an ERRORED session that ended within [`FLAPPING_SESSION_THRESHOLD`]
/// qualifies; a session that succeeded (even a fast single-call one) or that ran long before
/// failing is a real session, not a flap, and must reset the counter rather than extend it.
pub(crate) fn is_flapping_session(elapsed: std::time::Duration, errored: bool) -> bool {
    errored && elapsed < FLAPPING_SESSION_THRESHOLD
}

/// #250: exponential backoff after `consecutive_flaps` near-instant session deaths in a row,
/// same shape as [`admission_retry_backoff`]'s refused-admission path but capped lower (see
/// [`FLAPPING_SESSION_BACKOFF_CAP`]'s doc for why). Pure.
pub(crate) fn flapping_session_backoff(
    retry_backoff: std::time::Duration,
    consecutive_flaps: u32,
) -> std::time::Duration {
    let shift = consecutive_flaps.min(16);
    retry_backoff
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(FLAPPING_SESSION_BACKOFF_CAP)
}

/// #231: does an admission error mean the presenting holder was **definitively** refused (not a
/// channel member — see `channel-join NO [not-member]` on the edge) rather than a transient
/// failure (`channel join admission exchange stalled (#140)` and any other unrecognized error
/// are treated as transient/retryable-fast)? The `… refused the channel join` strings are
/// produced at several refusal sites across the join paths (the broker/relay ladders, the
/// relay-gate pre-auth, `reject_refused_outcome` for the serve loop) — all of them typed
/// [`AdmissionRefused`] (#20/#24), so classification is a downcast first; the substring half
/// below is the stringifying-boundary fallback.
pub(crate) fn is_definitive_admission_refusal(e: &BoxError) -> bool {
    // #20 (consolidation): typed classification first -- every in-process creation site now
    // returns [`AdmissionRefused`], so a future rewording of the operator-facing text can no
    // longer silently disable the #231 backoff (the failure mode of the old substring-only
    // check was not an error but a behavioral regression: definitive refusals retried at the
    // fast cadence, i.e. the exact edge-flood #231 was filed about). The substring fallback
    // is a DELIBERATE, permanent second line (#24 review decision -- the "one release"
    // deadline it used to carry was never tracked and is withdrawn): it covers errors that
    // crossed a stringifying boundary (e.g. a subprocess's stderr re-parsed into a fresh
    // error), costs one frozen operator-visible string, and fails safe (worst case: a
    // refusal-shaped transient backs off too long, never the reverse).
    if e.downcast_ref::<AdmissionRefused>().is_some() {
        return true;
    }
    e.to_string().contains("refused the channel join")
}

/// #20: typed marker for a DEFINITIVE broker/relay refusal -- the peer's wire `NO`. `Display`
/// emits the exact historical strings (field-visible contract: operators grep these, docs quote
/// them, the sort bridge's fault attribution matches on them), but in-process classification
/// ([`is_definitive_admission_refusal`]) is a downcast, not a substring search. The client-side
/// sibling of the edge's `DefinitiveJoinRefusal` (CADS-Tunnel, same day, same class of fix).
#[derive(Debug)]
pub(crate) struct AdmissionRefused(pub(crate) std::borrow::Cow<'static, str>);

impl std::fmt::Display for AdmissionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AdmissionRefused {}

impl AdmissionRefused {
    /// The category-less constructor -- boxed, ready to return. Emits the exact
    /// historical string, for the sites (and old edges) with no category to add.
    pub(crate) fn boxed(text: &'static str) -> BoxError {
        Box::new(AdmissionRefused(text.into()))
    }

    /// #524: the category-aware constructor every wire-refusal site uses. `base` is the
    /// site's exact historical string (frozen: operators grep it, the substring half of
    /// [`is_definitive_admission_refusal`] matches on it — it must stay a PREFIX of
    /// whatever this renders); `category` is the edge's closed-vocabulary refusal token
    /// when the wire carried one. Known categories get an actionable self-diagnosis
    /// hint; unknown tokens (a newer edge's future vocabulary) surface raw with a
    /// generic pointer; `None` (an old edge / raced token) renders `base` unchanged.
    pub(crate) fn boxed_with_category(base: &'static str, category: Option<&str>) -> BoxError {
        let Some(cat) = category else {
            return Self::boxed(base); // old edge / raced token: byte-identical message
        };
        let text = match refusal_category_hint(cat) {
            Some(hint) => format!("{base} [{cat}]: {hint}"),
            None => format!(
                "{base} [{cat}] (unrecognized refusal category — likely a newer edge; \
                 the edge's own log has the detail)"
            ),
        };
        Box::new(AdmissionRefused(text.into()))
    }
}

/// #524: map a known refusal-category token (the edge's closed vocabulary — the
/// `[<tag>]` of its `channel-join NO` log line, now also on the wire) to an actionable
/// operator hint. The DETAILED reason deliberately stays server-side; these hints only
/// explain what the CLASS of failure means for this agent and what to check. Unknown
/// tokens return `None` and are surfaced raw by [`AdmissionRefused::boxed_with_category`].
pub(crate) fn refusal_category_hint(category: &str) -> Option<&'static str> {
    Some(match category {
        "possession" => {
            "the holder-possession proof failed — this agent's holder PRIVATE key does not \
             match the grant's holder. Usually a run under the wrong claimed identity, or a \
             grant minted for a different holder key; re-check which identity/holder key \
             this block runs as"
        }
        "grant-verify" => {
            "the grant failed signature/validity verification — expired, or not signed by \
             this channel's operator key; fetch a fresh grant"
        }
        "not-member" => {
            "the channel is unknown to this edge, or the holder is not currently a member — \
             check the channel id and whether this member was removed"
        }
        "endpoint" => {
            "the advertised endpoint was rejected as unsafe/undialable — advertise a public \
             address or the relay-only sentinel"
        }
        "malformed" | "len-oob" => {
            "the edge could not read the join request off the wire — likely an agent/edge \
             version skew"
        }
        "pairing" => {
            "admission succeeded but pairing the two members was refused — the problem is \
             with the PAIR (e.g. the partner's authorization), not this grant"
        }
        _ => return None,
    })
}

/// #40 (CADS-Tunnel#335): ceiling on the exponential backoff after consecutive TLS-handshake-EOF
/// admission failures (see [`is_transport_handshake_eof`]) -- deliberately BETWEEN the fast
/// `retry_backoff` and [`REFUSED_ADMISSION_BACKOFF_CAP`]'s 30s, same reasoning as
/// [`FLAPPING_SESSION_BACKOFF_CAP`]: unlike a definitive refusal, a saturated edge connection
/// cap clears on its own once load drops, so this loop should keep checking meaningfully
/// sooner than a refusal would justify -- while no longer hammering it at native retry speed
/// (CADS-Tunnel#335's field observation: two peers did exactly that for ~2 hours straight,
/// plausibly a real contributor to their own outage).
pub(crate) const HANDSHAKE_EOF_BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(10);

/// #40 (CADS-Tunnel#335): does this admission error mean the connection died with a clean
/// TLS-handshake EOF -- no application byte exchanged on either side -- rather than a genuine
/// refusal or a park expiry? CADS-Tunnel#335's traced root cause: the edge's `:443` connection
/// cap sheds an accepted TCP socket by dropping it BEFORE the TLS handshake when full, which
/// surfaces to the dialer as exactly this.
///
/// Typed first (consolidation program, typed-errors-first pass): the front-door TLS connect
/// step boxes its `std::io::Error` directly into
/// [`super::dialing::ChannelDialError::ConnectFailed`] (`?` preserves the concrete type), and
/// rustls/tokio-rustls surface a peer closing before the handshake completes as
/// `io::ErrorKind::UnexpectedEof` -- that call site does nothing else that could produce that
/// kind, so `kind()` alone is unambiguous THERE. It must stay scoped to `ConnectFailed`
/// specifically, not walked across the whole error generically: a post-handshake admission-
/// exchange failure (`ChannelDialError::Failed`) can surface the SAME `UnexpectedEof` kind for
/// a completely different reason (the peer closing mid-exchange, CADS-Tunnel#533's class), and
/// conflating the two would misfeed this backoff counter from the wrong signal.
///
/// The substring fallback below is kept for whatever still crosses a stringifying boundary
/// (mirrors [`is_definitive_admission_refusal`]'s typed-first-then-substring shape) -- the exact
/// wording CADS-Tunnel#335's field log captured (`ct-agent channel: debug relay-gate tcp+tls
/// connect to ... failed after ~35ms: tls handshake eof`). Extend the substring list here if
/// another TLS backend (the "boring" ALPN dialer,
/// [`crate::transport::tcp_tls_connect_channel_boring`]) is ever observed to word this
/// differently -- not assumed identical without a field sample.
pub(crate) fn is_transport_handshake_eof(e: &BoxError) -> bool {
    if let Some(super::dialing::ChannelDialError::ConnectFailed(inner)) =
        e.downcast_ref::<super::dialing::ChannelDialError>()
    {
        if let Some(io_err) = inner.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                return true;
            }
        }
    }
    e.to_string().contains("tls handshake eof")
}

/// #40: exponential backoff after `consecutive_handshake_eofs` TLS-handshake-EOF admission
/// failures in a row -- same shape as [`flapping_session_backoff`], deliberately an
/// INDEPENDENT counter from [`admission_retry_backoff`]'s `consecutive_refusals`: the two
/// failure modes have different causes and different natural resolution times, so one
/// streak escalating must not affect the other's classification or reset the other's count.
pub(crate) fn handshake_eof_backoff(
    retry_backoff: std::time::Duration,
    consecutive_eofs: u32,
) -> std::time::Duration {
    let shift = consecutive_eofs.min(16);
    retry_backoff
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(HANDSHAKE_EOF_BACKOFF_CAP)
}

/// #21: typed marker for a park expiry -- the edge reaped this member's park because no partner
/// arrived within the park TTL, and SAID SO on the wire (the bare `EX` token / the named QUIC
/// close reason). Deliberately a DISTINCT type from [`AdmissionRefused`]: a park expiry is
/// neither a refusal (nothing about the grant or holder is wrong -- there was simply nobody to
/// pair with yet) nor a transport failure (the rung worked end to end). The correct reaction is
/// to re-park immediately on the same transport; before this type existed the silent reap was
/// misread as a rung failure, advancing the dial ladder and burning a fresh 0-40s window per
/// expiry (the tester's measured 271 phantom "rung failures").
#[derive(Debug)]
pub(crate) struct ParkExpired(pub(crate) &'static str);

impl std::fmt::Display for ParkExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ParkExpired {}

impl ParkExpired {
    pub(crate) fn boxed(text: &'static str) -> BoxError {
        Box::new(ParkExpired(text))
    }
}

/// #21: is this admission error a park expiry (see [`ParkExpired`])? Typed downcast first; the
/// string half covers a park-expiry close reason that reached us flattened inside some other
/// error (e.g. an `open_bi`/write failure racing the edge's ApplicationClose) -- like
/// [`crate::channel::error_names_park_expiry`], that is wire-token parsing, not an in-process
/// substring contract.
pub(crate) fn is_park_expired(e: &BoxError) -> bool {
    if e.downcast_ref::<ParkExpired>().is_some() {
        return true;
    }
    crate::channel::error_names_park_expiry(e.as_ref())
}

/// #231: how long to wait before the next admission attempt. A definitive refusal (see
/// [`is_definitive_admission_refusal`]) will never resolve itself without operator action — a
/// holder that isn't a channel member stays that way until someone adds it — so retrying at the
/// same fast `retry_backoff` used for transient errors (200ms in production) does nothing but
/// flood the edge's admission path with attempts that can never succeed. Live-reproduced: an
/// orphaned process retrying a not-member holder measured at ~24-47 admission attempts/second
/// against the production edge, plausibly starving OTHER, genuinely valid joins of admission
/// capacity (the exact symptom #231 describes). Backs off exponentially
/// (`retry_backoff * 2^consecutive_refusals`), capped at [`REFUSED_ADMISSION_BACKOFF_CAP`]; a
/// transient error always gets the fast, unchanged `retry_backoff` so a genuine brief CP/edge
/// blip (#140) still recovers quickly. Pure — the loop supplies `consecutive_refusals`.
pub(crate) fn admission_retry_backoff(
    retry_backoff: std::time::Duration,
    refused: bool,
    consecutive_refusals: u32,
) -> std::time::Duration {
    if !refused {
        return retry_backoff;
    }
    let shift = consecutive_refusals.min(16); // avoids overflow in 2^shift well before the cap binds
    retry_backoff
        .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX))
        .min(REFUSED_ADMISSION_BACKOFF_CAP)
}
