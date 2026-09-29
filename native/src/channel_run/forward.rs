//! Accept side of the channel TCP forward (scimbe/ct-agent#255, slice 1 of 3).
//!
//! A paired channel already carries one end-to-end Noise session between two members.
//! #255 asks for a second use of it: an initiator may open a byte-transparent stream to a
//! TCP target that the *accepting* member reaches, so a database or an sshd stays bound to
//! the accepting host's loopback and is never exposed publicly ("Bau es über die channels,
//! ich moechte nichts oeffentlich exposed", CTO, 2026-09-29).
//!
//! This module is the gate in front of that: the accepting side's decision whether a
//! requested target may be dialed at all. It is deliberately the first slice, and it is
//! pure policy — no listener, no stream, nothing that touches the transport core. The
//! stream plumbing (slice 2) and the grant revocation that tears running streams down
//! (slice 3, coupled to #45) land on top of it.
//!
//! ## Default off, and off means off
//!
//! [`FORWARD_ALLOW_ENV`] is an **allowlist of exact `host:port` targets**, and an unset or
//! empty value is not "allow everything" — it is the shipped default and it refuses every
//! request. There is no wildcard spelling. A target that is not on the list is refused; a
//! target that is on the list but is *not* a loopback address is still refused unless the
//! operator gave the separate second grant [`FORWARD_ALLOW_NON_LOOPBACK_ENV`], because an
//! allowlist typo that turns a channel into an open proxy into the accepting host's network
//! is exactly the failure this feature must not have.
//!
//! Every refusal is counted and logged as one [`crate::events::FORWARD_REFUSED`] event with
//! the requested `target` and the `reason`, so an operator can tell a missing grant from a
//! typo without turning the option on to find out.

use std::net::IpAddr;

use crate::events;

/// `CT_CHANNEL_FORWARD_ALLOW`: comma-separated list of exact `host:port` targets this member
/// will dial for a peer's forward request. Unset or empty (the default) refuses everything.
pub const FORWARD_ALLOW_ENV: &str = "CT_CHANNEL_FORWARD_ALLOW";

/// `CT_CHANNEL_FORWARD_ALLOW_NON_LOOPBACK`: the second, separate grant a listed target that is
/// not a loopback address needs before it is dialed (#255 acceptance 3). `1`/`true`/`yes`/`on`.
pub const FORWARD_ALLOW_NON_LOOPBACK_ENV: &str = "CT_CHANNEL_FORWARD_ALLOW_NON_LOOPBACK";

/// Longest target string considered at all. The target arrives from the peer; a bounded
/// length keeps one request from writing an unbounded line into the event ring.
pub const MAX_TARGET_LEN: usize = 255;

/// The accept side's verdict on one forward request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardDecision {
    /// The target is listed, reachable under the grants given, and may be dialed.
    Allow,
    /// The request is refused; the payload is the operator-facing `reason`.
    Refuse(String),
}

/// Parse [`FORWARD_ALLOW_ENV`] into canonical targets.
///
/// Comma-separated, whitespace around an entry ignored, empty entries dropped — so `""`,
/// `"   "` and `",,"` all parse to the empty list, i.e. the feature stays off. An entry that
/// is not a `host:port` address is dropped rather than silently widened; it can then only
/// ever produce a "not listed" refusal for whatever the operator meant to write.
pub fn parse_forward_allowlist(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .filter_map(canonical_target)
        .collect()
}

/// Whether the second grant for non-loopback targets is given. Only the explicit positive
/// spellings count; anything else (including unset) leaves the restriction in place.
pub fn non_loopback_granted(raw: Option<&str>) -> bool {
    matches!(
        raw.unwrap_or_default().trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Decide one forward request against an already-parsed allowlist. Pure: no environment, no
/// events, no I/O — the whole policy of this slice is testable from here.
///
/// The order of the checks is the order of the operator's questions: is the feature on at
/// all, is this a target at all, did the operator list it, and may it be left of loopback.
pub fn decide_forward(target: &str, allowlist: &[String], non_loopback: bool) -> ForwardDecision {
    if allowlist.is_empty() {
        return ForwardDecision::Refuse(format!(
            "channel forwarding is off: {FORWARD_ALLOW_ENV} is unset or empty"
        ));
    }
    let Some(canonical) = canonical_target(target) else {
        return ForwardDecision::Refuse(format!(
            "forward target is not a host:port address (at most {MAX_TARGET_LEN} characters)"
        ));
    };
    if !allowlist.contains(&canonical) {
        return ForwardDecision::Refuse(format!(
            "forward target is not listed in {FORWARD_ALLOW_ENV}"
        ));
    }
    if !is_loopback_target(&canonical) && !non_loopback {
        return ForwardDecision::Refuse(format!(
            "forward target is not a loopback address and {FORWARD_ALLOW_NON_LOOPBACK_ENV} is not set"
        ));
    }
    ForwardDecision::Allow
}

/// [`decide_forward`] against the process environment, emitting the refusal event.
///
/// This is the entry point the stream plumbing of slice 2 calls; until then it is exercised
/// by the tests below only, which is the point of shipping the gate before the door.
pub fn accept_forward_request(target: &str) -> Result<(), String> {
    accept_forward_request_with(
        target,
        std::env::var(FORWARD_ALLOW_ENV).ok().as_deref(),
        std::env::var(FORWARD_ALLOW_NON_LOOPBACK_ENV)
            .ok()
            .as_deref(),
    )
}

/// [`accept_forward_request`] with both environment values injected, so a test needs no
/// process-wide `set_var` (this binary's tests run in parallel).
///
/// A refusal is emitted as one [`crate::events::FORWARD_REFUSED`] event carrying `target` and
/// `reason`. The emit is rate-limited like every other peer-triggerable event: a peer that
/// hammers a refused target still gets counted exactly on `/metrics`, but cannot rotate the
/// event ring out from under an operator.
pub fn accept_forward_request_with(
    target: &str,
    raw_allowlist: Option<&str>,
    raw_non_loopback: Option<&str>,
) -> Result<(), String> {
    let allowlist = parse_forward_allowlist(raw_allowlist);
    match decide_forward(target, &allowlist, non_loopback_granted(raw_non_loopback)) {
        ForwardDecision::Allow => Ok(()),
        ForwardDecision::Refuse(reason) => {
            events::emit_limited(
                events::FORWARD_REFUSED,
                serde_json::json!({ "target": redacted_target(target), "reason": reason }),
            );
            Err(reason)
        }
    }
}

/// Whether [`FORWARD_ALLOW_ENV`] is configured at all (scimbe/ct-agent#255 slice 2,
/// AUF-20260929-029): `channel_local`'s switch for whether THIS session should run as the
/// accept side of a channel TCP forward ([`super::forward_stream::forward_accept_local`])
/// instead of whatever it would otherwise build. Mirrors [`parse_forward_allowlist`]'s own
/// "unset or empty means off" rule exactly, so the two can never disagree about whether the
/// feature is on.
pub(crate) fn forward_allow_configured() -> bool {
    !parse_forward_allowlist(std::env::var(FORWARD_ALLOW_ENV).ok().as_deref()).is_empty()
}

/// The target as it goes into an event: trimmed to [`MAX_TARGET_LEN`]. Control characters
/// are escaped by the event layer itself (stderr) and by serde (the ring), so the only thing
/// left to bound here is the length.
fn redacted_target(target: &str) -> String {
    target.chars().take(MAX_TARGET_LEN).collect()
}

/// `host:port` in one canonical spelling, or `None` when `target` is not one.
///
/// Canonical means: the host lowercased, an IP address in the form its own parser prints
/// (so `[0:0:0:0:0:0:0:1]:22` and `[::1]:22` are one entry, not two), an IPv6 literal always
/// bracketed, and the port as decimal. Both the allowlist entries and the requested target
/// go through this, so the comparison in [`decide_forward`] is an exact match on equal terms
/// rather than a substring or prefix test.
fn canonical_target(target: &str) -> Option<String> {
    let target = target.trim();
    if target.is_empty() || target.len() > MAX_TARGET_LEN {
        return None;
    }
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (host, tail) = rest.split_once(']')?;
            (host, tail.strip_prefix(':')?)
        }
        None => {
            let (host, port) = target.rsplit_once(':')?;
            if host.contains(':') {
                return None;
            }
            (host, port)
        }
    };
    let port: u16 = port.parse().ok()?;
    if port == 0 || host.is_empty() {
        return None;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Some(format!("{ip}:{port}")),
        Ok(IpAddr::V6(ip)) => Some(format!("[{ip}]:{port}")),
        Err(_) => Some(format!("{}:{port}", host.to_ascii_lowercase())),
    }
}

/// Whether a canonical target names this host's loopback.
///
/// An IP literal is decided by its own `is_loopback`. The single name form accepted is
/// `localhost`, which every resolver this Agent runs on maps to `127.0.0.1`/`::1`; any other
/// name is treated as non-loopback, because deciding it would mean resolving it here and
/// then dialing a name that may resolve differently a moment later.
fn is_loopback_target(canonical: &str) -> bool {
    let host = match canonical.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => canonical
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or_default(),
    };
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(target: &str, allow: Option<&str>, non_loopback: Option<&str>) -> String {
        let list = parse_forward_allowlist(allow);
        match decide_forward(target, &list, non_loopback_granted(non_loopback)) {
            ForwardDecision::Refuse(reason) => reason,
            ForwardDecision::Allow => panic!("expected {target} to be refused"),
        }
    }

    /// #255 acceptance 1 + AUF-20260929-020 criterion 1: the shipped default refuses.
    #[test]
    fn an_unset_or_empty_allowlist_refuses_every_target() {
        for raw in [None, Some(""), Some("   "), Some(",,"), Some(" , ")] {
            assert_eq!(
                parse_forward_allowlist(raw),
                Vec::<String>::new(),
                "{raw:?}"
            );
            let reason = refusal("127.0.0.1:5432", raw, None);
            assert!(reason.contains(FORWARD_ALLOW_ENV), "{reason}");
            assert!(reason.contains("off"), "{reason}");
        }
    }

    /// #255 acceptance 1: listed loopback targets are the case the feature exists for.
    #[test]
    fn a_listed_loopback_target_is_allowed() {
        let allow = parse_forward_allowlist(Some("127.0.0.1:5432, [::1]:5432 ,localhost:22"));
        for target in [
            "127.0.0.1:5432",
            "[::1]:5432",
            "localhost:22",
            "LocalHost:22",
        ] {
            let decision = decide_forward(target, &allow, false);
            assert_eq!(decision, ForwardDecision::Allow, "{target}");
        }
        // The same list, written in other spellings of the same addresses.
        let same = parse_forward_allowlist(Some("127.000.000.001:5432,[0:0:0:0:0:0:0:1]:5432"));
        assert_eq!(
            decide_forward("[::1]:5432", &same, false),
            ForwardDecision::Allow
        );
    }

    /// #255 acceptance 3, half one: on the list or not, exactly.
    #[test]
    fn a_target_outside_the_allowlist_is_refused() {
        for target in [
            "127.0.0.1:5433",
            "127.0.0.2:5432",
            "localhost:5432",
            "10.0.0.5:5432",
        ] {
            let reason = refusal(target, Some("127.0.0.1:5432"), Some("1"));
            assert!(reason.contains("not listed"), "{target}: {reason}");
            assert!(reason.contains(FORWARD_ALLOW_ENV), "{target}: {reason}");
        }
    }

    /// #255 acceptance 3, half two: listed is not enough for a non-loopback target.
    #[test]
    fn a_non_loopback_target_needs_the_second_grant() {
        let listed = Some("10.0.0.5:5432,db.internal:5432,[2001:db8::1]:5432");
        for target in ["10.0.0.5:5432", "db.internal:5432", "[2001:db8::1]:5432"] {
            let reason = refusal(target, listed, None);
            assert!(reason.contains("loopback"), "{target}: {reason}");
            assert!(
                reason.contains(FORWARD_ALLOW_NON_LOOPBACK_ENV),
                "{target}: {reason}"
            );
            // With the second grant the very same request goes through.
            let allow = parse_forward_allowlist(listed);
            assert_eq!(
                decide_forward(target, &allow, true),
                ForwardDecision::Allow,
                "{target}"
            );
        }
    }

    /// Only the explicit positive spellings are a grant; a typo leaves the gate closed.
    #[test]
    fn the_second_grant_is_off_unless_explicitly_spelled() {
        for raw in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("please"),
        ] {
            assert!(!non_loopback_granted(raw), "{raw:?}");
        }
        for raw in ["1", "true", "YES", " on "] {
            assert!(non_loopback_granted(Some(raw)), "{raw}");
        }
    }

    /// A target that is not an address is refused, not guessed at, and never grows the event.
    #[test]
    fn a_malformed_target_is_refused() {
        let allow = Some("127.0.0.1:5432");
        for target in [
            "",
            "   ",
            "127.0.0.1",
            ":5432",
            "127.0.0.1:0",
            "::1:5432",
            "a:b",
        ] {
            let reason = refusal(target, allow, Some("1"));
            assert!(reason.contains("host:port"), "{target}: {reason}");
        }
        let long = format!("{}:5432", "h".repeat(MAX_TARGET_LEN));
        assert!(refusal(&long, allow, Some("1")).contains("host:port"));
        assert_eq!(redacted_target(&long).chars().count(), MAX_TARGET_LEN);
    }

    /// AUF-20260929-020 criterion 1: the refusal is observable — one counted
    /// `forward_refused` event per refused request, and none for a granted one.
    #[test]
    fn a_refused_request_writes_a_forward_refused_event() {
        let before = events::EVENT_COUNTS.get(events::FORWARD_REFUSED);
        let err = accept_forward_request_with("127.0.0.1:5432", None, None)
            .expect_err("the default refuses");
        assert!(err.contains(FORWARD_ALLOW_ENV), "{err}");
        let after = events::EVENT_COUNTS.get(events::FORWARD_REFUSED);
        assert!(after > before, "{before} -> {after}");

        // The event's shape, built the same way the emit site builds it.
        let ev = events::Event::new(
            events::FORWARD_REFUSED,
            serde_json::json!({ "target": "127.0.0.1:5432", "reason": err }),
        );
        assert_eq!(ev.kind, "forward_refused");
        assert_eq!(ev.to_json()["target"], "127.0.0.1:5432");
        assert!(ev.to_json()["reason"].is_string());

        accept_forward_request_with("127.0.0.1:5432", Some("127.0.0.1:5432"), None)
            .expect("a listed loopback target is granted");
    }
}
