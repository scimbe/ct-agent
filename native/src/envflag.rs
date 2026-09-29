//! The shared reading of the agent's on/off feature flags.
//!
//! There were about nine readers, and they disagreed: `CT_AGENT_FALLBACK_443=off` turned the
//! feature ON (anything but `""`/`0`/`false` was true), `CT_CHANNEL_PHASE_MARKER=false`
//! left it on, `CT_CHANNEL_SERVE=yes` meant "serve loop" to one reader and "plain pipe"
//! to another. Every flag keeps its own default; only the spelling is shared.
//!
//! Scope: the `CT_AGENT_*` config flags, the channel mode switches that go through this module
//! (`CT_CHANNEL_SERVE`, `_PHASE_MARKER`, `_CALL_PERSISTENT`, `_CALL_RECONNECT`), the ACME, relay
//! and manifest switches, and the SSH owner-auth opt-out. Deliberately NOT covered: a few
//! channel switches that still parse on their own (`CT_CHANNEL_ACCEPT_RACE`, `_RELAY_ONLY`,
//! `_DIRECT_UPGRADE`, `_FRONT_DOOR_ONLY`, `_GRANT_ANY`, `CT_INVITE_DELEGABLE`) -- not yet
//! migrated -- and `self_update`'s `CT_AGENT_UPDATE_SKIP_VERIFY`, whose narrower reading is
//! the safer one for a switch that disables verification and stays as it is.
//!
//! A set, non-empty value that is not a recognised spelling falls back to the flag's default
//! and is reported once per key on stderr, so a typo is visible at start instead of only in
//! behaviour.

/// `Some(true)` for `1`/`true`/`yes`/`on`, `Some(false)` for `0`/`false`/`no`/`off`
/// (trimmed, case-insensitive); `None` for unset, empty or anything else.
pub fn parse(value: Option<&str>) -> Option<bool> {
    let v = value?.trim();
    ["1", "true", "yes", "on"]
        .iter()
        .any(|t| v.eq_ignore_ascii_case(t))
        .then_some(true)
        .or_else(|| ["0", "false", "no", "off"].iter().any(|f| v.eq_ignore_ascii_case(f)).then_some(false))
}

/// The flag's value, or `default` when it is unset, empty or not a recognised spelling.
pub fn flag(value: Option<&str>, default: bool) -> bool {
    parse(value).unwrap_or(default)
}

/// [`flag`] for `key`'s `value`, reporting an unrecognised spelling (see the module doc).
pub fn flag_named(key: &str, value: Option<&str>, default: bool) -> bool {
    if let Some(warning) = unrecognised(key, value, default) {
        warn_once(key, &warning);
    }
    flag(value, default)
}

/// [`flag_named`] for the process environment.
pub fn env_flag(key: &str, default: bool) -> bool {
    flag_named(key, std::env::var(key).ok().as_deref(), default)
}

/// `key`'s raw value from the process environment, for a caller that feeds it to a pure
/// `*_from(Option<&str>)` helper; an unrecognised spelling is reported like [`flag_named`].
/// `default` is only used for that report.
pub fn env_value(key: &str, default: bool) -> Option<String> {
    let value = std::env::var(key).ok();
    if let Some(warning) = unrecognised(key, value.as_deref(), default) {
        warn_once(key, &warning);
    }
    value
}

/// The warning for a set, non-empty value that is neither an on nor an off spelling. Pure.
fn unrecognised(key: &str, value: Option<&str>, default: bool) -> Option<String> {
    let v = value?;
    if v.trim().is_empty() || parse(Some(v)).is_some() {
        return None;
    }
    let as_what = if default { "on" } else { "off" };
    Some(format!(
        "ct-agent: WARNING: {key}={v:?} is not a recognised on/off value (1/true/yes/on or \
         0/false/no/off) -- using the default ({as_what})"
    ))
}

fn warn_once(key: &str, warning: &str) {
    use ct_common::sync::MutexExt;
    static WARNED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut warned = WARNED.lock_safe();
    if !warned.iter().any(|k| k == key) {
        warned.push(key.to_string());
        eprintln!("{warning}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_means_the_same_everywhere() {
        for on in ["1", "true", "TRUE", " yes ", "On"] {
            assert!(flag(Some(on), false), "{on:?}");
        }
        for off in ["0", "false", "No", " off", "OFF"] {
            assert!(!flag(Some(off), true), "{off:?}");
        }
        for unset in [None, Some(""), Some("  "), Some("maybe")] {
            assert!(flag(unset, true) && !flag(unset, false), "{unset:?} keeps the default");
        }
    }

    #[test]
    fn only_a_set_unrecognised_value_is_reported() {
        for quiet in [None, Some(""), Some("  "), Some("yes"), Some("OFF")] {
            assert_eq!(unrecognised("CT_X", quiet, false), None, "{quiet:?}");
        }
        let w = unrecognised("CT_DIRECT_REQUIRE_TOKEN", Some("enforce"), false).unwrap();
        assert!(w.contains("CT_DIRECT_REQUIRE_TOKEN=\"enforce\"") && w.contains("default (off)"), "{w}");
        assert!(unrecognised("CT_CHANNEL_PHASE_MARKER", Some("disable"), true).unwrap().contains("default (on)"));
    }
}
