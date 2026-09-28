//! The one reading of a boolean environment flag.
//!
//! There were about nine, and they disagreed: `CT_AGENT_FALLBACK_443=off` turned the
//! feature ON (anything but `""`/`0`/`false` was true), `CT_CHANNEL_PHASE_MARKER=false`
//! left it on, `CT_CHANNEL_SERVE=yes` meant "serve loop" to one reader and "plain pipe"
//! to another. Every flag keeps its own default; only the spelling is shared.

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

/// [`flag`] for the process environment.
pub fn env_flag(key: &str, default: bool) -> bool {
    flag(std::env::var(key).ok().as_deref(), default)
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
}
