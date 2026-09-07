//! Secret-shape redaction for text that leaves this process towards a REMOTE peer
//! (ct-agent#169). The service handlers behind `service/<slug>` are typically LLM CLIs
//! running with API keys in their environment; a crash trace can quote them. The local
//! diagnostic sink keeps the full text (that is the operator's own log); anything sent to a
//! foreign channel member goes through [`redact_secrets`] first.
//!
//! Hand-written scanning, no regex crate. Three shapes are masked with `[REDACTED]`:
//!
//! 1. **key/value secrets** -- `(?i)(bearer|token|api[_-]?key|secret|password|authorization)`
//!    followed by an optional identifier suffix (`secret_key`, `token_v2`), optional
//!    whitespace, `:` or `=`, optional whitespace, then the value (`\S+`). A value that is
//!    itself the word `Bearer` keeps that word and masks the token after it
//!    (`Authorization: Bearer <masked>`). A bare `Bearer <token>` (no `:`/`=`) is masked too.
//! 2. **long hex runs** -- any maximal run of 64 or more hex digits (keys, channel ids,
//!    routing tokens, sha256 digests all look like this).
//! 3. **JWT-shaped tokens** -- `eyJ<base64url>.<base64url>[.<base64url>]`.
//!
//! Over-redaction is the deliberate bias: the peer only ever needs the exit status plus a
//! hint of what went wrong, never a faithful reproduction of the handler's stderr.

const MASK: &[u8] = b"[REDACTED]";

/// Minimum length of a hex-digit run that is treated as key material.
const HEX_RUN_MIN: usize = 64;

/// Keywords that introduce a secret value, matched case-insensitively anywhere in the text
/// (no word-boundary requirement -- `X-Api-Key:`, `mytoken=` and `--password=` all count).
const KEYWORDS: &[&str] = &["authorization", "api_key", "api-key", "apikey", "password", "bearer", "secret", "token"];

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c)
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

/// If one of [`KEYWORDS`] starts at `i`, the index just past it and whether it was `bearer`.
fn keyword_at(b: &[u8], i: usize) -> Option<(usize, bool)> {
    let rest = &b[i..];
    for kw in KEYWORDS {
        let k = kw.as_bytes();
        if rest.len() >= k.len() && rest[..k.len()].eq_ignore_ascii_case(k) {
            return Some((i + k.len(), *kw == "bearer"));
        }
    }
    None
}

/// Scan a whitespace-delimited value starting at `from`; the index just past it, or `None`
/// when there is no value there.
fn value_end(b: &[u8], from: usize) -> Option<usize> {
    let mut q = from;
    while q < b.len() && !is_ws(b[q]) {
        q += 1;
    }
    (q > from).then_some(q)
}

/// Try the key/value shape at `i`. On a match, copies the unmasked prefix and the mask into
/// `out` and returns the index to resume scanning from.
fn redact_keyword_value(b: &[u8], i: usize, out: &mut Vec<u8>) -> Option<usize> {
    let (mut p, bearer) = keyword_at(b, i)?;
    if !bearer {
        // `secret_key`, `api_key_v2`, `password-hash` ... the suffix is part of the key.
        while p < b.len() && is_ident(b[p]) {
            p += 1;
        }
        // A JSON/YAML-quoted key (`"password": "..."`) closes its quote before the colon.
        if p < b.len() && (b[p] == b'"' || b[p] == b'\'') {
            p += 1;
        }
    }
    let after_key = p;
    while p < b.len() && is_ws(b[p]) {
        p += 1;
    }
    let had_ws = p > after_key;
    let value_start = if p < b.len() && (b[p] == b':' || b[p] == b'=') {
        p += 1;
        while p < b.len() && is_ws(b[p]) {
            p += 1;
        }
        p
    } else if bearer && had_ws {
        // The HTTP header form: `Bearer <token>` with no separator at all.
        p
    } else {
        return None;
    };
    let end = value_end(b, value_start)?;
    // `Authorization: Bearer <token>` / `Basic <credentials>` -- keep the scheme word, mask
    // what follows it.
    let scheme = &b[value_start..end];
    if scheme.eq_ignore_ascii_case(b"bearer") || scheme.eq_ignore_ascii_case(b"basic") {
        let mut r = end;
        while r < b.len() && is_ws(b[r]) {
            r += 1;
        }
        if let Some(s) = value_end(b, r) {
            out.extend_from_slice(&b[i..r]);
            out.extend_from_slice(MASK);
            return Some(s);
        }
    }
    out.extend_from_slice(&b[i..value_start]);
    out.extend_from_slice(MASK);
    Some(end)
}

/// Try the JWT shape at `i` (`eyJ` + base64url, `.`, base64url, optionally `.` + base64url),
/// requiring that the token does not continue a longer base64url word before it.
fn redact_jwt(b: &[u8], i: usize, out: &mut Vec<u8>) -> Option<usize> {
    if !b[i..].starts_with(b"eyJ") || (i > 0 && is_b64url(b[i - 1])) {
        return None;
    }
    let mut j = i;
    while j < b.len() && is_b64url(b[j]) {
        j += 1;
    }
    if j >= b.len() || b[j] != b'.' {
        return None;
    }
    let mut k = j + 1;
    while k < b.len() && is_b64url(b[k]) {
        k += 1;
    }
    if k == j + 1 {
        return None;
    }
    let mut end = k;
    if k < b.len() && b[k] == b'.' {
        let mut m = k + 1;
        while m < b.len() && is_b64url(b[m]) {
            m += 1;
        }
        if m > k + 1 {
            end = m;
        }
    }
    out.extend_from_slice(MASK);
    Some(end)
}

/// Try the long-hex shape at `i`: a maximal run of at least [`HEX_RUN_MIN`] hex digits.
fn redact_hex_run(b: &[u8], i: usize, out: &mut Vec<u8>) -> Option<usize> {
    if !b[i].is_ascii_hexdigit() || (i > 0 && b[i - 1].is_ascii_hexdigit()) {
        return None;
    }
    let mut j = i;
    while j < b.len() && b[j].is_ascii_hexdigit() {
        j += 1;
    }
    if j - i < HEX_RUN_MIN {
        return None;
    }
    out.extend_from_slice(MASK);
    Some(j)
}

/// Mask every secret-shaped span in `input` with `[REDACTED]` (see the module doc for the
/// three shapes). All patterns are pure ASCII and every splice lands on an ASCII byte, so
/// the result is the same valid UTF-8 text with only those spans replaced.
pub(crate) fn redact_secrets(input: &str) -> String {
    let b = input.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if let Some(next) = redact_keyword_value(b, i, &mut out)
            .or_else(|| redact_jwt(b, i, &mut out))
            .or_else(|| redact_hex_run(b, i, &mut out))
        {
            i = next;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_secrets_masks_key_value_pairs_case_insensitively_169() {
        let cases = [
            ("api_key=sk-live-abc123 rest", "api_key=[REDACTED] rest"),
            ("API-KEY: sk-live-abc123", "API-KEY: [REDACTED]"),
            ("ApiKey = sk-live-abc123\nnext", "ApiKey = [REDACTED]\nnext"),
            ("--token=deadbeef --other=1", "--token=[REDACTED] --other=1"),
            ("\"password\": \"hunter2\",", "\"password\": [REDACTED]"),
            ("SECRET_KEY=abc", "SECRET_KEY=[REDACTED]"),
            ("client_secret: s3cr3t", "client_secret: [REDACTED]"),
            ("OPENAI_API_KEY=sk-proj-xyz", "OPENAI_API_KEY=[REDACTED]"),
            ("authorization=Basic dXNlcjpwYXNz", "authorization=Basic [REDACTED]"),
        ];
        for (input, expected) in cases {
            assert_eq!(redact_secrets(input), expected, "input: {input:?}");
        }
    }

    #[test]
    fn redact_secrets_masks_bearer_tokens_in_both_header_forms_169() {
        assert_eq!(
            redact_secrets("Authorization: Bearer abc.def.ghi\r\n"),
            "Authorization: Bearer [REDACTED]\r\n",
            "the scheme word stays, the token after it goes"
        );
        assert_eq!(redact_secrets("sent Bearer tok123 to api"), "sent Bearer [REDACTED] to api");
        assert_eq!(redact_secrets("bearer=tok123"), "bearer=[REDACTED]");
    }

    #[test]
    fn redact_secrets_masks_long_hex_runs_and_jwt_shapes_169() {
        let hex64 = "ab".repeat(32);
        assert_eq!(redact_secrets(&format!("key {hex64} end")), "key [REDACTED] end");
        let hex128 = "cd".repeat(64);
        assert_eq!(redact_secrets(&format!("sig={hex128}")), "sig=[REDACTED]", "longer runs are one mask");
        let hex63 = "ab".repeat(31) + "a";
        assert_eq!(redact_secrets(&hex63), hex63, "63 hex digits is below the threshold");
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(redact_secrets(&format!("jwt {jwt}!")), "jwt [REDACTED]!");
        assert_eq!(redact_secrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIifQ"), "[REDACTED]", "two-segment JWT");
        assert_eq!(redact_secrets("eyJ alone"), "eyJ alone", "no dot-separated segment -> not a JWT");
    }

    #[test]
    fn redact_secrets_leaves_ordinary_diagnostics_alone_169() {
        let text = "Traceback (most recent call last):\n  File \"cli.py\", line 12\nKeyError: 'model'\nexit 1\n";
        assert_eq!(redact_secrets(text), text);
        assert_eq!(redact_secrets("tokens used: 512"), "tokens used: 512", "a keyword needs its separator right after it");
        assert_eq!(redact_secrets("tokens: 512"), "tokens: [REDACTED]", "over-redaction is the accepted bias");
        assert_eq!(redact_secrets("token"), "token", "a keyword without a value is untouched");
        assert_eq!(redact_secrets("ümlaut ok, secret=ß end"), "ümlaut ok, secret=[REDACTED] end", "UTF-8 survives");
        assert_eq!(redact_secrets(""), "");
    }
}
