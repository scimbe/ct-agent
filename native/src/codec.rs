//! Small encoding helpers the agent used to carry in five or six private copies each
//! (hex, base64url, constant-time equality, the unix clock). One copy, one set of tests.

/// Lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s
}

/// Exactly `2 * N` ASCII hex digits (either case) into `N` bytes; `None` otherwise.
/// Strict on purpose: no trimming (callers that accept padding trim first), no sign --
/// `u8::from_str_radix`, which several copies used, accepts `"+f"` -- and never a byte
/// slice that could split a multi-byte character (the #606 panic).
pub fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let digits = s.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let nibble = |c: u8| (c as char).to_digit(16);
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nibble(digits[2 * i])? * 16 + nibble(digits[2 * i + 1])?) as u8;
    }
    Some(out)
}

/// RFC 4648 base64url without padding (JOSE / ACME).
pub fn base64url(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Equality whose running time does not depend on where the inputs first differ. A length
/// mismatch returns early: lengths are not secret here (tokens have fixed sizes).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Seconds since the unix epoch; 0 if the clock is before it.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_everything_else() {
        let bytes: [u8; 4] = [0x00, 0x7f, 0xab, 0xff];
        assert_eq!(hex_encode(&bytes), "007fabff");
        assert_eq!(hex_decode::<4>("007fabff"), Some(bytes));
        assert_eq!(hex_decode::<4>("007FABFF"), Some(bytes));
        assert_eq!(hex_decode::<4>("007fabf"), None, "short");
        assert_eq!(hex_decode::<4>(" 007fabff"), None, "not trimmed");
        assert_eq!(hex_decode::<1>("+f"), None, "no sign");
        assert_eq!(hex_decode::<2>("zz00"), None);
        assert_eq!(hex_decode::<2>("é0"), None, "multi-byte char, no panic");
        assert_eq!(hex_decode::<32>(&"é".repeat(32)), None, "64 bytes of non-ASCII, no panic");
    }

    #[test]
    fn ct_eq_is_plain_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn base64url_has_no_padding() {
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }
}
