//! QUIC variable-length integer encoding (RFC 9000 section 16), used by both the
//! Capsule Protocol (RFC 9297) and the UDP Proxying HTTP Datagram payload (RFC 9298)
//! for their Type/Length/Context-ID fields.
//!
//! Production copy of the same framing this codebase already proved twice (ct-agent
//! `spike-masque-h2/`, ADR-0024 M1; CADS-Tunnel `crates/masque-proxy`, M2) -- see
//! CADS-Tunnel's `docs/adr/0024-masque-connect-udp-fallback.md` for the design.
//!
//! ct-agent#176: nothing in this module panics. An out-of-range value on the encode
//! side is a typed error the caller surfaces (or drops the datagram for), never a
//! process abort on the data plane.

/// The largest value a QUIC varint can carry: 2^62 - 1 (RFC 9000 section 16).
pub(crate) const MAX_VARINT: u64 = (1 << 62) - 1;

/// A value handed to [`encode`] that the 62-bit QUIC varint range cannot represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VarintRangeError(pub(crate) u64);

impl std::fmt::Display for VarintRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "varint value {} exceeds the 62-bit QUIC varint range", self.0)
    }
}

impl std::error::Error for VarintRangeError {}

/// Encodes `v` as a QUIC varint, appending it to `out`. `Err` if `v` exceeds the
/// 62-bit range the encoding can represent -- every value this crate ever encodes
/// (capsule type 0x00, small lengths, context ID 0) is far below that ceiling, so
/// the error is a caller-side bug signal, not a runtime condition; it is still an
/// error rather than a panic (ct-agent#176) so a data-plane task can never abort
/// the process over it.
pub(crate) fn encode(v: u64, out: &mut Vec<u8>) -> Result<(), VarintRangeError> {
    if v < (1 << 6) {
        out.push(v as u8);
    } else if v < (1 << 14) {
        let b = (v as u16) | 0x4000;
        out.extend_from_slice(&b.to_be_bytes());
    } else if v < (1 << 30) {
        let b = (v as u32) | 0x8000_0000;
        out.extend_from_slice(&b.to_be_bytes());
    } else if v <= MAX_VARINT {
        let b = v | 0xC000_0000_0000_0000;
        out.extend_from_slice(&b.to_be_bytes());
    } else {
        return Err(VarintRangeError(v));
    }
    Ok(())
}

/// Decodes one QUIC varint from the front of `buf`, returning `(value, bytes_consumed)`.
/// `None` if `buf` doesn't contain enough bytes for the length the first byte's
/// 2-bit prefix declares -- the caller should buffer more input and retry. Every
/// byte pattern is a valid varint of some length, so this never fails on content,
/// only on truncation.
pub(crate) fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mask = first & 0x3f;
    let mut v = mask as u64;
    for &b in &buf[1..len] {
        v = (v << 8) | b as u64;
    }
    Some((v, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_values_at_each_length_boundary() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, MAX_VARINT] {
            let mut buf = Vec::new();
            encode(v, &mut buf).expect("in range");
            let (decoded, consumed) = decode(&buf).expect("decodes what we just encoded");
            assert_eq!(decoded, v, "value round-trips");
            assert_eq!(consumed, buf.len(), "consumes exactly what was encoded");
        }
    }

    #[test]
    fn decode_returns_none_on_truncated_input() {
        let mut buf = Vec::new();
        encode(16384, &mut buf).unwrap(); // a 4-byte encoding
        assert!(decode(&buf[..2]).is_none(), "truncated multi-byte varint must not decode");
    }

    #[test]
    fn encode_rejects_a_value_above_the_62_bit_range_instead_of_panicking() {
        // ct-agent#176: the old implementation panicked here.
        for v in [MAX_VARINT + 1, 1 << 62, u64::MAX] {
            let mut buf = Vec::new();
            let err = encode(v, &mut buf).expect_err("out of range must be an error");
            assert_eq!(err, VarintRangeError(v));
            assert!(err.to_string().contains("62-bit"), "error names the range: {err}");
            assert!(buf.is_empty(), "nothing is written on failure");
        }
    }

    #[test]
    fn decode_never_panics_on_any_first_byte() {
        // Every 2-bit prefix maps to a length of 1/2/4/8; a too-short buffer is `None`,
        // a long-enough one always decodes. Exhaustive over the prefix byte.
        for first in 0u8..=255 {
            let len = 1usize << (first >> 6);
            if len > 1 {
                let short = vec![first; len - 1];
                assert!(decode(&short).is_none(), "truncated {len}-byte varint is None, not a panic");
            }
            let full = vec![first; len];
            let (_, consumed) = decode(&full).expect("enough bytes for the declared length");
            assert_eq!(consumed, len);
        }
    }
}
