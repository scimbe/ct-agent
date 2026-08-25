//! RFC 9297 Capsule Protocol framing, specialized to the one capsule type this
//! spike needs: the DATAGRAM (0x00) capsule (RFC 9297 section 5.2) used to carry
//! an HTTP Datagram over a transport with no native unreliable-datagram frame --
//! exactly HTTP/2's situation, unlike HTTP/3's native QUIC DATAGRAM frame.
//!
//! Wire format (RFC 9297 section 3.2):
//!   Capsule { Capsule Type (i), Capsule Length (i), Capsule Value (..) }
//! For DATAGRAM, Capsule Type = 0x00 and Capsule Value = the HTTP Datagram payload
//! (here: an RFC 9298 UDP Proxying payload, see [`udp_datagram_payload`]).

use crate::varint;

const DATAGRAM_CAPSULE_TYPE: u64 = 0x00;

/// Encodes one DATAGRAM capsule wrapping `payload` (an already-encoded HTTP Datagram
/// payload, e.g. from [`udp_datagram_payload::encode`]).
pub fn encode_datagram(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint::encode(DATAGRAM_CAPSULE_TYPE, &mut out);
    varint::encode(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// Decodes one capsule from the front of `buf`. Returns `(capsule_type, value, bytes_consumed)`,
/// or `None` if `buf` doesn't yet contain a complete capsule (the caller should buffer more
/// bytes from the stream and retry -- this is the same "not enough yet" contract as
/// [`crate::varint::decode`]).
pub fn decode(buf: &[u8]) -> Option<(u64, &[u8], usize)> {
    let (cap_type, type_len) = varint::decode(buf)?;
    let (len, len_len) = varint::decode(&buf[type_len..])?;
    let header_len = type_len + len_len;
    let total = header_len + len as usize;
    if buf.len() < total {
        return None;
    }
    Some((cap_type, &buf[header_len..total], total))
}

/// RFC 9298's UDP Proxying HTTP Datagram payload: `Context ID (i) | UDP Proxying Payload (..)`.
/// This spike only ever uses Context ID 0 (an unmodified raw UDP payload -- RFC 9298
/// section 5's "Context ID zero" case; non-zero Context IDs are for future datagram
/// formats this spike has no need to model).
pub mod udp_datagram_payload {
    use crate::varint;

    const CONTEXT_ID_RAW_UDP: u64 = 0;

    pub fn encode(udp_payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode(CONTEXT_ID_RAW_UDP, &mut out);
        out.extend_from_slice(udp_payload);
        out
    }

    /// Decodes a full (already capsule-unwrapped) datagram payload, returning the raw
    /// UDP bytes if the Context ID is the raw-UDP one this spike supports.
    pub fn decode(buf: &[u8]) -> Option<&[u8]> {
        let (context_id, consumed) = varint::decode(buf)?;
        if context_id != CONTEXT_ID_RAW_UDP {
            return None; // out of scope for this spike -- see module doc
        }
        Some(&buf[consumed..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_udp_packet_round_trips_through_capsule_and_datagram_framing() {
        let udp_payload = b"hello over connect-udp";
        let datagram_payload = udp_datagram_payload::encode(udp_payload);
        let capsule = encode_datagram(&datagram_payload);

        let (cap_type, value, consumed) = decode(&capsule).expect("decodes the capsule we just built");
        assert_eq!(cap_type, DATAGRAM_CAPSULE_TYPE);
        assert_eq!(consumed, capsule.len(), "consumes the whole (single) capsule, no trailing bytes");

        let decoded_udp = udp_datagram_payload::decode(value).expect("context ID 0 -- raw UDP payload");
        assert_eq!(decoded_udp, udp_payload, "the original UDP bytes survive the round trip unchanged");
    }

    #[test]
    fn decode_returns_none_for_a_capsule_still_arriving_across_stream_reads() {
        // Simulates the real over-the-wire case: TCP/h2 delivers bytes in arbitrary
        // chunks, so a capsule can be split across reads. The decoder must say "not
        // yet" rather than misreading a partial capsule as a different, smaller one.
        let full = encode_datagram(&udp_datagram_payload::encode(b"a longer payload than one byte"));
        assert!(decode(&full[..full.len() - 1]).is_none(), "one byte short of complete must not decode");
    }
}
