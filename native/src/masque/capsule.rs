//! RFC 9297 Capsule Protocol framing, specialized to the one capsule type this
//! client needs: the DATAGRAM (0x00) capsule (RFC 9297 section 5.2), used to carry
//! an HTTP Datagram over HTTP/2, which has no native unreliable-datagram frame
//! (unlike HTTP/3's QUIC DATAGRAM frame).
//!
//! Production copy of the same framing this codebase already proved twice (ct-agent
//! `spike-masque-h2/`, ADR-0024 M1; CADS-Tunnel `crates/masque-proxy`, M2).

use super::varint;

const DATAGRAM_CAPSULE_TYPE: u64 = 0x00;

/// RFC 9298 section 6's own ceiling on a legitimate UDP payload -- see
/// CADS-Tunnel's `masque-proxy` crate for the matching server-side bound and its
/// rationale (a peer claiming an absurd declared length is refused immediately,
/// not buffered toward).
const MAX_CAPSULE_VALUE_LEN: u64 = 65_527 + 8;

/// Encodes one DATAGRAM capsule wrapping `payload` (an already-encoded HTTP Datagram
/// payload, e.g. from [`udp_datagram_payload::encode`]).
pub(crate) fn encode_datagram(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    varint::encode(DATAGRAM_CAPSULE_TYPE, &mut out);
    varint::encode(payload.len() as u64, &mut out);
    out.extend_from_slice(payload);
    out
}

/// Decodes one capsule from the front of `buf`. Returns `(capsule_type, value, bytes_consumed)`,
/// or `Ok(None)` if `buf` doesn't yet contain a complete capsule. `Err` only for a declared
/// length too large to ever be a legitimate DATAGRAM capsule -- a protocol violation the
/// caller should tear the stream down for, not keep buffering toward.
pub(crate) fn decode(buf: &[u8]) -> Result<Option<(u64, &[u8], usize)>, &'static str> {
    let Some((cap_type, type_len)) = varint::decode(buf) else {
        return Ok(None);
    };
    let Some((len, len_len)) = varint::decode(&buf[type_len..]) else {
        return Ok(None);
    };
    if len > MAX_CAPSULE_VALUE_LEN {
        return Err("capsule Length exceeds the maximum a legitimate UDP-proxying DATAGRAM capsule can carry");
    }
    let header_len = type_len + len_len;
    let total = header_len + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((cap_type, &buf[header_len..total], total)))
}

/// RFC 9298's UDP Proxying HTTP Datagram payload: `Context ID (i) | UDP Proxying Payload (..)`.
/// This client only ever uses Context ID 0 (an unmodified raw UDP payload).
pub(crate) mod udp_datagram_payload {
    use super::varint;

    const CONTEXT_ID_RAW_UDP: u64 = 0;

    pub(crate) fn encode(udp_payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode(CONTEXT_ID_RAW_UDP, &mut out);
        out.extend_from_slice(udp_payload);
        out
    }

    pub(crate) fn decode(buf: &[u8]) -> Option<&[u8]> {
        let (context_id, consumed) = varint::decode(buf)?;
        if context_id != CONTEXT_ID_RAW_UDP {
            return None;
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

        let (cap_type, value, consumed) = decode(&capsule).unwrap().expect("decodes the capsule we just built");
        assert_eq!(cap_type, DATAGRAM_CAPSULE_TYPE);
        assert_eq!(consumed, capsule.len());

        let decoded_udp = udp_datagram_payload::decode(value).expect("context ID 0 -- raw UDP payload");
        assert_eq!(decoded_udp, udp_payload);
    }

    #[test]
    fn decode_rejects_a_declared_length_too_large_to_ever_be_legitimate() {
        let mut malicious = Vec::new();
        varint::encode(0x00, &mut malicious);
        varint::encode(10_000_000_000, &mut malicious);
        malicious.extend_from_slice(b"only a few real bytes follow");
        assert!(decode(&malicious).unwrap_err().contains("exceeds"));
    }
}
