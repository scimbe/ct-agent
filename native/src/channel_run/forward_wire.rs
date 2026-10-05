//! The wire protocol multiplexing many TCP streams onto ONE already-established A2A channel
//! session (scimbe/ct-agent#255 slice 2, AUF-20260929-029).
//!
//! [`crate::channel_run::session::run_channel_session_on_stream`] pumps exactly one
//! `AsyncRead + AsyncWrite` (`local`) as the session's whole plaintext byte stream. A channel
//! forward needs MANY independent, byte-transparent TCP connections inside that one Noise
//! session — so this module defines the small framing that turns `local` itself into a
//! multiplexer: every frame is tagged with the logical stream id it belongs to, and
//! [`forward_stream`]'s engine is the thing that reads/writes these frames as `local`.
//!
//! Three frame kinds, deliberately not length-prefixed as a whole (each variant already
//! carries its own length field for its variable part, so [`Frame::read`] knows exactly how
//! many bytes it needs without a wrapping envelope):
//!
//! * `Open{id, target}` — sent ONLY by the initiate side, once per accepted local TCP
//!   connection: "start forwarding my new stream `id` to `target`". The accept side answers
//!   with `Data` (it dialed and is now pumping) or `Close` (refused or the dial failed).
//! * `Data{id, payload}` — either direction: `payload` bytes belong to stream `id`.
//! * `Close{id, reason}` — either direction: stream `id` is done; `reason` is set only when
//!   the sender wants the peer to know WHY (a policy refusal, an idle timeout), never on a
//!   plain EOF.
//!
//! Every field the wire hands this parser is peer-controlled, so every variable-length field
//! is capped ([`MAX_TARGET_WIRE_LEN`], [`MAX_DATA_FRAME_LEN`]) before anything is allocated —
//! a malformed or hostile length must fail the frame, not the process.
//
// trace: AUF-20261005-016

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const TAG_OPEN: u8 = 1;
const TAG_DATA: u8 = 2;
const TAG_CLOSE: u8 = 3;

/// Longest `target`/`reason` string this parser accepts. Generous above the accept-side
/// allowlist's own [`super::forward::MAX_TARGET_LEN`] (255) so a legitimate target is never
/// the thing that trips this cap — it exists purely to bound a hostile length field.
pub(crate) const MAX_TARGET_WIRE_LEN: usize = 2048;

/// Largest `Data` payload this parser accepts. Well above [`super::forward_stream::DATA_CHUNK_LEN`]
/// (our own senders never approach it) — bounds a hostile/corrupt length field before the
/// matching `Vec` is allocated, not a real operating limit.
pub(crate) const MAX_DATA_FRAME_LEN: usize = 1 << 20;

/// Close `reason` that RESETS a stream after a failed local socket (DEC-0061, 2026-10-05). Protocol
/// since flow control (#274): a Close WITHOUT reason is a half-close (the peer shuts its target's
/// write side and keeps relaying the target's reply); a Close WITH any reason -- this value, a
/// refusal, a dial failure, an idle timeout -- ends the stream fully and drops what is in flight.
/// An agent before DEC-0061 treats every Close as a half-close.
pub(crate) const CLOSE_REASON_ABORT: &str = "abort";

/// One multiplexed frame. See the module doc for the protocol these three carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame {
    Open { id: u32, target: String },
    Data { id: u32, payload: Vec<u8> },
    Close { id: u32, reason: Option<String> },
}

impl Frame {
    /// The exact bytes [`Frame::read`] parses back into an equal `Frame`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Frame::Open { id, target } => {
                let t = target.as_bytes();
                let mut out = Vec::with_capacity(1 + 4 + 2 + t.len());
                out.push(TAG_OPEN);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&(t.len() as u16).to_be_bytes());
                out.extend_from_slice(t);
                out
            }
            Frame::Data { id, payload } => {
                let mut out = Vec::with_capacity(1 + 4 + 4 + payload.len());
                out.push(TAG_DATA);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                out.extend_from_slice(payload);
                out
            }
            Frame::Close { id, reason } => {
                let r = reason.as_deref().unwrap_or("");
                let rb = r.as_bytes();
                let mut out = Vec::with_capacity(1 + 4 + 1 + 2 + rb.len());
                out.push(TAG_CLOSE);
                out.extend_from_slice(&id.to_be_bytes());
                out.push(u8::from(reason.is_some()));
                out.extend_from_slice(&(rb.len() as u16).to_be_bytes());
                out.extend_from_slice(rb);
                out
            }
        }
    }

    /// Write [`Frame::encode`]'s bytes to `w` in one call.
    pub(crate) async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.encode()).await
    }

    /// Read exactly one frame from `r`. `UnexpectedEof` (or any read error) means the peer
    /// closed or the underlying session ended — the caller's loop treats that as "stop", not
    /// as a protocol violation. A malformed frame (bad tag, oversize length, non-utf8 string)
    /// is `InvalidData`. Every error surfaced once the stream id itself has been read carries
    /// that id in its message (AUF-20261005-016: the caller logs "Art, Stream-Id" without
    /// needing its own parsing state) — these are still transport/framing-level failures (byte
    /// sync with the peer is lost), never a single misbehaving stream's fault, so the caller is
    /// right to end the whole session on any `Err` this returns.
    pub(crate) async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Frame> {
        let mut tag = [0u8; 1];
        r.read_exact(&mut tag).await?;
        let mut idb = [0u8; 4];
        r.read_exact(&mut idb).await?;
        let id = u32::from_be_bytes(idb);
        let with_id = |e: io::Error| io::Error::new(e.kind(), format!("stream {id}: {e}"));
        match tag[0] {
            TAG_OPEN => {
                let target = read_string(r, MAX_TARGET_WIRE_LEN).await.map_err(with_id)?;
                Ok(Frame::Open { id, target })
            }
            TAG_DATA => {
                let mut lb = [0u8; 4];
                r.read_exact(&mut lb).await.map_err(with_id)?;
                let len = u32::from_be_bytes(lb) as usize;
                if len > MAX_DATA_FRAME_LEN {
                    return Err(with_id(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("forward Data frame of {len} bytes exceeds the {MAX_DATA_FRAME_LEN}-byte cap"),
                    )));
                }
                let mut payload = vec![0u8; len];
                r.read_exact(&mut payload).await.map_err(with_id)?;
                Ok(Frame::Data { id, payload })
            }
            TAG_CLOSE => {
                let mut has_reason = [0u8; 1];
                r.read_exact(&mut has_reason).await.map_err(with_id)?;
                let text = read_string(r, MAX_TARGET_WIRE_LEN).await.map_err(with_id)?;
                let reason = if has_reason[0] != 0 { Some(text) } else { None };
                Ok(Frame::Close { id, reason })
            }
            other => Err(with_id(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown forward frame tag {other}"),
            ))),
        }
    }
}

async fn read_string<R: AsyncRead + Unpin>(r: &mut R, max_len: usize) -> io::Result<String> {
    let mut lb = [0u8; 2];
    r.read_exact(&mut lb).await?;
    let len = u16::from_be_bytes(lb) as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("forward frame string of {len} bytes exceeds the {max_len}-byte cap"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "forward frame string is not utf8",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn round_trip(frame: Frame) -> Frame {
        let mut buf = Vec::new();
        frame.write(&mut buf).await.unwrap();
        Frame::read(&mut &buf[..]).await.unwrap()
    }

    #[tokio::test]
    async fn open_data_close_round_trip_byte_exact() {
        assert_eq!(
            round_trip(Frame::Open {
                id: 7,
                target: "127.0.0.1:5432".to_string()
            })
            .await,
            Frame::Open {
                id: 7,
                target: "127.0.0.1:5432".to_string()
            }
        );
        assert_eq!(
            round_trip(Frame::Data {
                id: 7,
                payload: vec![1, 2, 3, 0, 255]
            })
            .await,
            Frame::Data {
                id: 7,
                payload: vec![1, 2, 3, 0, 255]
            }
        );
        assert_eq!(
            round_trip(Frame::Data {
                id: 9,
                payload: Vec::new()
            })
            .await,
            Frame::Data {
                id: 9,
                payload: Vec::new()
            },
            "an empty Data payload (a plain EOF marker some callers might send) round-trips too"
        );
        assert_eq!(
            round_trip(Frame::Close {
                id: 7,
                reason: None
            })
            .await,
            Frame::Close {
                id: 7,
                reason: None
            }
        );
        assert_eq!(
            round_trip(Frame::Close {
                id: 7,
                reason: Some("forward target is not listed".to_string())
            })
            .await,
            Frame::Close {
                id: 7,
                reason: Some("forward target is not listed".to_string())
            }
        );
    }

    #[tokio::test]
    async fn two_frames_back_to_back_on_one_stream_both_parse() {
        // The engine reads a continuous byte stream, not one frame per read() call -- prove
        // Frame::read leaves the cursor exactly after its own frame, ready for the next one.
        let mut buf = Vec::new();
        Frame::Data {
            id: 1,
            payload: b"hello".to_vec(),
        }
        .write(&mut buf)
        .await
        .unwrap();
        Frame::Close {
            id: 1,
            reason: None,
        }
        .write(&mut buf)
        .await
        .unwrap();
        let mut cursor = &buf[..];
        assert_eq!(
            Frame::read(&mut cursor).await.unwrap(),
            Frame::Data {
                id: 1,
                payload: b"hello".to_vec()
            }
        );
        assert_eq!(
            Frame::read(&mut cursor).await.unwrap(),
            Frame::Close {
                id: 1,
                reason: None
            }
        );
    }

    #[tokio::test]
    async fn a_data_frame_claiming_more_than_the_cap_is_rejected_before_allocating() {
        let mut buf = Vec::new();
        buf.push(TAG_DATA);
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.extend_from_slice(&((MAX_DATA_FRAME_LEN as u32) + 1).to_be_bytes());
        // No payload bytes follow -- if the length were honored, read_exact would hang/EOF
        // waiting for them. It must be refused BEFORE that read is attempted.
        let err = Frame::read(&mut &buf[..])
            .await
            .expect_err("oversize length must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_unknown_tag_is_refused_not_misparsed() {
        let mut buf = Vec::new();
        buf.push(0xEE);
        buf.extend_from_slice(&1u32.to_be_bytes());
        let err = Frame::read(&mut &buf[..])
            .await
            .expect_err("unknown tag must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn a_truncated_frame_is_an_eof_style_error() {
        let mut buf = Vec::new();
        Frame::Data {
            id: 1,
            payload: b"hello".to_vec(),
        }
        .write(&mut buf)
        .await
        .unwrap();
        buf.truncate(buf.len() - 2); // cut the last two payload bytes
        let err = Frame::read(&mut &buf[..])
            .await
            .expect_err("a truncated frame must not parse");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_non_utf8_target_is_refused() {
        let mut buf = Vec::new();
        buf.push(TAG_OPEN);
        buf.extend_from_slice(&1u32.to_be_bytes());
        let bad = [0xFFu8, 0xFE];
        buf.extend_from_slice(&(bad.len() as u16).to_be_bytes());
        buf.extend_from_slice(&bad);
        let err = Frame::read(&mut &buf[..])
            .await
            .expect_err("non-utf8 target must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
