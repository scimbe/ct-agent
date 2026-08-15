//! Agent Fabric — agent-side channel-join client (#72 AF4, ADR-0020).
//!
//! The counterpart to the edge broker's admission gate (`ct_edge::channel_broker`):
//! an agent that holds a `SignedChannelGrant` presents a [`ChannelJoinRequest`] to
//! the edge over QUIC and proves it holds the grant's `holder` private key, then
//! learns its paired peer's advertised endpoint. This module is the wire-protocol
//! client half; dialing the edge endpoint and custody of the channel key are the
//! caller's. (The broker is not yet mounted in the live edge — #81 SEC81c-c — so this
//! drives exactly the protocol the broker's own tests exercise.)
//!
//! ## Ack contract (normative — both ack readers implement THIS, #23)
//!
//! The edge's admission ack is a single line — `OK …` / `NO` / `EX` — terminated by
//! `\n` on stream legs; on QUIC the ack is delimiter-free by design and EOF (quinn's
//! `finish`) terminates it. A reader completes on the FIRST of: a `\n` (consumed,
//! never read past — session bytes may follow on the same stream), EOF, or the
//! [`CHANNEL_ACK_MAX_BYTES`] cap — exceeding the cap without a terminator is a
//! protocol violation and a hard error on both legs. LEADING NULs are the #500 park
//! keepalive and are skipped (no ack byte is 0x00). Classification: a non-empty ack
//! parses via `parse_channel_ack` (`OK…` → `Admitted`, `EX` → `ParkExpired`,
//! anything else → `Refused`). An EMPTY ack AFTER the possession handshake
//! completed is a dropped leg / handoff race ([`DroppedLegBeforeAck`], #148) —
//! retryable, NEVER `Refused`: on every leg a genuine refusal is an explicit `NO`.
//! (Pre-challenge is different: there an empty response stays `Refused`, because
//! over QUIC an explicit `NO` can race the teardown and arrive empty — see the
//! pre-challenge read in [`present_channel_join_on_stream`].)
//!
//! ### `OK`-line field grammar (normative — parse by grammar, never by count)
//!
//! ```text
//! OK <endpoint-or-mode> [<peer_noise_hex64> <peer_holder_hex64> <peer_attest_hex128>] [<key>=<value> ...]
//! ```
//!
//! - The `<noise> <holder> <attest>` triple is **optional and all-or-nothing** — present
//!   only when the edge relayed the peer's attested Noise key (#101); absent otherwise
//!   (then "no peer Noise key" is a real registration state, not a parse artifact).
//! - `<key>=<value>` tokens (`r=` reflexive #121, `sp=` same-public-IP #276, and any
//!   FUTURE tag) are **tagged, order-independent, and additively appended** — the line is
//!   deliberately extensible. `parse_channel_ack` therefore takes **bare** tokens as the
//!   positional fields and reads `key=value` tokens **by name**, ignoring unknown ones; it
//!   MUST NOT assume a fixed field count. A consumer that hard-checked the count broke on
//!   the U1 `r=`/`sp=` addition (webconference-demo outage, 2026-08-15); ct-agent#28
//!   hardened this reader to the grammar above. The authoritative producer + the same
//!   grammar live in CADS-Tunnel `channel_broker.rs` (`write_member_ack`) and ADR-0020 §4a.

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::{Signer, SigningKey};
use quinn::Connection;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Outcome of presenting a channel join to the edge broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelJoinOutcome {
    /// Admitted. `peer_endpoint` is the paired peer's advertised address when the
    /// edge ran a two-party rendezvous, or empty for a single-participant admission.
    /// `peer_noise_pubkey` is the peer's attested Noise key when the edge relayed it
    /// (#72 AF4 / #100) — so an initiator can pin it with no operator-conveyed value.
    Admitted {
        peer_endpoint: String,
        peer_noise_pubkey: Option<[u8; 32]>,
        /// The peer's grant-authenticated holder pubkey, when the edge relayed the
        /// attested-key triple (#101) — the key to verify `peer_attestation` against.
        peer_holder: Option<[u8; 32]>,
        /// The peer's holder-signed attestation over `peer_noise_pubkey` (#101), which
        /// the initiator verifies before pinning the key.
        peer_attestation: Option<[u8; 64]>,
        /// This member's own **reflexive** (post-NAT) address as the edge observed it on
        /// the authenticated join, when the ack carried it (#121 Phase B1 — the AutoNAT
        /// primitive). `None` on an older ack that omits it or on the relay leg (a
        /// relay-only member is behind symmetric NAT, so it has no punchable reflexive).
        /// This is the address the later hole-punch (B2) punches toward and the input to
        /// [`ct_common::channel::reachability_class`].
        observed_reflexive: Option<std::net::SocketAddr>,
    },
    /// Refused: a bad/expired grant, a non-member holder, an unsafe advertised
    /// endpoint, or a failed possession proof.
    Refused,
    /// #21: the edge reaped this member's park (no partner arrived within the park TTL)
    /// and SAID SO — the bare `EX` token on a stream leg, or a `park-expired` close reason
    /// on QUIC. Explicitly NOT a refusal and NOT a transport failure: the correct reaction
    /// is to re-park immediately (same transport), not to advance the dial ladder or back
    /// off. Before this variant existed the client read the silent close as a rung failure
    /// — measured live as 271 phantom "rung failures" and a 0–40s first-contact latency
    /// roulette (ct-agent#21).
    ParkExpired,
}

/// #140: how long the broker admission exchange (open the stream + send the join request + the
/// possession challenge/response + read the ack) may take. It runs *after* `dial_peer_direct`
/// connects but *before* #139 (post-admission stream setup) and #126 (Noise handshake) cover, so a
/// transport-alive-but-stalled admission was previously unbounded — the same hang class as #139/#126,
/// one layer earlier.
///
/// **Why 45s and not the 15s this shipped with**: the edge only sends the ack on the PAIRING
/// paths once a *partner* arrives, and it keeps a lone first-arriving member parked as pairable
/// for its full park TTL (30s server-side). With a 15s client bound, any pairing whose second
/// member takes 15-30s to show up (entirely normal when that member is walking its own dial
/// ladder off a blocked QUIC rung first) failed DETERMINISTICALLY: this side reported the #140
/// "stalled" error on every rung while the edge, at handoff time, found a corpse ("relay
/// handoff failed acking side A ... connection lost" — observed live 2026-08-13 16:48 UTC,
/// matching the field reports of all-rungs-stall). 45s = the server's 30s park window, plus
/// margin for the partner's own ladder walk. The exchange stays bounded — a genuinely dead
/// broker still fails in finite time — it just no longer gives up while the server is still
/// legitimately waiting for the partner on our behalf.
pub(crate) const ADMISSION_EXCHANGE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// #495 slice 2a (v0.4.14): the optional phase preamble a KA-generation client sends
/// before its length-framed join -- [0xFF, phase]. Only ever sent when the TLS
/// negotiation selected a KA id (see `transport::ka_negotiated`): an old edge selected a
/// legacy id and receives byte-identical legacy traffic. The magic 0xFF is unambiguous
/// against the length prefix (it would mean a >=65280-byte join, refused as len-oob by
/// every edge since the field existed).
/// #495 measurement isolation (requested by the tester after the 2a series proved
/// unrunnable with published binaries): `CT_CHANNEL_PHASE_MARKER=off` (or `0`)
/// suppresses the v0.4.14 phase preamble while keeping everything else identical —
/// the only way to vary the marker as a SINGLE variable, since every marked release
/// also carries the #494 ack-reader fix. Default: markers on.
pub(crate) fn phase_marker_enabled() -> bool {
    phase_marker_enabled_from(std::env::var("CT_CHANNEL_PHASE_MARKER").ok().as_deref())
}

/// Pure core of [`phase_marker_enabled`]: only the explicit strings `off`/`0`
/// disable the marker — unset, empty, or anything else keeps the default (on),
/// so a typo can never silently drop the marker generation.
pub(crate) fn phase_marker_enabled_from(v: Option<&str>) -> bool {
    !matches!(v.map(str::trim), Some("off") | Some("0"))
}

/// One cap, one posture (#23): the bound both ack readers enforce. A well-formed
/// ack line is far below this; reaching it without a terminator is a malformed
/// peer and a hard error on both legs (the readers used to disagree — the
/// rendezvous leg classified whatever arrived, the relay leg errored at 513).
pub(crate) const CHANNEL_ACK_MAX_BYTES: usize = 512;

/// #148/#23: a leg closed with ZERO ack bytes AFTER the possession handshake
/// completed — a transport/handoff race (the paired peer's stream died
/// mid-pairing), NOT an authorization refusal: a genuine refusal is always an
/// explicit `NO` (see the module header's ack contract). Typed so retry policies
/// classify it without string-matching; it must never be treated as definitive —
/// before #23 the rendezvous leg fell through to `Refused` here and paid the
/// #231 definitive 30 s backoff for a transport race.
#[derive(Debug)]
pub struct DroppedLegBeforeAck {
    /// Which leg observed it (`"rendezvous"` / `"relay"`), for operator logs.
    pub leg: &'static str,
}

impl std::fmt::Display for DroppedLegBeforeAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} pairing dropped after admission before the edge ack — a transport/handoff race \
             (the peer connection likely died mid-pairing, #148), not an authorization refusal; retry",
            self.leg
        )
    }
}

impl std::error::Error for DroppedLegBeforeAck {}

pub(crate) const PHASE_PREAMBLE_MAGIC: u8 = 0xFF;
/// Phase byte: rendezvous admission (the parked ack-and-close leg).
pub(crate) const PHASE_MARKER_RENDEZVOUS: u8 = 0x01;
/// Phase byte: relay leg (ack then spliced session on the same stream).
pub(crate) const PHASE_MARKER_RELAY: u8 = 0x02;

/// #495 2a: the ONE gate for sending a `[0xFF, phase]` preamble on a `:443` TLS
/// channel leg — the operator switch (v0.4.17, [`phase_marker_enabled`]) AND the
/// edge having negotiated a KA-generation ALPN ([`crate::transport::ka_negotiated`]).
/// A legacy edge selected a legacy id and must receive byte-identical legacy
/// traffic, so this returns `None` there regardless of the switch. Shared by the
/// rendezvous- and relay-leg dial sites so the two cannot drift (#25).
pub(crate) fn phase_marker_for(
    tls: &tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    phase: u8,
) -> Option<u8> {
    (phase_marker_enabled() && crate::transport::ka_negotiated(tls)).then_some(phase)
}

/// Present `request` on `conn` and complete the edge's possession handshake, signing
/// the edge-issued challenge with `holder` — whose public key must equal the grant's
/// `holder`. Returns whether the edge admitted the join and, if paired, the peer's
/// advertised endpoint.
///
/// Wire protocol (matches `ct_edge::channel_broker`): send a `u16`-BE length prefix +
/// the encoded request, keeping the stream open; if the edge replies with a 32-byte
/// challenge, answer with a 64-byte ed25519 signature over it; then read the
/// `OK[ <endpoint>]` / `NO` ack (see the module header's ack contract). A refusal
/// before the possession step finishes the stream with no challenge, which surfaces
/// as [`ChannelJoinOutcome::Refused`].
pub async fn present_channel_join(
    conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
) -> Result<ChannelJoinOutcome, BoxError> {
    // #140: bound `open_bi` too — it is the QUIC-path analog of the unbounded exchange below and
    // was equally unbounded past dial_peer_direct's connect timeout.
    let (send, recv) = tokio::time::timeout(ADMISSION_EXCHANGE_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| -> BoxError { "channel join open_bi stalled after connect (#140)".into() })??;
    // finish_send_after_sig = true: on QUIC the post-signature shutdown is quinn's clean
    // per-stream finish() -- connection-scoped state is untouched (unlike a TCP/TLS leg).
    present_channel_join_on_stream(send, recv, request, holder, ADMISSION_EXCHANGE_TIMEOUT, true, None, false).await
}

/// The transport-agnostic core of [`present_channel_join`]: run the channel-join wire
/// protocol over an already-open bidirectional stream (#106 client-dial). The QUIC
/// client reaches this via [`present_channel_join`] (a `quinn` bi-stream), but the
/// identical protocol — length-framed request, possession challenge/response, `OK`/`NO`
/// ack — runs over *any* duplex, so a TLS-over-TCP `:443` front-door stream (the
/// fallback when the channel UDP/TCP ports are blocked) speaks it unchanged. `send`/
/// `recv` are the write/read halves.
///
/// `finish_send_after_sig` (#21 follow-up, packet-capture-proven 2026-08-14): whether to
/// close the send half after the possession signature. On QUIC (`true`) this is quinn's
/// clean stream `finish()`. On a TCP/TLS stream leg it MUST be `false`: the "stream
/// finish" there is a close_notify + TCP FIN that half-closes the WHOLE connection, so a
/// parked member waits out its park as a half-closed flow — its unread close_notify then
/// makes the edge's post-reap teardown emit an RST that races (and at real-world RTT
/// beats) the in-flight `EX` record out of the receive buffer, and every stateful
/// middlebox on the path sees a closing flow where a live park is meant to be. The edge
/// never needed the EOF (every read on its side is exact-length).
/// #506: how long a KA leg's parked wait may go without a single byte (NUL tick or
/// ack) before the park is presumed dead. The edge ticks every parked KA leg every
/// 10 s (#500 K2), so 35 s = 3.5 missed ticks — far above jitter, far below the
/// old fixed bound's worst case. This is what lets a KA park outlive the 45 s
/// exchange bound: liveness is per-tick, not per-total (the edge's park TTL for KA
/// legs becomes an operator knob, CT_EDGE_KA_PARK_TTL_SECS).
pub(crate) const KA_PARK_INACTIVITY_BOUND: std::time::Duration = std::time::Duration::from_secs(35);

pub async fn present_channel_join_on_stream<W, R>(
    mut send: W,
    mut recv: R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    exchange_timeout: std::time::Duration,
    finish_send_after_sig: bool,
    phase_marker: Option<u8>,
    ka_tick_wait: bool,
) -> Result<ChannelJoinOutcome, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    // #140: bound the stall — a transport-alive-but-stalled admission (broker not
    // responding, half-open connection, early packet loss) fails fast instead of hanging
    // forever, same discipline as #139/#126. Since #506 the bound is TWO-PHASE: the
    // pre-ack phases (request, challenge, possession) always run under the whole
    // `exchange_timeout`; the ACK WAIT is bounded per-read — for a legacy leg by the
    // remaining total budget (exactly the old whole-exchange behavior), for a KA leg
    // (`ka_tick_wait`) by tick INACTIVITY: the edge ticks a parked KA leg every 10 s, so
    // the park is provably alive however long the edge's park TTL runs, and only 35 s of
    // SILENCE (dead park / wedged edge) fails the wait.
    let deadline = tokio::time::Instant::now() + exchange_timeout;
    let pre = async {
    let bytes = request.encode();
    let len = u16::try_from(bytes.len()).map_err(|_| "channel join request too large")?;
    if let Some(phase) = phase_marker {
        // #495 slice 2a: KA-negotiated legs mark their phase so the edge pairs
        // phase-compatibly (see PHASE_PREAMBLE_MAGIC's doc for the wire safety).
        send.write_all(&[PHASE_PREAMBLE_MAGIC, phase]).await?;
    }
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    // Flush before awaiting the challenge. On a quinn stream this is a no-op, but this
    // same function carries the `:443` front-door legs over a tokio-rustls TLS stream
    // (#106), and tokio-rustls documents that `poll_write` does NOT guarantee
    // transmission — buffered TLS records need an explicit flush. Without it, the join
    // request (or its tail) can sit in the TLS writer while both sides wait: the edge's
    // 15s JOIN_READ bound (#105) and this function's 15s exchange bound (#140) then
    // expire together as a mutual stall. The relay leg
    // (`present_channel_relay_join_on_stream`) has flushed at exactly these two points
    // all along — this leg missing it was an oversight, not a difference in contract.
    send.flush().await?;

    // The edge's response is one of: a 32-byte possession challenge (proceed), a short
    // "NO" (a pre-challenge validation refusal), a genuinely-malformed partial (a broken
    // connection), or nothing. #129: the old `read_exact(challenge).is_ok()` silently fell
    // through on ANY read failure and let it all become a generic `Refused`. We now read
    // enough to react to what actually arrived. NOTE: over QUIC an *empty* response is
    // wire-ambiguous — an explicit `NO` can race the connection teardown and arrive empty,
    // so empty stays `Refused` (turning a raced refusal into an error would be worse); the
    // server-side reason logs (#124-#128) are the authoritative diagnostic. Only a partial
    // response that is neither a full challenge nor `NO` is *unambiguously* a broken stream.
    let mut resp = Vec::new();
    let _ = (&mut recv).take(32).read_to_end(&mut resp).await;
    if resp.len() != 32 {
        let text = String::from_utf8_lossy(&resp);
        if resp.is_empty() || text.starts_with("NO") {
            // explicit NO, or an ambiguous empty (raced-NO/closed)
            return Ok(Some(ChannelJoinOutcome::Refused));
        }
        return Err(format!(
            "channel join: the edge sent a malformed {}-byte response before the possession \
             challenge — a broken connection, not a clean OK/NO (#129)",
            resp.len()
        )
        .into());
    }
    let challenge: [u8; 32] = resp.try_into().expect("length checked == 32");
    let sig = holder.sign(&challenge).to_bytes();
    send.write_all(&sig).await?;
    send.flush().await?;
    if finish_send_after_sig {
        // QUIC only: the clean stream `finish()`. Lenient: on a refusal the edge may
        // already have closed. See the doc comment for why a stream leg must NOT do this.
        let _ = send.shutdown().await;
    }
    Ok::<Option<ChannelJoinOutcome>, BoxError>(None)
    };
    match tokio::time::timeout_at(deadline, pre).await {
        Ok(Ok(None)) => {} // possession complete — proceed to the ack wait
        Ok(Ok(Some(early))) => return Ok(early),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("channel join admission exchange stalled (#140)".into()),
    }

    // This reader implements the module header's ack contract (#23). The #494 history
    // of why it is byte-wise: the old `take(512).read_to_end` completed only at EOF (or
    // 512 bytes) — correct on QUIC (the edge `finish()`es the rendezvous stream), but
    // the `:443` edge acks `OK ...\n` and never sends an EOF on this leg — so two fresh
    // members each sat on a fully-delivered ack waiting for an EOF only the OTHER side's
    // stall-timeout death could produce. Every fresh `:443` pairing paid 45–100 s this
    // way (the whole first-contact class of ct-agent#18/CADS-Tunnel#494).
    let mut ack = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        // #506: bound each read. A KA leg is bounded by tick INACTIVITY — every #500
        // NUL keepalive (or ack byte) restarts the window, so a long-TTL park waits as
        // long as it provably lives. A legacy leg is bounded by the remaining total
        // budget: byte-for-byte the old whole-exchange #140 behavior.
        let bound = if ka_tick_wait {
            KA_PARK_INACTIVITY_BOUND
        } else {
            deadline.saturating_duration_since(tokio::time::Instant::now())
        };
        let read = match tokio::time::timeout(bound, recv.read(&mut byte)).await {
            Ok(r) => r,
            Err(_) if ka_tick_wait => {
                return Err(format!(
                    "KA park went silent — no keepalive tick or ack for {}s: dead park or \
                     wedged edge, not a refusal; retry (#506)",
                    KA_PARK_INACTIVITY_BOUND.as_secs()
                )
                .into())
            }
            Err(_) => return Err("channel join admission exchange stalled (#140)".into()),
        };
        match read {
            // EOF: QUIC finish, a NO/EX teardown — or a leg dropped before any ack
            // byte, classified as [`DroppedLegBeforeAck`] below the loop (#23).
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if byte[0] == 0 && ack.is_empty() => continue, // #500 leading park NULs
            Ok(_) => {
                ack.push(byte[0]);
                if ack.len() >= CHANNEL_ACK_MAX_BYTES {
                    return Err(format!(
                        "channel ack exceeded {CHANNEL_ACK_MAX_BYTES} bytes without a terminator — malformed peer"
                    )
                    .into());
                }
            }
            Err(e) => {
                // #21 QUIC half: a reaped park does not write an ack at all — the edge
                // closes the whole connection with the NAMED ApplicationClose reason
                // "park-expired: ...", which quinn surfaces through this read as an
                // error. Recognizing the reason string here is WIRE parsing (the reason
                // IS the wire token, same contract as the stream leg's bare `EX`), not a
                // fragile in-process substring match. Any other read error keeps the
                // lenient behavior: classify from whatever arrived.
                if error_names_park_expiry(&e) {
                    return Ok(ChannelJoinOutcome::ParkExpired);
                }
                break;
            }
        }
    }
    // Empty after a completed possession handshake = dropped leg (#148), mirrored
    // from the relay leg — see the module header's ack contract (#23).
    if ack.is_empty() {
        return Err(Box::new(DroppedLegBeforeAck { leg: "rendezvous" }) as BoxError);
    }
    let ack = String::from_utf8_lossy(&ack);
    Ok(parse_channel_ack(&ack))
}

/// The substring the edge's QUIC park-expiry ApplicationClose reason always carries — the
/// colon-less stem of CADS-Tunnel's `QUIC_PARK_EXPIRED_REASON_PREFIX` (`"park-expired:"`), so
/// it matches the prefix and any honest human-readable suffix. This is the cross-repo wire
/// contract [`error_names_park_expiry`] classifies on; reword it on either side and a benign
/// park reap silently reads as a refusal (rung-ladder advance + refusal backoff instead of
/// re-park). Both repos pin it with a test — here `error_names_park_expiry_walks_the_source_chain_21`,
/// on the edge `quic_park_expiry_reasons_carry_the_wire_prefix` (CADS-Tunnel#526).
const QUIC_PARK_EXPIRED_MARKER: &str = "park-expired";

/// #21: does this error (anywhere in its source chain) carry the edge's named QUIC park-expiry
/// close reason? The edge reaps an idle QUIC park by closing the connection with the
/// ApplicationClose reason `park-expired: no partner within the park TTL` — quinn flattens that
/// reason into the error `Display` at some nesting depth depending on which read/open call
/// observed the close, so every level of the chain is checked. This is the QUIC analog of the
/// stream leg's bare `EX` token: parsing a wire-carried string, not matching in-process text.
pub(crate) fn error_names_park_expiry(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    while let Some(err) = cur {
        if err.to_string().contains(QUIC_PARK_EXPIRED_MARKER) {
            return true;
        }
        cur = err.source();
    }
    false
}

/// Parse a broker/relay admission ack into a [`ChannelJoinOutcome`]. `ack` is the whole ack
/// text (the relay leg strips its trailing `\n` delimiter first). An `OK`-prefixed ack is
/// `OK[ <endpoint>[ <noise_hex> <holder_hex> <attest_hex>]][ r=<reflexive>]`: the broker
/// appends the peer's attested Noise key, its holder, and the holder-signed attestation
/// (#101) when the registry has them (all-or-nothing), plus (#121 Phase B1) the joining
/// member's OWN edge-observed reflexive address as a tagged `r=<addr>` token. The `r=` token
/// is pulled out first (it is self-addressed, not peer material, and order-independent); a
/// missing field yields `None` — backward-additive. Anything else is a refusal.
fn parse_channel_ack(ack: &str) -> ChannelJoinOutcome {
    // #21: the edge's park-expiry token (a reaped park announcing itself) — checked before
    // the OK/Refused fallthrough so it can never be mistaken for a refusal. Wire contract:
    // the bare token, nothing else (CADS-Tunnel's PARK_EXPIRED_TOKEN).
    if ack.trim() == "EX" {
        return ChannelJoinOutcome::ParkExpired;
    }
    match ack.strip_prefix("OK") {
        Some(rest) => {
            let mut observed_reflexive = None;
            let mut fields: Vec<&str> = Vec::new();
            for tok in rest.split_whitespace() {
                if let Some(addr) = tok.strip_prefix("r=") {
                    observed_reflexive = addr.parse().ok();
                } else if tok.contains('=') {
                    // Any OTHER tagged `key=value` token (`sp=`, or a future additive
                    // tag) is NOT a positional field. Grammar-true parse per the normative
                    // ack grammar (CADS-Tunnel ADR-0020 4a): bare tokens are positional,
                    // `key=value` tokens are read by name and unknown ones ignored — so
                    // positional decoding stays immune to tag additions/reordering. Before
                    // this, only `r=` was separated and `sp=` leaked into `fields`, harmless
                    // solely by luck (it failed hex-decode / fell off after 4 takes); a
                    // future tag could have misparsed — the exact positional-fragility class
                    // that broke the webconference JS ack parser on the U1 `r=`/`sp=`
                    // addition (2026-08-15 outage).
                } else {
                    fields.push(tok);
                }
            }
            let mut parts = fields.into_iter();
            let peer_endpoint = parts.next().unwrap_or_default().to_string();
            let peer_noise_pubkey = parts.next().and_then(decode_hex_32);
            let peer_holder = parts.next().and_then(decode_hex_32);
            let peer_attestation = parts.next().and_then(decode_hex_64);
            ChannelJoinOutcome::Admitted {
                peer_endpoint,
                peer_noise_pubkey,
                peer_holder,
                peer_attestation,
                observed_reflexive,
            }
        }
        None => ChannelJoinOutcome::Refused,
    }
}

/// Present a channel join over a **relay** stream that then carries the spliced Noise
/// session on the *same* duplex (#106 relay-leg-443). This differs from
/// [`present_channel_join_on_stream`] — the QUIC / front-door **broker** leg, where the
/// join stream is throwaway (it reads the ack to EOF and closes its write half, and the
/// data path is a *separate* connection) — in two ways the `:443` relay leg requires:
/// it must **not** close the send half (the session writes over it next), and it must
/// read the ack **up to its `\n` delimiter and no further**, leaving every subsequent byte
/// for [`crate::channel_run::run_channel_session_on_stream`]. The edge relay
/// ([`ct_edge::channel_broker::finish_relay_pair_over_streams`]) now acks the RICH
/// `OK <peer_endpoint> <peer_noise> <peer_holder> <peer_attest>\n` line — conveying the
/// peer's attested Noise key (#122), so a fresh `:443`-only pair with no pre-shared peer key
/// learns it here — then splices the two members' streams. The trailing newline is exactly
/// where the ack ends and the Noise session's first frame begins, so reading up to it never
/// over-reads. `send`/`recv` are borrowed, not consumed, so the caller reuses them for the
/// session. A refusal is a bare `NO` (no newline), surfaced when the read hits EOF first.
pub async fn present_channel_relay_join_on_stream<W, R>(
    send: &mut W,
    recv: &mut R,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    phase_marker: Option<u8>,
) -> Result<ChannelJoinOutcome, BoxError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let bytes = request.encode();
    let len = u16::try_from(bytes.len()).map_err(|_| "channel join request too large")?;
    if let Some(phase) = phase_marker {
        // #495 slice 2a: see present_channel_join_on_stream -- same preamble, relay leg.
        send.write_all(&[PHASE_PREAMBLE_MAGIC, phase]).await?;
    }
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&bytes).await?;
    send.flush().await?;

    // Answer the edge's possession challenge, same as the broker leg — but leave the send
    // half OPEN afterward (the spliced session writes over it), so no `shutdown()` here.
    let mut challenge = [0u8; 32];
    recv.read_exact(&mut challenge).await?;
    let sig = holder.sign(&challenge).to_bytes();
    send.write_all(&sig).await?;
    send.flush().await?;

    // Read the ack LINE up to (and consuming) its `\n` delimiter — never past it: the Noise
    // session ciphertext follows immediately on this same relay-spliced stream, so reading a
    // fixed buffer could swallow the session's first frame. Reading byte-by-byte to the
    // newline consumes exactly the ack; the transport buffers the session bytes internally.
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match recv.read_exact(&mut byte).await {
            Ok(_) if byte[0] == b'\n' => break,
            // #500 K2 (v0.4.13): LEADING NULs are the edge's park keepalive (one per 10s
            // while this leg waited for its partner) -- skip them before the ack starts.
            // Unconditional and unambiguous: no ack byte is 0x00, and NULs only ever
            // precede the ack, never follow its first byte.
            Ok(_) if byte[0] == 0 && line.is_empty() => continue,
            Ok(_) => {
                line.push(byte[0]);
                if line.len() >= CHANNEL_ACK_MAX_BYTES {
                    return Err(format!(
                        "channel ack exceeded {CHANNEL_ACK_MAX_BYTES} bytes without a terminator — malformed peer"
                    )
                    .into());
                }
            }
            // EOF before a newline — a bare `NO` refusal, or a dropped relay leg. Classify
            // from whatever arrived below (a bare `NO` becomes `Refused`; nothing at all is a race).
            Err(_) => break,
        }
    }
    // Empty after a completed possession handshake = dropped leg / handoff race
    // (#148: `finish_relay_pair_over_streams` writes an explicit `b"NO"` before
    // closing on a genuine refusal, and the edge logs the race server-side) — see
    // the module header's ack contract (#23).
    if line.is_empty() {
        return Err(Box::new(DroppedLegBeforeAck { leg: "relay" }) as BoxError);
    }
    let ack = String::from_utf8_lossy(&line);
    Ok(parse_channel_ack(&ack))
}

/// Decode 64 lowercase-hex chars into 32 bytes (the peer Noise key / holder the
/// broker relays), or `None` if malformed.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// Decode 128 lowercase-hex chars into the 64-byte attestation, or `None`.
fn decode_hex_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::channel::{ChannelGrant, ChannelId, Direction, Rights, SignedChannelGrant};
    use ct_edge::channel_broker::{broker_channel_rendezvous, resolve_channel_join};
    use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};

    const OP_SEED: [u8; 32] = [7u8; 32];

    fn operator() -> SigningKey {
        SigningKey::from_bytes(&OP_SEED)
    }

    #[test]
    fn phase_marker_switch_disables_only_on_explicit_off_or_zero() {
        // #495 measurement isolation: only the explicit opt-outs disable the marker —
        // unset/empty/typos keep the default ON, so the marker generation can never be
        // dropped by accident.
        assert!(phase_marker_enabled_from(None), "unset -> on");
        assert!(phase_marker_enabled_from(Some("")), "empty -> on");
        assert!(phase_marker_enabled_from(Some("on")), "explicit on -> on");
        assert!(phase_marker_enabled_from(Some("false")), "unknown word -> on (no silent opt-out)");
        assert!(!phase_marker_enabled_from(Some("off")), "off -> disabled");
        assert!(!phase_marker_enabled_from(Some("0")), "0 -> disabled");
        assert!(!phase_marker_enabled_from(Some(" off ")), "trimmed -> disabled");
    }

    fn signed_grant(channel: [u8; 32], holder: &SigningKey, dir: Direction) -> SignedChannelGrant {
        let g = ChannelGrant {
            channel: ChannelId(channel),
            holder: holder.verifying_key().to_bytes(),
            direction: dir,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 1_000,
        };
        let signature = operator().sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    #[tokio::test]
    async fn present_channel_join_on_stream_bounds_a_stalled_admission_exchange() {
        // #140 (frozen): the admission exchange runs after dial_peer_direct connects but BEFORE
        // #139/#126 cover — an edge that accepts the stream but never sends the possession challenge
        // hung the client forever with no fallback. The bound turns that into a fast error. Here the
        // "edge" end stays open + silent (never writes the challenge), so the client's read blocks;
        // the exchange must time out (~200ms), not hang.
        use tokio::io::split;
        let channel = [0x3Cu8; 32];
        let holder = SigningKey::from_bytes(&[0x21u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, _silent_edge) = tokio::io::duplex(4096); // held open, never responds
        let (cli_r, cli_w) = split(client_end);
        let start = std::time::Instant::now();
        let r = present_channel_join_on_stream(cli_w, cli_r, &request, &holder, std::time::Duration::from_millis(200), false, None, false).await;
        assert!(r.is_err(), "a stalled admission exchange errors, it does not hang (#140)");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "the #140 bound fires fast (~200ms), not after a long hang"
        );
    }

    #[tokio::test]
    async fn present_channel_join_on_stream_speaks_the_protocol_over_a_plain_duplex() {
        // #106 client-dial (frozen): the channel-join wire protocol is transport-agnostic
        // — it runs over a plain in-memory duplex (the stand-in for a TLS-over-TCP :443
        // front-door stream) identically to the QUIC path. A minimal test "edge" reads
        // the framed request, issues a possession challenge, verifies the client's
        // signature under the grant holder, then acks OK + a peer endpoint; the client
        // returns Admitted with it.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x3Cu8; 32];
        let holder = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_pub = holder.verifying_key().to_bytes();
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            // send = write half, recv = read half — no quinn anywhere.
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        // Minimal "edge": read the framed request, challenge, verify possession, ack OK.
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        let challenge = [0x9u8; 32];
        ew.write_all(&challenge).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        VerifyingKey::from_bytes(&holder_pub)
            .unwrap()
            .verify(&challenge, &Signature::from_bytes(&sig))
            .expect("the client proved possession of the holder key over the duplex");
        ew.write_all(b"OK 198.51.100.9:8008").await.expect("ack");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("join") {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => assert_eq!(
                peer_endpoint, "198.51.100.9:8008",
                "the client learns the peer endpoint over a non-QUIC stream",
            ),
            other => panic!("a valid join over the duplex must be Admitted, got {other:?}"),
        }
    }

    /// #494 (CADS-Tunnel): the `:443` front door acks `OK ...\n` and then keeps the SAME
    /// stream open for the relay splice — no EOF ever arrives. The old
    /// `take(512).read_to_end` ack read therefore sat on a fully-delivered ack until the
    /// PEER's stall-timeout death produced an EOF: every fresh `:443` pairing paid
    /// 45–100s (the entire first-contact class). The newline must complete the read
    /// immediately, with leading #500 keepalive NULs still stripped.
    #[tokio::test]
    async fn a_newline_terminated_ack_on_a_held_open_stream_completes_immediately_494() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x3Eu8; 32];
        let holder = SigningKey::from_bytes(&[0x23u8; 32]);
        let holder_pub = holder.verifying_key().to_bytes();
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:8008".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        let challenge = [0xAu8; 32];
        ew.write_all(&challenge).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        VerifyingKey::from_bytes(&holder_pub)
            .unwrap()
            .verify(&challenge, &Signature::from_bytes(&sig))
            .expect("possession");
        // Two leading park-keepalive NULs (#500), then the newline-terminated relay-style
        // ack — and the stream is deliberately HELD OPEN (no shutdown): the #494 shape.
        ew.write_all(b"\0\0OK 198.51.100.10:9009\n").await.expect("ack");

        let start = std::time::Instant::now();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("the ack must complete WITHOUT an EOF -- hanging here is the #494 deadlock")
            .expect("client task")
            .expect("join");
        match outcome {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                assert_eq!(peer_endpoint, "198.51.100.10:9009");
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "the newline completes the ack immediately, not via a timeout"
        );
        drop(ew);
        drop(er);
    }

    /// #506 (tick-based wait contract): a KA leg's parked wait is bounded by tick
    /// INACTIVITY, not by the total exchange bound — the edge's 10 s NUL keepalives
    /// prove the park alive, so a long-TTL park (CT_EDGE_KA_PARK_TTL_SECS) must be
    /// waitable past the 45 s #140 bound. Driven here with a deliberately TINY
    /// exchange_timeout (500 ms) and a park that ticks well past it before acking:
    /// the ticking park must complete Admitted where the old total bound fired #140.
    #[tokio::test]
    async fn a_ticking_ka_park_outlives_the_exchange_bound_506() {
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x66u8; 32];
        let holder = SigningKey::from_bytes(&[0x2Bu8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Accept);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let exchange_timeout = std::time::Duration::from_millis(500);
        let client = tokio::spawn(async move {
            let start = std::time::Instant::now();
            let r = present_channel_join_on_stream(
                cli_w, cli_r, &request, &holder, exchange_timeout, false, None, true,
            )
            .await;
            (r, start.elapsed())
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0xAu8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        // The park ticks every 150 ms for 1.2 s — far past the 500 ms exchange bound —
        // then the partner arrives and the ack lands.
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            ew.write_all(&[0u8]).await.expect("tick");
        }
        ew.write_all(b"OK 198.51.100.9:9009\n").await.expect("ack");

        let (outcome, elapsed) = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("completes")
            .expect("client task");
        assert!(
            elapsed > exchange_timeout,
            "the test only proves something if the wait genuinely outlived the bound"
        );
        match outcome.expect("a ticking park must not time out (#506)") {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                assert_eq!(peer_endpoint, "198.51.100.9:9009");
            }
            other => panic!("expected Admitted after the ticking wait, got {other:?}"),
        }
    }

    /// #23 (ack contract): a leg that closes with ZERO ack bytes after the possession
    /// handshake completed is a dropped leg / handoff race — the typed, retryable
    /// [`DroppedLegBeforeAck`] — and must NOT classify as `Refused`, which the ladder
    /// escalates to `AdmissionRefused` and #231 punishes with the definitive 30 s
    /// backoff. (The relay leg has said so since #148; this pins the same rule on the
    /// rendezvous leg, where the empty ack silently fell through to `Refused`.)
    #[tokio::test]
    async fn an_empty_ack_after_possession_is_a_dropped_leg_not_a_refusal_23() {
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x51u8; 32];
        let holder = SigningKey::from_bytes(&[0x29u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.5:5005".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0xAu8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        // Possession complete — now the leg dies without a single ack byte.
        drop(ew);
        drop(er);

        let err = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("EOF completes the read promptly")
            .expect("client task")
            .expect_err("an empty post-possession ack is an error, not an outcome");
        assert!(
            err.downcast_ref::<DroppedLegBeforeAck>().is_some(),
            "typed as DroppedLegBeforeAck (retryable), got: {err}"
        );
    }

    /// #23 (ack contract): reaching [`CHANNEL_ACK_MAX_BYTES`] without a terminator is a
    /// malformed peer and a hard error — the rendezvous leg used to "classify what
    /// arrived", which let 512 garbage bytes parse into `Refused` (definitive backoff)
    /// or even a bogus `Admitted`.
    #[tokio::test]
    async fn an_oversized_unterminated_ack_is_a_hard_error_23() {
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        let channel = [0x52u8; 32];
        let holder = SigningKey::from_bytes(&[0x2Au8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.6:6006".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });

        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0xAu8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("sig");
        // 512 bytes of garbage, no terminator, stream held open (a newline or EOF
        // would end the read legitimately).
        ew.write_all(&[b'X'; CHANNEL_ACK_MAX_BYTES]).await.expect("garbage");

        let err = tokio::time::timeout(std::time::Duration::from_secs(5), client)
            .await
            .expect("the cap completes the read without needing EOF")
            .expect("client task")
            .expect_err("an unterminated oversized ack is a protocol violation");
        assert!(
            err.to_string().contains("without a terminator"),
            "names the cap violation, got: {err}"
        );
    }

    #[tokio::test]
    async fn present_channel_join_reports_a_malformed_partial_response_as_a_distinct_error() {
        // #129 (frozen): a partial pre-challenge response that is neither a full 32-byte
        // challenge nor an explicit "NO" is UNAMBIGUOUSLY a broken stream — the client must
        // return a DISTINCT Err, not silently conflate it into a generic Refused. (An *empty*
        // response stays Refused: over QUIC an explicit NO can race the teardown to empty, so
        // erroring on empty would misreport genuine refusals — see the fn comment.)
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x3Du8; 32];
        let holder = SigningKey::from_bytes(&[0x22u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        // "edge": read the framed request, then send a malformed partial (neither 32 bytes
        // nor "NO") and close — a broken stream.
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(b"XYZ").await.expect("partial"); // 3 bytes: not a challenge, not "NO"
        let _ = ew.shutdown().await;
        drop(ew);
        drop(er);

        let err = client
            .await
            .expect("client task")
            .expect_err("a malformed partial response must be a DISTINCT error, not Refused");
        assert!(
            err.to_string().contains("#129") && err.to_string().contains("broken connection"),
            "the error must name the broken-connection case, got: {err}",
        );
    }

    #[tokio::test]
    async fn present_channel_join_treats_an_explicit_pre_challenge_no_as_refused() {
        // #129: an explicit pre-challenge "NO" (a policy refusal the edge writes before the
        // challenge) stays Refused — distinct from a dropped connection.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x3Eu8; 32];
        let holder = SigningKey::from_bytes(&[0x23u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Initiate);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.7:7007".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(b"NO").await.expect("no");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("an explicit NO is a clean Refused, not an error") {
            ChannelJoinOutcome::Refused => {}
            other => panic!("an explicit NO must be Refused, got {other:?}"),
        }
    }

    #[test]
    fn parse_channel_ack_is_grammar_true_and_immune_to_tag_additions() {
        // Positional decoding must be immune to every `key=value` tag (present `r=`/`sp=`
        // and any future one), and `r=` still read by name — the grammar-true invariant that
        // the webconference JS parser lacked when it broke on the U1 `r=`/`sp=` addition.
        let noise = "aa".repeat(32);
        let holder = "bb".repeat(32);
        let attest = "cc".repeat(64);

        // Full ack + r= + sp= + a synthetic FUTURE tag: positional fields unaffected.
        let ack = format!("OK relay-only {noise} {holder} {attest} r=203.0.113.9:41000 sp=1 futuretag=whatever");
        match parse_channel_ack(&ack) {
            ChannelJoinOutcome::Admitted {
                peer_endpoint,
                peer_noise_pubkey,
                peer_holder,
                peer_attestation,
                observed_reflexive,
            } => {
                assert_eq!(peer_endpoint, "relay-only");
                assert_eq!(peer_noise_pubkey, decode_hex_32(&noise));
                assert_eq!(peer_holder, decode_hex_32(&holder));
                assert_eq!(peer_attestation, decode_hex_64(&attest));
                assert_eq!(observed_reflexive, Some("203.0.113.9:41000".parse().unwrap()));
            }
            other => panic!("expected Admitted, got {other:?}"),
        }

        // Tags interleaved BEFORE positional fields must not shift positions (true grammar
        // parse, not "tags happen to be last").
        let reordered = format!("OK sp=1 relay-only {noise} r=203.0.113.9:41000 {holder} {attest}");
        match parse_channel_ack(&reordered) {
            ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, observed_reflexive, .. } => {
                assert_eq!(peer_endpoint, "relay-only");
                assert_eq!(peer_noise_pubkey, decode_hex_32(&noise));
                assert_eq!(observed_reflexive, Some("203.0.113.9:41000".parse().unwrap()));
            }
            other => panic!("expected Admitted, got {other:?}"),
        }

        // No triple (registry lacks the peer's noise key): endpoint only, genuinely no key.
        match parse_channel_ack("OK relay-only r=0.0.0.0:0 sp=1") {
            ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, .. } => {
                assert_eq!(peer_endpoint, "relay-only");
                assert_eq!(peer_noise_pubkey, None, "no triple -> genuinely no peer noise key, not a parse artifact");
            }
            other => panic!("expected Admitted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn present_channel_join_classifies_the_ex_token_as_park_expired_21() {
        // #21: after a fully successful admission (challenge answered), a reaped park's stream
        // carries exactly the bare `EX` token before the close. That must classify as the
        // DISTINCT `ParkExpired` — never as `Refused` (nothing was refused: there was simply no
        // partner within the park TTL) and never as a transport error (the leg worked end to end).
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        let channel = [0x21u8; 32];
        let holder = SigningKey::from_bytes(&[0x24u8; 32]);
        let grant = signed_grant(channel, &holder, Direction::Accept);
        let request = ChannelJoinRequest { grant, endpoint: "203.0.113.8:7008".to_string() };

        let (client_end, edge_end) = tokio::io::duplex(4096);
        let (cli_r, cli_w) = split(client_end);
        let client = tokio::spawn(async move {
            present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
        });
        let (mut er, mut ew) = split(edge_end);
        let mut len_buf = [0u8; 2];
        er.read_exact(&mut len_buf).await.expect("len");
        let n = u16::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; n];
        er.read_exact(&mut body).await.expect("request");
        ew.write_all(&[0x42u8; 32]).await.expect("challenge");
        let mut sig = [0u8; 64];
        er.read_exact(&mut sig).await.expect("possession signature");
        ew.write_all(b"EX").await.expect("park-expiry token");
        let _ = ew.shutdown().await;

        match client.await.expect("client task").expect("EX is a clean ParkExpired, not an error") {
            ChannelJoinOutcome::ParkExpired => {}
            other => panic!("the bare EX token must classify as ParkExpired (#21), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn keepalive_nuls_are_stripped_before_the_ack_on_both_readers_500() {
        // #500 K2 client half (v0.4.13): a KA-negotiated park receives NUL bytes while
        // waiting; the classifiers must see the ack EXACTLY as if the NULs were never
        // there -- on the broker leg (read-to-EOF) and the relay leg (line reader) alike.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

        // Broker leg: NULs then EX -> ParkExpired; NULs then OK -> Admitted.
        for (tail, want_ex) in [(&b"EX"[..], true), (&b"OK 198.51.100.9:8008"[..], false)] {
            let channel = [0x77u8; 32];
            let holder = SigningKey::from_bytes(&[0x31u8; 32]);
            let grant = signed_grant(channel, &holder, Direction::Accept);
            let request = ChannelJoinRequest { grant, endpoint: "203.0.113.9:7009".to_string() };
            let (client_end, edge_end) = tokio::io::duplex(4096);
            let (cli_r, cli_w) = split(client_end);
            let client = tokio::spawn(async move {
                present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false).await
            });
            let (mut er, mut ew) = split(edge_end);
            let mut len_buf = [0u8; 2];
            er.read_exact(&mut len_buf).await.expect("len");
            let mut body = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            er.read_exact(&mut body).await.expect("request");
            ew.write_all(&[0x42u8; 32]).await.expect("challenge");
            let mut sig = [0u8; 64];
            er.read_exact(&mut sig).await.expect("sig");
            ew.write_all(&[0u8, 0u8, 0u8]).await.expect("keepalive NULs");
            ew.write_all(tail).await.expect("ack tail");
            let _ = ew.shutdown().await;
            let outcome = client.await.expect("client").expect("clean outcome");
            if want_ex {
                assert!(matches!(outcome, ChannelJoinOutcome::ParkExpired), "NULs+EX -> ParkExpired, got {outcome:?}");
            } else {
                assert!(matches!(outcome, ChannelJoinOutcome::Admitted { .. }), "NULs+OK -> Admitted, got {outcome:?}");
            }
        }

        // Relay leg (line reader): NULs before the OK line are skipped, the line parses.
        let channel = [0x78u8; 32];
        let holder = SigningKey::from_bytes(&[0x32u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6052".to_string(),
        };
        let (client, server) = tokio::io::duplex(4096);
        let (mut cr, mut cw) = split(client);
        let srv = tokio::spawn(async move {
            let (mut sr, mut sw) = split(server);
            let mut len = [0u8; 2];
            sr.read_exact(&mut len).await.unwrap();
            let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
            sr.read_exact(&mut req).await.unwrap();
            sw.write_all(&[0u8; 32]).await.unwrap();
            sw.flush().await.unwrap();
            let mut sig = [0u8; 64];
            sr.read_exact(&mut sig).await.unwrap();
            sw.write_all(&[0u8, 0u8]).await.unwrap(); // parked-phase keepalives
            sw.write_all(b"OK 198.51.100.7:7007\n").await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw, &mut cr, &request, &holder, None)
            .await
            .expect("relay join with leading NULs");
        srv.await.unwrap();
        match outcome {
            ChannelJoinOutcome::Admitted { peer_endpoint, .. } => {
                assert_eq!(peer_endpoint, "198.51.100.7:7007", "the ack parses exactly as without NULs");
            }
            other => panic!("NULs+OK line must be Admitted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn phase_marker_prefixes_the_join_and_absent_marker_stays_byte_identical_495a() {
        // #495 slice 2a client half: with a marker the wire starts [0xFF, phase, len_hi,
        // len_lo, ...]; without one it starts with the length prefix exactly as every
        // release before v0.4.14 -- the edge-side compatibility contract in one assert.
        use tokio::io::{split, AsyncReadExt, AsyncWriteExt};
        for marker in [Some(PHASE_MARKER_RELAY), None] {
            let channel = [0x14u8; 32];
            let holder = SigningKey::from_bytes(&[0x41u8; 32]);
            let request = ChannelJoinRequest {
                grant: signed_grant(channel, &holder, Direction::Initiate),
                endpoint: "203.0.113.14:1414".to_string(),
            };
            let expected_len = request.encode().len() as u16;
            let (client, server) = tokio::io::duplex(4096);
            let (mut cr, mut cw) = split(client);
            let m = marker;
            let req = request.clone();
            let hk = SigningKey::from_bytes(&[0x41u8; 32]);
            let presenter = tokio::spawn(async move {
                let _ = present_channel_relay_join_on_stream(&mut cw, &mut cr, &req, &hk, m).await;
            });
            let (mut sr, mut sw) = split(server);
            let mut head = [0u8; 4];
            sr.read_exact(&mut head).await.expect("wire head");
            match marker {
                Some(p) => {
                    assert_eq!(head[0], PHASE_PREAMBLE_MAGIC, "preamble magic first");
                    assert_eq!(head[1], p, "phase byte second");
                    assert_eq!(u16::from_be_bytes([head[2], head[3]]), expected_len, "then the length");
                }
                None => {
                    assert_eq!(
                        u16::from_be_bytes([head[0], head[1]]),
                        expected_len,
                        "no marker: the wire begins with the length prefix, byte-identical to pre-v0.4.14"
                    );
                }
            }
            let _ = sw.shutdown().await;
            let _ = presenter.await;
        }
    }

    #[test]
    fn error_names_park_expiry_walks_the_source_chain_21() {
        // #21 QUIC half: quinn buries the ApplicationClose reason at a nesting depth that
        // depends on which call observed the close — the classifier must find the wire token
        // at any level of the source chain, and must not fire on unrelated errors.
        // CADS-Tunnel#526 cross-repo contract: the marker must be a substring of the edge's
        // ACTUAL close reasons, so this pins our stem against a copy of what the edge emits.
        assert!(
            "park-expired: no partner within the park TTL".contains(QUIC_PARK_EXPIRED_MARKER)
                && "park-expired: superseded by a newer join from the same holder".contains(QUIC_PARK_EXPIRED_MARKER),
            "the client marker must match every edge QUIC park-expiry reason"
        );
        let inner = std::io::Error::other("connection lost: closed by peer: 0: park-expired: no partner within the park TTL");
        let outer = std::io::Error::other(inner);
        assert!(error_names_park_expiry(&outer), "the nested close reason is recognized");
        let direct = std::io::Error::other("park-expired: no partner within the park TTL");
        assert!(error_names_park_expiry(&direct), "the top-level reason is recognized");
        let unrelated = std::io::Error::other("connection reset by peer");
        assert!(!error_names_park_expiry(&unrelated), "an unrelated error never classifies as park expiry");
    }

    #[tokio::test]
    async fn present_channel_join_completes_the_possession_handshake() {
        // AF4: the agent-side client drives the full broker handshake end-to-end
        // against the real edge broker. A genuine holder is admitted; a holder that
        // signs the possession challenge with the wrong key is refused.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xA0u8; 32];
        let holder = SigningKey::from_bytes(&[0x11u8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.7:9000".to_string(),
        };

        // (1) genuine holder -> Admitted.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            resolve_channel_join(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        assert_eq!(
            outcome,
            ChannelJoinOutcome::Admitted { peer_endpoint: String::new(), peer_noise_pubkey: None, peer_holder: None, peer_attestation: None, observed_reflexive: None },
            "the genuine holder proves possession and is admitted"
        );
        conn.close(0u32.into(), b"done");
        let _ = srv.await;

        // (2) wrong possession key -> Refused (the grant is valid, possession is not).
        let thief = SigningKey::from_bytes(&[0x99u8; 32]);
        let (server2, cert2) = build_server_endpoint_with_cert().expect("server");
        let addr2 = server2.local_addr().expect("addr");
        let srv2 = tokio::spawn(async move {
            resolve_channel_join(&server2, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let client2 = build_client_endpoint(cert2).expect("client");
        let conn2 = client2.connect(addr2, "localhost").expect("cfg").await.expect("conn");
        let outcome2 = present_channel_join(&conn2, &request, &thief).await.expect("join drives");
        assert_eq!(outcome2, ChannelJoinOutcome::Refused, "a wrong possession key is refused");
        let _ = srv2.await;
    }

    #[tokio::test]
    async fn two_agent_clients_learn_each_others_endpoint() {
        // AF4 end-to-end: two agent clients present joins for the same channel; the
        // broker pairs them and each client parses the PEER's advertised endpoint out
        // of its Admitted outcome.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xB0u8; 32];
        let holder_a = SigningKey::from_bytes(&[0x21u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x22u8; 32]);
        let req_a = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_a, Direction::Initiate),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_b, Direction::Accept),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, _h| async move { (c.0 == channel).then_some((op_pub, None, None)) })
                .await
                .map(|_| ())
        });
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_a, &holder_a).await.expect("a joins");
            conn.close(0u32.into(), b"done");
            out
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_b, &holder_b).await.expect("b joins");
            conn.close(0u32.into(), b"done");
            out
        });

        let out_a = a.await.expect("a");
        let out_b = b.await.expect("b");
        let _ = srv.await;
        // Each side learns the PEER's endpoint AND (#121 B1-follow) its OWN edge-observed
        // reflexive from the live rendezvous finisher — previously `None`, now the loopback
        // source it connected from.
        for (out, peer_ep, who) in [(out_a, "203.0.113.2:7002", "A"), (out_b, "203.0.113.1:7001", "B")] {
            match out {
                ChannelJoinOutcome::Admitted {
                    peer_endpoint,
                    peer_noise_pubkey,
                    peer_holder,
                    peer_attestation,
                    observed_reflexive,
                } => {
                    assert_eq!(peer_endpoint, peer_ep, "agent {who} learns the peer endpoint");
                    assert_eq!((peer_noise_pubkey, peer_holder, peer_attestation), (None, None, None));
                    let r = observed_reflexive.expect("learns its reflexive via the live rendezvous finisher");
                    assert!(r.ip().is_loopback(), "agent {who} reflexive is the loopback source it dialed from");
                }
                other => panic!("expected Admitted, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn rendezvous_relays_each_peers_attested_noise_key() {
        // #72 AF4 / #100 (hands-off): when the registry has each member's Noise key,
        // the broker relays the PEER's key in the ack, so each agent learns the peer's
        // Noise pubkey to pin — no operator-conveyed value. The authorize closure
        // returns (operator, this-holder's-noise), keyed on the holder.
        let op_pub = operator().verifying_key().to_bytes();
        let channel = [0xC0u8; 32];
        let holder_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let holder_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let hkey_a = holder_a.verifying_key().to_bytes();
        let hkey_b = holder_b.verifying_key().to_bytes();
        let noise_a = [0xAAu8; 32];
        let noise_b = [0xBBu8; 32];
        // Each member attests its own Noise key with its holder key (#101).
        let attest_a = holder_a
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hkey_a, &noise_a))
            .to_bytes();
        let attest_b = holder_b
            .sign(&ct_common::channel::member_noise_attest_bytes(&ChannelId(channel), &hkey_b, &noise_b))
            .to_bytes();
        let req_a = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_a, Direction::Initiate),
            endpoint: "203.0.113.1:7001".to_string(),
        };
        let req_b = ChannelJoinRequest {
            grant: signed_grant(channel, &holder_b, Direction::Accept),
            endpoint: "203.0.113.2:7002".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        let srv = tokio::spawn(async move {
            broker_channel_rendezvous(&server, 500, move |c, h| async move {
                // Each member resolves to (operator, its Noise key, its attestation).
                let (noise, attest) = if h == hkey_a { (noise_a, attest_a) } else { (noise_b, attest_b) };
                (c.0 == channel).then_some((op_pub, Some(noise), Some(attest)))
            })
            .await
            .map(|_| ())
        });
        let cert_b = cert.clone();
        let a = tokio::spawn(async move {
            let c = build_client_endpoint(cert).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_a, &holder_a).await.expect("a joins");
            conn.close(0u32.into(), b"done");
            out
        });
        let b = tokio::spawn(async move {
            let c = build_client_endpoint(cert_b).expect("client");
            let conn = c.connect(addr, "localhost").expect("cfg").await.expect("conn");
            let out = present_channel_join(&conn, &req_b, &holder_b).await.expect("b joins");
            conn.close(0u32.into(), b"done");
            out
        });

        let out_a = a.await.expect("a");
        let out_b = b.await.expect("b");
        let _ = srv.await;
        // A learns B's endpoint + attested Noise key/holder/attestation, plus its OWN
        // reflexive from the live finisher (#121 B1-follow — loopback source here).
        for (out, peer_ep, pn, ph, pa, who) in [
            (out_a, "203.0.113.2:7002", noise_b, hkey_b, attest_b, "A"),
            (out_b, "203.0.113.1:7001", noise_a, hkey_a, attest_a, "B"),
        ] {
            match out {
                ChannelJoinOutcome::Admitted {
                    peer_endpoint,
                    peer_noise_pubkey,
                    peer_holder,
                    peer_attestation,
                    observed_reflexive,
                } => {
                    assert_eq!(peer_endpoint, peer_ep, "agent {who} learns the peer endpoint");
                    assert_eq!(peer_noise_pubkey, Some(pn), "agent {who} learns the peer Noise key");
                    assert_eq!(peer_holder, Some(ph), "agent {who} learns the peer holder");
                    assert_eq!(peer_attestation, Some(pa), "agent {who} learns the peer attestation");
                    let r = observed_reflexive.expect("learns its reflexive via the live rendezvous finisher");
                    assert!(r.ip().is_loopback(), "agent {who} reflexive is the loopback source");
                }
                other => panic!("expected Admitted, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn two_agents_carry_data_over_a_channel_session() {
        // #72 AF4-session end-to-end over a REAL QUIC connection: this is the payoff
        // of the rendezvous above. Once each agent has learned its peer's endpoint,
        // the initiator dials the responder and they run a Noise_IK A2A session keyed
        // on their member Noise static keys, then exchange application data BOTH ways
        // — the live, encrypted, mutually-authenticated tunnel-to-tunnel data path.
        use ct_common::a2a::{a2a_initiate, a2a_recv, a2a_respond, a2a_send};
        use ct_common::noise::generate_static_keypair;
        use ct_edge::transport::{build_client_endpoint, build_server_endpoint_with_cert};

        let initiator = generate_static_keypair();
        let responder = generate_static_keypair();
        let resp_priv = responder.private;

        // The responder listens on its advertised endpoint; the initiator dials it.
        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut s, mut r) = conn.accept_bi().await.expect("accept_bi");
            let mut sess = a2a_respond(&mut s, &mut r, &resp_priv).await.expect("responder handshake");
            let got = a2a_recv(&mut r, &mut sess).await.expect("recv");
            assert_eq!(got, b"hello from agent A", "responder decrypts A's application data");
            a2a_send(&mut s, &mut sess, b"ack from agent B").await.expect("send ack");
            // Keep the connection (and endpoint) alive until the initiator is done so
            // the ack is delivered before teardown.
            conn.closed().await;
        });

        let client = build_client_endpoint(cert).expect("client");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let (mut s, mut r) = conn.open_bi().await.expect("open_bi");
        let mut sess = a2a_initiate(&mut s, &mut r, &initiator.private, &responder.public)
            .await
            .expect("initiator handshake");
        a2a_send(&mut s, &mut sess, b"hello from agent A").await.expect("send");
        let ack = a2a_recv(&mut r, &mut sess).await.expect("recv");
        assert_eq!(ack, b"ack from agent B", "agent A decrypts agent B's encrypted reply");
        conn.close(0u32.into(), b"done");
        srv.await.expect("responder task");
    }

    #[tokio::test]
    async fn member_learns_its_edge_observed_reflexive_over_quic() {
        // #121 Phase B1 (frozen): the AutoNAT round-trip over REAL QUIC. A member joins over the
        // authenticated channel connection; the edge observes its reflexive (post-NAT) source
        // via `read_join_on_connection` (`conn.remote_address()`) and reports it back in the OK
        // ack as the `r=<addr>` token; the joining member parses it into
        // `Admitted { observed_reflexive: Some(..) }`. The learned address MUST equal both what
        // the edge observed AND the loopback source the client actually connected from.
        use ct_edge::channel_broker::read_join_on_connection;

        let pk = operator().verifying_key().to_bytes();
        let channel = [0x5Bu8; 32];
        let holder = SigningKey::from_bytes(&[0x0au8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6011".to_string(),
        };

        let (server, cert) = build_server_endpoint_with_cert().expect("server");
        let addr = server.local_addr().expect("addr");
        // The edge task: admit the join, then ack `OK r=<observed reflexive>` — the exact
        // primitive the B2 hole-punch and Phase C superpeer election consume.
        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").await.expect("conn");
            let (mut send, _req, _op, _noise, _attest, observed) =
                read_join_on_connection(&conn, 500, std::time::Duration::from_secs(5), &move |c, _h| async move {
                    (c.0 == channel).then_some((pk, None, None))
                })
                .await
                .expect("admitted");
            send.write_all(format!("OK r={observed}").as_bytes()).await.expect("ack");
            send.finish().expect("finish");
            conn.closed().await; // hold the connection so the member reads the ack to EOF
            observed
        });

        let client = build_client_endpoint(cert).expect("client");
        let client_source = client.local_addr().expect("client local addr");
        let conn = client.connect(addr, "localhost").expect("cfg").await.expect("conn");
        let outcome = present_channel_join(&conn, &request, &holder).await.expect("join drives");
        conn.close(0u32.into(), b"done");
        let observed = srv.await.expect("edge task");

        match outcome {
            ChannelJoinOutcome::Admitted { observed_reflexive, .. } => {
                assert_eq!(
                    observed_reflexive,
                    Some(observed),
                    "the member learns exactly the reflexive address the edge observed",
                );
                assert_eq!(
                    observed_reflexive,
                    Some(client_source),
                    "the observed reflexive equals the loopback source the client connected from",
                );
                assert!(observed.ip().is_loopback(), "the test's source is loopback");
            }
            other => panic!("a valid join must be Admitted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn member_learns_its_edge_observed_reflexive_over_tls_tcp_443() {
        // #121 Phase B1 (frozen): the same AutoNAT round-trip over a REAL TLS-over-TCP `:443`
        // front-door stream — the fallback path for a member whose network blocks the channel
        // ports. The edge takes the reflexive from the accepted `TcpStream`'s `peer_addr()`,
        // threads it through `admit_channel_join_on_duplex`, and reports it in the `r=<addr>`
        // token; the member parses it into `Admitted { observed_reflexive: Some(..) }` via the
        // transport-agnostic `present_channel_join_on_stream`. Proves BOTH transports carry it.
        use ct_edge::channel_broker::admit_channel_join_on_duplex;
        use ct_edge::transport::{build_tcp_tls_listener_at, tcp_tls_connect};
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::io::split;

        let pk = operator().verifying_key().to_bytes();
        let channel = [0xF4u8; 32];
        let holder = SigningKey::from_bytes(&[0x0au8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6041".to_string(),
        };

        let (listener, acceptor, cert) = build_tcp_tls_listener_at((Ipv4Addr::LOCALHOST, 0).into())
            .await
            .expect("tls-tcp listener");
        let listen_addr: SocketAddr = listener.local_addr().expect("addr");

        let srv = tokio::spawn(async move {
            let (tcp, peer) = listener.accept().await.expect("tcp accept");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let (mut stream, _req, _op, _noise, _attest, observed) = admit_channel_join_on_duplex(
                tls,
                peer,
                500,
                std::time::Duration::from_secs(5),
                &move |c, _h| async move { (c.0 == channel).then_some((pk, None, None)) },
            )
            .await
            .expect("admitted over a real TLS-TCP stream");
            stream.write_all(format!("OK r={observed}").as_bytes()).await.expect("ack");
            stream.shutdown().await.expect("shutdown");
            observed
        });

        let client_tls = tcp_tls_connect(listen_addr, cert).await.expect("tls-tcp connect");
        let (cli_r, cli_w) = split(client_tls);
        let outcome = present_channel_join_on_stream(cli_w, cli_r, &request, &holder, ADMISSION_EXCHANGE_TIMEOUT, false, None, false)
            .await
            .expect("join drives over the :443 duplex");
        let observed = srv.await.expect("edge task");

        match outcome {
            ChannelJoinOutcome::Admitted { observed_reflexive, .. } => {
                assert_eq!(
                    observed_reflexive,
                    Some(observed),
                    "the :443 member learns exactly the reflexive the edge observed on the TCP peer",
                );
                assert!(observed.ip().is_loopback(), "the test's TCP source is loopback");
            }
            other => panic!("a valid :443 join must be Admitted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn present_relay_join_reports_a_dropped_leg_distinctly_from_a_refusal() {
        // #148 client-facing (frozen): on the relay path a refusal is an explicit `NO`, so an EMPTY
        // ack after the challenge was accepted is a dropped leg / handoff race — a DISTINCT retryable
        // error, not the generic `Refused` that reads like an authorization denial. An explicit `NO`
        // still parses to `Refused`.
        use tokio::io::{duplex, split, AsyncReadExt, AsyncWriteExt};
        let channel = [0xC1u8; 32];
        let holder = SigningKey::from_bytes(&[0x0bu8; 32]);
        let request = ChannelJoinRequest {
            grant: signed_grant(channel, &holder, Direction::Initiate),
            endpoint: "203.0.113.9:6051".to_string(),
        };

        // Play the edge side up to the ack: read the framed request, send a 32-byte challenge, read
        // the 64-byte possession sig — then run `finish` (drop = empty ack, or write an explicit NO).
        async fn edge_until_ack(
            server: tokio::io::DuplexStream,
        ) -> (
            tokio::io::ReadHalf<tokio::io::DuplexStream>,
            tokio::io::WriteHalf<tokio::io::DuplexStream>,
        ) {
            let (mut sr, mut sw) = split(server);
            let mut len = [0u8; 2];
            sr.read_exact(&mut len).await.unwrap();
            let mut req = vec![0u8; u16::from_be_bytes(len) as usize];
            sr.read_exact(&mut req).await.unwrap();
            sw.write_all(&[0u8; 32]).await.unwrap(); // possession challenge
            sw.flush().await.unwrap();
            let mut sig = [0u8; 64];
            sr.read_exact(&mut sig).await.unwrap();
            (sr, sw)
        }

        // (1) Dropped leg: the edge closes without any OK/NO after admission → a distinct retryable Err.
        let (client, server) = duplex(4096);
        let (mut cr, mut cw) = split(client);
        let srv = tokio::spawn(async move {
            let (_sr, sw) = edge_until_ack(server).await;
            drop(sw); // no OK/NO — the #148 dropped leg
        });
        let err = present_channel_relay_join_on_stream(&mut cw, &mut cr, &request, &holder, None)
            .await
            .expect_err("a dropped relay leg after admission must be a distinct error, not Ok(Refused)");
        srv.await.unwrap();
        let msg = format!("{err}").to_lowercase();
        assert!(msg.contains("race") && msg.contains("retry"), "distinct retryable message: {msg}");
        assert!(
            msg.contains("not an authorization refusal"),
            "must explicitly disclaim being a refusal, not read like one: {msg}"
        );

        // (2) Explicit NO: a genuine post-pairing refusal still parses to Refused.
        let (client2, server2) = duplex(4096);
        let (mut cr2, mut cw2) = split(client2);
        let srv2 = tokio::spawn(async move {
            let (_sr, mut sw) = edge_until_ack(server2).await;
            sw.write_all(b"NO").await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw2, &mut cr2, &request, &holder, None)
            .await
            .expect("an explicit NO is a clean outcome, not an error");
        srv2.await.unwrap();
        assert!(matches!(outcome, ChannelJoinOutcome::Refused), "an explicit post-pairing NO stays Refused");

        // (3) #21: the bare `EX` park-expiry token on the relay leg classifies as ParkExpired —
        // neither the #148 dropped-leg error nor a Refused.
        let (client3, server3) = duplex(4096);
        let (mut cr3, mut cw3) = split(client3);
        let srv3 = tokio::spawn(async move {
            let (_sr, mut sw) = edge_until_ack(server3).await;
            sw.write_all(b"EX").await.unwrap();
            sw.flush().await.unwrap();
        });
        let outcome = present_channel_relay_join_on_stream(&mut cw3, &mut cr3, &request, &holder, None)
            .await
            .expect("the EX token is a clean outcome, not an error");
        srv3.await.unwrap();
        assert!(
            matches!(outcome, ChannelJoinOutcome::ParkExpired),
            "the relay leg's bare EX classifies as ParkExpired (#21), got {outcome:?}"
        );
    }
}
