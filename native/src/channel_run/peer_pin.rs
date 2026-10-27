//! Binding a channel endpoint to its partner: the opt-in peer pin (`CT_CHANNEL_PEER_PIN`).
//!
//! A channel is a hub of pairwise sessions (ADR-0020). The edge pairs a parked member with the
//! oldest parked other member of the same channel, and every check a member runs answers "is this
//! a member": the attestation binds the peer's Noise key to the peer's holder for this channel
//! (#101), Noise_IK binds the session to that key, and the peer-grant check, when on, binds the
//! holder to an operator-signed grant with the complementary direction. Within one session no
//! other source gets a message in. Across sessions nothing bound an endpoint to ONE peer: any
//! other member holding a grant for the channel got a session with a persistent acceptor (next to
//! the partner's), and a holder could come back with any Noise key it ever attested
//! (CADS-Tunnel#574). On a forward channel that is every granted member reaching the forward
//! targets, and a second accept-side member receiving an initiator's connections (#292).
//!
//! The pin is that binding, local to one member and opt-in. Each side pins on its own; nothing
//! changes on the wire, and the peer needs no upgrade.
//!
//! * `link` -- the peer must be the other end of a link channel: `channel_id_for_link(operator,
//!   own holder, peer holder)` has to be this member's channel. Nothing to copy, and the peer may
//!   rotate its Noise key; it only fits a channel whose id was derived that way (`channel
//!   member-material`), under the operator key it was derived with. The operator key is
//!   `CT_CHANNEL_OPERATOR_PUBKEY`, never a value from the edge, so a compromised edge cannot choose
//!   the derivation (CADS-Tunnel#582: no live gate consulted it before).
//! * `holder:<64 hex>[,noise:<64 hex>]`, several separated by `;` -- the partner's holder public
//!   key, optionally with its Noise public key. Holder only: any Noise key that holder attests
//!   passes, so a rotation needs nothing. With `noise:` a rotated or rolled-back key is refused
//!   until the operator re-pins (the agent-side answer to #574's rollback); two entries for one
//!   holder cover a planned re-key.
//!
//! Unset or empty keeps the hub semantics. A value that does not parse (not 64 hex, an unknown
//! field, a holder key that is no ed25519 point) is a configuration error at start, never "off"
//! (the rule `CT_CHANNEL_REVOCATION` follows too), and so is `link` under an operator key that did
//! not sign this member's own grant.
//!
//! ## What is compared, and why that is the live key
//!
//! Once per session, right after the peer's attestation was verified: in
//! `run_channel_join_with_admission` (the one-shot join, the serve loop, the forward initiator,
//! the persistent call) and in both DCUtR joins. The values compared are the ones the session
//! would run with: the initiator's Noise_IK pins exactly the attested key and the acceptor refuses
//! any other live static key (`a2a_respond_verified`), on the direct, relay, upgraded and
//! hole-punched legs alike, and the peer-grant check, when on, refuses a grant for another holder
//! than the attested one. So the decision refuses exactly the peers a check after the handshake
//! would.
//!
//! ## A refusal still takes its transport leg
//!
//! The refused member does not learn that it was refused: it dials this endpoint, or parks its
//! relay leg, as for any session. And the edge pairs relay legs on their own -- a relay leg is
//! spliced with the oldest waiting relay leg of another holder of the channel, not with the
//! member the rendezvous paired. A refusal that opened no leg left the refused member's leg
//! waiting at the edge, and the edge spliced it with this endpoint's NEXT relay leg, the
//! partner's: that session failed its handshake and counted as a #250 flap. A refused
//! initiator's direct dial was picked up the same way by a concurrent session on the shared
//! listener. So [`close_refused_pairing`] takes exactly the leg the session would have taken
//! (the direct dial or accept, else the relay leg) and closes it at once, before the Noise
//! handshake: the refused member's leg is used up, and it gets no handshake message and no byte
//! inside a session. On the DCUtR joins the admission itself is the relay leg, which is closed
//! right after the refusal.
//!
//! A refusal is [`PeerNotPinned`]: one `channel_session` event (`state: refused`) and a session
//! error. Nothing is recorded as a grant end (#267), so a forward initiator reconnects as after
//! any failed session (with its usual backoff), and the persistent serve loop admits the next peer
//! without counting the refusal as a flap (#250).
//!
//! What the pin cannot do: keep the edge from pairing that member with this endpoint again, and
//! keep the edge from splicing two relay legs of this endpoint that wait at the same time with
//! each other's partners -- that happens with or without a pin, and the session then fails its
//! handshake. The relay ack names the member the edge spliced; checking it against the admission
//! is the follow-up that would make such a splice visible at once.
//!
//! ## What a pin cannot tell apart
//!
//! It names an identity, not a process. Two processes running with the same holder key (and the
//! same Noise key) pass the same pin, and the edge pairs them like any two parks of that identity.
//! Run one process per identity on a channel; where several must share one (replicas), the
//! identity is the unit, and every process holding it has to front the same targets.

use std::net::SocketAddr;
use std::time::Duration;

use ct_common::channel::{
    channel_id_for_link, ChannelId, ChannelJoinRequest, GrantError, SignedChannelGrant, CHANNEL_ENDPOINT_RELAY_ONLY,
};
use ed25519_dalek::SigningKey;
use quinn::Endpoint;

use super::peer_grant::OPERATOR_PUBKEY_ENV;
use super::{
    dial_peer_direct, own_endpoint_looks_reachable, park_relay_leg, BoxError, ChannelDialError, ChannelRole,
    ParkedRelayLeg, RelayFallback,
};
use crate::channel::ChannelJoinOutcome;

/// The switch: unset or empty keeps the hub semantics (see the module doc).
pub const PEER_PIN_ENV: &str = "CT_CHANNEL_PEER_PIN";

/// The QUIC close reason on a refused pairing's leg: the edge logs it, a directly dialed peer
/// reads it from its connection error.
const PIN_CLOSE_REASON: &[u8] = b"peer not pinned (#292)";

/// One pinned partner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedPeer {
    /// The partner's holder public key (ed25519), the `holder` of its grant.
    pub holder: [u8; 32],
    /// The partner's member Noise public key; `None` accepts any key the holder attests.
    pub noise: Option<[u8; 32]>,
}

/// The partner(s) this endpoint is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerPin {
    /// `link`: the peer must be the other end of this member's link channel under `operator`.
    Link { operator: [u8; 32] },
    /// The listed partners (never empty).
    Peers(Vec<PinnedPeer>),
}

impl PeerPin {
    /// `Ok(None)` when no pin is set (unset, empty or blank); `Err` naming the problem for a value
    /// that does not parse -- such a value has to stop the start, not switch the pin off. Read
    /// once, by `ChannelJoinCliConfig::from_lookup`.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let raw = f(PEER_PIN_ENV).unwrap_or_default();
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.eq_ignore_ascii_case("link") {
            let op = f(OPERATOR_PUBKEY_ENV).unwrap_or_default();
            let operator = crate::codec::hex_decode::<32>(op.trim()).ok_or_else(|| {
                format!(
                    "{PEER_PIN_ENV}=link needs {OPERATOR_PUBKEY_ENV} (64 hex): the link channel id is \
                     derived from the operator key, and that key must not come from the edge"
                )
            })?;
            return Ok(Some(Self::Link { operator }));
        }
        let mut peers = Vec::new();
        for (i, entry) in raw.split(';').enumerate() {
            let peer = parse_entry(entry.trim()).map_err(|why| {
                format!(
                    "{PEER_PIN_ENV} entry {}: {why} (expected `link`, or `holder:<64 hex>[,noise:<64 hex>]` \
                     with several entries separated by `;`)",
                    i + 1
                )
            })?;
            peers.push(peer);
        }
        Ok(Some(Self::Peers(peers)))
    }

    /// Whether the peer admission attested may have a session with this member: `channel` and
    /// `own_holder` are this member's grant, `peer_holder`/`peer_noise` the attested peer. Pure.
    pub fn check(
        &self,
        channel: &ChannelId,
        own_holder: &[u8; 32],
        peer_holder: &[u8; 32],
        peer_noise: &[u8; 32],
    ) -> Result<(), PeerNotPinned> {
        match self {
            Self::Link { operator } => {
                if channel_id_for_link(operator, own_holder, peer_holder) == *channel {
                    return Ok(());
                }
                Err(PeerNotPinned::new(
                    peer_holder,
                    format!(
                        "{PEER_PIN_ENV}=link, but this channel is not the link channel of this holder and \
                         holder {} under operator {} -- the edge paired another member, or the channel id \
                         was not derived as a link for this pair under this operator key (after an operator-key \
                         rotation the id keeps the old derivation: pin the holder instead)",
                        hex(peer_holder),
                        hex(operator)
                    ),
                ))
            }
            Self::Peers(peers) => {
                // Keep looking after a holder match with another Noise key: a second entry for the
                // same holder (a planned re-key) may name the admitted key.
                let mut pinned_noise = None;
                for p in peers.iter().filter(|p| p.holder == *peer_holder) {
                    match p.noise {
                        None => return Ok(()),
                        Some(n) if n == *peer_noise => return Ok(()),
                        Some(n) => pinned_noise = Some(n),
                    }
                }
                let why = match pinned_noise {
                    Some(n) => format!(
                        "holder {} is pinned with Noise key {}, but admission attested {} -- a rotated or \
                         rolled-back key needs a new pin (CADS-Tunnel#574)",
                        hex(peer_holder),
                        hex(&n),
                        hex(peer_noise)
                    ),
                    None => format!("holder {} is not pinned", hex(peer_holder)),
                };
                Err(PeerNotPinned::new(peer_holder, why))
            }
        }
    }

    /// The start check against this member's own grant: under `link`, the grant must be signed by
    /// the configured operator key, or the derivation would refuse every peer, the partner included,
    /// with nothing at start to say why. Expiry is not this check's business.
    pub fn check_own_grant(&self, own: &SignedChannelGrant) -> Result<(), String> {
        let Self::Link { operator } = self else {
            return Ok(());
        };
        match ct_common::channel::verify_stateless(operator, own, 0) {
            Err(GrantError::BadKey | GrantError::BadSignature) => Err(format!(
                "{PEER_PIN_ENV}=link, but this member's grant (CT_CHANNEL_GRANT) is not signed by \
                 {OPERATOR_PUBKEY_ENV}: the link derivation would refuse every peer -- check the operator key"
            )),
            _ => Ok(()),
        }
    }

    /// What is pinned, for the start line: the full public keys, so an operator can compare them
    /// character by character with the refusal reasons and with the peer's own key.
    pub fn describe(&self) -> String {
        match self {
            Self::Link { operator } => {
                format!("the other end of this link channel (operator {})", hex(operator))
            }
            Self::Peers(peers) => peers
                .iter()
                .map(|p| match p.noise {
                    Some(n) => format!("holder {} with Noise key {}", hex(&p.holder), hex(&n)),
                    None => format!("holder {} (any Noise key it attests)", hex(&p.holder)),
                })
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

/// One `holder:<hex>[,noise:<hex>]` entry.
fn parse_entry(entry: &str) -> Result<PinnedPeer, String> {
    if entry.is_empty() {
        return Err("is empty (a stray `;`?)".to_string());
    }
    let (mut holder, mut noise) = (None, None);
    for field in entry.split(',').map(str::trim) {
        let (key, value) = field
            .split_once(':')
            .ok_or_else(|| format!("`{field}` is neither `holder:<hex>` nor `noise:<hex>`"))?;
        let key = key.trim().to_ascii_lowercase();
        let slot = match key.as_str() {
            "holder" => &mut holder,
            "noise" => &mut noise,
            _ => return Err(format!("unknown field `{key}` (only `holder` and `noise`)")),
        };
        if slot.is_some() {
            return Err(format!("`{key}` is given twice"));
        }
        let value = value.trim();
        *slot = Some(crate::codec::hex_decode::<32>(value).ok_or_else(|| {
            format!(
                "`{key}:` needs a 64-hex public key, got {} character(s){}",
                value.len(),
                if value.len() == 64 { " with a non-hex character in it" } else { "" }
            )
        })?);
    }
    let holder = holder.ok_or("names no `holder:` (a Noise key alone does not name a member)")?;
    // A holder key is an ed25519 public key; about half of all 64-hex strings are not one, so a
    // mistyped digit is often caught here instead of locking the partner out at the first session.
    // A Noise key (X25519) has no such check: every 32 bytes are a key.
    if ed25519_dalek::VerifyingKey::from_bytes(&holder).is_err() {
        return Err(format!("`holder:{}` is not an ed25519 public key (a typo?)", hex(&holder)));
    }
    Ok(PinnedPeer { holder, noise })
}

/// A key in full: refusal reasons and the start line are compared with the pin by eye, and an
/// abbreviated key hides exactly the mistyped digit that would explain a lock-out.
fn hex(key: &[u8; 32]) -> String {
    crate::codec::hex_encode(key)
}

/// A session refused because admission paired this member with a peer its pin does not name (see
/// the module doc). Typed so the serve loop can tell it from a flapping session
/// ([`is_peer_not_pinned`]).
#[derive(Debug)]
pub struct PeerNotPinned {
    peer_holder: [u8; 32],
    why: String,
}

impl PeerNotPinned {
    fn new(peer_holder: &[u8; 32], why: String) -> Self {
        Self { peer_holder: *peer_holder, why }
    }
}

impl std::fmt::Display for PeerNotPinned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer not pinned: {} -- session refused before the Noise handshake", self.why)
    }
}

impl std::error::Error for PeerNotPinned {}

/// Whether `e` is (or wraps) a [`PeerNotPinned`] refusal.
pub(crate) fn is_peer_not_pinned(e: &BoxError) -> bool {
    let first: &(dyn std::error::Error + 'static) = &**e;
    let mut cur = Some(first);
    while let Some(err) = cur {
        if err.is::<PeerNotPinned>() {
            return true;
        }
        cur = err.source();
    }
    false
}

/// [`PeerPin::check`] for one admitted session, plus the operator event. `Ok(())` without a pin:
/// the hub semantics, unchanged.
pub(crate) fn check_peer_pin(
    pin: Option<&PeerPin>,
    request: &ChannelJoinRequest,
    peer_holder: &[u8; 32],
    peer_noise: &[u8; 32],
) -> Result<(), BoxError> {
    let Some(pin) = pin else {
        return Ok(());
    };
    let own = &request.grant.grant;
    pin.check(&own.channel, &own.holder, peer_holder, peer_noise).map_err(|refused| {
        // Rate-limited: any member holding a grant for the channel can trigger it, as often as
        // the edge pairs it with this endpoint. The counter on `/metrics` stays exact.
        crate::events::emit_limited(
            crate::events::CHANNEL_SESSION,
            serde_json::json!({
                "state": "refused",
                "reason": refused.to_string(),
                "peer_holder": hex(&refused.peer_holder),
            }),
        );
        Box::new(refused) as BoxError
    })
}

/// Whether the pin refuses the peer `admission` names, read from the admission as it came in --
/// before the attestation check, so it only ever decides towards a refusal (a value the
/// attestation would reject is refused anyway). Pure, no event: the persistent serve path uses it
/// to skip building its local side (a handler process, a forward engine) for a pairing that is
/// going to be refused; [`check_peer_pin`] after the attestation check stays the decision.
pub(crate) fn pin_refuses_admission(
    pin: Option<&PeerPin>,
    request: &ChannelJoinRequest,
    admission: &ChannelJoinOutcome,
) -> bool {
    let (Some(pin), ChannelJoinOutcome::Admitted { peer_holder: Some(peer_holder), peer_noise_pubkey: Some(peer_noise), .. }) =
        (pin, admission)
    else {
        return false;
    };
    let own = &request.grant.grant;
    pin.check(&own.channel, &own.holder, peer_holder, peer_noise).is_err()
}

/// What a refused pairing still does (see the module doc): take the transport leg its session
/// would have taken, and close it before the Noise handshake, so the refused member's own leg is
/// used up instead of waiting at the edge for this endpoint's next session. The leg choice is that
/// of `run_channel_join_with_admission`, minus its options: the accept window is served before the
/// relay leg (no accept-vs-relay race), and no direct-upgrade candidate is built. Best effort: a leg
/// that cannot be set up is not there to use up, and the caller returns the refusal either way.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn close_refused_pairing(
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    peer_endpoint: &str,
    listener: Option<Endpoint>,
    dial_timeout: Duration,
    accept_timeout: Duration,
    observed_reflexive: Option<SocketAddr>,
) {
    let direct = match role {
        // The peer has no dialable address: it parks its relay leg at once.
        ChannelRole::Initiate if peer_endpoint == CHANNEL_ENDPOINT_RELAY_ONLY => None,
        ChannelRole::Initiate => {
            // An unparseable endpoint or a failed dial ends the session before any leg as well.
            let Ok(addr) = peer_endpoint.parse::<SocketAddr>() else {
                return;
            };
            match dial_peer_direct(addr, dial_timeout).await {
                Ok(conn) => Some(conn),
                Err(ChannelDialError::Unreachable) => None,
                Err(ChannelDialError::Failed(_) | ChannelDialError::ConnectFailed(_)) => return,
            }
        }
        ChannelRole::Accept => match listener {
            Some(ep) if own_endpoint_looks_reachable(&request.endpoint, observed_reflexive) => {
                match tokio::time::timeout(accept_timeout, ep.accept()).await {
                    Ok(Some(incoming)) => match incoming.await {
                        Ok(conn) => Some(conn),
                        Err(_) => return,
                    },
                    Ok(None) => return,
                    // No direct connection: the peer went to the relay, as it does for a session.
                    Err(_timeout) => None,
                }
            }
            // Relay-only, or an advertised address the edge contradicts: straight to the relay.
            _ => None,
        },
    };
    match direct {
        Some(conn) => conn.close(0u32.into(), PIN_CLOSE_REASON),
        None => match park_relay_leg(relay, request, holder).await {
            Ok(ParkedRelayLeg::Quic(conn)) => conn.close(0u32.into(), PIN_CLOSE_REASON),
            // The `:443` leg has no close reason on the wire; its close_notify tells the edge at once.
            Ok(leg) => leg.close().await,
            Err(_) => {}
        },
    }
}

/// The DCUtR joins' refusal: their admission is the relay leg itself (the edge spliced it with the
/// peer's when it acked), so closing that connection is all that is left to do.
pub(crate) fn close_refused_relay_conn(conn: &quinn::Connection) {
    conn.close(0u32.into(), PIN_CLOSE_REASON);
}

/// The start line about the pin. `forward`: this process runs a TCP forward (either side), where
/// an unpinned endpoint is worth a warning; `None` for an unpinned non-forward member, whose start
/// output stays as it was.
pub(crate) fn peer_pin_start_line(pin: Option<&PeerPin>, forward: bool) -> Option<String> {
    match (pin, forward) {
        (Some(pin), _) => Some(format!(
            "ct-agent channel: {PEER_PIN_ENV}: sessions only with {} -- any other member of this \
             channel is refused before the Noise handshake",
            pin.describe()
        )),
        (None, true) => Some(format!(
            "ct-agent channel: WARNING: this forward runs without {PEER_PIN_ENV}: every member of the \
             channel holding a valid grant can be paired with this endpoint (a channel is a hub, \
             ADR-0020) -- set {PEER_PIN_ENV} to bind it to its partner"
        )),
        (None, false) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATOR: [u8; 32] = [0x0A; 32];
    const CHANNEL: ChannelId = ChannelId([0x5C; 32]);

    fn key(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    fn parse(pin: &str, operator: Option<&str>) -> Result<Option<PeerPin>, String> {
        let (pin, operator) = (pin.to_string(), operator.map(str::to_string));
        PeerPin::from_lookup(move |k| match k {
            PEER_PIN_ENV => Some(pin.clone()),
            OPERATOR_PUBKEY_ENV => operator.clone(),
            _ => None,
        })
    }

    fn pinned(holder: [u8; 32], noise: Option<[u8; 32]>) -> PeerPin {
        PeerPin::Peers(vec![PinnedPeer { holder, noise }])
    }

    #[test]
    fn unset_or_empty_keeps_the_hub_semantics_292() {
        assert_eq!(PeerPin::from_lookup(|_| None), Ok(None), "unset: off");
        assert_eq!(parse("", None), Ok(None), "empty: off (compose passes an unset var as empty)");
        assert_eq!(parse("  \t", None), Ok(None), "blank: off");
        assert!(check_peer_pin(None, &request_for(key(1)), &key(2), &[7; 32]).is_ok(), "no pin, no check");
    }

    #[test]
    fn parses_the_link_holder_and_holder_noise_forms_292() {
        let (h, n, h2) = (key(1), [0x77u8; 32], key(2));
        assert_eq!(parse(" LINK ", Some(&hex(&OPERATOR))), Ok(Some(PeerPin::Link { operator: OPERATOR })));
        assert_eq!(parse(&format!("holder:{}", hex(&h)), None), Ok(Some(pinned(h, None))));
        assert_eq!(
            parse(&format!(" holder: {} , noise: {} ", hex(&h).to_uppercase(), hex(&n)), None),
            Ok(Some(pinned(h, Some(n)))),
            "whitespace around fields and upper-case hex are accepted"
        );
        assert_eq!(
            parse(&format!("noise:{},holder:{}", hex(&n), hex(&h)), None),
            Ok(Some(pinned(h, Some(n)))),
            "the field order does not matter"
        );
        assert_eq!(
            parse(&format!("holder:{};holder:{},noise:{}", hex(&h), hex(&h2), hex(&n)), None),
            Ok(Some(PeerPin::Peers(vec![
                PinnedPeer { holder: h, noise: None },
                PinnedPeer { holder: h2, noise: Some(n) },
            ])))
        );
    }

    #[test]
    fn a_malformed_value_is_a_config_error_never_off_292() {
        let h = hex(&key(1));
        let bad = [
            "holder".to_string(),
            "holder:zz".to_string(),
            format!("holder:{}", &h[..63]),
            format!("holder:{}x", &h[..63]),
            format!("noise:{h}"),
            format!("holder:{h},noise:{h},noise:{h}"),
            format!("holder:{h},holder:{h}"),
            format!("holder:{h};"),
            format!("peer:{h}"),
            format!("holder={h}"),
            h.clone(),
            "linkx".to_string(),
            // 64 hex, but no ed25519 point: a mistyped holder key that the format check misses.
            format!("holder:{}", hex(&[0x02; 32])),
        ];
        for value in &bad {
            let err = parse(value, Some(&hex(&OPERATOR))).expect_err(value);
            assert!(err.contains(PEER_PIN_ENV), "{value}: the error names the variable: {err}");
        }
        let err = parse(&format!("holder:{}", hex(&[0x02; 32])), None).expect_err("no ed25519 point");
        assert!(err.contains("not an ed25519 public key"), "{err}");
        let err = parse("link", None).expect_err("link without the operator key");
        assert!(err.contains(OPERATOR_PUBKEY_ENV), "{err}");
        assert!(parse("link", Some("not-hex")).is_err());
    }

    #[test]
    fn the_pinned_holder_is_accepted_and_any_other_holder_refused_292() {
        let (me, partner, other) = (key(1), key(2), key(3));
        let pin = pinned(partner, None);
        assert!(pin.check(&CHANNEL, &me, &partner, &[0x21; 32]).is_ok());
        let err = pin.check(&CHANNEL, &me, &other, &[0x21; 32]).expect_err("another member of the channel");
        let text = err.to_string();
        assert!(text.starts_with("peer not pinned: holder"), "{text}");
        assert!(text.contains(&hex(&other)), "the refused holder is named in full: {text}");
    }

    #[test]
    fn a_holder_only_pin_accepts_a_rotated_noise_key_292() {
        let (me, partner) = (key(1), key(2));
        let pin = pinned(partner, None);
        for noise in [[0x21u8; 32], [0x22; 32]] {
            assert!(pin.check(&CHANNEL, &me, &partner, &noise).is_ok(), "any key the holder attests");
        }
    }

    #[test]
    fn a_noise_pin_refuses_the_same_holder_with_another_noise_key_292() {
        let (me, partner) = (key(1), key(2));
        let (old, new) = ([0x21u8; 32], [0x22u8; 32]);
        let pin = pinned(partner, Some(old));
        assert!(pin.check(&CHANNEL, &me, &partner, &old).is_ok());
        let text = pin.check(&CHANNEL, &me, &partner, &new).expect_err("rotated or rolled back").to_string();
        assert!(text.contains("is pinned with Noise key") && text.contains("CADS-Tunnel#574"), "{text}");
        assert!(text.contains(&hex(&old)) && text.contains(&hex(&new)), "both keys in full: {text}");
        // A planned re-key: both keys pinned for the switch-over, then the old entry is dropped.
        let both = PeerPin::Peers(vec![
            PinnedPeer { holder: partner, noise: Some(old) },
            PinnedPeer { holder: partner, noise: Some(new) },
        ]);
        assert!(both.check(&CHANNEL, &me, &partner, &old).is_ok());
        assert!(both.check(&CHANNEL, &me, &partner, &new).is_ok());
        assert!(both.check(&CHANNEL, &me, &partner, &[0x23; 32]).is_err());
    }

    #[test]
    fn link_accepts_exactly_the_other_end_of_the_link_channel_292() {
        let (me, partner, other) = (key(1), key(2), key(3));
        let channel = channel_id_for_link(&OPERATOR, &partner, &me);
        let pin = PeerPin::Link { operator: OPERATOR };
        assert!(pin.check(&channel, &me, &partner, &[0x21; 32]).is_ok(), "the derived counterpart");
        assert!(pin.check(&channel, &me, &other, &[0x21; 32]).is_err(), "any other member");
        assert!(pin.check(&channel, &me, &me, &[0x21; 32]).is_err(), "this member's own identity is not its partner");
        let other_operator = PeerPin::Link { operator: [0x0B; 32] };
        let text = other_operator
            .check(&channel, &me, &partner, &[0x21; 32])
            .expect_err("the operator key is part of the derivation: a wrong one refuses even the partner")
            .to_string();
        assert!(text.contains("operator-key rotation"), "the reason points at a rotated operator key: {text}");
        assert!(pin.check(&CHANNEL, &me, &partner, &[0x21; 32]).is_err(), "a channel id that is no link refuses everyone");
    }

    #[test]
    fn link_needs_the_operator_key_that_signed_this_members_grant_292() {
        use ct_common::channel::{ChannelGrant, Direction, Rights};
        use ed25519_dalek::Signer as _;
        let op = SigningKey::from_bytes(&[0x0C; 32]);
        let g = ChannelGrant {
            channel: CHANNEL,
            holder: key(1),
            direction: Direction::Accept,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at: 0,
        };
        let own = SignedChannelGrant { signature: op.sign(&g.signing_bytes()).to_bytes(), grant: g };
        let right = PeerPin::Link { operator: op.verifying_key().to_bytes() };
        assert!(right.check_own_grant(&own).is_ok(), "the signing operator; expiry is not this check's business");
        let err = PeerPin::Link { operator: key(9) }.check_own_grant(&own).expect_err("another operator");
        assert!(err.contains(PEER_PIN_ENV) && err.contains(OPERATOR_PUBKEY_ENV), "{err}");
        assert!(PeerPin::Link { operator: [0xFF; 32] }.check_own_grant(&own).is_err(), "no usable key at all");
        assert!(pinned(key(2), None).check_own_grant(&own).is_ok(), "a holder pin does not use the operator key");
    }

    #[test]
    fn a_refusal_is_typed_and_names_the_peer_292() {
        let (me, other) = (key(1), key(3));
        let err = check_peer_pin(Some(&pinned(key(2), None)), &request_for(me), &other, &[7; 32])
            .expect_err("refused");
        assert!(is_peer_not_pinned(&err), "{err}");
        assert!(!is_peer_not_pinned(&BoxError::from("edge broker refused the channel join")));
        assert!(!is_peer_not_pinned(&BoxError::from("peer not pinned: a look-alike string is no refusal")));
    }

    #[test]
    fn the_start_line_names_the_pin_and_warns_for_an_unpinned_forward_292() {
        let pin = pinned(key(2), Some([0x21; 32]));
        let line = peer_pin_start_line(Some(&pin), true).expect("a pin is always reported");
        assert!(line.contains(&hex(&key(2))) && line.contains(&hex(&[0x21; 32])), "full keys: {line}");
        assert!(!line.contains("WARNING"), "{line}");
        let warn = peer_pin_start_line(None, true).expect("an unpinned forward is warned about");
        assert!(warn.contains("WARNING") && warn.contains(PEER_PIN_ENV), "{warn}");
        assert_eq!(peer_pin_start_line(None, false), None, "an unpinned hub member starts as before");
    }

    #[test]
    fn the_serve_path_sees_a_refusal_before_it_builds_its_local_side_292() {
        // `serve_admitted_session` builds its local side (a handler process, a forward engine)
        // only for an admission the pin does not refuse.
        let (me, partner, other, noise) = (key(1), key(2), key(3), [0x21u8; 32]);
        let admitted = |holder: [u8; 32]| ChannelJoinOutcome::Admitted {
            peer_endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
            peer_noise_pubkey: Some(noise),
            peer_holder: Some(holder),
            peer_attestation: Some([0; 64]),
            observed_reflexive: None,
        };
        let (pin, request) = (pinned(partner, None), request_for(me));
        assert!(pin_refuses_admission(Some(&pin), &request, &admitted(other)), "another member");
        assert!(!pin_refuses_admission(Some(&pin), &request, &admitted(partner)), "the partner");
        assert!(!pin_refuses_admission(None, &request, &admitted(other)), "no pin: the hub, unchanged");
        assert!(
            !pin_refuses_admission(Some(&pin), &request, &ChannelJoinOutcome::ParkExpired),
            "no admitted peer: the session's own error path decides"
        );
    }

    /// A join request of holder `holder` on [`CHANNEL`] (only the grant's channel and holder matter here).
    fn request_for(holder: [u8; 32]) -> ChannelJoinRequest {
        use ct_common::channel::{ChannelGrant, Direction, Rights};
        ChannelJoinRequest {
            grant: SignedChannelGrant {
                grant: ChannelGrant {
                    channel: CHANNEL,
                    holder,
                    direction: Direction::Accept,
                    rights: Rights::ReadWrite,
                    delegable: false,
                    expires_at: 1_000,
                },
                signature: [0; 64],
            },
            endpoint: CHANNEL_ENDPOINT_RELAY_ONLY.to_string(),
        }
    }
}
