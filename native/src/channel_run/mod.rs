//! Agent Fabric — the A2A channel *runner* (#72 AF4-session-wire, #98/#100).
//!
//! [`crate::channel`] rendezvouses two members and [`ct_common::a2a`] establishes the
//! Noise_IK session; this module is the piece that makes it *runnable*: given an
//! established QUIC connection, a role, and the Noise keys, it completes the A2A
//! handshake and then pumps a local byte stream (the CLI's stdin/stdout, or any
//! `AsyncRead + AsyncWrite`) over the encrypted tunnel — a "netcat over the channel".
//! A thin `ct-agent` subcommand feeds it stdio; tests feed it an in-memory duplex.
//!
//! ## Mode landscape (#25)
//!
//! Three independent axes select the code path a `ct-agent channel` process runs;
//! confusing them has cost real debugging hours, so they are named here once:
//!
//! 1. **Direct-address vs. Plane** (`main.rs` dispatch): `CT_CHANNEL_BROKER` set means
//!    plane-brokered ([`ChannelJoinCliConfig`] → [`run_channel_join_command`]); unset
//!    means the direct-address [`ChannelRunConfig`] path (`CT_CHANNEL_ADDR` +
//!    `CT_CHANNEL_PEER_NOISE_KEY`, no edge involved at all).
//! 2. **Plain broker vs. Ladder** (within the plane mode): a configured
//!    `CT_CHANNEL_FRONT_DOOR` cert selects the dial LADDER
//!    ([`present_channel_join_via_ladder`]); without it, admission is a single direct
//!    QUIC dial to the broker. The `dialing … rung …` log lines exist ONLY on the
//!    ladder path — their absence on a plain-broker member is a different code path,
//!    not a failure.
//! 3. **Relay-only DCUtR variants** (`CT_CHANNEL_RELAY_GATE`, preferred over
//!    `CT_CHANNEL_CIRCUIT_RELAY`; both via [`run_dcutr_join_loop`]): the gated
//!    relay leg for NAT-hostile networks and the nat-lab rig. The libp2p upgrade itself
//!    runs only with `CT_CHANNEL_EXPERIMENTAL_DCUTR=1` (#296); without it the same join
//!    stays on the edge relay ([`join_via_relay_without_dcutr`]).

use std::io;
use std::net::SocketAddr;

use ct_common::channel::ChannelJoinRequest;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use quinn::{Connection, Endpoint};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::channel::{
    present_channel_join_marked, present_channel_join_on_stream, present_channel_relay_join_on_stream,
    ChannelJoinOutcome, ADMISSION_EXCHANGE_TIMEOUT, PHASE_MARKER_RELAY, PHASE_MARKER_RENDEZVOUS,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Hands-off A2A join with automatic **direct-then-relay** recovery (#72 AF4 /
/// AF4-session-resilience): present `request` to the edge broker over `broker_conn`,
/// learn the peer endpoint + Noise key the rendezvous relays, then try the **direct**
/// path and, if it can't connect, transparently fall back to the edge **relay**
/// (`relay_conn`) — so a blocked direct path (NAT/firewall) recovers with no caller
/// intervention. `role` (from the grant `Direction`) selects the side: an `Initiate`
/// peer dials `peer_endpoint` (bounded by `dial_timeout`; `Unreachable` → relay); an
/// `Accept` peer waits on its `listener` (bounded by `accept_timeout`; timeout →
/// relay, since the initiator that can't reach it directly went to the relay too). The
/// relay carries ciphertext only — the Noise_IK session stays end-to-end either way.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_join<P>(
    broker_conn: &Connection,
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    dial_timeout: std::time::Duration,
    accept_timeout: std::time::Duration,
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // Admit over the single pre-dialed QUIC broker connection, then run the
    // outcome-driven data path. The plane CLI instead admits over the broker *ladder*
    // (direct QUIC → the `:443` front door) and calls [`run_channel_join_with_admission`]
    // directly — same data path, but the broker leg reachable when the ports are blocked.
    // CADS-Tunnel#495 U2 (a'): broker_conn is admission-only -- the actual session runs
    // over the separately-passed relay_conn/direct connection below -- PHASE_MARKER_RENDEZVOUS.
    let admission = present_channel_join_marked(broker_conn, request, holder, PHASE_MARKER_RENDEZVOUS).await?;
    run_channel_join_with_admission(
        admission,
        RelayFallback::Quic(relay_conn),
        request,
        holder,
        role,
        own_noise_private,
        listener,
        dial_timeout,
        accept_timeout,
        local,
        false, // #104: this entry point predates the option and stays opt-out by default
        false, // ct-agent#22 (b): same -- the accept-vs-relay race is opt-in (CT_CHANNEL_ACCEPT_RACE)
    )
    .await
}

/// The **outcome-driven** core of [`run_channel_join`] (#106 client-dial-wire): given the
/// broker's already-computed `admission` — obtained over a direct QUIC broker connection
/// *or* the broker fallback ladder (direct QUIC → the `:443` TLS-TCP front door) — verify
/// the peer's attested Noise key (#101) and run the same **direct-then-relay** data path.
/// Decoupling admission (how we *reach* the broker) from the data path (how the two
/// members *connect*) is what lets a restrictive network admit over `:443` while the
/// direct/relay data legs stay unchanged. `role`, `listener`, and the timeouts behave
/// exactly as in [`run_channel_join`]. `relay` selects the relay-leg transport used on
/// direct-dial failure: [`RelayFallback::Quic`] (a pre-dialed QUIC relay connection) or —
/// for a member whose relay port is also blocked — [`RelayFallback::Ladder`], which walks
/// the relay ladder (direct QUIC → the `:443` front door) via [`join_via_relay_ladder`].
/// `accept_race` (ct-agent#22 (b), opt-in) makes an `Accept` member with a bound listener
/// race its accept window against the relay leg (`race_accept_against_relay`) instead of
/// serialising the two; off, the accept-then-relay order is byte-for-byte unchanged.
#[allow(clippy::too_many_arguments)]
pub async fn run_channel_join_with_admission<P>(
    admission: ChannelJoinOutcome,
    relay: RelayFallback<'_>,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    listener: Option<Endpoint>,
    dial_timeout: std::time::Duration,
    accept_timeout: std::time::Duration,
    local: P,
    // #104, opt-in via CT_CHANNEL_DIRECT_UPGRADE (default false -> unchanged behavior):
    // whether to attempt the in-band relay->direct upgrade if/when this session ends up
    // on the relay leg.
    direct_upgrade: bool,
    // ct-agent#22 (b), opt-in via CT_CHANNEL_ACCEPT_RACE (default false -> unchanged
    // behavior): whether an Accept member with a bound listener RACES its accept window
    // against the relay leg ([`race_accept_against_relay`]) instead of waiting the full
    // `accept_timeout` before it even dials the relay.
    accept_race: bool,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    let (peer_endpoint, peer_noise, observed_reflexive, peer_holder) = match admission {
        ChannelJoinOutcome::Admitted { peer_endpoint, peer_noise_pubkey, peer_holder, peer_attestation, observed_reflexive } => {
            let noise = peer_noise_pubkey
                .ok_or("broker admitted the join but relayed no peer Noise key (registry has none)")?;
            // #101 SEC101c-ii: verify the peer's Noise key is attested by its
            // grant-authenticated holder before pinning it — so even a tampered DB
            // can't make us pin a substituted key (the attestation wouldn't verify).
            let peer_holder = peer_holder
                .ok_or("broker relayed a Noise key without the peer holder — cannot verify (#101)")?;
            let attestation = peer_attestation
                .ok_or("broker relayed a Noise key without an attestation (#101)")?;
            if !ct_common::channel::verify_member_noise_attestation(
                &request.grant.grant.channel,
                &peer_holder,
                &noise,
                &attestation,
            ) {
                return Err("peer Noise-key attestation failed — refusing to pin a possibly-substituted key (#101)".into());
            }
            (peer_endpoint, noise, observed_reflexive, peer_holder)
        }
        ChannelJoinOutcome::Refused { category } => {
            // #524: the frozen base string stays the prefix; the category (when the
            // edge sent one) appends the actionable class of failure.
            return Err(AdmissionRefused::boxed_with_category(
                "edge broker refused the channel join",
                category.as_deref(),
            ));
        }
        // #21: unreachable in practice (admit_one_peer converts a ParkExpired before spawning a
        // session), kept as the typed error so a future caller can never misread it as refused.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("channel park expired with no partner within the edge park window (#21) -- re-parking"))
        }
    };
    // The attestation binds the Noise key to `peer_holder` only; the peer's operator-signed grant
    // binds `peer_holder` to this channel (checked inside the session when enabled).
    let local = gate_local(local, request, role, peer_holder, holder)?;
    // #104: built once, moved into whichever single relay-fallback call site below
    // actually fires (they're mutually exclusive). `None` whenever direct_upgrade is off
    // (the default) or the edge reported no reflexive address for this admission.
    // #296: `r=` only decides whether to take part; the offered address is asked through the
    // shared listener socket later, where CT_CHANNEL_REFLEXIVE_EDGE says (as on the relay-gate path).
    let upgrade = if direct_upgrade {
        build_upgrade_candidate(observed_reflexive, std::env::var("CT_CHANNEL_REFLEXIVE_EDGE").ok())
    } else {
        None
    };
    match role {
        // #121: the paired peer advertised the relay-only sentinel — it has no dialable
        // address, so skip the wasted direct dial + timeout and go straight to the relay.
        ChannelRole::Initiate if peer_endpoint == ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY => {
            eprintln!("ct-agent channel: peer is relay-only (no dialable address) — using the edge relay (#121)");
            join_via_relay_fallback(relay, request, holder, ChannelRole::Initiate, own_noise_private, &peer_noise, local, upgrade).await?;
        }
        ChannelRole::Initiate => {
            let addr = peer_endpoint
                .parse()
                .map_err(|_| format!("broker returned an unparseable peer endpoint: {peer_endpoint:?}"))?;
            let dial_started = std::time::Instant::now();
            match dial_peer_direct(addr, dial_timeout).await {
                Ok(conn) => {
                    if debug_timing_enabled() {
                        eprintln!("ct-agent channel: debug direct dial to {addr} connected in {}ms", dial_started.elapsed().as_millis());
                    }
                    run_channel_session(&conn, ChannelRole::Initiate, own_noise_private, &peer_noise, local).await?;
                }
                Err(ChannelDialError::Unreachable) => {
                    eprintln!(
                        "ct-agent channel: direct dial to {addr} unreachable after {}ms — falling back to the edge relay (#72)",
                        dial_started.elapsed().as_millis()
                    );
                    join_via_relay_fallback(relay, request, holder, ChannelRole::Initiate, own_noise_private, &peer_noise, local, upgrade).await?;
                }
                Err(ChannelDialError::Failed(e) | ChannelDialError::ConnectFailed(e)) => return Err(e),
            }
        }
        ChannelRole::Accept => match listener {
            // #121: a relay-only acceptor has no bound listener — it can't be dialed, so it
            // relays directly instead of waiting for a direct connection that can never come.
            None => {
                eprintln!("ct-agent channel: relay-only acceptor (no listener) — using the edge relay (#121)");
                join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local, upgrade).await?;
            }
            Some(ep) => {
                // ct-agent#22: do not spend the accept window on a connection that cannot
                // arrive. The edge just told this member which address it is seen on; if
                // that contradicts what it advertises, inbound is not going to happen and
                // the 8 s is pure latency on every single first contact.
                if !own_endpoint_looks_reachable(&request.endpoint, observed_reflexive) {
                    eprintln!(
                        "ct-agent channel: advertised {} but the edge observes this member on {} \
                         -- inbound cannot reach the advertised address, going straight to the \
                         edge relay instead of waiting {accept_timeout:?} (#22). Set \
                         CT_CHANNEL_RELAY_ONLY=1 to make this explicit.",
                        request.endpoint,
                        observed_reflexive.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                    );
                    join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local, upgrade).await?;
                    return Ok(());
                }
                // ct-agent#22 (b): race the accept window against the relay leg instead of
                // serialising them -- the 8 s vanish from the critical path for EVERY
                // acceptor, not just a misconfigured one (part (a) above). Opt-in for now:
                // the edge must detect an abandoned park on both transports before this can
                // be the default (issue Befund 2, Vorschlag B).
                // TODO(#22): auto-enable on the ack's cl=1 tag
                if accept_race {
                    race_accept_against_relay(
                        ep,
                        accept_timeout,
                        relay,
                        request,
                        holder,
                        own_noise_private,
                        &peer_noise,
                        local,
                        upgrade,
                    )
                    .await?;
                    return Ok(());
                }
                let accept_started = std::time::Instant::now();
                match tokio::time::timeout(accept_timeout, ep.accept()).await {
                    Ok(Some(incoming)) => {
                        let conn = incoming.await?;
                        if debug_timing_enabled() {
                            eprintln!("ct-agent channel: debug direct accept connected in {}ms", accept_started.elapsed().as_millis());
                        }
                        run_channel_session(&conn, ChannelRole::Accept, own_noise_private, &peer_noise, local).await?;
                    }
                    Ok(None) => return Err("channel listener closed with no incoming".into()),
                    Err(_timeout) => {
                        eprintln!("ct-agent channel: no direct connection within {accept_timeout:?} — falling back to the edge relay (#72)");
                        join_via_relay_fallback(relay, request, holder, ChannelRole::Accept, own_noise_private, &peer_noise, local, upgrade).await?;
                    }
                }
            }
        },
    }
    Ok(())
}

/// Agent-side relay fallback (#72 AF4-session-resilience): when the direct dial to a
/// paired peer is [`ChannelDialError::Unreachable`], the agent reconnects to the edge
/// **relay** endpoint (`ct_edge::channel_broker::broker_channel_relay`), presents its
/// grant (proving possession), and runs the Noise_IK session over the stream the edge
/// splices to the peer. Both members call this; the edge pairs + splices them while
/// preserving the direct-path stream roles, so this simply presents the join and then
/// reuses [`run_channel_session`] over the edge connection. Noise stays end-to-end —
/// the edge only forwards ciphertext.
///
/// `upgrade`, when `Some(..)` (#104, opt-in via
/// `CT_CHANNEL_DIRECT_UPGRADE`), runs [`run_channel_session_upgradable`] instead of the
/// plain session: the two peers negotiate a direct-dial candidate **in-band, over this
/// same already-admitted, already-Noise-authenticated relay stream** and opportunistically
/// upgrade to it, falling back to the relay transparently on failure. `None` (the default)
/// is byte-for-byte the pre-existing behavior.
// pre-existing signature; refactor tracked separately
#[allow(clippy::too_many_arguments)]
pub async fn join_via_relay<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
    local: P,
    upgrade: Option<DirectUpgrade>,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // ct-agent#22 (b): present-and-park (phase 1, `park_relay_leg`) and the Noise session
    // (phase 2, `ParkedRelayLeg::run_session`) are the one shared implementation in
    // `connectivity.rs`; this is the serial composition of the two. The typed
    // Refused/ParkExpired errors and the PHASE_MARKER_RELAY preamble are unchanged.
    join_via_relay_fallback(
        RelayFallback::Quic(relay_conn),
        request,
        holder,
        role,
        own_noise_private,
        peer_noise_public,
        local,
        upgrade,
    )
    .await
}

/// **#136 N-wire — DCUtR-upgradable relay join for a NAT-to-NAT (relay-only) member.** Like
/// [`join_via_relay`], but instead of running a plain edge-relay session it runs the
/// **upgradable DCUtR** session ([`crate::p2p::run_channel_session_upgradable_dcutr`]): the byte
/// stream starts on the edge relay (both members are NAT'd, so neither can be dialed directly),
/// and in the background the pair opportunistically hole-punches to a **direct** link via the
/// configured libp2p Circuit-Relay v2 `circuit_relay` and cuts the stream over — offloading the
/// edge. Hole-punch failure stays on the relay; the relay leg is end-to-end throughout. The
/// peer's Noise key is learned from the relayed admission (no out-of-band exchange). The actual
/// cross-NAT punch is proven in the Docker 2-NAT lab (N-rig-2); on loopback it degrades to the
/// relay. **Not on the live plane** — the "/ the live plane (N-rig-3)" this line used to carry
/// is the same overclaim corrected at [`run_channel_session_upgradable`] and
/// [`crate::p2p::run_upgradable_dcutr_session`]: ct-agent#6 (open) measures every real cross-NAT
/// direct dial failing. The lab half of the sentence is accurate and stays.
/// ct-agent#41 (#35 "Path A"): verify a relay-admitted DCUtR peer's Noise key is attested by
/// its grant-authenticated holder before pinning it -- the same check
/// `run_channel_join_with_admission` already does for the main path (mod.rs, #101 SEC101c-ii).
/// Shared by [`join_via_relay_dcutr`] and [`join_via_relay_gate_dcutr`], the two joins that do
/// their OWN [`present_channel_join`] call rather than going through
/// `run_channel_join_with_admission`, so neither had this check at all before.
///
/// Without it, a malicious/compromised edge could substitute its own key in the admission
/// response; the DCUtR "verified" responder downstream (`p2p.rs`, ct-agent#11) only checks the
/// LIVE peer against whatever key this function hands it, so a consistent substitution at both
/// points would defeat that check too. Only the independently-signed attestation (which the
/// edge cannot forge) closes it. Pure (no I/O), so unit-testable without a live relay.
/// `local` behind the peer-grant check when [`REQUIRE_PEER_GRANT_ENV`] is on (see `peer_grant`),
/// a pass-through otherwise. `peer_holder` is the holder admission attested the pinned Noise key
/// with. Fails when the check is on but cannot run (no operator key configured).
///
/// A TCP forward session (`CT_CHANNEL_FORWARD` / `CT_CHANNEL_FORWARD_ALLOW`) always runs the check,
/// and its accept side also re-checks the peer's grant against the control plane every
/// `CT_CHANNEL_GRANT_RECHECK_SECS`, because only that can end a forward after the grant was
/// revoked once the edge is out of the data path. The control plane is `CT_AGENT_CP_URL` (the agent
/// has no other source for it). Without it the forward starts as before, with a warning that the
/// re-check is disabled; `CT_CHANNEL_REVOCATION=require` makes that an error instead.
pub(crate) fn gate_local<P>(
    local: P,
    request: &ChannelJoinRequest,
    role: ChannelRole,
    peer_holder: [u8; 32],
    holder: &SigningKey,
) -> Result<PeerGrantGate<P>, BoxError> {
    let forward = forward_session_configured();
    let watch = if forward && role == ChannelRole::Accept {
        let cp_url = std::env::var("CT_AGENT_CP_URL").ok().filter(|s| !s.trim().is_empty());
        let required = revocation_required(std::env::var(REVOCATION_ENV).ok().as_deref())?;
        match resolve_cp(cp_url, required)? {
            Some(cp_url) => {
                let config = grant_watch::WatchConfig::from_env()?.requiring(required);
                Some(grant_watch::WatchPlan::control_plane(&cp_url, holder, &request.grant, config))
            }
            None => {
                eprintln!(
                    "ct-agent channel: WARNING: revocation re-check disabled: no control-plane URL \
                     (set CT_AGENT_CP_URL); a revoked grant will not end this forward session"
                );
                None
            }
        }
    } else {
        None
    };
    let check = PeerGrantPolicy::from_env_for(forward)?.map(|policy| PeerGrantCheck {
        policy,
        own_grant: request.grant.clone(),
        peer_holder,
        role,
        watch,
    });
    Ok(PeerGrantGate::new(local, check))
}

/// `CT_CHANNEL_REVOCATION=require` turns "no control-plane URL for the forward's grant re-check"
/// from a warning into a refusal to join. Unset or `warn` is the default.
pub(crate) const REVOCATION_ENV: &str = "CT_CHANNEL_REVOCATION";

/// The control plane the re-check asks: the configured URL, or none (warn) / an error (require).
pub(crate) fn resolve_cp(cp_url: Option<String>, required: bool) -> Result<Option<String>, String> {
    match (cp_url, required) {
        (Some(u), _) => check_cp_url(&u).map(|()| Some(u)),
        (None, true) => Err(format!(
            "{REVOCATION_ENV}=require but no control-plane URL (CT_AGENT_CP_URL) is set: \
             a revoked grant could not end this forward -- refusing to join"
        )),
        (None, false) => Ok(None),
    }
}

/// The re-check sends a signed question to this URL and believes the answer, so it has to be
/// https; plain http is accepted only to a loopback host (a local control plane, a test).
pub(crate) fn check_cp_url(url: &str) -> Result<(), String> {
    let bad = |why: &str| format!("CT_AGENT_CP_URL {url:?} {why} (the grant re-check needs https, or http to a loopback host)");
    let parsed = reqwest::Url::parse(url.trim()).map_err(|_| bad("is not a URL"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or("").trim_matches(['[', ']']);
            let loopback = host.eq_ignore_ascii_case("localhost")
                || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
            if loopback { Ok(()) } else { Err(bad("is plain http to a non-loopback host")) }
        }
        _ => Err(bad("is not an http(s) URL")),
    }
}

pub(crate) fn revocation_required(v: Option<&str>) -> Result<bool, String> {
    match v.map(str::trim) {
        None | Some("") | Some("warn") => Ok(false),
        Some("require") => Ok(true),
        Some(o) => Err(format!("{REVOCATION_ENV}={o:?} is not understood (use `require` or `warn`)")),
    }
}

/// Startup check of the revocation switch, run before any network is set up: an unknown
/// `CT_CHANNEL_REVOCATION` value, or `require` on the accept side of a forward without
/// `CT_AGENT_CP_URL`, a control-plane URL that is not https (or loopback), or a malformed
/// `CT_CHANNEL_GRANT_RECHECK_*` value fails the process start instead of the first join.
/// [`gate_local`] keeps its own check for the paths that do not start here.
pub fn check_revocation_config() -> Result<(), String> {
    check_revocation_config_from(
        forward_session_configured(),
        std::env::var("CT_CHANNEL_ROLE").ok().as_deref(),
        std::env::var("CT_AGENT_CP_URL").ok().as_deref(),
        std::env::var(REVOCATION_ENV).ok().as_deref(),
        &|k: &str| std::env::var(k).ok(),
    )
}

pub(crate) fn check_revocation_config_from(
    forward: bool,
    role: Option<&str>,
    cp_url: Option<&str>,
    mode: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<(), String> {
    let required = revocation_required(mode)?;
    let accept = matches!(
        role.map(|r| r.trim().to_ascii_lowercase()).as_deref(),
        Some("accept" | "responder" | "listen")
    );
    if forward && accept {
        let cp = cp_url.map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        resolve_cp(cp, required)?;
        grant_watch::WatchConfig::from_lookup(env)?;
    }
    Ok(())
}

/// Whether this process runs a TCP forward session, on either side.
fn forward_session_configured() -> bool {
    std::env::var(forward_stream::FORWARD_ENV).is_ok() || forward::forward_allow_configured()
}

/// The peer's attested Noise key and the holder that attested it.
pub(crate) fn verify_relayed_dcutr_peer(
    request: &ChannelJoinRequest,
    noise: [u8; 32],
    peer_holder: Option<[u8; 32]>,
    peer_attestation: Option<[u8; 64]>,
) -> Result<([u8; 32], [u8; 32]), BoxError> {
    let peer_holder =
        peer_holder.ok_or("relay admitted the DCUtR join but relayed no peer holder -- cannot verify (#101)")?;
    let attestation =
        peer_attestation.ok_or("relay admitted the DCUtR join but relayed no attestation (#101)")?;
    if !ct_common::channel::verify_member_noise_attestation(
        &request.grant.grant.channel,
        &peer_holder,
        &noise,
        &attestation,
    ) {
        return Err("peer Noise-key attestation failed -- refusing to pin a possibly-substituted key (#101)".into());
    }
    Ok((noise, peer_holder))
}

pub async fn join_via_relay_dcutr<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    local: P,
    circuit_relay: libp2p::Multiaddr,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // CADS-Tunnel#495 U2 (a'): relay_conn's own bi-stream carries the DCUtR base leg
    // below -- PHASE_MARKER_RELAY.
    let (peer_noise, peer_holder) = match present_channel_join_marked(relay_conn, request, holder, PHASE_MARKER_RELAY).await? {
        ChannelJoinOutcome::Admitted { peer_noise_pubkey: Some(noise), peer_holder, peer_attestation, .. } => {
            verify_relayed_dcutr_peer(request, noise, peer_holder, peer_attestation)?
        }
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("DCUtR relay join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused { category } => {
            // #524: base string frozen, category appended when present.
            return Err(AdmissionRefused::boxed_with_category(
                "edge relay refused the channel join",
                category.as_deref(),
            ));
        }
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    };
    let local = gate_local(local, request, role, peer_holder, holder)?;
    // The DCUtR session runs the Noise_IK over the relay bi-stream as its base leg, punching to
    // direct in the background. Initiator opens the bi-stream; acceptor accepts the edge-opened one.
    let (relay_send, relay_recv) = open_relay_channel_streams(relay_conn, role).await?;
    let client = crate::p2p::build_dcutr_relay_client_swarm()?;
    crate::p2p::run_channel_session_upgradable_dcutr(
        relay_send,
        relay_recv,
        local,
        role,
        own_noise_private,
        &peer_noise,
        client,
        circuit_relay,
    )
    .await
}

/// #296: the start-up line of a relay-only member whose DCUtR knob (`CT_CHANNEL_RELAY_GATE` or
/// `CT_CHANNEL_CIRCUIT_RELAY`) is set without `CT_CHANNEL_EXPERIMENTAL_DCUTR`. It also says what
/// switching it on brings back: this release fixes the candidate socket only for the
/// `CT_CHANNEL_DIRECT_UPGRADE` path, the DCUtR swarm is still seeded from a throwaway socket.
pub(crate) const DCUTR_FENCED_NOTICE: &str = "ct-agent channel: the libp2p DCUtR upgrade is experimental and OFF \
     (#296): an upgraded session opens its stream on the relayed libp2p connection, which the \
     relay-node cuts at 2 min / 128 KiB. This member joins on the same relay port as before and \
     keeps every session on the edge relay; set CT_CHANNEL_EXPERIMENTAL_DCUTR=1 to try the upgrade \
     -- its punch candidate is still learned on a throwaway socket (#296, not fixed on this path), \
     so expect the hole punch itself to time out.";

/// #296: what a relay-only member's DCUtR knob decides -- which join loop runs (the relay-gate one
/// wins over the circuit-relay one) and whether that loop runs the libp2p upgrade (`upgrade`,
/// `CT_CHANNEL_EXPERIMENTAL_DCUTR`) or the same relay-port join without it
/// ([`join_via_relay_without_dcutr`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DcutrKnob {
    /// `CT_CHANNEL_RELAY_GATE` set.
    RelayGate { upgrade: bool },
    /// `CT_CHANNEL_CIRCUIT_RELAY` set (and no relay-gate).
    CircuitRelay { upgrade: bool },
}

impl DcutrKnob {
    /// Whether the libp2p DCUtR upgrade runs.
    pub(crate) fn upgrade(self) -> bool {
        match self {
            Self::RelayGate { upgrade } | Self::CircuitRelay { upgrade } => upgrade,
        }
    }
}

/// #296: the fence as one pure decision, so the table is tested rather than only the two joins it
/// chooses between. `None`: not relay-only, or neither knob set -- the member takes the broker
/// path of [`run_channel_join_command`].
pub(crate) fn dcutr_knob(relay_only: bool, relay_gate: bool, circuit_relay: bool, experimental_dcutr: bool) -> Option<DcutrKnob> {
    if !relay_only {
        return None;
    }
    let upgrade = experimental_dcutr;
    if relay_gate {
        Some(DcutrKnob::RelayGate { upgrade })
    } else if circuit_relay {
        Some(DcutrKnob::CircuitRelay { upgrade })
    } else {
        None
    }
}

/// #296 (finding D3): the relay-only join of a member with `CT_CHANNEL_RELAY_GATE` or
/// `CT_CHANNEL_CIRCUIT_RELAY` set but without `CT_CHANNEL_EXPERIMENTAL_DCUTR`. Admission is the one
/// [`join_via_relay_gate_dcutr`] / [`join_via_relay_dcutr`] run -- the join goes to `relay_conn`,
/// the relay port, so the member parks in the same edge pairer as before and still meets a peer
/// that keeps the experimental path on -- and the session uses the in-band upgrade framing those
/// peers speak (every pump frame is tagged; a plain session would garble it). It just never
/// offers and declines every offer, so the bytes stay on the edge relay.
///
/// Why fence it: an accepted DCUtR "upgrade" opens the channel stream as soon as the RELAYED
/// libp2p connection exists (libp2p-stream picks a random existing connection, and that is the
/// only one), so the session moves onto the relay-node's circuit, whose default limits (2 min,
/// 128 KiB) then end it mid-transfer. Since the v0.4.20 pin (CADS-Tunnel#480) a responder of
/// this release already refuses the circuit-address offer -- it does not parse as one socket
/// address -- so between two current members the upgrade never happened anyway; the switch makes
/// that explicit, spares the initiator its relay-gate dial, swarm and reservation, and keeps an
/// older responder from accepting the offer.
pub async fn join_via_relay_without_dcutr<P>(
    relay_conn: &Connection,
    request: &ChannelJoinRequest,
    holder: &SigningKey,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    local: P,
) -> Result<(), BoxError>
where
    P: AsyncRead + AsyncWrite + Unpin,
{
    // CADS-Tunnel#495 U2 (a'): relay_conn's own bi-stream carries the session -- PHASE_MARKER_RELAY,
    // as on both DCUtR joins.
    let (peer_noise, peer_holder) = match present_channel_join_marked(relay_conn, request, holder, PHASE_MARKER_RELAY).await? {
        ChannelJoinOutcome::Admitted { peer_noise_pubkey: Some(noise), peer_holder, peer_attestation, .. } => {
            verify_relayed_dcutr_peer(request, noise, peer_holder, peer_attestation)?
        }
        ChannelJoinOutcome::Admitted { .. } => {
            return Err("relay-only join needs the peer's relayed Noise key (register the member's key, #101)".into())
        }
        ChannelJoinOutcome::Refused { category } => {
            // #524: base string frozen, category appended when present.
            return Err(AdmissionRefused::boxed_with_category(
                "edge relay refused the channel join",
                category.as_deref(),
            ));
        }
        // #21: the relay park was reaped before a partner arrived -- retryable, not a refusal.
        ChannelJoinOutcome::ParkExpired => {
            return Err(ParkExpired::boxed("edge relay park expired with no partner within the park window (#21) -- re-park the relay leg"))
        }
    };
    let local = gate_local(local, request, role, peer_holder, holder)?;
    let (relay_send, relay_recv) = open_relay_channel_streams(relay_conn, role).await?;
    run_relay_session_declining_upgrades(relay_send, relay_recv, local, role, own_noise_private, &peer_noise).await
}

/// #296: the in-band upgradable relay session ([`ct_common::upgrade`]) with no upgrade in it:
/// the initiator never offers, the responder answers every Offer with `Abort`. A DCUtR peer on
/// the other end sees the framing it expects and stays on the relay with us.
pub(crate) async fn run_relay_session_declining_upgrades<RW, RR, P>(
    relay_send: RW,
    relay_recv: RR,
    local: P,
    role: ChannelRole,
    own_noise_private: &[u8; 32],
    peer_noise_public: &[u8; 32],
) -> Result<(), BoxError>
where
    RW: AsyncWrite + Unpin,
    RR: AsyncRead + Unpin,
    P: AsyncRead + AsyncWrite + Unpin,
{
    use ct_common::upgrade::{
        run_upgradable_session_initiator, run_upgradable_session_responder_verified, Role, UpgradeCoordinator,
    };
    // What an upgrade would hand to the pump; never built here, named only to fix the types.
    type NoDirect = Option<(snow::TransportState, tokio::io::DuplexStream, tokio::io::DuplexStream)>;
    match role {
        ChannelRole::Initiate => run_upgradable_session_initiator(
            relay_send,
            relay_recv,
            local,
            own_noise_private,
            peer_noise_public,
            UpgradeCoordinator::with_backoff(Role::Initiator, 0, 1, 100),
            1,
            || async { None::<String> },
            || async { NoDirect::None },
        )
        .await
        .map_err(Into::into),
        ChannelRole::Accept => run_upgradable_session_responder_verified(
            relay_send,
            relay_recv,
            local,
            own_noise_private,
            peer_noise_public,
            UpgradeCoordinator::with_backoff(Role::Responder, 0, 1, 100),
            1,
            |offered: String| async move {
                eprintln!(
                    "ct-agent channel: peer offered a direct upgrade to {offered} -- declined, the session \
                     stays on the edge relay (CT_CHANNEL_EXPERIMENTAL_DCUTR is off, #296)"
                );
                false
            },
            |_offered: String, _peer: [u8; 32]| async { NoDirect::None },
        )
        .await
        .map_err(Into::into),
    }
}

/// Dial the edge's `:443` **relay-gate** leg (`CT_EDGE_RELAY_GATE`) for a real NAT-to-NAT
/// hole-punch, multiplexed onto the same front door every other `:443` leg uses — no new
/// public port. TLS-connects with ALPN `ct-edge-relay`
/// ([`crate::transport::tcp_tls_connect_with_alpn`]), then runs the pre-auth wire protocol
/// `crates/edge/src/relay_gate.rs` on the edge side implements: present `grant` (the fixed-size
/// [`ct_common::channel::SignedChannelGrant`] wire form, no framing needed), sign the edge's
/// fresh 32-byte challenge with `holder`, and on `OK` read the trailing `u16-BE len + utf8`
/// relay-node `PeerId` the edge's ack carries (needed because this connection never reaches the
/// relay-node directly — see `relay_gate.rs`'s own doc comment for why). Returns the
/// still-open, now-pre-authed TLS stream plus that `PeerId`, ready for
/// [`crate::p2p::build_relay_gate_client`].
pub async fn dial_relay_gate_over_443(
    addr: SocketAddr,
    edge_cert: CertificateDer<'static>,
    grant: &ct_common::channel::SignedChannelGrant,
    holder: &SigningKey,
) -> Result<(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, libp2p::PeerId), BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // #248: per-step timing under CT_DEBUG_A2A_TIMING -- this function's own errors (from
    // run_channel_join_command's retry wrapper) were all indistinguishable generic messages
    // ("Connection refused", "early eof") with no way to tell which of these six sequential
    // steps actually failed. Live-reproduced needing exactly this while debugging bob1/bob2's
    // real hole-punch failures.
    let dbg = debug_timing_enabled();
    let t0 = std::time::Instant::now();
    let mut stream = crate::transport::tcp_tls_connect_relay(addr, edge_cert).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate tcp+tls connect to {addr} failed after {:?}: {e}", t0.elapsed()); } e })?;
    if dbg { eprintln!("ct-agent channel: debug relay-gate tcp+tls connect to {addr} ok in {:?}", t0.elapsed()); }
    let t1 = std::time::Instant::now();
    stream.write_all(&grant.encode()).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate write grant failed after {:?}: {e}", t1.elapsed()); } e })?;
    let mut challenge = [0u8; 32];
    stream.read_exact(&mut challenge).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read challenge failed after {:?}: {e}", t1.elapsed()); } e })?;
    if dbg { eprintln!("ct-agent channel: debug relay-gate grant+challenge round-trip ok in {:?}", t1.elapsed()); }
    let sig = holder.sign(&challenge).to_bytes();
    stream.write_all(&sig).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate write possession sig failed: {e}"); } e })?;
    let mut ack = [0u8; 2];
    let t2 = std::time::Instant::now();
    stream.read_exact(&mut ack).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read ack failed after {:?}: {e}", t2.elapsed()); } e })?;
    if &ack != b"OK" {
        if dbg { eprintln!("ct-agent channel: debug relay-gate pre-auth refused, ack={ack:?}"); }
        // #524: on a refusal the edge follows the `NO` sentinel with a length-framed
        // category token and shuts the stream down — opportunistically read it (bounded;
        // an old edge yields EOF at once → None → the generic message below, unchanged).
        let category = if &ack == b"NO" {
            let mut tail = Vec::new();
            let mut bounded = (&mut stream).take(crate::channel::REFUSAL_CATEGORY_MAX_LEN as u64 + 1);
            match tokio::time::timeout(std::time::Duration::from_secs(2), bounded.read_to_end(&mut tail)).await {
                Ok(Ok(_)) => crate::channel::decode_refusal_category(&tail),
                _ => None,
            }
        } else {
            None
        };
        // #24: typed -- this is the relay-gate's wire `NO`, a DEFINITIVE refusal the
        // retry policy must back off on (it was a bare string before, invisible to
        // `is_definitive_admission_refusal`, so the serve loop hot-looped on it).
        return Err(AdmissionRefused::boxed_with_category(
            "relay-gate: pre-auth refused (grant not authorized -- see the edge's own log)",
            category.as_deref(),
        ));
    }
    if dbg { eprintln!("ct-agent channel: debug relay-gate pre-auth ok (ack=OK) in {:?} total", t0.elapsed()); }
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read peer-id length failed: {e}"); } e })?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut peer_buf = vec![0u8; len];
    stream.read_exact(&mut peer_buf).await
        .map_err(|e| { if dbg { eprintln!("ct-agent channel: debug relay-gate read peer-id bytes ({len}B) failed: {e}"); } e })?;
    let peer_str = String::from_utf8(peer_buf)
        .map_err(|e| -> BoxError { format!("relay-gate: relay-node peer id not utf8: {e}").into() })?;
    let relay_peer: libp2p::PeerId = peer_str
        .parse()
        .map_err(|e| -> BoxError { format!("relay-gate: malformed relay-node peer id {peer_str:?}: {e}").into() })?;
    if dbg { eprintln!("ct-agent channel: debug relay-gate handshake complete, relay-node peer={relay_peer} in {:?} total", t0.elapsed()); }
    Ok((stream, relay_peer))
}

/// Run the plane-brokered `ct-agent channel` flow (#98 / #103): connect to the edge
/// rendezvous + relay, present the grant, and pipe **stdin/stdout** over the A2A tunnel
/// with automatic direct-then-relay recovery via [`run_channel_join`]. The broker
/// relays the peer's Noise key, so no `CT_CHANNEL_PEER_*` is needed.
pub async fn run_channel_join_command(cfg: ChannelJoinCliConfig) -> Result<(), BoxError> {
    // Capture what the broker/relay ladders need before `cfg.grant` is moved into
    // `request` (a partial move would forbid the `cfg.broker_ladder()` `&self` call).
    // CT_CHANNEL_FRONT_DOOR_SNI: install before any front-door dial (None = unchanged).
    crate::transport::set_front_door_sni(cfg.front_door_sni.clone());
    let broker_ladder = cfg.broker_ladder();
    let relay_ladder = cfg.relay_ladder();
    let front_door_cert = cfg.front_door_cert.clone();
    // #121: a relay-only member advertises the sentinel instead of a dialable address — it
    // can't be reached directly, so it participates purely via the relay + `:443` fallback.
    let request = ChannelJoinRequest {
        // #179: clone (not move) the grant so `cfg` stays whole for the multi-session serve loop
        // below, which re-runs admission for each successive peer.
        grant: cfg.grant.clone(),
        endpoint: if cfg.relay_only {
            ct_common::channel::CHANNEL_ENDPOINT_RELAY_ONLY.to_string()
        } else {
            cfg.advertise_addr.to_string()
        },
    };
    // #136 N-wire: a relay-only (NAT-to-NAT) member with a libp2p circuit relay configured runs
    // the DCUtR-upgradable relay join — start on the edge relay, then opportunistically hole-punch
    // to a direct link via the circuit relay. Both members are NAT'd, so this is the only path that
    // can ever go direct; without a circuit relay it falls through to the plain relay session below.
    //
    // #248-follow: a long-lived `Accept`+`--serve` member on this path must retry a transient
    // stall exactly like the plain broker path a few lines below already does (see that path's
    // own comment for the #179 lesson this mirrors) -- NOT propagate the error out of this
    // function and take the whole process down. Live-reproduced: this path's first-ever real
    // cross-NAT test hit a transient "#140" stall (nothing DCUtR-specific -- the same admission
    // hiccup the plain path tolerates fine) and, before this fix, that killed an otherwise
    // perfectly healthy long-lived --serve process instead of just re-admitting. `Initiate`
    // (and `Accept` without `--serve`) stay single-attempt, matching every other one-shot path.
    let serve_loop = should_serve_loop(cfg.role, crate::envflag::env_value("CT_CHANNEL_SERVE", false).as_deref());
    // #248: a one-shot Initiate (or non-serve Accept) on the relay-gate/circuit-relay DCUtR
    // path shouldn't fail on the very first #140 stall either -- live-reproduced on the
    // a2a-demo's plain "bob" scenario (previously thought stable, now exercising this same
    // path): the persistent --serve side eventually gets past a stall by retrying forever,
    // while the one-shot side had zero tolerance and failed the whole call on one hiccup.
    // #296: the knob picks the join loop below ([`dcutr_knob`]); without
    // CT_CHANNEL_EXPERIMENTAL_DCUTR both loops keep their admission (relay port, same pairer,
    // same session framing) but skip the libp2p upgrade.
    if let Some(knob) =
        dcutr_knob(cfg.relay_only, cfg.relay_gate_addr.is_some(), cfg.circuit_relay.is_some(), cfg.experimental_dcutr)
    {
        let dcutr = knob.upgrade();
        if !dcutr {
            eprintln!("{DCUTR_FENCED_NOTICE}");
        }
        let upgrade_label = if dcutr { "DCUtR-upgradable" } else { "edge-relay (DCUtR off, #296)" };
        // The real gated relay-gate leg (no new public port, grant+possession pre-auth) takes
        // priority when configured — `circuit_relay` (a directly-dialable relay multiaddr) is
        // kept for the nat-lab test rig, not the deployed path.
        if let (DcutrKnob::RelayGate { .. }, Some(relay_gate_addr)) = (knob, cfg.relay_gate_addr) {
            let relay_gate_cert = cfg
                .relay_gate_cert
                .clone()
                .ok_or("CT_CHANNEL_RELAY_GATE set without CT_CHANNEL_RELAY_GATE_CERT")?;
            eprintln!(
                "ct-agent channel: relay-only {upgrade_label} {:?} via relay-gate (relay {}, gate {}){}",
                cfg.role, cfg.relay_addr, relay_gate_addr,
                if serve_loop { " — persistent serve: retries transient stalls (#248)" } else { "" }
            );
            let request = &request;
            let cfg = &cfg;
            let relay_gate_cert = &relay_gate_cert;
            return run_dcutr_join_loop("relay-gate", serve_loop, move || async move {
                let relay_conn =
                    dial_relay_preferring_direct(cfg.relay_addr_direct, cfg.relay_addr, DIRECT_DIAL_TIMEOUT).await?;
                // Admission via the relay gate happens below, after this call -- peer not yet known.
                let local = channel_local(None);
                if !dcutr {
                    return Ok(join_via_relay_without_dcutr(
                        &relay_conn,
                        request,
                        &cfg.holder,
                        cfg.role,
                        &cfg.own_noise_private,
                        local,
                    )
                    .await);
                }
                Ok(join_via_relay_gate_dcutr(
                    &relay_conn,
                    request,
                    &cfg.holder,
                    cfg.role,
                    &cfg.own_noise_private,
                    local,
                    relay_gate_addr,
                    relay_gate_cert.clone(),
                    &cfg.grant,
                )
                .await)
            })
            .await;
        }
        if let (DcutrKnob::CircuitRelay { .. }, Some(circuit)) = (knob, cfg.circuit_relay.clone()) {
            eprintln!(
                "ct-agent channel: relay-only {upgrade_label} {:?} (relay {}, circuit {}){}",
                cfg.role, cfg.relay_addr, circuit,
                if serve_loop { " — persistent serve: retries transient stalls (#248)" } else { "" }
            );
            let request = &request;
            let cfg = &cfg;
            let circuit = &circuit;
            // #24: the label is a parameter now -- this branch used to print
            // "relay-gate admission error" from its copied loop body.
            return run_dcutr_join_loop("circuit-relay", serve_loop, move || async move {
                let relay_conn = crate::transport::build_channel_dialer()?
                    .connect(cfg.relay_addr, "localhost")?
                    .await?;
                // Admission via the circuit relay happens below, after this call -- peer not yet known.
                let local = channel_local(None);
                if !dcutr {
                    return Ok(join_via_relay_without_dcutr(
                        &relay_conn,
                        request,
                        &cfg.holder,
                        cfg.role,
                        &cfg.own_noise_private,
                        local,
                    )
                    .await);
                }
                Ok(join_via_relay_dcutr(
                    &relay_conn,
                    request,
                    &cfg.holder,
                    cfg.role,
                    &cfg.own_noise_private,
                    local,
                    circuit.clone(),
                )
                .await)
            })
            .await;
        }
    }
    // Broker admission (the grant + possession proof are the auth; Noise_IK authenticates
    // the peer end-to-end). With a `:443` front-door cert configured, walk the broker
    // ladder — direct QUIC first, then the `:443` TLS-TCP front door — so a network that
    // blocks the channel port still reaches the broker (#106 client-dial-wire). Otherwise
    // the direct-QUIC broker join, unchanged. Borrow the cert so it survives for the relay
    // leg's ladder below.
    // #179: an accept-side SERVE member must stay parked across MANY sequential peer sessions —
    // admit one, serve it, loop back to admit the next — instead of exiting after the first. Exiting
    // forced every operator (central, sink, source-2, …) into an external restart loop whose ~0.2s
    // re-park gap dropped real user calls ("art role unreachable" on first try, ok on retry). A
    // transient per-session error (admission stall #140, peer drop) is logged and retried, not fatal;
    // one-shot roles (initiator / `--call` / non-serve) run exactly once, unchanged.
    // (`serve_loop` already computed above, ahead of the relay-gate/circuit-relay block, which
    // needs the same value.)
    eprintln!(
        "ct-agent channel: plane-brokered {:?} (relay {}){}",
        cfg.role,
        cfg.relay_addr,
        if serve_loop { " — persistent serve: concurrent sessions (#200)" } else { "" }
    );
    if !serve_loop {
        // ct-agent#47: a persistent --call-service session (the default under
        // CT_CHANNEL_CALL_PERSISTENT) gets its own internal redial loop unless the operator
        // opted out (CT_CHANNEL_CALL_RECONNECT=0) -- see run_persistent_call_reconnect_loop's
        // doc comment for why this can't just be another channel_local() branch (the #248
        // stdin-reuse trap). Every other one-shot role (initiator / `--call` / a non-serve
        // accept, and non-reconnect persistent CALL mode) keeps exactly one session, unchanged.
        if let Ok(slug) = std::env::var("CT_CHANNEL_CALL_SERVICE") {
            if cfg.call_reconnect
                && call_persistent_enabled_from(crate::envflag::env_value("CT_CHANNEL_CALL_PERSISTENT", true).as_deref())
            {
                return run_persistent_call_reconnect_loop(
                    slug.trim().to_string(),
                    &cfg,
                    &request,
                    &broker_ladder,
                    &relay_ladder,
                    &front_door_cert,
                )
                .await;
            }
        }
        // ct-agent#267: a forward must survive a peer restart or a relay
        // drop, so with CT_CHANNEL_FORWARD set (the same env-only selection `channel_local` makes)
        // the one session becomes a reconnecting session loop over one listener.
        if let Ok(raw) = std::env::var(forward_stream::FORWARD_ENV) {
            return run_forward_initiate_sessions(&raw, &cfg, &request, &broker_ladder, &relay_ladder, &front_door_cert)
                .await;
        }
        return run_one_admission_session(&cfg, &request, &broker_ladder, &relay_ladder, &front_door_cert).await;
    }
    // #200: persistent serve is now CONCURRENT. The #179 loop admitted a peer, served it to
    // completion, and only THEN re-admitted the next — so two users clicking Build within the same
    // window collided: whoever wasn't currently being served got a fast "role unreachable" and fell
    // back to the stand-in (central's 5-at-once test: 1 built, 4 unreachable, incl. central's own
    // safety_check — the serve model, not a per-role bug). We now ADMIT sequentially (one parked
    // accept at a time, so the edge pairer never has to hold two accepts for one channel) but SPAWN
    // each paired session, looping straight back to admit the next peer. A bounded semaphore caps how
    // many sessions run at once so a flood of Builds can't fork-bomb the host (each session may spawn
    // a `claude -p`); at capacity the next peer simply waits at the broker.
    //
    // The direct listener is bound ONCE and shared across sessions (quinn `Endpoint` is a cheap
    // clonable handle) — a per-session re-bind of the same advertised port would conflict. Over the
    // plane the direct accept times out to the edge relay, so each session's relay leg is independent
    // and fully concurrent; central must e2e the concurrent case (the regression bar: N concurrent
    // builds all succeed, no `role unreachable` fallbacks, single-request builds unchanged).
    let shared_listener: Option<Endpoint> = match cfg.role {
        ChannelRole::Accept if !cfg.relay_only => {
            Some(crate::transport::build_direct_listener_at(cfg.listen_addr)?.0)
        }
        _ => None,
    };
    // Built in `ServeSessionCtx::from_cfg` (serving.rs), which also starts
    // the background refresher for the join names.
    let serve_ctx = ServeSessionCtx::from_cfg(&cfg, request.clone(), shared_listener);
    let ctx = std::sync::Arc::new(serve_ctx);
    let max = serve_concurrency_from_env(
        std::env::var("CT_CHANNEL_SERVE_CONCURRENCY")
            .ok()
            .as_deref(),
    );
    eprintln!("ct-agent channel: persistent serve — up to {max} concurrent sessions (#200)");
    let admit_ctx = ctx.clone();
    serve_loop_concurrent(
        max,
        std::time::Duration::from_millis(200),
        move || {
            let c = admit_ctx.clone();
            async move { admit_one_peer(&c).await }
        },
        move |admission| {
            let c = ctx.clone();
            async move { serve_admitted_session(c, admission).await }
        },
    )
    .await
}




/// Configuration for the `ct-agent channel` runner (#98/#100), read from the
/// environment so the whole thing fits a copy-paste one-liner. The peer's transport
/// cert and Noise key travel as hex (as the broker/CP will hand them over); Noise_IK
/// is the real mutual authentication, so the QUIC cert is only the transport anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRunConfig {
    pub role: ChannelRole,
    /// Responder: the address to bind. Initiator: the peer address to dial.
    pub addr: SocketAddr,
    /// This agent's member Noise (X25519) private key.
    pub own_noise_private: [u8; 32],
    /// The peer's member Noise public key (pinned by the initiator).
    pub peer_noise_public: [u8; 32],
    /// Initiator only: the peer responder's QUIC cert (DER) to trust for the dial.
    pub peer_cert_der: Option<Vec<u8>>,
}

impl ChannelRunConfig {
    /// Parse from the process environment (`CT_CHANNEL_*`).
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from an arbitrary key→value lookup (testable without touching real env).
    /// Required: `CT_CHANNEL_ROLE` (initiate|accept), `CT_CHANNEL_ADDR` (host:port),
    /// `CT_CHANNEL_NOISE_KEY` + `CT_CHANNEL_PEER_NOISE_KEY` (64 hex each). For
    /// `initiate`, `CT_CHANNEL_PEER_CERT` (hex DER of the responder's cert) is required.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let role = match f("CT_CHANNEL_ROLE").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref r) if r == "initiate" || r == "initiator" => ChannelRole::Initiate,
            Some(ref r) if r == "accept" || r == "responder" || r == "listen" => ChannelRole::Accept,
            other => return Err(format!("CT_CHANNEL_ROLE must be initiate|accept, got {other:?}")),
        };
        let addr = f("CT_CHANNEL_ADDR")
            .ok_or("CT_CHANNEL_ADDR required (host:port)")?
            .trim()
            .parse::<SocketAddr>()
            .map_err(|e| format!("CT_CHANNEL_ADDR invalid: {e}"))?;
        let own_noise_private = f("CT_CHANNEL_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_NOISE_KEY required (64 hex chars)")?;
        let peer_noise_public = f("CT_CHANNEL_PEER_NOISE_KEY")
            .as_deref()
            .and_then(hex32)
            .ok_or("CT_CHANNEL_PEER_NOISE_KEY required (64 hex chars)")?;
        // Optional: pin the peer's transport cert. Omit it and the initiator dials
        // accept-any (Noise_IK authenticates), which keeps the one-liner self-contained.
        let peer_cert_der = match f("CT_CHANNEL_PEER_CERT").filter(|s| !s.trim().is_empty()) {
            Some(h) => {
                let der = hex_bytes(&h).ok_or("CT_CHANNEL_PEER_CERT must be hex DER")?;
                // ct-agent#26: same structural DER check CT_CHANNEL_FRONT_DOOR_CERT already
                // gets (join_config.rs) -- this is hand-copied out of a responder's printed
                // cert too, so it deserves the same named-here-not-a-generic-TLS-error-later
                // treatment.
                der_certificate_shape(&der)
                    .map_err(|why| format!("invalid CT_CHANNEL_PEER_CERT: {why}"))?;
                Some(der)
            }
            None => None,
        };
        Ok(Self { role, addr, own_noise_private, peer_noise_public, peer_cert_der })
    }
}

/// Run the `ct-agent channel` subcommand: bring up this agent as one side of an A2A
/// channel and pipe **stdin/stdout** over the encrypted tunnel (#98/#100). The
/// responder binds `addr` and prints its cert (hex) so the initiator can trust the
/// direct path; the initiator dials `addr` trusting the configured peer cert. The
/// real mutual auth is the Noise_IK session keyed on the member Noise keys.
pub async fn run_channel_command(cfg: ChannelRunConfig) -> Result<(), BoxError> {
    // Direct-address mode already knows the peer's Noise key from config (CT_CHANNEL_PEER_NOISE_KEY)
    // -- no admission round-trip needed to learn it, unlike the broker-mediated paths above.
    let local = channel_local(Some(cfg.peer_noise_public));
    match cfg.role {
        ChannelRole::Accept => {
            let (endpoint, cert) = crate::transport::build_direct_listener_at(cfg.addr)?;
            eprintln!(
                "ct-agent channel: listening on {} (responder); peer must set \
                 CT_CHANNEL_PEER_CERT={}",
                cfg.addr,
                hex_encode(cert.as_ref())
            );
            let conn = endpoint
                .accept()
                .await
                .ok_or("channel endpoint closed with no incoming")?
                .await?;
            run_channel_session(
                &conn,
                ChannelRole::Accept,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
        ChannelRole::Initiate => {
            // Pin the peer's transport cert if one was supplied; otherwise dial with
            // the accept-any channel dialer — Noise_IK is the real auth, so no cert
            // needs to be conveyed (self-contained one-liner, #100).
            let conn = match cfg.peer_cert_der.clone() {
                Some(der) => crate::transport::dial_quic(cfg.addr, CertificateDer::from(der)).await?,
                None => {
                    let endpoint = crate::transport::build_channel_dialer()?;
                    endpoint.connect(cfg.addr, "localhost")?.await?
                }
            };
            eprintln!("ct-agent channel: connected to {} (initiator)", cfg.addr);
            run_channel_session(
                &conn,
                ChannelRole::Initiate,
                &cfg.own_noise_private,
                &cfg.peer_noise_public,
                local,
            )
            .await?;
        }
    }
    Ok(())
}

mod session;
pub use session::*;

// Security audit: the peer's grant, checked end to end after the Noise handshake (opt-in).
mod peer_grant;
pub use peer_grant::*;

// Control-plane re-check of the peer's grant while a forward session runs.
pub(crate) mod grant_watch;

// Revoking one issued grant at the control plane (CLI and bridge tool).
mod grant_revoke;
pub use grant_revoke::*;

mod errors;
pub(crate) use errors::*;

mod serving;
pub(crate) use serving::*;

mod service_calls;
pub use service_calls::*;

mod provisioning;
pub use provisioning::*;

mod cli_config;
pub use cli_config::*;

mod dialing;
pub use dialing::*;

mod connectivity;
pub use connectivity::*;

mod join_config;
pub use join_config::*;

// scimbe/ct-agent#255: the accept side's gate in front of the channel TCP forward.
// Default off; nothing here touches the transport until the stream slice lands.
mod forward;
pub use forward::*;

// scimbe/ct-agent#255 slice 2: the wire framing and the stream engine that
// actually run a channel TCP forward -- the initiate side's local listener and the byte-
// transparent per-connection pump on both sides, built on `forward`'s policy gate above.
mod forward_stream;
mod forward_wire;
#[allow(unused_imports)] // re-export for the forward tests; the lib itself uses the module path (ct-agent#255)
pub(crate) use forward_stream::*;

// ct-agent#169: secret-shape redaction for text that leaves this process towards a remote peer.
mod redact;
pub(crate) use redact::redact_secrets;

#[cfg(test)]
mod tests;
