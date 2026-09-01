//! Self-service channel provisioning -- local key minting, operator grant issuance, and the
//! env-parsed CLI request structs behind the `ct-agent channel` provisioning subcommands
//! (consolidation program: module split, slice 4 -- moved verbatim out of the former
//! single-file `channel_run.rs`; every public item was already `pub` and is re-exported
//! unchanged by the parent, so no caller sees a new path, and the only edit was widening the
//! two private `compute` helpers to `pub(super)` -- exactly their previous reachability, since
//! `channel_run::tests` used to reach them as a descendant of the module that defined them).
//!
//! Covers the #117 self-service flow end to end: [`ChannelIdentity`] (a member's locally
//! generated holder + Noise keypairs), [`OperatorIdentity`] (the channel authority that signs
//! member grants, invitations, membership staples and overlay links into [`CompiledLink`]s),
//! and the `from_env`/`from_lookup`/`render` request structs the CLI dispatches on --
//! [`PipelineRoleMaterialRequest`], [`OperatorGrantRequest`], [`OperatorInviteRequest`],
//! [`MemberMaterialRequest`], [`ChannelRegisterRequest`], [`ChannelAllowlistRequest`].
//!
//! What unites them is that they are all *provisioning-time*, offline-or-control-plane work:
//! nothing here dials a peer, opens a QUIC connection or runs a session. That is also why the
//! block was chosen for this slice -- it had ZERO inbound references from the rest of
//! `channel_run` (measured by grep over every item name); its only coupling is outward, onto
//! the shared hex/`req_*` env-parsing helpers the parent still owns, which `use super::*`
//! supplies exactly as before the move.

use super::*;

/// A freshly-minted Agent-Fabric channel identity for **self-service** participation
/// (#117): the ed25519 *holder* keypair (proves possession of a grant) and the X25519
/// *Noise* keypair (the member's session key). Both are generated **locally** so the
/// private keys never leave the participant's machine — which is why self-service
/// channel setup is a local CLI step, not a browser/server flow: it preserves the
/// provider-blind property (the operator never sees a private key). Before this, a
/// participant had to hand-craft these keys or have the operator provision them by hand
/// for every new member. The hex accessors emit exactly what the `ct-agent channel` CLI
/// consumes (`CT_CHANNEL_HOLDER_KEY`, `CT_CHANNEL_NOISE_KEY`) plus the two **public**
/// keys an operator needs to register the channel / sign this member's grant.
pub struct ChannelIdentity {
    /// The holder ed25519 keypair (its private half proves grant possession).
    pub holder: SigningKey,
    /// The member's X25519 Noise static keypair.
    pub noise: ct_common::noise::StaticKeypair,
}

impl ChannelIdentity {
    /// Mint a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut holder_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut holder_seed);
        let holder = SigningKey::from_bytes(&holder_seed);
        let noise = ct_common::noise::generate_static_keypair();
        Self { holder, noise }
    }

    /// Value for `CT_CHANNEL_HOLDER_KEY` — the 64-hex ed25519 holder **private** key. SECRET.
    pub fn holder_key_hex(&self) -> String {
        hex_encode(&self.holder.to_bytes())
    }
    /// Value for `CT_CHANNEL_NOISE_KEY` — the 64-hex X25519 Noise **private** key. SECRET.
    pub fn noise_key_hex(&self) -> String {
        hex_encode(&self.noise.private)
    }
    /// The 64-hex ed25519 holder **public** key — an operator signs this member's grant over it.
    pub fn holder_pubkey_hex(&self) -> String {
        hex_encode(self.holder.verifying_key().as_bytes())
    }
    /// The 64-hex X25519 Noise **public** key — the member's attested session key.
    pub fn noise_pubkey_hex(&self) -> String {
        hex_encode(&self.noise.public)
    }

    /// A copy-pasteable shell block a self-service participant `eval`s (or sources)
    /// before running `ct-agent channel` (#117): the two **secret** private keys as
    /// `export`s the CLI reads, plus the two **public** keys — ALSO as `export`s, not
    /// only comments, because `channel member-material` and `channel join-pipeline-role`
    /// consume `CT_CHANNEL_HOLDER_PUBKEY`/`CT_CHANNEL_NOISE_PUBKEY` as env vars (found
    /// live: an agent following the hello-world README sourced this block, then hit
    /// "CT_CHANNEL_NOISE_PUBKEY required" and had to hand-copy the value out of a
    /// comment — the one file this block exists to make copy-paste-complete). The
    /// pubkeys are public by definition, so exporting them leaks nothing. The channel
    /// operator (who signs this member's grant / registers the channel) still supplies
    /// `CT_CHANNEL_GRANT` and the broker/relay/front-door addresses. Private keys are
    /// generated locally and never printed as anything but the participant's own env —
    /// they never reach the operator or the server.
    pub fn env_block(&self) -> String {
        format!(
            "# Agent-Fabric channel identity — generated locally, keep the private keys secret.\n\
             # Give these PUBLIC keys to the channel operator (to sign your grant / register):\n\
             export CT_CHANNEL_HOLDER_PUBKEY={holder_pub}\n\
             export CT_CHANNEL_NOISE_PUBKEY={noise_pub}\n\
             export CT_CHANNEL_HOLDER_KEY={holder_priv}\n\
             export CT_CHANNEL_NOISE_KEY={noise_priv}\n\
             #\n\
             # #330: if you're behind a NAT and can't reach the operator's broker/relay ports\n\
             # directly, you ALSO need CT_CHANNEL_RELAY_GATE (+ _CERT) — a separate, relay-gate\n\
             # protocol from plain CT_CHANNEL_RELAY, not interchangeable with it. Ask your\n\
             # operator whether this deployment needs it; if so, CT_CHANNEL_RELAY_GATE is the\n\
             # deployment's unified front-door address (ask the operator, or fetch it from this\n\
             # control plane's GET /network-info -> channel_relay_gate_port, same host as\n\
             # CT_AGENT_CP_URL) and CT_CHANNEL_RELAY_GATE_CERT is the DER from GET /pki/ca (same\n\
             # CA root you already trust for everything else). Omitting this when your side of a\n\
             # channel pairing needs it fails silently downstream (an unhelpful early-eof), not\n\
             # with an error naming the missing var — see docs.bunsenbrenner.org for details.\n",
            holder_pub = self.holder_pubkey_hex(),
            noise_pub = self.noise_pubkey_hex(),
            holder_priv = self.holder_key_hex(),
            noise_priv = self.noise_key_hex(),
        )
    }
}

/// One overlay link compiled into a concrete A2A channel (#107-nway): the derived
/// [`ct_common::channel::ChannelId`] and the two operator-signed grants the link's members
/// present to join it. The initiator holder is the canonically-smaller node id of the link
/// (the `Initiate`-direction side); the acceptor is the other. Both members independently
/// derive the same `channel` from their holder keys, so no coordination round-trip is
/// needed to agree on the channel address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledLink {
    pub channel: ct_common::channel::ChannelId,
    pub initiator_holder: [u8; 32],
    pub acceptor_holder: [u8; 32],
    pub initiator_grant: ct_common::channel::SignedChannelGrant,
    pub acceptor_grant: ct_common::channel::SignedChannelGrant,
}

/// A channel **operator's** signing identity (#117-operator-flow): the ed25519 key that
/// *authorizes* a channel — its public key is the channel's authority (registered with
/// the control plane so the edge can verify member grants), and it signs every member's
/// grant. Generated locally, like a member's [`ChannelIdentity`]; the operator private
/// key never leaves the operator's machine (provider-blind — the server sees only the
/// public key). This lets an account create channels and admit members with no manual
/// crypto provisioning by central.
pub struct OperatorIdentity {
    /// The operator ed25519 keypair (its private half signs member grants).
    pub key: SigningKey,
}

impl OperatorIdentity {
    /// Mint a fresh operator key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self { key: SigningKey::from_bytes(&seed) }
    }

    /// The 64-hex operator **private** key (`CT_CHANNEL_OPERATOR_KEY`). SECRET.
    pub fn key_hex(&self) -> String {
        hex_encode(&self.key.to_bytes())
    }
    /// The 64-hex operator **public** key — the channel's authority, registered with the
    /// control plane so the edge verifies member grants against it.
    pub fn pubkey_hex(&self) -> String {
        hex_encode(self.key.verifying_key().as_bytes())
    }

    /// Issue a member grant: sign a `ChannelGrant` binding `holder_pubkey` (the member's
    /// `channel init` holder public key) to `channel` with `direction`/`expires_at`, and
    /// return the hex the member sets as `CT_CHANNEL_GRANT`. Pure crypto — the operator
    /// runs this locally after the member hands over their holder public key; no server
    /// round-trip and no private key ever leaves either machine.
    pub fn issue_member_grant(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        direction: ct_common::channel::Direction,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> String {
        hex_encode(&self.sign_member_grant(channel, holder_pubkey, direction, expires_at).encode())
    }

    /// Sign a `ChannelGrant` binding `holder_pubkey` to `channel` with `direction`/
    /// `expires_at` under the local operator key, returning the structured grant. The
    /// crypto shared by [`issue_member_grant`](Self::issue_member_grant) (which hex-encodes
    /// this for the member one-liner) and [`compile_overlay_grants`](Self::compile_overlay_grants).
    fn sign_member_grant(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        direction: ct_common::channel::Direction,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> ct_common::channel::SignedChannelGrant {
        use ct_common::channel::{ChannelGrant, Rights, SignedChannelGrant};
        let g = ChannelGrant {
            channel,
            holder: holder_pubkey,
            direction,
            rights: Rights::ReadWrite,
            delegable: false,
            expires_at,
        };
        let signature = self.key.sign(&g.signing_bytes()).to_bytes();
        SignedChannelGrant { grant: g, signature }
    }

    /// scimbe/ct-agent#9: sign a `ChannelInvitation` for `invitee_identity` to join `channel`,
    /// returning the hex the invitee redeems (`ct-agent channel invite` prints this; the
    /// receiving-side endpoints and `verify_invitation`/`redeem_invitation` already exist in
    /// `ct_common::channel` and in the control plane — this was the missing producer). Pure
    /// crypto, same shape as [`issue_member_grant`]: the operator runs this locally, no server
    /// round-trip, no private key ever leaves either machine. Unlike a grant (which binds a
    /// `holder` key the operator already has in hand), an invitation targets an **identity**
    /// key the operator may only know from, e.g., a registry lookup or an out-of-band email —
    /// this is the actual cross-account case a plain `channel grant` can't cover.
    pub fn issue_member_invitation(
        &self,
        channel: ct_common::channel::ChannelId,
        invitee_identity: [u8; 32],
        direction: ct_common::channel::Direction,
        rights: ct_common::channel::Rights,
        delegable: bool,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> String {
        hex_encode(
            &self
                .sign_member_invitation(channel, invitee_identity, direction, rights, delegable, expires_at)
                .encode(),
        )
    }

    /// Sign a `ChannelInvitation` binding `invitee_identity` to `channel` under the local
    /// operator key, returning the structured invitation. Mirrors [`sign_member_grant`]:
    /// `ChannelInvitation::signing_bytes()` is domain-separated from a grant's (`"ct-chan-
    /// invite:v1|..."` vs. the grant's own prefix), so a captured invitation can never be
    /// replayed as a grant or vice versa.
    fn sign_member_invitation(
        &self,
        channel: ct_common::channel::ChannelId,
        invitee_identity: [u8; 32],
        direction: ct_common::channel::Direction,
        rights: ct_common::channel::Rights,
        delegable: bool,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> ct_common::channel::SignedChannelInvitation {
        use ct_common::channel::{ChannelInvitation, SignedChannelInvitation};
        let i = ChannelInvitation { channel, invitee_identity, direction, rights, delegable, expires_at };
        let signature = self.key.sign(&i.signing_bytes()).to_bytes();
        SignedChannelInvitation { invitation: i, signature }
    }

    /// Compile a topology's overlay `plan` into per-link A2A channels (#107-nway): each
    /// link (a canonical pair of agent node-ids) becomes a channel
    /// ([`ct_common::channel::channel_id_for_link`]) plus the two operator-signed grants its
    /// members present to join it. `holder_of` maps a node id to that agent's member holder
    /// pubkey (the controller knows each registered agent's key). The canonically-smaller
    /// node id of each link is the **Initiate** side — a stable, caller-independent split,
    /// like the broker's `authorize_channel_pair`. Returns `Err(node_id)` if a link names an
    /// agent with no holder mapping (the plan can't be wired without every endpoint's key).
    ///
    /// Pure given `holder_of`: the operator mints every grant **locally** with its own key
    /// (invariant #6) — no central round-trip; central only distributes the compiled grants.
    pub fn compile_overlay_grants(
        &self,
        plan: &ct_common::overlay::OverlayPlan,
        holder_of: impl Fn(&str) -> Option<[u8; 32]>,
        expires_at: ct_common::channel::UnixSeconds,
    ) -> Result<Vec<CompiledLink>, String> {
        use ct_common::channel::{channel_id_for_link, Direction};
        let op_pub = self.key.verifying_key().to_bytes();
        let mut out = Vec::with_capacity(plan.links.len());
        for (a_id, b_id) in &plan.links {
            let initiator_holder = holder_of(a_id).ok_or_else(|| a_id.clone())?;
            let acceptor_holder = holder_of(b_id).ok_or_else(|| b_id.clone())?;
            // channel_id_for_link sorts by holder bytes, so both members derive the same id.
            let channel = channel_id_for_link(&op_pub, &initiator_holder, &acceptor_holder);
            out.push(CompiledLink {
                channel,
                initiator_holder,
                acceptor_holder,
                initiator_grant: self.sign_member_grant(
                    channel,
                    initiator_holder,
                    Direction::Initiate,
                    expires_at,
                ),
                acceptor_grant: self.sign_member_grant(
                    channel,
                    acceptor_holder,
                    Direction::Accept,
                    expires_at,
                ),
            });
        }
        Ok(out)
    }

    /// Issue a short-lived **membership staple** (E-fail-static, invariant #7): the operator
    /// re-affirms that `holder_pubkey` is *currently* a member of `channel`, valid for
    /// `ttl_secs` from `stapled_at`. Unlike [`issue_member_grant`](Self::issue_member_grant)
    /// — a long-lived capability — a staple is minted **frequently** and gossiped so peers
    /// keep admitting the member (via [`ct_common::channel::StapleCache`]) while central is
    /// unreachable, and it dies within one TTL once the operator stops re-issuing it
    /// (revocation latency = staple TTL).
    ///
    /// Minted with the **local** operator key (invariant #6): central never holds the key,
    /// so it can *distribute/refresh* staples but can never mint — nor forge — one. This is
    /// why a central compromise degrades to DoS/metadata, never impersonation. Returns the
    /// staple object (the gossip transport encodes it); the operator runs this locally on a
    /// refresh timer, no server round-trip.
    pub fn issue_membership_staple(
        &self,
        channel: ct_common::channel::ChannelId,
        holder_pubkey: [u8; 32],
        stapled_at: ct_common::channel::UnixSeconds,
        ttl_secs: u64,
    ) -> ct_common::channel::MembershipStaple {
        use ct_common::channel::MembershipStaple;
        let expires_at = stapled_at.saturating_add(ttl_secs);
        let signature = self
            .key
            .sign(&MembershipStaple::signing_bytes(
                &channel,
                &holder_pubkey,
                stapled_at,
                expires_at,
            ))
            .to_bytes();
        MembershipStaple {
            channel,
            holder: holder_pubkey,
            stapled_at,
            expires_at,
            signature,
        }
    }

    /// A copy-pasteable, `eval`-safe shell block for `ct-agent channel operator-init`
    /// (#117): the operator private key as the `export` the `channel grant` command
    /// reads, plus the operator public key as a comment (the channel authority to
    /// register with the control plane). Generated locally; the private key never leaves.
    pub fn operator_env_block(&self) -> String {
        format!(
            "# Agent-Fabric channel OPERATOR identity — generated locally, keep the key secret.\n\
             # Register this PUBLIC key as the channel authority (POST /channel/register):\n\
             #   operator_pubkey = {op_pub}\n\
             export CT_CHANNEL_OPERATOR_KEY={op_priv}\n",
            op_pub = self.pubkey_hex(),
            op_priv = self.key_hex(),
        )
    }

    /// Prove possession of this operator key for binding to a Topology-Editor topology
    /// (#698): a signature over [`ct_common::channel::topology_operator_binding_bytes`],
    /// the exact preimage `PUT /me/topologies/:id/operator` verifies. Pure local crypto —
    /// no server round-trip, the operator private key never leaves this machine. Returns
    /// `(operator_pubkey_hex, proof_hex)`, the two fields that request body wants.
    pub fn bind_topology(&self, topology_id: &str) -> (String, String) {
        let op_pub = self.key.verifying_key().to_bytes();
        let msg = ct_common::channel::topology_operator_binding_bytes(topology_id, &op_pub);
        let proof = self.key.sign(&msg).to_bytes();
        (hex_encode(&op_pub), hex_encode(&proof))
    }
}

/// Inputs for `ct-agent channel join-pipeline-role` (#214 follow-up: generic pipeline
/// provisioning). Unlike [`MemberMaterialRequest`] — which needs `CT_CHANNEL_BRIDGE_HOLDER`, the
/// COUNTERPART's public key, so both sides must exchange keys before either can derive the
/// channel id — this derives the id from PUBLIC, PUBLISHED information only (the operator's
/// pubkey, the pipeline's id, and the role tag: exactly what `GET /registry/pipelines/:id`
/// returns). A bridge that needs a role's output and any agent capable of serving it each run this
/// independently and land on the *same* channel id with **no coordination round-trip** — no
/// GitHub-comment pubkey relay, no waiting on the other side. Reads the operator's PUBLIC key +
/// the pipeline id + role tag (all public, from the pipeline registry), the caller's own holder
/// PRIVATE key (to derive its pubkey and sign the attestation), and the caller's noise PUBLIC key.
/// Pure local compute — nothing is minted, nothing leaves the box.
pub struct PipelineRoleMaterialRequest {
    operator_pubkey: [u8; 32],
    pipeline_id: String,
    role: String,
    holder: SigningKey,
    noise_pubkey: [u8; 32],
}

impl PipelineRoleMaterialRequest {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        Ok(Self {
            operator_pubkey: req_hex32(
                &f,
                "CT_CHANNEL_OPERATOR_PUBKEY",
                "64 hex operator pubkey (from the pipeline registry entry's operator_pubkey_hex)",
            )?,
            pipeline_id: req_str(&f, "CT_PIPELINE_ID", "the pipeline's published id")?,
            role: req_str(&f, "CT_PIPELINE_ROLE", "the role tag you're joining (a role.tag from the pipeline spec)")?,
            holder: req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex; your holder PRIVATE key")?,
            noise_pubkey: req_hex32(&f, "CT_CHANNEL_NOISE_PUBKEY", "64 hex; your noise PUBLIC key")?,
        })
    }

    /// `(channel_id, holder_pubkey, noise_attestation)` — the derived material. The channel id is
    /// this pipeline role's canonical address (independent of who else has or hasn't joined yet);
    /// the attestation is this holder's signed binding of its noise key (#101), which the
    /// pipeline's channel owner relays so the peer can pin the key safely.
    pub(super) fn compute(&self) -> (ct_common::channel::ChannelId, [u8; 32], [u8; 64]) {
        use ct_common::channel::{channel_id_for_pipeline_role, member_noise_attest_bytes};
        let holder_pubkey = self.holder.verifying_key().to_bytes();
        let channel = channel_id_for_pipeline_role(&self.operator_pubkey, &self.pipeline_id, &self.role);
        let attestation = self
            .holder
            .sign(&member_noise_attest_bytes(&channel, &holder_pubkey, &self.noise_pubkey))
            .to_bytes();
        (channel, holder_pubkey, attestation)
    }

    /// The paste-able block the caller hands to the pipeline's channel owner (whoever ran
    /// `POST /me/channels` for this role) so it can `POST /me/channels/:channel/members` on the
    /// caller's behalf.
    pub fn render(&self) -> String {
        let (channel, holder_pubkey, attestation) = self.compute();
        format!(
            "pipeline_id       = {}\nrole              = {}\nholder_pubkey     = {}\nnoise_pubkey      = {}\nchannel_id        = {}\nnoise_attestation = {}\n",
            self.pipeline_id,
            self.role,
            hex_encode(&holder_pubkey),
            hex_encode(&self.noise_pubkey),
            hex_encode(&channel.0),
            hex_encode(&attestation),
        )
    }
}

/// Inputs for `ct-agent channel grant` (#117-operator-flow): an operator signs one
/// member's grant from the environment, parsed like [`ChannelJoinCliConfig::from_lookup`].
/// `CT_CHANNEL_OPERATOR_KEY` is the operator's own key (from `channel operator-init`);
/// `CT_GRANT_*` describe the member being admitted (their `channel init`
/// `holder_pubkey`, the channel id, the direction, and an expiry).
pub struct OperatorGrantRequest {
    pub operator: SigningKey,
    pub channel: ct_common::channel::ChannelId,
    pub member_holder: [u8; 32],
    pub direction: ct_common::channel::Direction,
    pub expires_at: ct_common::channel::UnixSeconds,
}

impl OperatorGrantRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let operator = req_key(&f, "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")?;
        let channel = ct_common::channel::ChannelId(req_hex32(&f, "CT_GRANT_CHANNEL", "64 hex channel id")?);
        let member_holder = req_hex32(&f, "CT_GRANT_MEMBER_HOLDER", "64 hex member holder pubkey")?;
        let direction = match f("CT_GRANT_DIRECTION").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref d) if d == "initiate" || d == "initiator" => ct_common::channel::Direction::Initiate,
            Some(ref d) if d == "accept" || d == "responder" => ct_common::channel::Direction::Accept,
            other => return Err(format!("CT_GRANT_DIRECTION must be initiate|accept, got {other:?}")),
        };
        let expires_at = req_str(&f, "CT_GRANT_EXPIRES", "unix seconds")?
            .trim()
            .parse()
            .map_err(|e| format!("CT_GRANT_EXPIRES invalid: {e}"))?;
        Ok(Self { operator, channel, member_holder, direction, expires_at })
    }

    /// The signed grant hex the member sets as `CT_CHANNEL_GRANT`.
    pub fn issue(&self) -> String {
        OperatorIdentity { key: self.operator.clone() }.issue_member_grant(
            self.channel,
            self.member_holder,
            self.direction,
            self.expires_at,
        )
    }
}

/// The operator's own signing key from `CT_CHANNEL_OPERATOR_KEY` — the one piece of
/// [`OperatorGrantRequest::from_env`]'s parsing `ct-agent channel grant --interactive`
/// still needs from the environment rather than an interactive prompt (a private key
/// must never be typed at a terminal where it could be echoed or land in shell
/// history). `pub` (unlike the `pub(crate)` `req_key` it wraps) since the CLI dispatch
/// in `main.rs` is a separate crate from this library.
pub fn operator_key_from_env() -> Result<SigningKey, String> {
    req_key(&|k: &str| std::env::var(k).ok(), "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")
}

/// Parse a duration for `--interactive` grant expiry: `<N>d`/`<N>h`/`<N>m`/`<N>s`
/// (case-insensitive), or bare digits meaning seconds. Deliberately relative-only
/// (never an absolute timestamp) — the raw `CT_GRANT_EXPIRES` env interface makes an
/// operator compute `now + N` by hand (a real `date -d ... +%s` error class; this is
/// what wrapper scripts like `grantChannel.sh` exist to paper over), and a relative
/// duration removes that arithmetic entirely rather than just hiding it in a script.
pub(crate) fn parse_duration_secs(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_lowercase()) {
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some('h') => (&s[..s.len() - 1], 3_600),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('s') => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    let n: u64 = num.trim().parse().map_err(|_| format!("{s:?} is not a valid duration (e.g. 30d, 24h, 90m, 3600, or 3600s)"))?;
    n.checked_mul(mult).ok_or_else(|| format!("{s:?} overflows"))
}

/// Interactive, validated, self-verifying grant issuance for `ct-agent channel grant
/// --interactive` (2026-09-01, operator ask relayed via a peer maintainer: the raw
/// `CT_GRANT_*` env-var interface was error-prone enough by hand that a wrapper shell
/// script (`grantChannel.sh`) grew up around it). `prompt` is injected so this is
/// testable without real stdin — it receives the prompt text and returns the raw
/// line, matching the `from_lookup(f: impl Fn...)` testability convention the rest of
/// this module already uses for env parsing. Each field retries on invalid input
/// instead of failing the whole flow on the first typo. After issuing, the grant is
/// immediately verified against the operator's OWN public key
/// ([`ct_common::channel::verify_stateless`]) before being handed back — catching a
/// garbled/mistyped channel or holder value right here, rather than only when the
/// member's own admission attempt fails later with an unhelpful signature error.
pub fn issue_grant_interactively(
    operator: SigningKey,
    mut prompt: impl FnMut(&str) -> Result<String, String>,
) -> Result<String, String> {
    let channel = loop {
        let raw = prompt("Channel id (64 hex, from `channel operator-init`'s registration): ")?;
        match hex32(raw.trim()) {
            Some(c) => break ct_common::channel::ChannelId(c),
            None => eprintln!("  not 64 hex characters, try again"),
        }
    };
    let member_holder = loop {
        let raw = prompt("Member's holder pubkey (64 hex, from their `channel init`): ")?;
        match hex32(raw.trim()) {
            Some(h) => break h,
            None => eprintln!("  not 64 hex characters, try again"),
        }
    };
    let direction = loop {
        let raw = prompt("Direction (initiate/accept): ")?;
        match raw.trim().to_ascii_lowercase().as_str() {
            "initiate" | "initiator" => break ct_common::channel::Direction::Initiate,
            "accept" | "responder" => break ct_common::channel::Direction::Accept,
            _ => eprintln!("  must be \"initiate\" or \"accept\", try again"),
        }
    };
    let expires_in = loop {
        let raw = prompt("Expires in (e.g. 30d, 24h, 90m; bare number = seconds): ")?;
        match parse_duration_secs(&raw) {
            Ok(secs) => break secs,
            Err(e) => eprintln!("  {e}"),
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at = now.saturating_add(expires_in);
    let operator_pubkey = operator.verifying_key().to_bytes();
    let req = OperatorGrantRequest { operator, channel, member_holder, direction, expires_at };
    let grant_hex = req.issue();
    let decoded = ct_common::channel::SignedChannelGrant::decode(&hex_bytes(&grant_hex).ok_or("internal: issued grant hex failed to decode")?)
        .map_err(|e| format!("internal: issued grant failed to re-decode: {e}"))?;
    ct_common::channel::verify_stateless(&operator_pubkey, &decoded, now)
        .map_err(|e| format!("internal: issued grant failed self-verification ({e}) -- this should never happen, please report it"))?;
    Ok(grant_hex)
}

/// scimbe/ct-agent#9 `ct-agent channel invite`: as the operator, sign an invitation for an
/// **identity** key you don't otherwise coordinate holder/noise material with directly — the
/// cross-account case `channel grant`/`provision-link-channel.sh` can't cover, since those
/// both assume you already have the other side's holder pubkey in hand. Reads
/// CT_CHANNEL_OPERATOR_KEY + CT_INVITE_*.
pub struct OperatorInviteRequest {
    pub operator: SigningKey,
    pub channel: ct_common::channel::ChannelId,
    pub invitee_identity: [u8; 32],
    pub direction: ct_common::channel::Direction,
    pub rights: ct_common::channel::Rights,
    pub delegable: bool,
    pub expires_at: ct_common::channel::UnixSeconds,
}

impl OperatorInviteRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let operator = req_key(&f, "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")?;
        let channel = ct_common::channel::ChannelId(req_hex32(&f, "CT_INVITE_CHANNEL", "64 hex channel id")?);
        let invitee_identity =
            req_hex32(&f, "CT_INVITE_IDENTITY", "64 hex invitee identity pubkey")?;
        let direction = match f("CT_INVITE_DIRECTION").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            Some(ref d) if d == "initiate" || d == "initiator" => ct_common::channel::Direction::Initiate,
            Some(ref d) if d == "accept" || d == "responder" => ct_common::channel::Direction::Accept,
            Some(ref d) if d == "both" => ct_common::channel::Direction::Both,
            other => return Err(format!("CT_INVITE_DIRECTION must be initiate|accept|both, got {other:?}")),
        };
        let rights = match f("CT_INVITE_RIGHTS").as_deref().map(|s| s.trim().to_ascii_lowercase()) {
            None => ct_common::channel::Rights::ReadWrite, // matches OperatorGrantRequest's fixed ReadWrite default
            Some(ref r) if r == "read" || r == "r" => ct_common::channel::Rights::Read,
            Some(ref r) if r == "write" || r == "w" => ct_common::channel::Rights::Write,
            Some(ref r) if r == "readwrite" || r == "read-write" || r == "rw" => {
                ct_common::channel::Rights::ReadWrite
            }
            other => return Err(format!("CT_INVITE_RIGHTS must be read|write|readwrite, got {other:?}")),
        };
        let delegable = match f("CT_INVITE_DELEGABLE").as_deref() {
            None => false,
            Some(v) => v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"),
        };
        let expires_at = req_str(&f, "CT_INVITE_EXPIRES", "unix seconds")?
            .trim()
            .parse()
            .map_err(|e| format!("CT_INVITE_EXPIRES invalid: {e}"))?;
        Ok(Self { operator, channel, invitee_identity, direction, rights, delegable, expires_at })
    }

    /// The signed invitation hex the invitee redeems (see `ct_common::channel::redeem_invitation`
    /// / `invitation_redeem_bytes` for the receiving-side flow this feeds).
    pub fn issue(&self) -> String {
        OperatorIdentity { key: self.operator.clone() }.issue_member_invitation(
            self.channel,
            self.invitee_identity,
            self.direction,
            self.rights,
            self.delegable,
            self.expires_at,
        )
    }
}

/// #698 `ct-agent channel bind-topology`: the missing producer for the Topology Editor's
/// operator-binding step. A live-walkthrough finding (#698) confirmed the guided flow's
/// intro text promises this step but the editor never surfaces it — the actual gap was
/// never a missing UI checkbox, it was that no tool existed to compute `PUT
/// /me/topologies/:id/operator`'s `proof` (a signature over
/// [`ct_common::channel::topology_operator_binding_bytes`]) at all. This closes that:
/// pure local crypto over `CT_CHANNEL_OPERATOR_KEY` (from `channel operator-init`) +
/// `CT_TOPOLOGY_ID` (the topology's id, shown in its editor URL), no server round-trip,
/// private key never leaves this machine — same shape as `channel grant`/`channel invite`.
pub struct OperatorTopologyBindRequest {
    pub operator: SigningKey,
    pub topology_id: String,
}

impl OperatorTopologyBindRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let operator = req_key(&f, "CT_CHANNEL_OPERATOR_KEY", "64 hex; from `channel operator-init`")?;
        let topology_id = req_str(&f, "CT_TOPOLOGY_ID", "the topology's id, from its editor URL")?;
        Ok(Self { operator, topology_id })
    }

    /// The `operator_pubkey`/`proof` pair, formatted for direct copy-paste into the
    /// Topology Editor's operator-binding fields (and matching `PUT
    /// /me/topologies/:id/operator`'s JSON body field names byte-for-byte).
    pub fn issue(&self) -> String {
        let (operator_pubkey, proof) =
            OperatorIdentity { key: self.operator.clone() }.bind_topology(&self.topology_id);
        format!("operator_pubkey = {operator_pubkey}\nproof           = {proof}\n")
    }
}

/// #207 Slice A onboarding helper — compute the material a channel MEMBER hands its operator/central
/// so the operator can mint its grant and admit it to a link channel (e.g. sink's standby joining a
/// bridge role for failover). A member otherwise has to hand-roll `channel_id_for_link` +
/// `member_noise_attest_bytes` + an ed25519 signature; this does it in one local command. Reads the
/// operator + bridge-holder PUBLIC keys the operator supplies, the member's own holder PRIVATE key
/// (to derive its holder pubkey and sign the attestation), and the member's noise PUBLIC key. Pure
/// local compute — nothing is minted, nothing leaves the box.
pub struct MemberMaterialRequest {
    operator_pubkey: [u8; 32],
    bridge_holder: [u8; 32],
    holder: SigningKey,
    noise_pubkey: [u8; 32],
}

impl MemberMaterialRequest {
    /// Read from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        Ok(Self {
            operator_pubkey: req_hex32(&f, "CT_CHANNEL_OPERATOR_PUBKEY", "64 hex operator pubkey (from central)")?,
            bridge_holder: req_hex32(&f, "CT_CHANNEL_BRIDGE_HOLDER", "64 hex bridge holder pubkey (from central)")?,
            holder: req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex; your member holder PRIVATE key")?,
            noise_pubkey: req_hex32(&f, "CT_CHANNEL_NOISE_PUBKEY", "64 hex; your member noise PUBLIC key")?,
        })
    }

    /// `(channel_id, holder_pubkey, noise_attestation)` — the derived material. The channel id is the
    /// operator-scoped link between the bridge holder and this member (order-independent); the
    /// attestation is this member's holder-signed binding of its noise key (#101), which the operator
    /// relays so the peer can pin the key safely.
    pub(super) fn compute(&self) -> (ct_common::channel::ChannelId, [u8; 32], [u8; 64]) {
        use ct_common::channel::{channel_id_for_link, member_noise_attest_bytes};
        let holder_pubkey = self.holder.verifying_key().to_bytes();
        let channel = channel_id_for_link(&self.operator_pubkey, &self.bridge_holder, &holder_pubkey);
        let attestation = self
            .holder
            .sign(&member_noise_attest_bytes(&channel, &holder_pubkey, &self.noise_pubkey))
            .to_bytes();
        (channel, holder_pubkey, attestation)
    }

    /// The paste-able block the member posts back to the operator/central.
    pub fn render(&self) -> String {
        let (channel, holder_pubkey, attestation) = self.compute();
        format!(
            "holder_pubkey     = {}\nnoise_pubkey      = {}\nchannel_id        = {}\nnoise_attestation = {}\n",
            hex_encode(&holder_pubkey),
            hex_encode(&self.noise_pubkey),
            hex_encode(&channel.0),
            hex_encode(&attestation),
        )
    }
}

/// Inputs for `ct-agent channel register` (#117-operator-register): register the
/// operator's channel authority with the control plane (`POST /me/channels`) so the edge
/// accepts the member grants the operator signs — the last CP round-trip for an
/// end-to-end self-service Agent-Fabric channel. Parsed from the environment like
/// [`OperatorGrantRequest::from_lookup`], reusing the onboarding/operator vars:
/// the control-plane URL (`CT_AGENT_CP_URL`, as onboarding uses), the channel id
/// (`CT_CHANNEL_ID`, falling back to the grant-flow's `CT_GRANT_CHANNEL` for
/// back-compat -- #96, this command isn't a grant operation so the primary name
/// shouldn't be grant-namespaced), the OIDC bearer token (`CT_OIDC_TOKEN`), and the
/// operator public key — derived from `CT_CHANNEL_OPERATOR_KEY` (the operator's own
/// private key from `channel operator-init`) or supplied directly as
/// `CT_CHANNEL_OPERATOR_PUBKEY`.
pub struct ChannelRegisterRequest {
    /// Control-plane base URL (`POST {cp_url}/me/channels`).
    pub cp_url: String,
    /// The channel id, canonical 64-hex.
    pub channel_hex: String,
    /// The operator ed25519 public key, canonical 64-hex — the channel's authority.
    pub operator_pubkey_hex: String,
    /// The OIDC bearer token identifying the owner (the verified subject).
    pub token: String,
}

impl ChannelRegisterRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let token = f("CT_OIDC_TOKEN")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_OIDC_TOKEN required (OIDC bearer token for the channel owner)")?;
        Self::from_lookup_with_token(f, token)
    }

    /// Like [`Self::from_lookup`], but the caller has already resolved the OIDC bearer
    /// token itself (`CT_OIDC_TOKEN` if it was explicitly set, else the token
    /// `ct-agent login` stored on disk — see [`crate::login::resolve_oidc_token`]) rather
    /// than requiring `CT_OIDC_TOKEN` to be present in `f`. Every other field is read
    /// from `f` exactly as `from_lookup` does — `from_lookup` itself is just this with
    /// `CT_OIDC_TOKEN` read out of `f` first, so nothing about its behavior changed.
    pub fn from_lookup_with_token(f: impl Fn(&str) -> Option<String>, token: String) -> Result<Self, String> {
        let cp_url = f("CT_AGENT_CP_URL")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_AGENT_CP_URL required (control-plane base URL)")?;
        let channel_hex = hex_encode(&req_hex32_aliased(&f, "CT_CHANNEL_ID", "CT_GRANT_CHANNEL", "64 hex channel id")?);
        // The channel authority: derive from the operator's own private key
        // (CT_CHANNEL_OPERATOR_KEY, from `channel operator-init`), or take the public key
        // directly (CT_CHANNEL_OPERATOR_PUBKEY) when only the pubkey is at hand.
        let operator_pubkey_hex = if let Some(pk) = opt_hex32(&f, "CT_CHANNEL_OPERATOR_PUBKEY") {
            hex_encode(&pk)
        } else if let Some(sk) = opt_hex32(&f, "CT_CHANNEL_OPERATOR_KEY") {
            OperatorIdentity { key: SigningKey::from_bytes(&sk) }.pubkey_hex()
        } else {
            return Err(
                "CT_CHANNEL_OPERATOR_KEY (64 hex operator private, from `channel operator-init`) \
                 or CT_CHANNEL_OPERATOR_PUBKEY (64 hex) required"
                    .to_string(),
            );
        };
        Ok(Self { cp_url, channel_hex, operator_pubkey_hex, token })
    }
}

/// Configuration for `ct-agent channel allowlist add|remove|list` (#248-follow): the
/// owner-scoped self-service channel-allowlist CLI, so an operator can manage a
/// channel's e-mail allow-list without leaving the terminal for the portal web UI.
/// Shares its shape with [`ChannelRegisterRequest`] (same `CT_AGENT_CP_URL`/
/// `CT_CHANNEL_ID` (or `CT_GRANT_CHANNEL`)/`CT_OIDC_TOKEN`), minus the operator
/// pubkey — the allow-list routes are owner-scoped by the bearer token alone, no
/// operator key needed.
pub struct ChannelAllowlistRequest {
    /// Control-plane base URL (`{cp_url}/me/channels/:channel/allowlist`).
    pub cp_url: String,
    /// The channel id, canonical 64-hex.
    pub channel_hex: String,
    /// The OIDC bearer token identifying the owner (the verified subject).
    pub token: String,
}

impl ChannelAllowlistRequest {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let token = f("CT_OIDC_TOKEN")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_OIDC_TOKEN required (OIDC bearer token for the channel owner)")?;
        Self::from_lookup_with_token(f, token)
    }

    /// See [`ChannelRegisterRequest::from_lookup_with_token`] — same shape, same reason:
    /// the caller supplies an already-resolved OIDC token instead of requiring
    /// `CT_OIDC_TOKEN` in `f`.
    pub fn from_lookup_with_token(f: impl Fn(&str) -> Option<String>, token: String) -> Result<Self, String> {
        let cp_url = f("CT_AGENT_CP_URL")
            .filter(|s| !s.trim().is_empty())
            .ok_or("CT_AGENT_CP_URL required (control-plane base URL)")?;
        let channel_hex = hex_encode(&req_hex32_aliased(&f, "CT_CHANNEL_ID", "CT_GRANT_CHANNEL", "64 hex channel id")?);
        Ok(Self { cp_url, channel_hex, token })
    }
}
