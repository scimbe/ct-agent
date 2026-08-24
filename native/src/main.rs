//! CADS Tunnel Agent daemon (M5.4c).
//!
//! Waits for the Edge cert on a shared path, mints a Capability (written to the
//! shared volume for the Client), registers its tunnel, and serves the Origin.

use std::time::Duration;
use tokio::time::Instant;

use ct_agent::capability::{parse_routing_token_hex, resolve_serving_identity_with_token};
use ct_agent::config::AgentConfig;
use ct_agent::onboard::{onboard_or_restore, OnboardEnv};
use ct_agent::serve::run_agent;
use ct_agent::transport::load_cert;

const EDGE_CERT_WAIT_LOG_THROTTLE_SECS: u64 = 5;

/// #239: a bare `ct-agent --help`/`-h`, or any unrecognized first argument, used to
/// fall straight through every subcommand check below into the default onboard/serve
/// path -- a typo'd subcommand didn't fail loudly, it started serving. Three separate
/// docs pages ended up independently documenting "don't rely on --help, read this
/// page instead" as a workaround. This is the actual reference now; keep it in sync
/// with the subcommand checks below when one is added, removed, or renamed.
const USAGE: &str = "\
ct-agent -- CADS Tunnel agent daemon

USAGE:
    ct-agent                    Serve using CT_AGENT_* env config (the default; no
                                 subcommand needed if you already have a routing token)
    ct-agent onboard            Redeem CT_AGENT_JOIN_TOKEN, then serve
    ct-agent rotate             Rotate the origin key, keeping the routing token
    ct-agent certificate        Run the ACME DNS-01 certificate renewal loop
    ct-agent relay-node         Run a Circuit-Relay v2 / DCUtR relay node
    ct-agent channel init                 Mint a fresh channel member identity
    ct-agent channel operator-init        Mint a fresh channel operator identity
    ct-agent channel member-material      Derive this member's channel_id/attestation
    ct-agent channel join-pipeline-role   Derive a published pipeline role's channel_id
    ct-agent channel grant                As operator, sign a member's channel grant
    ct-agent channel invite               As operator, sign a cross-account channel invitation
    ct-agent channel register             Register a channel authority with the CP
    ct-agent channel allowlist add|remove|list   Manage a channel's self-service allow-list
    ct-agent channel agent-card           Write (and optionally register) this agent's card
    ct-agent channel agent-card --verify <file>  Verify a card file's signature/expiry
    ct-agent channel super-peer           Run as an opt-in LAN-local relay for same-network members
    ct-agent channel                      Join a channel (CT_CHANNEL_* env config)
    ct-agent manifest create              Print an UNSIGNED service manifest skeleton
    ct-agent manifest sign                Sign a manifest skeleton with the holder key
    ct-agent manifest publish             PUT a signed manifest to an object-storage URL
    ct-agent manifest activate            Fetch, verify and install a signed manifest

Every subcommand is configured entirely via CT_*/CT_AGENT_*/CT_CHANNEL_* environment
variables, not flags -- see docs.bunsenbrenner.org for the full reference per command.

`manifest` (CADS-agent-marketplace: Compose services since Phase 1, Binary executables since
Phase 5 -- K8s remains a reserved, unexecuted schema slot) reads:
    create    CT_MANIFEST_NAME, CT_MANIFEST_VERSION, CT_MANIFEST_BUNDLE_URL,
              CT_MANIFEST_BUNDLE_SHA256 (64 hex), CT_MANIFEST_COMPOSE_FILE (path inside the
              bundle to the compose file for Compose kind, or the executable for Binary kind),
              CT_MANIFEST_VERIFY_SCRIPT, CT_MANIFEST_VERIFY_TIMEOUT_SECS; optional
              CT_MANIFEST_KIND (compose|binary|k8s, default compose), CT_MANIFEST_ENV_VARS
              (`;`-separated NAME:required:description, NAMES only -- never a secret value) and
              CT_MANIFEST_EXPIRES_IN_SECS (default 31536000).
              Writes the unsigned JSON to stdout; needs no key and no network.
    sign      CT_MANIFEST_HOLDER_KEY (64 hex ed25519 private key, same format as
              CT_CHANNEL_HOLDER_KEY); manifest JSON from CT_MANIFEST_IN or stdin.
              Writes the signed JSON to stdout; no network.
    publish   CT_MANIFEST_PUBLISH_URL (https://); signed JSON from CT_MANIFEST_IN or stdin.
    activate  CT_MANIFEST_URL (https:// URL or local path), CT_MANIFEST_PROJECT_NAME,
              CT_MANIFEST_WORK_DIR, and exactly one of CT_MANIFEST_TRUST_ALLOWLIST
              (comma-separated 64-hex publisher pubkeys) / CT_MANIFEST_TRUST_ALLOWLIST_FILE
              (one per line); optional CT_MANIFEST_ENV_FILE (KEY=value secrets, supplied
              locally, never from the manifest) and CT_MANIFEST_PROTECTED_NAMES (comma-
              separated substrings this install must never collide with). Writes the install
              report JSON to stdout and exits non-zero unless the status is \"ok\".
";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // #248-follow: opt-in only -- quinn and libp2p already emit their own `tracing`
    // spans/events (DCUtR handshake attempts, QUIC connection state, etc.), but with no
    // subscriber installed they go nowhere no matter what env var is set. `RUST_LOG`
    // absent -> zero behavior change (no subscriber installed at all), same off-by-default
    // pattern as `CT_DEBUG_A2A_TIMING`.
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();
    }
    // #248: mark actual process start before anything else, so the always-on
    // uptime/bytes status line (ct_agent::channel_run::traffic_status_line) reports
    // real process uptime even for a long-lived --serve process's first session.
    ct_agent::channel_run::mark_process_start();
    if matches!(std::env::args().nth(1).as_deref(), Some("--help") | Some("-h")) {
        print!("{USAGE}");
        return Ok(());
    }
    // scimbe/ct-agent#14: no way to ask a binary what it is was the second, bigger cost in a
    // real version-skew debugging session (see #12) -- the first thing anyone types to check
    // whether they have the right build now actually works, instead of falling through to the
    // default serve path and hanging.
    if matches!(std::env::args().nth(1).as_deref(), Some("--version") | Some("-V")) {
        println!("ct-agent {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    // `rotate` subcommand (#12 K4): rotate the origin key while KEEPING the
    // routing token, then exit. Re-mints the capability (same token, new origin),
    // retires the old key into CT_AGENT_ORIGIN_KEY_DIR, and promotes the new key.
    // Restart the agent (with that dir set) to serve both identities.
    if std::env::args().nth(1).as_deref() == Some("rotate") {
        let key_path = std::env::var("CT_AGENT_ORIGIN_KEY")
            .map_err(|_| "rotate requires CT_AGENT_ORIGIN_KEY (the primary key path)")?;
        let cap_out = std::env::var("CT_AGENT_CAPABILITY_OUT")
            .unwrap_or_else(|_| "/shared/capability.bin".to_string());
        let dir = std::env::var("CT_AGENT_ORIGIN_KEY_DIR")
            .map_err(|_| "rotate requires CT_AGENT_ORIGIN_KEY_DIR (the retired-key dir)")?;
        let new_cap = ct_agent::capability::rotate_origin_key(&key_path, &cap_out, &dir)?;
        eprintln!(
            "ct-agent: rotated origin key — new capability at {cap_out} (same token, new origin); \
             old key retired to {dir}. Restart the agent to serve both, then distribute the new \
             capability and remove the retired key once the window closes."
        );
        let _ = new_cap;
        return Ok(());
    }

    // `relay-node` subcommand (#136): run the Circuit-Relay v2 + DCUtR relay node --
    // the internal-only counterpart to CADS-Tunnel's edge `:443` relay-gate leg
    // (`crates/edge/src/relay_gate.rs`), which pre-authorizes every connection (grant +
    // possession) BEFORE ever splicing a byte here. This relay's own protocol-level
    // acceptance stays deliberately unguarded (see `ct_agent::p2p::nat_lab_relay`'s doc
    // comment) -- network isolation, not anything checked in this process, is the gate.
    // Never bind CT_RELAY_LISTEN to a publicly reachable address directly.
    if std::env::args().nth(1).as_deref() == Some("relay-node") {
        let listen = std::env::var("CT_RELAY_LISTEN")
            .map_err(|_| "relay-node requires CT_RELAY_LISTEN (e.g. /ip4/0.0.0.0/tcp/4437)")?;
        ct_agent::p2p::nat_lab_relay(&listen).await?;
        return Ok(());
    }

    // `certificate` subcommand (ADR-0003): obtain (and keep renewed) a real,
    // publicly-trusted certificate for this tunnel's hostname via ACME DNS-01 --
    // the agent's own private key never leaves this machine; the operator only
    // ever sees the DNS-01 challenge value, via the control plane's
    // /agent/dns01-challenge (proven by this tunnel's own routing token, never
    // a DNS credential). Writes fullchain.pem/privkey.pem where the origin's own
    // webserver (Caddy) already expects a static cert pair, and re-checks every
    // few hours, only actually contacting the ACME server once renewal is due.
    if std::env::args().nth(1).as_deref() == Some("certificate") {
        let config = ct_agent::acme_orchestrate::AcmeCertConfig::from_env()?;
        ct_agent::acme_orchestrate::run_renewal_loop(config).await;
    }

    // `channel` subcommand (#72 AF4 / #98/#100): bring this agent up as one side of
    // an Agent-Fabric A2A channel and pipe stdin/stdout over the encrypted Noise_IK
    // tunnel to the paired peer. Config comes from CT_CHANNEL_* so it fits a one-liner.
    if std::env::args().nth(1).as_deref() == Some("channel") {
        // #117 `ct-agent channel init`: mint a fresh channel identity LOCALLY and print
        // the copy-pasteable env block (private keys never leave this machine — the
        // self-service, provider-blind alternative to hand-crafted keys / central
        // provisioning). The participant `eval`s it, hands the public keys to the
        // operator, then runs `ct-agent channel` with the operator-supplied grant.
        if std::env::args().nth(2).as_deref() == Some("init") {
            print!("{}", ct_agent::channel_run::ChannelIdentity::generate().env_block());
            return Ok(());
        }
        // #117 `ct-agent channel operator-init`: mint a channel OPERATOR key locally and
        // print its env block (the operator authorizes a channel + signs member grants).
        if std::env::args().nth(2).as_deref() == Some("operator-init") {
            print!("{}", ct_agent::channel_run::OperatorIdentity::generate().operator_env_block());
            return Ok(());
        }
        // #207 `ct-agent channel member-material`: compute the (holder_pubkey, noise_pubkey,
        // channel_id, noise_attestation) a MEMBER hands its operator/central to be admitted to a link
        // channel — so a member never hand-rolls channel_id_for_link / member_noise_attest_bytes.
        // Reads CT_CHANNEL_OPERATOR_PUBKEY + CT_CHANNEL_BRIDGE_HOLDER (from central) + the member's
        // CT_CHANNEL_HOLDER_KEY (private) + CT_CHANNEL_NOISE_PUBKEY. Pure local compute.
        if std::env::args().nth(2).as_deref() == Some("member-material") {
            let req = ct_agent::channel_run::MemberMaterialRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            print!("{}", req.render());
            return Ok(());
        }
        // #214 follow-up `ct-agent channel join-pipeline-role`: the generic-provisioning analogue
        // of `member-material` — derives a PUBLISHED PIPELINE's role channel_id (from
        // CT_CHANNEL_OPERATOR_PUBKEY + CT_PIPELINE_ID + CT_PIPELINE_ROLE, all public/discoverable
        // via GET /registry/pipelines/:id) instead of a pairwise link, so a bridge and a
        // role-serving agent never need to exchange keys before either can compute the same id.
        if std::env::args().nth(2).as_deref() == Some("join-pipeline-role") {
            let req = ct_agent::channel_run::PipelineRoleMaterialRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            print!("{}", req.render());
            return Ok(());
        }
        // #117 `ct-agent channel grant`: as the operator, sign a member's grant (from
        // CT_CHANNEL_OPERATOR_KEY + CT_GRANT_*) and print the CT_CHANNEL_GRANT hex the
        // member uses — self-service admission, no central provisioning.
        if std::env::args().nth(2).as_deref() == Some("grant") {
            let req = ct_agent::channel_run::OperatorGrantRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            println!("{}", req.issue());
            return Ok(());
        }
        // scimbe/ct-agent#9 `ct-agent channel invite`: as the operator, sign an invitation for
        // an identity you don't already have holder/noise material for (the cross-account case
        // `channel grant` can't cover). Reads CT_CHANNEL_OPERATOR_KEY + CT_INVITE_*, pure local
        // compute, mirrors `grant`.
        if std::env::args().nth(2).as_deref() == Some("invite") {
            let req = ct_agent::channel_run::OperatorInviteRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            println!("{}", req.issue());
            return Ok(());
        }
        // #276 piece 2 `ct-agent channel super-peer`: run this process as an opt-in LAN-local
        // relay for other same-network channel members, turning N edge-relay connections into
        // 1 (this process) + N-1 local hops. LISTEN is what LAN-local members point their own
        // CT_CHANNEL_BROKER/CT_CHANNEL_RELAY at instead of the real edge; UPSTREAM is this
        // super-peer's own real edge broker/relay address. Deliberately protocol-unaware --
        // see super_peer.rs's module doc for why a plain byte-transparent relay is the right
        // (and simplest correct) design, preserving the same end-to-end Noise_IK trust
        // boundary as the edge relay itself.
        if std::env::args().nth(2).as_deref() == Some("super-peer") {
            let listen: std::net::SocketAddr = std::env::var("CT_CHANNEL_SUPER_PEER_LISTEN")
                .map_err(|_| "CT_CHANNEL_SUPER_PEER_LISTEN required (host:port LAN clients dial)")?
                .parse()
                .map_err(|e| format!("CT_CHANNEL_SUPER_PEER_LISTEN invalid: {e}"))?;
            let upstream: std::net::SocketAddr = std::env::var("CT_CHANNEL_SUPER_PEER_UPSTREAM")
                .map_err(|_| "CT_CHANNEL_SUPER_PEER_UPSTREAM required (this super-peer's real edge host:port)")?
                .parse()
                .map_err(|e| format!("CT_CHANNEL_SUPER_PEER_UPSTREAM invalid: {e}"))?;
            ct_agent::super_peer::run(listen, upstream).await?;
            return Ok(());
        }
        // #117 `ct-agent channel register`: register the operator's channel authority with
        // the control plane (POST /me/channels, owner = the OIDC subject) so the edge
        // accepts the grants that operator signs — the last CP round-trip that makes an
        // Agent-Fabric channel fully self-service. Reads CT_AGENT_CP_URL + CT_GRANT_CHANNEL
        // + CT_OIDC_TOKEN + the operator key (CT_CHANNEL_OPERATOR_KEY / _PUBKEY).
        if std::env::args().nth(2).as_deref() == Some("register") {
            let req = ct_agent::channel_run::ChannelRegisterRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            ct_control_plane::client::ControlPlaneClient::new(req.cp_url.clone())
                .register_channel(&req.channel_hex, &req.operator_pubkey_hex, &req.token)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
            eprintln!("registered channel {} with the control plane", req.channel_hex);
            return Ok(());
        }
        // #248-follow `ct-agent channel allowlist add|remove|list`: manage a channel's
        // self-service e-mail allow-list from the CLI (owner-scoped, same
        // CT_AGENT_CP_URL/CT_GRANT_CHANNEL/CT_OIDC_TOKEN as `register`) — the CLI
        // counterpart to the portal web UI, so an operator never has to leave the
        // terminal to grant a teammate self-service channel access.
        if std::env::args().nth(2).as_deref() == Some("allowlist") {
            let req = ct_agent::channel_run::ChannelAllowlistRequest::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let client = ct_control_plane::client::ControlPlaneClient::new(req.cp_url.clone());
            match std::env::args().nth(3).as_deref() {
                Some("add") => {
                    let email = std::env::args()
                        .nth(4)
                        .ok_or("usage: ct-agent channel allowlist add <email>")?;
                    client
                        .channel_allowlist_add(&req.channel_hex, &email, &req.token)
                        .await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                    eprintln!("allow-listed {email} on channel {}", req.channel_hex);
                }
                Some("remove") => {
                    let email = std::env::args()
                        .nth(4)
                        .ok_or("usage: ct-agent channel allowlist remove <email>")?;
                    client
                        .channel_allowlist_remove(&req.channel_hex, &email, &req.token)
                        .await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                    eprintln!("removed {email} from channel {}'s allow-list", req.channel_hex);
                }
                Some("list") => {
                    let emails = client
                        .channel_allowlist_list(&req.channel_hex, &req.token)
                        .await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                    if emails.is_empty() {
                        eprintln!("channel {} has no allow-listed emails", req.channel_hex);
                    } else {
                        for email in emails {
                            println!("{email}");
                        }
                    }
                }
                _ => return Err("usage: ct-agent channel allowlist <add|remove|list> [email]".into()),
            }
            return Ok(());
        }
        // #144 ①-wiring `ct-agent channel agent-card`: assemble + sign this agent's holder
        // AgentCard from CT_CHANNEL_HOLDER_KEY + CT_AGENT_CARD_* claims and write it to
        // <CT_AGENT_CARD_OUT>/.well-known/agent-card.json for the origin to serve — the runnable
        // path that closes the discovery chain (no hand-rolled ed25519). Prints the written path.
        if std::env::args().nth(2).as_deref() == Some("agent-card") {
            // `agent-card --verify <file>`: the fetcher/operator self-check — parse the card and
            // re-verify its holder signature + expiry, exiting non-zero on any failure so it
            // scripts cleanly. No key needed; the trust anchor is the signature in the file.
            if std::env::args().nth(3).as_deref() == Some("--verify") {
                let file = std::env::args()
                    .nth(4)
                    .ok_or("usage: ct-agent channel agent-card --verify <file>")?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                    .as_secs();
                let card = ct_agent::well_known::read_and_verify_agent_card(
                    std::path::Path::new(&file),
                    now,
                )
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let holder: String =
                    card.holder_pubkey.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "valid  holder={holder}  role_tags={:?}  expires_at={}",
                    card.role_tags, card.expires_at
                );
                return Ok(());
            }
            let cfg = ct_agent::channel_run::AgentCardCliConfig::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .as_secs();
            let path = cfg.write_card(now)?;
            println!("{}", path.display());
            // #214 follow-up: fold "tell the registry" into the same command when the operator
            // supplied CT_AGENT_CP_URL/CT_AGENT_CARD_URL/CT_CP_EDGE_ADMIN_TOKEN — the empty "AI
            // agents" list on the operator landing page was exactly this manual step never
            // having been run. Absent -> unchanged behavior, just a note that it CAN be automatic.
            match ct_agent::channel_run::AgentCardAutoRegister::from_env() {
                Some(reg) => {
                    let holder_hex: String =
                        cfg.build_card(now).holder_pubkey.iter().map(|b| format!("{b:02x}")).collect();
                    let cp_url = reg.cp_url.clone();
                    ct_control_plane::client::ControlPlaneClient::new(reg.cp_url)
                        .with_admin_token(reg.admin_token)
                        .register_agent(&holder_hex, &reg.card_url, &cfg.role_tags, &cfg.skill_ids())
                        .await
                        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
                    eprintln!("registered at {cp_url}/registry/agents (card_url={})", reg.card_url);
                }
                None => eprintln!(
                    "ct-agent: not auto-registered with /registry/agents — set CT_AGENT_CP_URL, \
                     CT_AGENT_CARD_URL (the https:// URL this card will be served at), and \
                     CT_CP_EDGE_ADMIN_TOKEN to do this automatically next time."
                ),
            }
            return Ok(());
        }
        // scimbe/ct-agent#14: every recognized `channel <subcommand>` above already
        // returned. A THIRD positional arg that isn't one of them is almost certainly a
        // typo'd subcommand (reported live: `channel invite` against a pre-#9 binary that
        // didn't have it fell through here silently and produced a confusing, unrelated
        // "CT_CHANNEL_ROLE must be initiate|accept" error -- indistinguishable from a real
        // env-config mistake). Only `channel` with NO third arg is the legitimate "join a
        // channel via CT_CHANNEL_* env config" mode below; fail loudly otherwise, same
        // #239 discipline already applied to unrecognized top-level subcommands.
        if let Some(sub) = std::env::args().nth(2) {
            const KNOWN: &[&str] = &[
                "init", "operator-init", "member-material", "join-pipeline-role", "grant",
                "invite", "super-peer", "register", "allowlist", "agent-card",
            ];
            if !KNOWN.contains(&sub.as_str()) {
                eprintln!("ct-agent: unrecognized channel subcommand '{sub}'\n");
                eprint!("{USAGE}");
                std::process::exit(1);
            }
        }
        // Plane-brokered flow (#98/#103) when an edge rendezvous is configured: present
        // the grant, learn the peer via the broker (keys relayed), connect
        // direct-then-relay. Otherwise the direct-address path (CT_CHANNEL_ADDR).
        if std::env::var("CT_CHANNEL_BROKER").map(|v| !v.is_empty()).unwrap_or(false) {
            let cfg = ct_agent::channel_run::ChannelJoinCliConfig::from_env()
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            return ct_agent::channel_run::run_channel_join_command(cfg).await;
        }
        let cfg = ct_agent::channel_run::ChannelRunConfig::from_env()
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        return ct_agent::channel_run::run_channel_command(cfg).await;
    }

    // `manifest` subcommand (CADS-agent-marketplace Phase 1): author, sign, publish and install
    // a signed ServiceManifest describing ONE docker-compose service. The three authoring steps
    // are split so the holder key is needed exactly once and never alongside the network:
    // `create` (no key, no network) -> `sign` (key, no network) -> `publish` (network, no key).
    // `activate` is the consuming side and delegates the whole fetch/verify/guardrail/compose/
    // verify pipeline to installer-engine -- nothing here decides whether a publisher is trusted.
    // Config comes from CT_MANIFEST_* (see USAGE); every parser fails loudly on a missing or
    // malformed value rather than guessing a default.
    if std::env::args().nth(1).as_deref() == Some("manifest") {
        match std::env::args().nth(2).as_deref() {
            Some("create") => {
                let cfg = ct_agent::manifest_run::CreateConfig::from_env()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let now = ct_agent::manifest_run::unix_now()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let json = cfg
                    .unsigned(now)
                    .to_json()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                println!("{json}");
                return Ok(());
            }
            Some("sign") => {
                let json = ct_agent::manifest_run::run_sign()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                println!("{json}");
                return Ok(());
            }
            Some("publish") => {
                ct_agent::manifest_run::run_publish()
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                return Ok(());
            }
            Some("activate") => {
                let cfg = ct_agent::manifest_run::ActivateCliConfig::from_env()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                let report = ct_agent::manifest_run::run_activate(cfg)
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
                // The report is the product of the command -- print it either way, then let the
                // exit code carry the verdict so `manifest activate && …` scripts correctly.
                println!("{}", report.to_json());
                if !ct_agent::manifest_run::report_is_ok(&report) {
                    std::process::exit(1);
                }
                return Ok(());
            }
            // Same #239/#14 discipline as `channel` above: a typo'd subcommand must never fall
            // through to the default serve path.
            Some(other) => {
                eprintln!("ct-agent: unrecognized manifest subcommand '{other}'\n");
                eprint!("{USAGE}");
                std::process::exit(1);
            }
            None => {
                eprintln!("ct-agent: `manifest` requires a subcommand (create|sign|publish|activate)\n");
                eprint!("{USAGE}");
                std::process::exit(1);
            }
        }
    }

    // #239: every recognized subcommand above already returned. `onboard` is the
    // one remaining valid arg1 (checked just below); no other value belongs here at
    // all -- serving via env config alone means arg1 is simply *absent*, never some
    // other word. Anything else is almost certainly a typo'd subcommand, and used to
    // silently fall through to the default serve path instead of failing loudly.
    if let Some(arg) = std::env::args().nth(1) {
        if arg != "onboard" {
            eprintln!("ct-agent: unrecognized argument '{arg}'\n");
            eprint!("{USAGE}");
            std::process::exit(1);
        }
    }

    // One-command onboarding: if a join token is present (env or `onboard`
    // subcommand), auto-enroll against the control plane before serving. This
    // is the "install -> enroll -> tunnel" single step — the operator supplies
    // only a control-plane URL and a single-use join token.
    let onboarding = std::env::args().nth(1).as_deref() == Some("onboard")
        || std::env::var("CT_AGENT_JOIN_TOKEN").is_ok();
    let config = if onboarding {
        let env = OnboardEnv::from_env()?;
        let edge = env.config.edge;
        let cp_url = env.cp_url.clone();
        // Onboarding redeems a SINGLE-USE join token. A timeout here that fires
        // after the token is already spent server-side would, on restart, re-onboard
        // with a dead token and never recover (#36). So the timeout is OPT-IN: unset
        // ⇒ wait indefinitely (prior behaviour, resilient); set only where a bounded
        // fail-fast is wanted (CI / the e2e smoke script).
        //
        // #141 restart-safety: with CT_AGENT_STATE_DIR set (a persistent volume), the
        // FIRST boot redeems + persists the bound identity/tenant there and every
        // later boot RESTORES it — so a container restart never replays the spent
        // token into a crash-loop (the help-agent outage). Unset ⇒ prior always-redeem.
        let state_dir = std::env::var("CT_AGENT_STATE_DIR").ok();
        let run = async move {
            match state_dir.as_deref() {
                Some(dir) => onboard_or_restore(
                    &env.cp_url,
                    &env.join_token,
                    env.agent_id,
                    env.config,
                    std::path::Path::new(dir),
                )
                .await
                .map_err(|e| e.to_string()),
                None => env.onboard().await.map_err(|e| e.to_string()),
            }
        };
        let onboarded = match std::env::var("CT_AGENT_ONBOARD_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            Some(secs) => tokio::time::timeout(Duration::from_secs(secs), run)
                .await
                .map_err(|_| format!("ct-agent: onboarding timed out after {secs}s"))??,
            None => run.await?,
        };
        eprintln!(
            "ct-agent: onboarded agent={} tenant={} via {} (edge={})",
            onboarded.agent_id.0, onboarded.tenant.0, cp_url, edge
        );
        onboarded.config
    } else {
        AgentConfig::from_env()?
    };
    let cert_path =
        std::env::var("CT_AGENT_EDGE_CERT").unwrap_or_else(|_| "/shared/edge-cert.der".to_string());
    let cap_out = std::env::var("CT_AGENT_CAPABILITY_OUT")
        .unwrap_or_else(|_| "/shared/capability.bin".to_string());

    // Obtain the Edge CA root. With CT_AGENT_EDGE_CERT_URL set, fetch it from the
    // control plane's published /pki/ca (#11 C2) — self-serve cross-host, no
    // out-of-band copy. Otherwise wait for it on the shared-volume path.
    let edge_cert = if let Ok(url) = std::env::var("CT_AGENT_EDGE_CERT_URL") {
        let der = ct_control_plane::client::ControlPlaneClient::new(url.clone())
            .fetch_edge_cert()
            .await
            .map_err(|e| format!("ct-agent: fetch edge cert from {url}: {e:?}"))?;
        eprintln!(
            "ct-agent: fetched edge cert from {url} ({} bytes)",
            der.len()
        );
        rustls::pki_types::CertificateDer::from(der)
    } else {
        // This wait runs AFTER onboarding has spent the single-use token, so the
        // bound is OPT-IN too: unset ⇒ wait indefinitely for the edge to publish its
        // cert on the shared volume (prior behaviour — an agent that can't re-onboard
        // must not give up), set only for fail-fast (CI / smoke). Log throttling is
        // always on so a long wait doesn't spam the log twice a second.
        let cert_deadline = std::env::var("CT_AGENT_EDGE_CERT_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(|secs| (Instant::now() + Duration::from_secs(secs), secs));
        let cert_log_interval_secs = std::env::var("CT_AGENT_EDGE_CERT_LOG_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(EDGE_CERT_WAIT_LOG_THROTTLE_SECS);
        let mut next_log_at = Instant::now();
        loop {
            let now = Instant::now();
            match load_cert(&cert_path) {
                Ok(cert) => break cert,
                Err(_) => {
                    if let Some((deadline, secs)) = cert_deadline {
                        if now >= deadline {
                            return Err(format!(
                                "ct-agent: edge cert not available within {secs}s at {cert_path}"
                            )
                            .into());
                        }
                    }
                    if now >= next_log_at {
                        eprintln!("ct-agent: waiting for edge cert at {cert_path} ...");
                        next_log_at = now + Duration::from_secs(cert_log_interval_secs);
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    };

    // Resolve the serving identity (Capability + Origin static key). The Agent is
    // custodian of the Origin static Noise keypair; only its public half travels
    // in the Capability. The private half stays here to terminate the E2E
    // handshake (M8.3). With CT_AGENT_ORIGIN_KEY set, the key + capability are
    // persisted/shared so multiple agents can serve one tunnel (redundancy, #8).
    // With CT_AGENT_ORIGIN_KEY_DIR set, additional (retired) origin keys in that
    // directory are also served, so old capabilities keep working during a key
    // rotation window (#12).
    let origin_key_path = std::env::var("CT_AGENT_ORIGIN_KEY").ok();
    let origin_key_dir = std::env::var("CT_AGENT_ORIGIN_KEY_DIR").ok();
    // #27 RB2b: if the portal supplied the tunnel's routing token (CT_AGENT_TOKEN,
    // set by the install one-liner), register at the edge under THAT token so a
    // revocation can find and drop this tunnel. Otherwise mint a random token.
    let forced_token = std::env::var("CT_AGENT_TOKEN")
        .ok()
        .and_then(|s| parse_routing_token_hex(&s));
    let identity = resolve_serving_identity_with_token(
        origin_key_path.as_deref(),
        &cap_out,
        &config.edge.to_string(),
        origin_key_dir.as_deref(),
        forced_token,
    )?;
    eprintln!(
        "ct-agent: edge={} origin={} capability -> {} (serving {} origin identit{}){}",
        config.edge,
        config.origin,
        cap_out,
        identity.origin_keys.len(),
        if identity.origin_keys.len() == 1 {
            "y"
        } else {
            "ies"
        },
        match &origin_key_path {
            Some(p) => format!(", shared origin key {p}"),
            None => String::new(),
        }
    );

    run_agent(
        &config,
        edge_cert,
        identity.cap.token,
        std::sync::Arc::new(identity.origin_keys),
    )
    .await
}
