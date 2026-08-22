//! CLI-Konfiguration und Zerlegung fuer die `ct-agent channel`-Unterbefehle.
//!
//! Herausgeloest aus `channel_run/mod.rs` (Konsolidierungsprogramm, Modulsplit): reine
//! Zerlegung und Gueltigkeitspruefung von Umgebungs-/CLI-Werten, ohne Sitzungszustand und
//! ohne Protokolllogik. Das war die sauberste Naht in einer 3200-Zeilen-Datei -- die
//! Grenze verlaeuft entlang einer Zustaendigkeit, nicht entlang einer Zeilenzahl.
//!
//! Reiner Verschiebeschnitt: kein Verhalten geaendert. Sichtbarkeiten wurden nur so weit
//! geoeffnet, wie der Umzug es verlangt (`pub(crate)` statt privat), damit `mod.rs` und die
//! Testdatei dieselben Namen wie zuvor sehen.

use super::*;

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// ct-agent#26: is `der` structurally a DER certificate?
///
/// `CT_CHANNEL_FRONT_DOOR_CERT` is a ~740-character unbroken hex string that a human copies
/// out of a join page. The reported failure was one byte lost at a terminal line-wrap — the
/// leading `0x30` (SEQUENCE) of the SubjectPublicKeyInfo. The result is still valid hex of
/// even length, so `hex_bytes` accepted it happily and the corruption only surfaced much
/// later as a generic TLS/connection error, i.e. indistinguishable from the DPI/firewall
/// mysteries this thread had already been chasing for weeks.
///
/// The check is deliberately structural rather than a full X.509 parse: outer tag must be
/// SEQUENCE, the definite length must be well-formed, and the declared length must match the
/// bytes actually present. That is exactly enough to catch a truncated, over-long or
/// wrong-start value — the transcription damage this exists for — and it does not pretend to
/// judge whether the certificate is valid, current or the right one. Saying which of the two
/// it proves matters: a check that quietly implied "this is a good certificate" would be a
/// worse lie than no check.
///
/// Returns `Err(reason)` naming what was wrong and where, so the message can be acted on.
pub(crate) fn der_certificate_shape(der: &[u8]) -> Result<(), String> {
    let n = der.len();
    if n < 2 {
        return Err(format!("only {n} byte(s) -- far too short for a certificate"));
    }
    if der[0] != 0x30 {
        return Err(format!(
            "starts with 0x{:02x}, expected 0x30 (ASN.1 SEQUENCE) -- the usual cause is a \
             byte lost at the start, e.g. at a line wrap while copying",
            der[0]
        ));
    }
    // Definite length: short form (<=0x7f) or long form (0x80 | count-of-length-bytes).
    let first = der[1] as usize;
    let (declared, header) = if first < 0x80 {
        (first, 2usize)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return Err(format!("length header byte 0x{first:02x} is not a usable definite length"));
        }
        if n < 2 + count {
            return Err(format!("truncated inside the length header ({n} bytes total)"));
        }
        let mut v = 0usize;
        for b in &der[2..2 + count] {
            v = (v << 8) | *b as usize;
        }
        (v, 2 + count)
    };
    let expected = header + declared;
    if expected != n {
        return Err(format!(
            "declares {declared} content byte(s) (total {expected}) but {n} byte(s) were given \
             -- {} byte(s) {}",
            expected.abs_diff(n),
            if expected > n { "missing" } else { "too many" }
        ));
    }
    Ok(())
}

/// Decode a run of ASCII hex digits into bytes.
///
/// The ASCII-hex check comes BEFORE any indexed slicing: `&s[i..i+2]` on unchecked `&str`
/// input can land mid multi-byte-UTF-8-char and panic instead of returning `None` -- the
/// #417 / `grant/src/main.rs::from_hex32` bug class this codebase has already hit five
/// times (`capability.rs`, `admin.rs`, `edge_mesh.rs`, `payment_provider.rs` x2, the
/// supervisor binary). This value is exactly the kind of input that trips it: holder keys
/// and DER certificates (`CT_CHANNEL_FRONT_DOOR_CERT`/`CT_CHANNEL_RELAY_GATE_CERT`/
/// `CT_CHANNEL_PEER_CERT`) copied by hand out of a join page, where `der_certificate_shape`'s
/// own doc comment already documents one field transcription mishap on this exact value.
pub(crate) fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let digits = s.trim().as_bytes();
    if digits.is_empty() || digits.len() % 2 != 0 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for i in 0..digits.len() / 2 {
        let hi = (digits[2 * i] as char).to_digit(16)?;
        let lo = (digits[2 * i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

pub(crate) fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex_bytes(s)?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

/// #190: the shared "required env field" parses the CliConfig `from_lookup` parsers repeat. Each was
/// hand-rolling `f(K).and_then(hex32).ok_or("K required (…)")` per field (~a dozen times across the
/// channel-session, grant, register, agent-card and offer parsers), duplicating both the boilerplate
/// and the `X required (…)` message format. These centralise it. `f` is the same env lookup every
/// parser already takes; `what` is the parenthetical hint. Behaviour is byte-identical to the inlined
/// forms (same message text), so a missing var still fails loudly at startup with the exact same error.
pub(crate) fn req_str<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<String, String> {
    f(key).ok_or_else(|| format!("{key} required ({what})"))
}
/// Required 32-byte hex env field: present, valid 64-hex → `[u8;32]`; else the `X required (…)` error.
pub(crate) fn req_hex32<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<[u8; 32], String> {
    f(key).as_deref().and_then(hex32).ok_or_else(|| format!("{key} required ({what})"))
}
/// Required ed25519 key env field: [`req_hex32`] + `SigningKey::from_bytes` (the seed is validated 32 bytes).
pub(crate) fn req_key<F: Fn(&str) -> Option<String>>(f: &F, key: &str, what: &str) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&req_hex32(f, key, what)?))
}
/// Optional 32-byte hex env field: absent or malformed → `None` (the caller decides what that means).
pub(crate) fn opt_hex32<F: Fn(&str) -> Option<String>>(f: &F, key: &str) -> Option<[u8; 32]> {
    f(key).as_deref().and_then(hex32)
}

/// Split a comma-separated env value into trimmed, non-empty tokens (empty input → no tokens).
pub(crate) fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Configuration for `ct-agent channel agent-card` (#144 ①-wiring): assemble + sign this
/// agent's holder [`AgentCard`](ct_common::channel::AgentCard) from `CT_CHANNEL_HOLDER_KEY`
/// plus the advertised claims, and write it to `<CT_AGENT_CARD_OUT>/.well-known/agent-card.json`
/// for the operator's origin to serve — the runnable path that closes the emit chain without
/// anyone hand-rolling ed25519. Env-parsed with the clock injected at [`write_card`], so the
/// assembly is a pure, testable function.
pub struct AgentCardCliConfig {
    /// The holder ed25519 signing key the card is bound to (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    pub holder: SigningKey,
    /// Advertised role tags (`CT_AGENT_CARD_ROLES`, comma-separated) — at least one required.
    pub role_tags: Vec<String>,
    /// Advertised skills (`CT_AGENT_CARD_SKILLS`, `;`-separated `id|description` entries).
    pub skills: Vec<ct_common::channel::Skill>,
    /// Self-asserted cells (`CT_AGENT_CARD_CELLS`, comma-separated 64-hex) — usually empty.
    pub cells: Vec<ct_common::channel::CellId>,
    /// Channels the agent advertises reachability via (`CT_AGENT_CARD_CHANNELS`, comma-separated 64-hex).
    pub channels: Vec<ct_common::channel::ChannelId>,
    /// Validity window in seconds (`CT_AGENT_CARD_TTL_SECS`, default 86400).
    pub ttl_secs: u64,
    /// Directory the `.well-known/agent-card.json` is written under (`CT_AGENT_CARD_OUT`, default `.`).
    pub out_dir: std::path::PathBuf,
}

impl AgentCardCliConfig {
    /// Read the config from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let holder = req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex")?;
        let role_tags = split_csv(f("CT_AGENT_CARD_ROLES").as_deref().unwrap_or_default());
        if role_tags.is_empty() {
            return Err("CT_AGENT_CARD_ROLES required (comma-separated role tags)".to_string());
        }
        let skills = parse_card_skills(f("CT_AGENT_CARD_SKILLS").as_deref().unwrap_or_default());
        let channels = parse_hex32_ids(f("CT_AGENT_CARD_CHANNELS").as_deref().unwrap_or_default())
            .map_err(|bad| format!("CT_AGENT_CARD_CHANNELS entry not 64 hex: {bad}"))?
            .into_iter()
            .map(ct_common::channel::ChannelId)
            .collect();
        let cells = parse_hex32_ids(f("CT_AGENT_CARD_CELLS").as_deref().unwrap_or_default())
            .map_err(|bad| format!("CT_AGENT_CARD_CELLS entry not 64 hex: {bad}"))?
            .into_iter()
            .map(ct_common::channel::CellId)
            .collect();
        let ttl_secs = match f("CT_AGENT_CARD_TTL_SECS").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => s
                .parse::<u64>()
                .map_err(|e| format!("CT_AGENT_CARD_TTL_SECS invalid: {e}"))?,
            _ => 86_400,
        };
        let out_dir = std::path::PathBuf::from(
            f("CT_AGENT_CARD_OUT").unwrap_or_else(|| ".".to_string()),
        );
        Ok(Self { holder, role_tags, skills, cells, channels, ttl_secs, out_dir })
    }

    /// Assemble + sign the agent's card (`issued_at = now`, `expires_at = now + ttl_secs`). The clock
    /// is a parameter so the assembly is deterministic + testable. Shared by [`write_card`] (emit to
    /// the origin) and the `agent/card` MCP tool (serve the identity over the authenticated channel).
    pub fn build_card(&self, now: u64) -> ct_common::channel::AgentCard {
        ct_common::channel::AgentCard::sign_new(
            &self.holder,
            self.role_tags.clone(),
            self.skills.clone(),
            self.cells.clone(),
            self.channels.clone(),
            now,
            now.saturating_add(self.ttl_secs),
        )
    }

    /// Sign the card and write it to `<out_dir>/.well-known/agent-card.json`. Returns the written path.
    pub fn write_card(&self, now: u64) -> std::io::Result<std::path::PathBuf> {
        crate::well_known::write_agent_card_for_origin(&self.build_card(now), &self.out_dir)
    }

    /// This card's role tags as its `skill_ids` for `POST /registry/agents` (the id half of each
    /// [`Skill`](ct_common::channel::Skill), matching what the directory search matches against).
    pub fn skill_ids(&self) -> Vec<String> {
        self.skills.iter().map(|s| s.id.clone()).collect()
    }
}

/// Optional auto-registration inputs for `ct-agent channel agent-card` (#214 follow-up: automatic
/// agent discoverability). Publishing a card used to be TWO separate manual steps — write it
/// locally, then remember to also `POST` it to `/registry/agents` — and the second step was easy
/// to forget entirely (the empty "AI agents" list on the operator landing page was exactly this:
/// nobody had ever run it). When all three of `CT_AGENT_CP_URL`/`CT_AGENT_CARD_URL`/
/// `CT_CP_EDGE_ADMIN_TOKEN` are present, `agent-card` folds both into one command. Absent →
/// unchanged behavior (card written locally only) — this is purely additive, opt-in by presence.
pub struct AgentCardAutoRegister {
    /// Control-plane base URL (`CT_AGENT_CP_URL`, same var other subcommands use).
    pub cp_url: String,
    /// The public `https://` URL this card will be served at once written (`CT_AGENT_CARD_URL`) —
    /// the CP rejects anything else (SSRF defence-in-depth).
    pub card_url: String,
    /// The shared machine-writer admin token (`CT_CP_EDGE_ADMIN_TOKEN`) — self-registration is
    /// gated by this, not an OIDC bearer, since an autonomous agent has no interactive login (#161).
    pub admin_token: String,
}

impl AgentCardAutoRegister {
    /// `None` if any required var is absent — auto-registration is opt-in, never required.
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env).
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let present = |k: &str| f(k).filter(|s| !s.trim().is_empty());
        Some(Self {
            cp_url: present("CT_AGENT_CP_URL")?,
            card_url: present("CT_AGENT_CARD_URL")?,
            admin_token: present("CT_CP_EDGE_ADMIN_TOKEN")?,
        })
    }
}

/// CLI/env config for a **`CapacityOffer`** (#152 — the seller side of the #147 marketplace over the
/// `ct-agent` CLI, mirroring [`AgentCardCliConfig`]). When these vars are present, `--serve` mode also
/// exposes the `auction/offer` + `auction/bid` MCP tools so an operator can stand up a live offer and
/// have a live bid clear against it over a real authenticated channel — the `#144`-style live proof for
/// the marketplace. The holder key is reused from `CT_CHANNEL_HOLDER_KEY` (same as the card).
pub struct AgentOfferCliConfig {
    /// The holder ed25519 signing key the offer is bound to (`CT_CHANNEL_HOLDER_KEY`, hex). SECRET.
    signing_key: SigningKey,
    /// Capacity kind (`CT_AGENT_OFFER_KIND` = `cloud` | `local`).
    kind: ct_common::channel::CapacityKind,
    /// Model ids served (`CT_AGENT_OFFER_MODELS`, comma-separated) — at least one required.
    models: Vec<String>,
    /// Units offered (`CT_AGENT_OFFER_UNITS`).
    units_available: u64,
    /// The buyer's guaranteed-minimum floor (`CT_AGENT_OFFER_MIN_PRICE`).
    min_price: u64,
    /// Opaque settlement-currency id (`CT_AGENT_OFFER_CURRENCY`).
    currency_id: String,
    /// Validity window in seconds (`CT_AGENT_OFFER_TTL_SECS`, default 86400).
    ttl_secs: u64,
    /// #149-A.3 per-consumer bid rate limit (`CT_AGENT_OFFER_MAX_BIDS`, default 60).
    pub max_bids_per_window: u32,
    /// Rate-limit window (`CT_AGENT_OFFER_WINDOW_SECS`, default 60).
    pub window_secs: u64,
    /// #167/#149-A.1: the service catalog this offer **declares** (`CT_AGENT_OFFER_SERVICES`,
    /// comma-separated slugs). Empty = a generic offer that declares no services. This is the
    /// signed, buyer-verifiable ceiling on which `service/<slug>` tools the agent may register —
    /// so what a `CapacityOffer` claims and what the agent actually serves can no longer drift.
    pub services: Vec<ct_common::channel::ServiceType>,
}

impl AgentOfferCliConfig {
    /// Read the config from the process environment.
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Parse from a variable lookup (the `from_env` seam — testable without touching the real env). An
    /// absent required var is an `Err`, which the caller treats as "no offer configured" (auction tools
    /// stay off), exactly like the card path.
    pub fn from_lookup(f: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let signing_key = req_key(&f, "CT_CHANNEL_HOLDER_KEY", "64 hex")?;
        let kind = match f("CT_AGENT_OFFER_KIND").as_deref().map(str::trim) {
            Some("cloud") | Some("cloud-api") | Some("CloudApiQuota") => {
                ct_common::channel::CapacityKind::CloudApiQuota
            }
            Some("local") | Some("local-hardware") | Some("LocalHardware") => {
                ct_common::channel::CapacityKind::LocalHardware
            }
            Some(other) if !other.is_empty() => {
                return Err(format!("CT_AGENT_OFFER_KIND must be 'cloud' or 'local', got '{other}'"))
            }
            _ => return Err("CT_AGENT_OFFER_KIND required ('cloud' or 'local')".to_string()),
        };
        let models = split_csv(f("CT_AGENT_OFFER_MODELS").as_deref().unwrap_or_default());
        if models.is_empty() {
            return Err("CT_AGENT_OFFER_MODELS required (comma-separated model ids)".to_string());
        }
        let req_u64 = |var: &str| -> Result<u64, String> {
            f(var)
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{var} required"))?
                .parse::<u64>()
                .map_err(|e| format!("{var} invalid: {e}"))
        };
        let units_available = req_u64("CT_AGENT_OFFER_UNITS")?;
        let min_price = req_u64("CT_AGENT_OFFER_MIN_PRICE")?;
        let currency_id = f("CT_AGENT_OFFER_CURRENCY")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or("CT_AGENT_OFFER_CURRENCY required")?;
        let opt_u64 = |var: &str, default: u64| -> Result<u64, String> {
            match f(var).as_deref().map(str::trim) {
                Some(s) if !s.is_empty() => s.parse::<u64>().map_err(|e| format!("{var} invalid: {e}")),
                _ => Ok(default),
            }
        };
        let ttl_secs = opt_u64("CT_AGENT_OFFER_TTL_SECS", 86_400)?;
        let window_secs = opt_u64("CT_AGENT_OFFER_WINDOW_SECS", 60)?;
        let max_bids_per_window = match f("CT_AGENT_OFFER_MAX_BIDS").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                s.parse::<u32>().map_err(|e| format!("CT_AGENT_OFFER_MAX_BIDS invalid: {e}"))?
            }
            _ => 60,
        };
        // #167: the offer's declared service catalog. Comma-separated slugs (same vocabulary as
        // `CT_AGENT_SERVICES`). #382 follow-up: a slug outside the four fixed variants is no
        // longer a hard config error -- it's a real, signed `ServiceType::Custom` declaration
        // (e.g. `static_analysis`), so an operator can offer a pipeline-designer-declared service
        // in a real, buyer-verifiable CapacityOffer without a CADS-Tunnel core release per new
        // service name. `parse_service_type` only returns `None` for an empty token, which the
        // filter below already excludes -- the `None` arm stays as a defensive, never-actually-
        // reached safety net rather than an assumption baked in silently. Absent/empty var =
        // a generic offer (unchanged).
        let services = match f("CT_AGENT_OFFER_SERVICES").as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => {
                let mut out = Vec::new();
                for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                    match parse_service_type(tok) {
                        Some(st) => out.push(st),
                        None => return Err("CT_AGENT_OFFER_SERVICES has an empty entry (check for a stray comma)".to_string()),
                    }
                }
                out
            }
            _ => Vec::new(),
        };
        Ok(Self {
            signing_key,
            kind,
            models,
            units_available,
            min_price,
            currency_id,
            ttl_secs,
            max_bids_per_window,
            window_secs,
            services,
        })
    }

    /// Assemble + sign the offer (`issued_at = now`, `expires_at = now + ttl_secs`). The clock is a
    /// parameter so the assembly is deterministic + testable, exactly like [`AgentCardCliConfig::build_card`].
    pub fn build_offer(&self, now: u64) -> ct_common::channel::CapacityOffer {
        // #167: when a service catalog is declared, sign it into the offer (so a buyer can
        // cryptographically verify which services the agent offers, and `#149-A.1`'s `match_offer`
        // service filter actually has something to enforce). An empty catalog keeps the historical
        // generic offer (`sign_new`) so nothing changes for offers that make no service claims.
        if self.services.is_empty() {
            ct_common::channel::CapacityOffer::sign_new(
                &self.signing_key,
                self.kind,
                self.models.clone(),
                self.units_available,
                self.min_price,
                self.currency_id.clone(),
                now,
                now.saturating_add(self.ttl_secs),
            )
        } else {
            ct_common::channel::CapacityOffer::sign_new_with_services(
                &self.signing_key,
                self.kind,
                self.models.clone(),
                self.units_available,
                self.min_price,
                self.currency_id.clone(),
                now,
                now.saturating_add(self.ttl_secs),
                self.services.clone(),
            )
        }
    }
}

/// Parse `CT_AGENT_CARD_SKILLS`: `;`-separated entries, each `id|description` (a bare `id`
/// yields an empty description). Empty/blank entries are dropped. Examples are left empty —
/// the card is a discovery advertisement, not an invocation contract.
pub(crate) fn parse_card_skills(s: &str) -> Vec<ct_common::channel::Skill> {
    s.split(';')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|entry| {
            let (id, description) = match entry.split_once('|') {
                Some((i, d)) => (i.trim().to_string(), d.trim().to_string()),
                None => (entry.to_string(), String::new()),
            };
            ct_common::channel::Skill { id, description, examples: Vec::new() }
        })
        .collect()
}

/// Parse a comma-separated list of 64-hex tokens into `[u8; 32]`s. Returns the first
/// malformed token as `Err` so the caller can name the offending field.
pub(crate) fn parse_hex32_ids(s: &str) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        out.push(hex32(tok).ok_or_else(|| tok.to_string())?);
    }
    Ok(out)
}
