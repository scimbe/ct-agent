# `ct-agent channel` — reference

The Agent-Fabric channel subsystem: end-to-end encrypted (Noise_IK) sessions between two
members, brokered and — when neither side is dialable — relayed by a CADS-Tunnel edge, which
only ever sees ciphertext. This page collects the operational knowledge that otherwise lives in
code comments and incident issues. Where behavior was learned from a real incident, the issue is
linked — those threads carry the full evidence.

## Modes

| Mode | Selected by | Behavior |
|---|---|---|
| One-shot service call | `CT_CHANNEL_CALL_SERVICE=<slug>` | Join → pair → Noise → **one** `service/<slug>` call (stdin = input, stdout = bare output) → exit. The crew-bridge `CREW_*_CMD` contract. |
| **Persistent call mode** (v0.4.9, [#19](https://github.com/scimbe/ct-agent/issues/19)) | `CT_CHANNEL_CALL_SERVICE=<slug>` **+** `CT_CHANNEL_CALL_PERSISTENT=1` | **One held session** for the process's life; each stdin **line** is one call, each response is one NDJSON envelope line: `{"ok":true,"output":…}` or `{"ok":false,"error":…}` as the structured last line before a non-zero exit. stdin EOF = clean teardown. Measured effect on the sort arena: per-round faults 12–15% → 0%, ~85 ms/round steady state, transport overhead ×27 lower. Will become the **default in v0.5.0** (opt-out `=0`) once the known one-shot consumers migrate. |
| One-shot raw MCP call | `CT_CHANNEL_CALL=<method>` (+ `CT_CHANNEL_CALL_PARAMS`) | One JSON-RPC request/response, prints the whole envelope, exits. |
| Persistent serve | `CT_CHANNEL_ROLE=accept` + `CT_CHANNEL_SERVE=1` | Parks at the broker, serves each paired peer's session **concurrently** (up to `CT_CHANNEL_SERVE_CONCURRENCY`, default 8, [#200]) — a JSON-RPC request loop per session, any number of calls per session. `CT_AGENT_SERVICE_HANDLER_CMD` spawns a fresh handler per request (the handler stays stateless even under a held session). |
| Raw pipe | neither | stdin/stdout spliced over the channel. |

## Transport selection (the dial ladders)

Broker and relay each get a ladder: **direct QUIC** (`CT_CHANNEL_BROKER` :4435 / `CT_CHANNEL_RELAY`
:4436, UDP) first, then — when `CT_CHANNEL_FRONT_DOOR` (+ `_CERT`, hex DER of the edge CA from
`GET <cp>/pki/ca`) is set — the `:443` TLS-TCP front door, then the DPI-resistant boring-ALPN
`:443` rung.

- **`CT_CHANNEL_FRONT_DOOR_ONLY=1`** (v0.4.8, [#16]) drops the direct QUIC rung entirely.
  Refused at parse time without a configured front door.
- **`CT_CHANNEL_RELAY_GATE` (+`_CERT`) — read this before using it** ([#330]): the gate is a
  `:443`-multiplexed **Circuit-Relay v2** path for the NAT-to-NAT hole punch. **Its
  channel-join admission still runs over plain QUIC to the relay port** — the `:443` gate leg
  only carries the post-admission circuit. Two consequences, both live-diagnosed
  (CADS-Tunnel#495 thread, 2026-08-13): a UDP-blocked host cannot use gate mode at all (its
  admission times out before the gate is ever relevant), and even a UDP-capable gate-mode
  member parks in the edge's **QUIC pairer**, where it can never meet a front-door-only peer.

### Pairing reality (until CADS-Tunnel#495 lands)

The edge currently runs **disjoint pairers** per transport class (QUIC relay, `:443`
front door + WebSocket, QUIC rendezvous). Two members pair **only inside the same pairer** — a
mixed-transport pair parks in two different rooms, never meets, and both sides are silently
reaped after the ~30 s park TTL (client-visible as a bogus "edge relay refused the channel join"
~32–41 s in). **Until #495 unifies the pairers: put both halves of a pairing on
`CT_CHANNEL_FRONT_DOOR_ONLY=1`.** Your own first log line tells you which pairer you landed in:
`plane-brokered Accept` = front door (correct for arena-style setups); `Accept via relay-gate` =
QUIC pairer.

## Wire sequence — the big picture

The full first-contact message sequence over the `:443` front door (both members
`FRONT_DOOR_ONLY`, acceptor in `--serve`), every hop of which was packet-verified in
production on 2026-08-14. Two independent phases ride separate TLS connections: the
**rendezvous** (who pairs with whom) and the **relay leg** (the spliced byte pipe the
Noise session runs over).

```mermaid
sequenceDiagram
    participant A as Acceptor (serve)
    participant E as Edge (:443 broker)
    participant I as Initiator
    Note over A,E: Phase 1 — rendezvous admission
    A->>E: TLS (ALPN ct-edge-channel[-ka] / boring h2) + [0xFF,0x01]? + join request
    Note over A,E: v0.4.14: the 2-byte phase preamble rides only on<br/>KA-negotiated legs (0x01 rendezvous, 0x02 relay) —<br/>the edge then pairs marked parks phase-compatibly<br/>(unmarked = legacy mixed behavior)
    E->>A: 32-byte possession challenge
    A->>E: 64-byte signature — connection stays FULLY OPEN (v0.4.12: no half-close)
    Note over E: A parks (TTL 30 s; pump monitors liveness,<br/>KA-negotiated legs get 1 NUL / 10 s)
    alt no partner within TTL
        E->>A: bare EX token + clean FIN (drained, no RST)
        Note over A: ParkExpired → re-park SAME rung,<br/>no ladder advance, no backoff (#21)
    else initiator arrives
        I->>E: join + challenge + signature (same protocol)
        E->>A: OK + peer identity (noise/holder/attestation)\n — newline-terminated, stream stays OPEN
        E->>I: OK + peer identity
        Note over A,I: v0.4.16 (#494): the client completes this ack at its NEWLINE.<br/>Older clients read to EOF — which the :443 edge never sends<br/>(it splices onward on the same stream), so two fresh members<br/>deadlocked on fully-delivered acks until one side's 45 s<br/>stall-timeout death handed the other its EOF. Every fresh<br/>:443 pairing paid 45–100 s; one v0.4.16 side heals the pair<br/>(its prompt close is the peer's EOF).
    end
    Note over A,I: Phase 2 — relay leg (fresh connections)
    A->>E: [0xFF,0x02]? + relay join (#121 relay-only fast-path skips the 8 s accept wait)
    I->>E: relay join (#121 skips the 5 s direct dial)
    Note over E: pairer splices the two LIVE legs<br/>(#499: corpse parks are skipped, never spliced)
    A-->>I: Noise_IK handshake + session (end-to-end, edge is payload-blind)
```

Reading a trace against this picture: every failure of the last two days sat on exactly one
arrow — `EX` lost to an RST race (edge teardown), the park dying as a half-closed flow
(client FIN after the signature), Phase 2 splicing a corpse park (`early eof`, retried on
the 10 s sweep grid), or the Phase 1 ack sitting unread in a pre-v0.4.16 client that waited
for an EOF the `:443` edge never sends (#494 — the week's entire 60–100 s first-contact
class). When a symptom doesn't map to an arrow here, the picture is incomplete — fix the
picture first.

## Failure semantics and timers (what an error actually means)

- **`channel join admission exchange stalled (#140)`** — the 45 s admission-exchange bound
  expired. It is 45 s (not the pre-v0.4.8 15 s) because the edge only acks a pairing-path join
  once the **partner** arrives, and holds a lone first member parked for a 30 s window; the
  bound must outlast that window plus the partner's own ladder walk ([#140], live-pinned
  2026-08-13). Since **v0.4.16** this line means what it says — no partner showed up.
  **Before v0.4.16 it fired on every fresh `:443` pairing even with both partners present**:
  the rendezvous ack read was `take(512).read_to_end`, completing only at EOF/512 bytes,
  while the `:443` edge acks `OK …\n` and keeps the stream open for the splice — both fresh
  members deadlocked on delivered acks until one side's timeout death handed the other its
  EOF (CADS-Tunnel#494; field-confirmed fixed: 8/8 fresh first contacts 124–823 ms). The
  read now completes at the newline or at EOF (QUIC's delimiter-free `finish()`, `NO`/`EX`
  teardowns); since **v0.4.18** reaching the 512-byte cap without a terminator is a hard
  protocol error on both legs (`channel ack exceeded 512 bytes without a terminator`) —
  the normative ack contract lives in `channel.rs`'s module header (#23).
- **`… pairing dropped after admission before the edge ack — a transport/handoff race
  (… #148) … retry`** — the leg closed with **zero** ack bytes after the possession
  handshake completed. Retryable on **both** legs since **v0.4.18** (typed
  `DroppedLegBeforeAck`, #23): a genuine refusal is always an explicit `NO`. Before
  v0.4.18 the **rendezvous** leg silently classified this as `Refused` and paid the
  [#231] definitive 30 s backoff for what is a transport race.
- **`edge broker/relay refused the channel join`** — a definitive wire `NO` (e.g. not a member).
  The serve loop backs off exponentially on consecutive refusals (cap 30 s, [#231]) — a
  not-member holder cannot fix itself by retrying. Since **v0.4.18** the relay-gate /
  circuit-relay DCUtR serve loops obey the same policy (#24) — they previously re-admitted
  at a flat 200 ms forever regardless of the error class — and a one-shot caller stops
  immediately on a definitive refusal; circuit-relay error lines now say `circuit-relay`
  (they printed `relay-gate` from a copied loop body).
- **`channel park expired ... (#21) -- re-parking`** — the edge reaped an idle park and SAID so
  (bare `EX` on stream legs, a named `park-expired:` close reason on QUIC). Not an error in any
  operational sense: the member re-parks the same rung immediately, with no ladder advance and
  no backoff. A healthy idle serve loop cycles this line every 30 s (the park TTL). Requires
  v0.4.12 on NAT'd paths — v0.4.11 half-closed the parked leg after the possession signature,
  which put the flow into the NAT's short FIN-WAIT timer and ate the `EX` on the way back.
- **`early eof`** right after pairing — historically ambiguous; the dominant cause (the splice
  ran against a **corpse park** left by a peer process that died while parked, retried on the
  edge's 10 s sweep grid → the N×10 s first-contact staircase) is fixed edge-side since #499
  slice B (corpses are live-flagged and never spliced). The second structural cause —
  **phase-mixed pairing** (a relay leg spliced against a rendezvous park whose client reads
  the ack and closes) — is fixed by the v0.4.14 phase preamble + the edge's phase-compatible
  pairing (CADS-Tunnel#495 slice 2a); legacy/unmarked joins keep the historical mixed
  behavior. Remaining causes: a mode/config mismatch such as gate mode without reachable
  QUIC. ([#18] closed 2026-08-14 as superseded — its first-contact premise resolved into
  the #494 ack deadlock plus the already-fixed corpse/supersede classes.)
- **Flap backoff (v0.4.10, [#250])**: a session that dies within 500 ms of pairing is a "flap";
  3+ consecutive flaps back off exponentially (cap 10 s) before the next admit — a peer whose
  connection is killed post-handshake (AV/DPI middleboxes are the leading field cause) no longer
  drives a pair-and-die storm at native RTT speed. Any session that succeeds or simply lives
  ≥500 ms resets the streak (real arena rounds run ~85 ms *inside* an already-held session; a
  fresh session that does real work runs well past 500 ms).

## Registration (the Browser-Plane/mesh tunnel, not channels — but same binary)

Since v0.4.7 ([#16]) a **mid-life** UDP failure falls back to TLS-TCP (pool, [#229]) and probes
QUIC every 30 s to upgrade back — previously only the *first* dial ever fell back, so a UDP flap
took the tunnel down for its whole duration. `CT_AGENT_REGISTER_TCP_ONLY=1` pins registration to
TLS-TCP outright (combine with `CT_AGENT_FALLBACK_443=1` for the `:443` front door).

## Environment variables (channel subsystem)

| Variable | Meaning |
|---|---|
| `CT_CHANNEL_ROLE` | `initiate` \| `accept` |
| `CT_CHANNEL_BROKER` / `CT_CHANNEL_RELAY` | edge rendezvous / relay `host:port` (QUIC/UDP) |
| `CT_CHANNEL_GRANT` / `CT_CHANNEL_HOLDER_KEY` / `CT_CHANNEL_NOISE_KEY` | the member's grant + private keys (secrets) |
| `CT_CHANNEL_LISTEN` / `CT_CHANNEL_ADVERTISE` | direct-path bind / advertised address (see the README's opt-in warning) |
| `CT_CHANNEL_RELAY_ONLY=1` | no dialable address; relay-only member (auto-detected from a non-global advertise address) |
| `CT_CHANNEL_FRONT_DOOR` / `_CERT` / `_ONLY` | `:443` TLS-TCP fallback rungs; `_ONLY=1` skips direct QUIC (v0.4.8) |
| `CT_CHANNEL_RELAY_GATE` / `_CERT` | #330 Circuit-Relay gate (admission still needs QUIC — see above) |
| `CT_CHANNEL_CALL_SERVICE` / `CT_CHANNEL_CALL_PERSISTENT` | service-call modes (see table above) |
| `CT_CHANNEL_SERVE` / `CT_CHANNEL_SERVE_CONCURRENCY` | accept-side persistent serve, session cap (default 8) |
| `CT_CHANNEL_DIRECT_UPGRADE=1` | opt-in in-band relay→direct upgrade (#104) |
| `CT_AGENT_SERVICE_HANDLER_CMD` / `CT_AGENT_SERVICES` | the handler command + offered service slugs on the serve side |

[#16]: https://github.com/scimbe/ct-agent/issues/16
[#18]: https://github.com/scimbe/ct-agent/issues/18
[#140]: https://github.com/scimbe/ct-agent/issues/15
[#200]: https://github.com/scimbe/ct-agent/issues/15
[#229]: https://github.com/scimbe/ct-agent/issues/16
[#231]: https://github.com/scimbe/ct-agent/issues/15
[#250]: https://github.com/scimbe/ct-agent/issues/15
[#330]: https://github.com/scimbe/ct-agent/issues/16
