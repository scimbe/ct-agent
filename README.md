# ct-agent

Customer-run, outbound-only agent for [CADS-Tunnel](https://github.com/scimbe/CADS-Tunnel)
— a zero-knowledge tunnel. `ct-agent` is the custodian of your Origin's private key; the
tunnel operator never sees it. It dials out to a CADS-Tunnel edge, maintains the tunnel,
and (via the `certificate` subcommand) drives self-service ACME certificate issuance
across the Rot → Gelb → Grün tiers, using its own account key end to end.

> **The one opt-in exception:** an Agent-Fabric channel member normally only ever dials
> *out* — the edge broker/relay is the only thing it ever reaches, and it never accepts
> a connection from the open internet. `CT_CHANNEL_ADVERTISE` (see `ct-agent channel`)
> lets an operator running **directly on a host they control** (not this project's own
> managed/containerized deployments) advertise a real, directly-dialable address for a
> peer-to-peer data path instead. It is off by default — unset, nothing changes — and
> using it means *you* deliberately opened that port on *your own* box; nobody upstream
> of `ct-agent` does it for you. Once open, the socket is technically reachable by
> anyone, but only the channel's own operator-signed grant + Noise_IK possession
> challenge admits a session — an unauthenticated peer that reaches the port gets
> nothing. This platform's own hosted demos/agents never set it and stay relay-only.

This repo is its own related project, extracted from the
[CADS-Tunnel](https://github.com/scimbe/CADS-Tunnel) monorepo (the core system: control
plane + edge) and published separately so it can be downloaded and installed without
cloning the whole tunnel/edge/control-plane workspace. See that repo's docs (`docs/adr`,
`docs/agent-onboarding.md`) for the full system design — and **[docs/channel.md](docs/channel.md)**
for the `ct-agent channel` reference (modes incl. the persistent call mode that is the default
since v0.5.0, transport ladders, the front-door-only pairing guidance, the opt-in TCP forward, and
what each failure message actually means). Step-by-step paths are in
**[docs/quickstarts.md](docs/quickstarts.md)**.

## Tunnel or channel?

`ct-agent` does two different jobs. Pick by who has to reach whom.

| | **Tunnel** | **Channel** |
|---|---|---|
| What it is | Publishes one service of yours under a public hostname | An end-to-end encrypted session between two members of an Agent-Fabric channel |
| Who can reach it | Anyone who can reach the hostname (browser, `curl`, `ssh`) | Only the two paired members, admitted by an operator-signed grant |
| Path | Agent dials out to the edge; the edge relays clients to it (QUIC first, TLS over TCP `:443` as fallback) | Both members dial out to the edge's broker and relay, which only see ciphertext (Noise_IK); QUIC first, then the `:443` front door |
| Login / credentials | Routing token from the portal (bootstrap token for the first start); a certificate for Grün | Member keys and a grant; an OIDC login (`ct-agent login`) for the operator only |
| Command | `ct-agent` (serve) | `ct-agent channel …` |
| Use it for | Websites and services for the public or for your own users | Agent-to-agent calls, pipes, and private TCP access that must not be public |

| | Over a tunnel | Over a channel |
|---|---|---|
| **SSH** | `ssh <hostname>`; `ct-agent ssh` is the ProxyCommand and speaks TLS to the edge on `:443`. The agent terminates TLS with the hostname's certificate and checks an owner key before sshd sees a byte. Needs tier Grün. | No `ssh` subcommand: the opt-in TCP forward (`CT_CHANNEL_FORWARD`) maps a loopback port on the client to `127.0.0.1:22` of the accepting member. Nothing is published; access is limited to the paired member. |

Quickstarts: [Tunnel](docs/quickstarts.md#1-tunnel) ·
[Channel](docs/quickstarts.md#2-channel) ·
[SSH over a tunnel](docs/quickstarts.md#3-ssh-over-a-tunnel) ·
[SSH over a channel](docs/quickstarts.md#4-ssh-over-a-channel)

## Install and first tunnel (recommended)

A guided setup script that checks your environment, walks you through a `.env`
file, optionally grabs a starter site template, installs + onboards the agent
(directly on this host, or as a Docker container), and reports your tunnel's
certificate tier (Rot/Gelb/Grün) with the exact commands to stop/reset it or go
from Gelb to Grün:

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash
```

```powershell
# Windows
irm https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.ps1 | iex
```

Add `--docker`/`-Docker` to run as a container instead of directly on the host (the
direct-host path is meant for an isolated VM/container/dedicated host — the script
warns about this before proceeding). See `scripts/setup.sh --help` for all flags.

**CLI only** (`ct-agent ssh`, `ssh-config`, `login`, `channel …`): these take everything
via flags and need no `.env`, tunnel config or running agent. Install just the binary:

```bash
curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash -s -- --client-only
```

This is the one supported way to install `ct-agent` — it downloads the right
[prebuilt release binary](https://github.com/scimbe/ct-agent/releases) for your
OS/arch itself, so there's no separate manual-download path to keep in sync. If
you're contributing to `ct-agent` itself, `cargo build --release` (Rust 1.85+) works
as usual from a clone of this repo.

Releases ship `ct-agent` and `ct-agent-supervisor` for Linux (x86_64, i686, aarch64), macOS
(x86_64, aarch64) and Windows (x86_64, i686, aarch64). Binary activations of `ct-agent manifest`
are refused on Windows (compose manifests and `manifest plan` work there).

## Subcommands

`ct-agent --help` is the reference; every subcommand is configured through `CT_*` environment
variables, and a mistyped subcommand fails instead of starting the agent.

| Group | Subcommands |
|---|---|
| Serve a tunnel | `ct-agent` (default), `onboard`, `rotate`, `certificate` (ACME DNS-01 renewal loop) |
| Account | `login` (OIDC device grant), `signup <name>` (self-service tunnel creation) |
| Operate | `status`, `update`, `doctor sandbox`, `local-auth set\|reset\|rotate\|link\|links\|link-revoke`, `relay-node` |
| SSH | `ssh <hostname>`, `ssh-config <hostname>`, `ssh-owner show\|init` |
| Channels | `channel` (join), `channel init`, `operator-init`, `member-material`, `join-pipeline-role`, `grant`, `invite`, `bind-topology`, `register [--rekey]`, `allowlist`, `agent-card`, `super-peer`, `health [readyz\|healthz]` |
| Marketplace | `manifest create\|sign\|publish\|activate\|plan`, `harness run [--plan]` |

`ct-agent update` replaces the binary in place and checks every download against the release's
published checksum (and its signed manifest, once a release key is pinned in the build). `CT_AGENT_AUTO_UPDATE=1` does this in the background while
serving; it only takes effect if something restarts the process (see `ct-agent-supervisor` below).

## `ct-agent-supervisor` (#331)

A second binary ships beside `ct-agent`: a thin external wrapper that spawns the real agent
as a child, classifies **why** it exited, restarts it with backoff on a crash loop, and keeps
a short crash history. `ct-agent` itself is unchanged by it.

Usage is identical to `ct-agent` — `ct-agent-supervisor <subcommand> [args...]`, same
environment — so it drops in wherever the agent is invoked today (a systemd unit, a launch
script). Two variables are its own:

| variable | default | meaning |
|---|---|---|
| `CT_AGENT_SUPERVISOR_BIN` | `ct-agent` (resolved via `PATH`) | the binary to supervise |
| `CT_AGENT_SUPERVISOR_STATUS_LISTEN` | unset | `host:port` serving `GET /crashes`, the crash history as JSON, for live debugging |

It observes only what a parent process can see from outside: a panic printed by Rust's
default hook, an explicit `exit(1)` after whatever was logged, and an OS-level kill (OOM,
`docker stop`, `kill -9`) as a signal on the child's wait status.

**What it cannot repair:** an agent that exits after exhausting its reconnect budget. The
single-use join token is already spent by then, so restarting the same process just fails to
re-onboard. That is why `CT_AGENT_RECONNECT_MAX_ATTEMPTS` defaults to retry-forever — the
supervisor handles crashes, not give-ups.

## Versioning

`ct-agent`'s dependency on CADS-Tunnel's shared crates (`ct-common`, `ct-control-plane`,
`ct-dns`) is pinned to a specific CADS-Tunnel git tag in `Cargo.toml`, bumped deliberately
on each release rather than tracking `main` — this keeps the wire protocol between
`ct-agent` and a deployed edge/control-plane from drifting apart silently.

## License

PolyForm Noncommercial License 1.0.0 — see [LICENSE](LICENSE). Noncommercial use
(research, personal, educational, nonprofit) is freely permitted; commercial use requires
a separate license (contact scimbe@gmail.com).

## Support the project

Bunsenbrenner (the live CADS-Tunnel deployment this agent talks to) is free to use and
runs on donated time and server costs. If it helped you get something live, a small
contribution keeps it going:

- [Support as a member](https://steady.page/plans/77a32d9c-c399-4ca1-9515-7a628c7a9413)
- [Buy me a coffee](https://buymeacoffee.com/bunsenbrenner)
