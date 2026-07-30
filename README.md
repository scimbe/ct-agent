# ct-agent

Customer-run, outbound-only agent for [CADS-Tunnel](https://github.com/scimbe/CADS-Tunnel)
— a zero-knowledge tunnel. `ct-agent` is the custodian of your Origin's private key; the
tunnel operator never sees it. It dials out to a CADS-Tunnel edge, maintains the tunnel,
and (via the `certificate` subcommand) drives self-service ACME certificate issuance
across the Rot → Gelb → Grün tiers, using its own account key end to end.

This repo is its own related project, extracted from the
[CADS-Tunnel](https://github.com/scimbe/CADS-Tunnel) monorepo (the core system: control
plane + edge) and published separately so it can be downloaded and installed without
cloning the whole tunnel/edge/control-plane workspace. See that repo's docs (`docs/adr`,
`docs/agent-onboarding.md`) for the full system design.

## Quick start (recommended)

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

This is the one supported way to install `ct-agent` — it downloads the right
[prebuilt release binary](https://github.com/scimbe/ct-agent/releases) for your
OS/arch itself, so there's no separate manual-download path to keep in sync. If
you're contributing to `ct-agent` itself, `cargo build --release` (Rust 1.85+) works
as usual from a clone of this repo.

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
