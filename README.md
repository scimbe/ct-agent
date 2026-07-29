# ct-agent

Customer-run, outbound-only agent for [CADS-Tunnel](https://github.com/scimbe/CADS-Tunnel)
— a zero-knowledge tunnel. `ct-agent` is the custodian of your Origin's private key; the
tunnel operator never sees it. It dials out to a CADS-Tunnel edge, maintains the tunnel,
and (via the `certificate` subcommand) drives self-service ACME certificate issuance
across the Rot → Gelb → Grün tiers, using its own account key end to end.

This repo is the standalone extraction of the `ct-agent` crate from the
[CADS-Tunnel](https://github.com/scimbe/CADS-Tunnel) monorepo, published separately so it
can be downloaded and installed without cloning the whole tunnel/edge/control-plane
workspace. See that repo's docs (`docs/adr`, `docs/agent-onboarding.md`) for the full
system design.

## Install

Prebuilt binaries are attached to every [release](https://github.com/scimbe/ct-agent/releases)
for Linux (x86_64, i686, aarch64), Windows (x86_64, i686), and macOS (x86_64, aarch64).

```bash
curl -fsSL https://github.com/scimbe/ct-agent/releases/latest/download/ct-agent-linux-x86_64 -o ct-agent
chmod +x ct-agent
```

Or build from source (Rust 1.85+):

```bash
cargo build --release
```

## Versioning

`ct-agent`'s dependency on CADS-Tunnel's shared crates (`ct-common`, `ct-control-plane`,
`ct-dns`) is pinned to a specific CADS-Tunnel git tag in `Cargo.toml`, bumped deliberately
on each release rather than tracking `main` — this keeps the wire protocol between
`ct-agent` and a deployed edge/control-plane from drifting apart silently.

## License

PolyForm Noncommercial License 1.0.0 — see [LICENSE](LICENSE). Noncommercial use
(research, personal, educational, nonprofit) is freely permitted; commercial use requires
a separate license (contact scimbe@gmail.com).
