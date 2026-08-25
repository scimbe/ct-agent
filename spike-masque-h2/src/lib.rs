//! ADR-0024 M1 feasibility spike. See `Cargo.toml`'s description and
//! `CADS-Tunnel/docs/adr/0024-masque-connect-udp-fallback.md` for what this proves
//! and why. Library crate so `tests/roundtrip.rs` can exercise the framing modules
//! directly; deliberately has no `main.rs` -- this spike has nothing to run
//! standalone, only a claim to prove via its test.

pub mod capsule;
pub mod varint;
