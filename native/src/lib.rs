//! CADS Tunnel Agent — customer-run, outbound-only. Custodian of the Origin
//! key; mints Capabilities. See ADR-0004 (transport), ADR-0005 (identity).

// ct-agent#176: the data plane is panic-free by construction. Every `unwrap`/`expect`/
// `panic!`/`unreachable!`/`todo!`/`unimplemented!` in NON-test code is a build error
// (CI runs clippy with -D warnings); a provably-infallible site may carry a scoped
// `#[allow(clippy::expect_used)]` with a one-line proof. Tests keep their unwraps.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

pub mod acme;
pub mod acme_ca;
pub mod acme_client;
pub mod acme_jws;
pub mod acme_orchestrate;
pub mod capability;
pub mod channel;
pub mod channel_run;
pub mod config;
pub mod dns01_authoritative;
pub mod dns01_propagation;
pub mod harness_run;
pub mod ladder;
pub mod local_auth;
pub mod login;
pub mod masque;
pub mod identity;
pub mod manifest_run;
pub mod observe;
pub mod onboard;
pub mod origin;
pub mod p2p;
pub mod reconnect;
pub mod secret_file;
pub mod self_update;
pub mod serve;
pub mod signup;
pub mod super_peer;
pub mod transport;
pub mod well_known;

/// Stable crate identifier, used by the P0.1 smoke test.
pub const CRATE_NAME: &str = "ct-agent";

#[cfg(test)]
mod tests {
    #[test]
    fn depends_on_common() {
        assert_eq!(ct_common::CRATE_NAME, "ct-common");
        assert_eq!(super::CRATE_NAME, "ct-agent");
    }
}
