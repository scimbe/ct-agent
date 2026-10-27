//! ct-agent#299: protocol v2 for this agent's channel sessions -- end-to-end delivery
//! confirmation.
//!
//! Before v2, `channel_session ok=true` only meant "the transport closed cleanly". A relay that cut
//! the stream, or an edge that dropped a half-closed leg (the park pump before CADS-Tunnel#856),
//! produced exactly the same clean close, and a pipe member lost its data with exit status 0.
//! ct-common's `delivery` module adds records with FIN and FIN_ACK on top of the Noise session;
//! this module is the agent side of it:
//!
//! * **Which sessions:** every session that runs through [`run_channel_session_on_stream`] --
//!   pipe, forward, serve and the call modes, direct or relayed -- offers v2 unless
//!   [`DELIVERY_ACK_ENV`] is off. The #104-upgradable and the DCUtR sessions keep their own pumps
//!   and stay legacy.
//! * **Compatibility:** v2 is negotiated inside the Noise handshake. A peer from before v2 means a
//!   legacy session, byte for byte, so members can be updated one at a time.
//! * **Why a session ended:** when the peer-grant gate ends a session (a grant expired, the peer's
//!   grant was revoked or refused) it records the cause in the task-local [`SessionEndCause`], and
//!   the pump sends that cause as the FIN reason. The peer then reports "the peer's own grant
//!   expired" instead of a bare cut. A reason received is only the peer's word: it is logged and
//!   nothing else -- no authorization or exit decision rests on it (that needs the control plane).
//!
//! [`run_channel_session_on_stream`]: super::run_channel_session_on_stream

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ct_common::delivery::{FinReason, SessionCaps};

/// Opt-out for protocol v2: `CT_CHANNEL_DELIVERY_ACK=0` (or `false`/`no`/`off`) offers and accepts
/// only the legacy session. Default on. Meant as a way back if a v2 session misbehaves in the
/// field, not as a tuning knob.
pub(crate) const DELIVERY_ACK_ENV: &str = "CT_CHANNEL_DELIVERY_ACK";

/// What this member offers (initiator) or accepts (responder) in the handshake.
pub(crate) fn delivery_offer() -> SessionCaps {
    delivery_offer_from(crate::envflag::env_value(DELIVERY_ACK_ENV, true).as_deref())
}

/// Pure core of [`delivery_offer`]: only an explicit off spelling turns v2 off.
pub(crate) fn delivery_offer_from(v: Option<&str>) -> SessionCaps {
    if crate::envflag::flag(v, true) {
        SessionCaps::DELIVERY_ACK
    } else {
        SessionCaps::NONE
    }
}

/// How long a v2 session waits for the peer's FIN_ACK without hearing anything from the peer.
/// Every record from the peer restarts it (ct-common's progress-based bound).
pub(crate) const FIN_ACK_IDLE: Duration = ct_common::delivery::DEFAULT_FIN_ACK_IDLE;

/// The drain after a FAILED v2 session (#150 keeps the process alive until its tail has left). A
/// v2 session fails when the transport already ended, when the peer ended it, or when the peer
/// reported no progress on our bytes for [`FIN_ACK_IDLE`] -- a peer that is still delivering says
/// so with PROGRESS records. None of these leaves a tail worth the 30 s of a normal drain, only an
/// abort record to let out; what the peer did not take is reported as unconfirmed, not waited for.
pub(crate) const FAILED_DELIVERY_DRAIN: Duration = Duration::from_secs(2);

/// Why this member's side of a v2 session ended, when something other than its local input did
/// it. Set at most once (the first cause wins), read when the pump writes its FIN.
#[derive(Clone, Default)]
pub(crate) struct SessionEndCause(Arc<Mutex<Option<FinReason>>>);

impl SessionEndCause {
    fn set(&self, reason: FinReason) {
        if let Ok(mut slot) = self.0.lock() {
            slot.get_or_insert(reason);
        }
    }

    /// The recorded cause, if any.
    pub(crate) fn get(&self) -> Option<FinReason> {
        self.0.lock().ok().and_then(|slot| *slot)
    }

    /// The reason for this side's FIN: the recorded cause, else an ordinary end of input (no
    /// error) or a failed local side (an error).
    pub(crate) fn fin_reason(&self, err: Option<&io::Error>) -> FinReason {
        match (self.get(), err) {
            (Some(reason), _) => reason,
            (None, Some(_)) => FinReason::LocalError,
            (None, None) => FinReason::Normal,
        }
    }
}

tokio::task_local! {
    /// The cause cell of the v2 session running in this task. A task-local for the same reason as
    /// the grant-end record (ct-agent#267): the gate that knows the cause is built deep inside the
    /// join path, long before the session runner, and only meets the pump through `local`.
    static SESSION_END_CAUSE: SessionEndCause;
}

/// Run `session` with `cause` as the place [`note_session_end`] writes into.
pub(crate) async fn with_session_end_cause<F: std::future::Future>(cause: SessionEndCause, session: F) -> F::Output {
    SESSION_END_CAUSE.scope(cause, session).await
}

/// Record why the session running in this task ends -- called by the peer-grant gate when it ends
/// or refuses the session. Outside a v2 session (legacy, or no session at all) it does nothing.
pub(crate) fn note_session_end(reason: FinReason) {
    let _ = SESSION_END_CAUSE.try_with(|cause| cause.set(reason));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_ack_is_on_unless_explicitly_switched_off_299() {
        assert_eq!(delivery_offer_from(None), SessionCaps::DELIVERY_ACK, "unset -> on");
        assert_eq!(delivery_offer_from(Some("")), SessionCaps::DELIVERY_ACK, "empty -> on");
        assert_eq!(delivery_offer_from(Some("1")), SessionCaps::DELIVERY_ACK);
        assert_eq!(delivery_offer_from(Some("maybe")), SessionCaps::DELIVERY_ACK, "a typo keeps the default");
        for off in ["0", "false", "no", "off", " OFF "] {
            assert_eq!(delivery_offer_from(Some(off)), SessionCaps::NONE, "{off:?} -> legacy");
        }
    }

    #[tokio::test]
    async fn the_first_recorded_cause_becomes_the_fin_reason_and_only_inside_a_session_299() {
        // Outside a session scope there is nothing to write into: a no-op, not a panic.
        note_session_end(FinReason::OwnGrantExpired);

        let cause = SessionEndCause::default();
        assert_eq!(cause.fin_reason(None), FinReason::Normal, "no cause, end of input: normal");
        assert_eq!(
            cause.fin_reason(Some(&io::Error::other("stdin failed"))),
            FinReason::LocalError,
            "no cause, a local error: never a normal end"
        );
        with_session_end_cause(cause.clone(), async {
            note_session_end(FinReason::OwnGrantExpired);
            note_session_end(FinReason::PeerGrantEnded);
        })
        .await;
        assert_eq!(cause.get(), Some(FinReason::OwnGrantExpired), "the first cause wins");
        assert_eq!(cause.fin_reason(None), FinReason::OwnGrantExpired);
    }
}
