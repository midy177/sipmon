#![allow(dead_code)]
//! Call-level metric helpers: PDD, setup delay, outcome classification.
//!
//! The live state machine (correlate::call) computes these incrementally; the
//! functions here recompute them from a finished `Call` and are used by
//! replay/export consumers and tests.

use crate::model::sip::{Call, CallState, Outcome};

/// Post-Dial Delay: time from INVITE to the first provisional response (1xx,
/// typically 100 Trying or 180 Ringing / 183). If only a final response is
/// seen, no provisional exists and PDD is unavailable.
pub fn compute_pdd_ms(call: &Call) -> Option<u32> {
    let invite = call.invite_ts?;
    let provisional = match (call.trying_ts, call.ringing_ts) {
        (Some(t), Some(r)) => Some(t.min(r)),
        (Some(t), None) => Some(t),
        (None, Some(r)) => Some(r),
        (None, None) => None,
    }?;
    Some(((provisional - invite) / 1000) as u32)
}

/// Setup delay: time from INVITE to the first 2xx answer.
pub fn compute_setup_ms(call: &Call) -> Option<u32> {
    let invite = call.invite_ts?;
    let answer = call.answer_ts?;
    Some(((answer - invite) / 1000) as u32)
}

/// Classify final outcome based on observed messages/state.
pub fn classify_outcome(call: &Call) -> Outcome {
    match call.state {
        CallState::Completed => Outcome::Answered,
        CallState::Canceled => Outcome::Canceled,
        CallState::Failed => match call.hangup.code {
            Some(c) if (400..500).contains(&c) => Outcome::Rejected,
            Some(487) => Outcome::Canceled,
            _ => Outcome::Failed,
        },
        _ => Outcome::InProgress,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdd_and_setup_from_timestamps() {
        let mut c = Call::new("x".into());
        c.invite_ts = Some(1_000_000);
        c.ringing_ts = Some(1_150_000);
        c.answer_ts = Some(2_000_000);
        assert_eq!(compute_pdd_ms(&c), Some(150));
        assert_eq!(compute_setup_ms(&c), Some(1000));
    }
}
