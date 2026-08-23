//! What one step of a flow answered, and what a flow answers from its steps.
//!
//! Pure: no store, no clock, no credential. What runs a step is elsewhere; this
//! says what a flow makes of the answers, and it is the part that decides
//! whether somebody is let in.

use models::entities::auth::AuthenticatorRequirement;

/// What one step answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It established what it was there to establish.
    Passed,
    /// It ran and did not.
    Failed,
    /// It needs something from the caller before it can say. A password form, a
    /// second factor, a consent screen.
    Pending,
    /// It did not run. A step whose requirement disables it, or one an earlier
    /// answer made unnecessary.
    Skipped,
}

/// One step, as the fold sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub requirement: AuthenticatorRequirement,
    pub outcome: Outcome,
}

/// What a flow decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decided {
    /// Everything it required is established.
    Admitted,
    /// It cannot be, and running more steps will not change that.
    Refused,
    /// A step is waiting on the caller.
    Waiting,
}

/// What a flow makes of its steps.
///
/// Required steps are the flow's own conditions: one that failed refuses it,
/// and one still waiting holds it. Alternatives are a set of ways in, so one
/// that passed satisfies them all and they only refuse when every one has
/// failed.
///
/// A flow with no enabled step refuses. A flow that authenticated nobody must
/// not admit everybody, which is the same argument the empty policy set is
/// refused under.
pub fn decide(steps: &[Step]) -> Decided {
    let enabled: Vec<&Step> = steps
        .iter()
        .filter(|step| step.requirement.is_enabled())
        .collect();

    if enabled.is_empty() {
        return Decided::Refused;
    }

    let required: Vec<&&Step> = enabled
        .iter()
        .filter(|step| step.requirement == AuthenticatorRequirement::Required)
        .collect();

    // A refusal is final wherever it is, so it is looked for before anything
    // that could report waiting: a flow held open on a step nobody can pass is
    // a caller asked to answer a challenge that will not help them.
    if required.iter().any(|step| step.outcome == Outcome::Failed) {
        return Decided::Refused;
    }

    let alternatives: Vec<&&Step> = enabled
        .iter()
        .filter(|step| step.requirement == AuthenticatorRequirement::Alternative)
        .collect();

    let ways_in_exhausted = !alternatives.is_empty()
        && alternatives
            .iter()
            .all(|step| step.outcome == Outcome::Failed);
    if ways_in_exhausted {
        return Decided::Refused;
    }

    let conditions_met = required.iter().all(|step| step.outcome == Outcome::Passed);
    let a_way_in = alternatives.is_empty()
        || alternatives
            .iter()
            .any(|step| step.outcome == Outcome::Passed);

    // A way in that was taken settles every other way in. Waiting on one that
    // is merely still offered would hold a login open on a question the caller
    // has already answered another way, and a flow offering two ways would
    // admit through neither.
    let waiting = enabled.iter().any(|step| {
        step.outcome == Outcome::Pending
            && (step.requirement == AuthenticatorRequirement::Required || !a_way_in)
    });
    if waiting {
        return Decided::Waiting;
    }

    if conditions_met && a_way_in {
        Decided::Admitted
    } else {
        // Nothing failed and nothing waits, yet a condition is unmet: a step
        // was skipped that the flow needed. Refused rather than waited on,
        // since no challenge is outstanding for the caller to answer.
        Decided::Refused
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AuthenticatorRequirement::{Alternative, Disabled, Required};

    /// A flow offering two ways in admits through the one that was taken. The
    /// other is still offered, and offering is not waiting.
    #[test]
    fn a_way_in_that_was_taken_settles_the_ones_that_were_not() {
        assert_eq!(
            decide(&[
                Step {
                    requirement: Alternative,
                    outcome: Outcome::Pending
                },
                Step {
                    requirement: Alternative,
                    outcome: Outcome::Passed
                },
            ]),
            Decided::Admitted
        );
        // And a required step still holds it, whichever way in was taken.
        assert_eq!(
            decide(&[
                Step {
                    requirement: Required,
                    outcome: Outcome::Pending
                },
                Step {
                    requirement: Alternative,
                    outcome: Outcome::Passed
                },
            ]),
            Decided::Waiting
        );
        // With none of them taken, the offer is what the caller answers.
        assert_eq!(
            decide(&[
                Step {
                    requirement: Alternative,
                    outcome: Outcome::Pending
                },
                Step {
                    requirement: Alternative,
                    outcome: Outcome::Pending
                },
            ]),
            Decided::Waiting
        );
    }

    fn step(requirement: AuthenticatorRequirement, outcome: Outcome) -> Step {
        Step {
            requirement,
            outcome,
        }
    }

    /// A flow with nothing to run refuses. One that authenticated nobody must
    /// not admit everybody.
    #[test]
    fn a_flow_that_runs_nothing_admits_nobody() {
        assert_eq!(decide(&[]), Decided::Refused);
        assert_eq!(
            decide(&[step(Disabled, Outcome::Passed)]),
            Decided::Refused,
            "a disabled step admitted somebody"
        );
    }

    /// Required steps are the flow's own conditions.
    #[test]
    fn every_condition_has_to_be_met() {
        assert_eq!(
            decide(&[
                step(Required, Outcome::Passed),
                step(Required, Outcome::Passed)
            ]),
            Decided::Admitted
        );
        assert_eq!(
            decide(&[
                step(Required, Outcome::Passed),
                step(Required, Outcome::Failed)
            ]),
            Decided::Refused
        );
    }

    /// Alternatives are ways in: one is enough, and they refuse only when every
    /// one has been tried and failed.
    #[test]
    fn one_way_in_is_enough_and_all_of_them_failing_is_a_refusal() {
        assert_eq!(
            decide(&[
                step(Alternative, Outcome::Failed),
                step(Alternative, Outcome::Passed)
            ]),
            Decided::Admitted
        );
        assert_eq!(
            decide(&[
                step(Alternative, Outcome::Failed),
                step(Alternative, Outcome::Failed)
            ]),
            Decided::Refused
        );
    }

    /// A condition and a way in are different questions, and both are asked.
    #[test]
    fn a_way_in_does_not_stand_in_for_a_condition() {
        assert_eq!(
            decide(&[
                step(Required, Outcome::Failed),
                step(Alternative, Outcome::Passed)
            ]),
            Decided::Refused,
            "a failed condition was covered by an alternative"
        );
        assert_eq!(
            decide(&[
                step(Required, Outcome::Passed),
                step(Alternative, Outcome::Failed),
                step(Alternative, Outcome::Failed)
            ]),
            Decided::Refused,
            "every way in failed and the flow admitted anyway"
        );
    }

    /// A step waiting on the caller holds the flow, and a refusal outranks it:
    /// a caller held on a challenge that cannot help them is a caller misled.
    #[test]
    fn waiting_holds_the_flow_and_a_refusal_outranks_it() {
        assert_eq!(
            decide(&[
                step(Required, Outcome::Passed),
                step(Required, Outcome::Pending)
            ]),
            Decided::Waiting
        );
        assert_eq!(
            decide(&[
                step(Required, Outcome::Failed),
                step(Required, Outcome::Pending)
            ]),
            Decided::Refused,
            "a caller was asked to answer a challenge that could not admit them"
        );
        assert_eq!(
            decide(&[
                step(Alternative, Outcome::Failed),
                step(Alternative, Outcome::Failed),
                step(Required, Outcome::Pending)
            ]),
            Decided::Refused,
            "every way in was exhausted and the flow still waited"
        );
    }

    /// Nothing failed, nothing waits, and a condition was never run. No
    /// challenge is outstanding, so there is nothing to wait for.
    #[test]
    fn a_condition_that_never_ran_is_a_refusal_and_not_a_wait() {
        assert_eq!(
            decide(&[
                step(Required, Outcome::Passed),
                step(Required, Outcome::Skipped)
            ]),
            Decided::Refused
        );
    }

    /// A disabled step counts for nothing, whatever it says.
    #[test]
    fn a_disabled_step_is_not_read() {
        assert_eq!(
            decide(&[
                step(Required, Outcome::Passed),
                step(Disabled, Outcome::Failed)
            ]),
            Decided::Admitted,
            "a disabled step refused a flow it does not belong to"
        );
    }
}
