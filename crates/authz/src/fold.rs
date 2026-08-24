use models::entities::authz::{Decision, DecisionLogic, DecisionStrategy};

/// The one place a boolean becomes a decision.
///
/// Every other place has to say which of the three it means, so a predicate
/// that could not be evaluated cannot reach an answer by defaulting to false.
pub(crate) fn holds(matched: bool) -> Decision {
    if matched {
        Decision::Permit
    } else {
        Decision::Deny
    }
}

/// Combine answers under a strategy.
///
/// The empty set is `Deny` under all three, checked once before any of them.
/// Reading it as a vacuous permit is how a question nobody wrote a policy for
/// comes to be answered yes, and no strategy is an exception: the caller
/// discipline that would make one safe is not a property anything can check.
pub fn fold(strategy: DecisionStrategy, outcomes: &[Decision]) -> Decision {
    if outcomes.is_empty() {
        return Decision::Deny;
    }

    let total = outcomes.len();
    let permits = outcomes
        .iter()
        .filter(|outcome| **outcome == Decision::Permit)
        .count();
    let denies = outcomes
        .iter()
        .filter(|outcome| **outcome == Decision::Deny)
        .count();
    let unanswered = total - permits - denies;

    match strategy {
        DecisionStrategy::Affirmative => {
            if permits > 0 {
                Decision::Permit
            } else if unanswered > 0 {
                Decision::Indeterminate
            } else {
                Decision::Deny
            }
        }
        DecisionStrategy::Unanimous => {
            if denies > 0 {
                Decision::Deny
            } else if unanswered > 0 {
                Decision::Indeterminate
            } else {
                Decision::Permit
            }
        }
        // A strict majority of the whole, unanswered policies included in the
        // denominator. Excluding them would let one permit among nine
        // unevaluable policies carry a permit, and withholding consent is the
        // entire purpose of the third value. Nothing here needs a tie break:
        // both tests cannot hold at once, so a tie falls through to neither.
        DecisionStrategy::Consensus => {
            if permits * 2 > total {
                Decision::Permit
            } else if denies * 2 > total {
                Decision::Deny
            } else {
                Decision::Indeterminate
            }
        }
    }
}

/// Apply a policy's own logic to its own answer.
///
/// The third column is the guarantee the rest of the crate rests on. Inverting
/// an inability is how "the claim was missing" becomes "grant to everybody", so
/// negation swaps the two answers and leaves the absence of one alone.
pub fn apply(logic: DecisionLogic, outcome: Decision) -> Decision {
    match logic {
        DecisionLogic::Positive => outcome,
        DecisionLogic::Negative => match outcome {
            Decision::Permit => Decision::Deny,
            Decision::Deny => Decision::Permit,
            Decision::Indeterminate => Decision::Indeterminate,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: Decision = Decision::Permit;
    const D: Decision = Decision::Deny;
    const I: Decision = Decision::Indeterminate;

    /// The whole table, written out. Every row is a claim about what a set of
    /// answers means, and a change to the fold that suits one strategy shows up
    /// here as the row it broke in another.
    #[test]
    fn the_fold_answers_every_row_of_its_table() {
        let table: &[(&[Decision], Decision, Decision, Decision)] = &[
            // outcomes         affirmative  unanimous  consensus
            (&[], D, D, D),
            (&[P], P, P, P),
            (&[D], D, D, D),
            (&[I], I, I, I),
            (&[P, D], P, D, I),
            (&[D, I], I, D, I),
            (&[P, I], P, I, I),
            (&[D, D], D, D, D),
            (&[P, P], P, P, P),
            (&[P, P, D], P, D, P),
            (&[P, D, D], P, D, D),
            (&[P, I, I], P, I, I),
            (&[P, P, I], P, I, P),
            (&[P, P, D, D], P, D, I),
        ];

        for (outcomes, affirmative, unanimous, consensus) in table {
            assert_eq!(
                fold(DecisionStrategy::Affirmative, outcomes),
                *affirmative,
                "affirmative over {outcomes:?}"
            );
            assert_eq!(
                fold(DecisionStrategy::Unanimous, outcomes),
                *unanimous,
                "unanimous over {outcomes:?}"
            );
            assert_eq!(
                fold(DecisionStrategy::Consensus, outcomes),
                *consensus,
                "consensus over {outcomes:?}"
            );
        }
    }

    /// One fold and one convention. A set nobody wrote a policy for is refused
    /// under all three, since the caller discipline that would make a vacuous
    /// permit safe is not a property anything can check.
    #[test]
    fn nothing_at_all_refuses_under_every_strategy() {
        for strategy in DecisionStrategy::ALL {
            assert_eq!(fold(*strategy, &[]), Decision::Deny, "{strategy:?}");
        }
    }

    /// A set that is entirely unanswered is not the empty set. It has members,
    /// none of them said anything, and that is its own outcome.
    #[test]
    fn a_set_that_answered_nothing_is_not_an_empty_set() {
        for strategy in DecisionStrategy::ALL {
            assert_eq!(fold(*strategy, &[I, I, I]), Decision::Indeterminate);
            assert_eq!(fold(*strategy, &[]), Decision::Deny);
        }
    }

    /// The answer does not depend on the order the policies came back in, which
    /// is what makes a recorded decision replayable.
    #[test]
    fn the_order_of_the_answers_does_not_change_the_answer() {
        let orders: &[&[Decision]] = &[&[P, D, I], &[D, I, P], &[I, P, D], &[P, I, D]];
        for strategy in DecisionStrategy::ALL {
            let first = fold(*strategy, orders[0]);
            for order in orders {
                assert_eq!(fold(*strategy, order), first, "{strategy:?} over {order:?}");
            }
        }
    }

    /// A strict majority of the whole, unanswered policies counted in it.
    /// Excluding them would let one permit among nine unevaluable policies
    /// carry a permit.
    #[test]
    fn consensus_counts_what_was_not_answered_against_a_majority() {
        assert_eq!(fold(DecisionStrategy::Consensus, &[P, I]), I);
        assert_eq!(fold(DecisionStrategy::Consensus, &[P, I, I]), I);
        assert_eq!(fold(DecisionStrategy::Consensus, &[P, P, I]), P);
        assert_eq!(
            fold(DecisionStrategy::Consensus, &[P, D]),
            I,
            "a tie is not a majority either way"
        );
    }

    /// The guarantee every other one rests on. Inverting an inability is how a
    /// missing claim becomes a grant for everybody.
    #[test]
    fn negation_swaps_two_answers_and_leaves_the_third() {
        assert_eq!(apply(DecisionLogic::Negative, P), D);
        assert_eq!(apply(DecisionLogic::Negative, D), P);
        assert_eq!(
            apply(DecisionLogic::Negative, I),
            I,
            "an inability was inverted into an answer"
        );

        for outcome in Decision::ALL {
            assert_eq!(apply(DecisionLogic::Positive, *outcome), *outcome);
            assert_eq!(
                apply(
                    DecisionLogic::Negative,
                    apply(DecisionLogic::Negative, *outcome)
                ),
                *outcome,
                "negating twice did not come back to where it started"
            );
        }
    }
}
