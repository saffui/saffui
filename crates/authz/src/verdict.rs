use models::entities::authz::{
    Decision, FactSource, PolicyEnforcementMode, PolicyType, ReportedDecision, WindowDefect,
};
use serde::{Deserialize, Serialize};

/// Why an evaluation could not decide, or decided the way it did.
///
/// Every variant names the policy it is about, because a fold that reached no
/// answer and did not say which policy withheld it is a fold nobody can act on.
/// These land in the journal's replay payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Reason {
    /// A stored row whose rule names no kind this build can read.
    Quarantined { policy_id: String },
    /// A kind that decides by naming things, naming none. Reachable without a
    /// write fault: the binding rows cascade when what they name is deleted.
    EmptyBinding { policy_id: String, kind: PolicyType },
    /// A condition the policy names and the set does not hold.
    DanglingCondition {
        policy_id: String,
        condition: String,
    },
    /// The rule reads a source the caller could not establish.
    SourceUnavailable {
        policy_id: String,
        source: FactSource,
    },
    /// The rule reads a client and no client presented the call.
    NoPresenter { policy_id: String },
    /// The source was read and the fact was not in it.
    ClaimAbsent { policy_id: String, claim: String },
    /// The two sides cannot be compared under the operator asked of them.
    Uncomparable { policy_id: String },
    /// A test every value passes, which reads nothing about the caller.
    ConstantCondition { policy_id: String },
    /// A pattern that would not compile, so nothing can be matched against it.
    PatternUnusable { policy_id: String },
    WindowUnusable {
        policy_id: String,
        defect: WindowDefect,
    },
    /// A policy conditioned on something that leads back to it.
    AggregationCycle { policy_id: String },
    /// A graph too deep or too wide to answer within its budget.
    AggregationTooLarge { policy_id: String },
    /// A dimension of the caller nobody could establish, named by the kind of
    /// policy that reads it.
    SubjectFactsUnknown { policy_id: String, kind: PolicyType },
    /// An instant that cannot be placed against the bounds a window states.
    InstantUnplaceable { policy_id: String },
    /// A policy confined to an organization, met by a caller who is not in it
    /// or whose own could not be established.
    Confined { policy_id: String },
    /// The resource named is not one this application protects, answered
    /// before the mode is read.
    NotThisApplication {
        server_id: String,
        resource_id: String,
    },
    /// The verb is not one this resource declares.
    VerbNotDeclared {
        resource_id: String,
        scope_id: String,
    },
    /// The resource's verbs were not read, so nothing can be said about them.
    VerbsNotLoaded { resource_id: String },
    /// No permission governs this resource and verb at all.
    NothingGoverns {
        resource_id: String,
        scope_id: String,
    },
    /// The server evaluates nothing, so nothing was evaluated.
    EnforcementDisabled,
    /// The server is rolling a policy out, so the caller was told yes over an
    /// answer that was not one.
    Masked,
}

/// One decision, in both the vocabularies it has to be said in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// What the caller is told.
    pub reported: ReportedDecision,
    /// What the evaluation reached.
    pub computed: Decision,
    /// What the evaluation met, in the order it met it.
    pub reasons: Vec<Reason>,
}

/// Turn what was computed into what is reported, under the server's mode.
///
/// The one place `Indeterminate` stops, and the one place the mode is read. The
/// mode decides whether to evaluate at all, what the computed answer is, and
/// what is said about it, so all three come out of a single exhaustive match: a
/// fourth mode is then a compile error here rather than a value that quietly
/// falls through to enforcing at one site and to permissive at another.
pub fn conclude(
    mode: PolicyEnforcementMode,
    evaluate: impl FnOnce() -> (Decision, Vec<Reason>),
) -> Verdict {
    match mode {
        // Nothing is evaluated, and the record says so rather than claiming an
        // evaluation reached a permit. The resource was still resolved before
        // this point, so a call about a resource nobody protects is still not a
        // call this answers yes to.
        PolicyEnforcementMode::Disabled => Verdict {
            reported: ReportedDecision::Permit,
            computed: Decision::Indeterminate,
            reasons: vec![Reason::EnforcementDisabled],
        },
        PolicyEnforcementMode::Enforcing => {
            let (computed, reasons) = evaluate();
            Verdict {
                reported: match computed {
                    Decision::Permit => ReportedDecision::Permit,
                    // An evaluation that reached nothing is refused, like a
                    // refusal. This is where the third value is spent, and it
                    // is spent closed.
                    Decision::Deny | Decision::Indeterminate => ReportedDecision::Deny,
                },
                computed,
                reasons,
            }
        }
        // The same policies apply and the same answer is computed. What changes
        // is only what the caller is told, and the record keeps both so the
        // refusal that was masked is still there to be found.
        PolicyEnforcementMode::Permissive => {
            let (computed, mut reasons) = evaluate();
            if computed != Decision::Permit {
                reasons.push(Reason::Masked);
            }
            Verdict {
                reported: ReportedDecision::Permit,
                computed,
                reasons,
            }
        }
    }
}
