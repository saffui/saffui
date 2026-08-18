//! A server's policies, indexed and walked.
//!
//! The index and the compiled patterns come out of one call over one slice, so
//! a cache prepared from a different load, or refreshed on a different cadence
//! than the policies it belongs to, is not something a caller can express. Two
//! parameters would make that mismatch look exactly like a pattern that would
//! not compile, and the two faults have nothing to do with each other.

use std::collections::{BTreeMap, BTreeSet};

use commons::walk::{Budget, POLICY_AGGREGATION};
use models::entities::authz::{Decision, PolicyModel, PolicyRule, StoredPolicy};
use regex::Regex;

use crate::fold::{apply, fold};
use crate::request::{Membership, Request, Target};
use crate::rule;
use crate::verdict::Reason;

/// The patterns of one policy set, compiled once.
pub struct Patterns<'a> {
    compiled: BTreeMap<&'a str, Regex>,
}

impl<'a> Patterns<'a> {
    /// The pattern, or nothing if it would not compile.
    pub(crate) fn get(&self, pattern: &str) -> Option<&Regex> {
        self.compiled.get(pattern)
    }
}

/// One application's policies, ready to answer.
pub struct Evaluable<'a> {
    ordered: &'a [StoredPolicy],
    by_id: BTreeMap<&'a str, &'a StoredPolicy>,
    patterns: Patterns<'a>,
}

impl<'a> Evaluable<'a> {
    /// Index a set and compile its patterns.
    ///
    /// A pattern that will not compile is left out rather than refused here:
    /// the policy carrying it answers that it could not be evaluated, and the
    /// rest of the set still answers. One bad pattern is not a reason for an
    /// application to stop deciding.
    pub fn index(policies: &'a [StoredPolicy]) -> Self {
        let mut by_id = BTreeMap::new();
        let mut compiled = BTreeMap::new();

        for stored in policies {
            by_id.insert(stored.policy_id(), stored);
            if let StoredPolicy::Read(policy) = stored
                && let PolicyRule::Regex { target_regex, .. } = &policy.terms.rule
                && let Ok(pattern) = commons::pattern::compile(target_regex)
            {
                compiled.insert(target_regex.as_str(), pattern);
            }
        }

        Evaluable {
            ordered: policies,
            by_id,
            patterns: Patterns { compiled },
        }
    }

    pub(crate) fn all(&self) -> &'a [StoredPolicy] {
        self.ordered
    }

    pub(crate) fn get(&self, policy_id: &str) -> Option<&'a StoredPolicy> {
        self.by_id.get(policy_id).copied()
    }

    pub(crate) fn patterns(&'a self) -> &'a Patterns<'a> {
        &self.patterns
    }
}

/// Whether a policy has anything to say about the resource and verb in hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applicability {
    /// It governs the target, so its answer counts.
    Governs,
    /// It is about something else, so it contributes nothing. Contributing
    /// `Indeterminate` instead would let one permission about another resource
    /// withhold every answer on the application.
    Silent,
    /// It might govern and cannot say, so it withholds.
    Undecided,
}

/// One decision's walk of the aggregation graph.
///
/// Built per decision and dropped with it. A memo that outlived the question
/// would be keyed by policy alone while what it holds depends on the caller
/// too, and the second caller would be handed the first one's answer.
pub(crate) struct Walk<'a> {
    set: &'a Evaluable<'a>,
    request: Request<'a>,
    budget: Budget,
    /// What each policy answered for this caller, so a policy two permissions
    /// share is evaluated once and a diamond does not reopen.
    answered: BTreeMap<String, Decision>,
    /// What is being evaluated right now, which is how a cycle is seen.
    on_path: BTreeSet<String>,
    visited: usize,
}

impl<'a> Walk<'a> {
    pub(crate) fn new(set: &'a Evaluable<'a>, request: Request<'a>) -> Self {
        Walk {
            set,
            request,
            budget: POLICY_AGGREGATION,
            answered: BTreeMap::new(),
            on_path: BTreeSet::new(),
            visited: 0,
        }
    }

    /// What one policy answers for this caller, its own logic applied.
    ///
    /// The budget is the same one the write path refuses a cycle under, so a
    /// policy set that could be saved is one that can be walked. Reaching it
    /// here is not a refusal but an inability: the graph was too large to
    /// answer, which is not the same as an answer of no.
    pub(crate) fn evaluate(&mut self, policy_id: &str, reasons: &mut Vec<Reason>) -> Decision {
        if let Some(answered) = self.answered.get(policy_id) {
            return *answered;
        }
        // Refused where it is written, so meeting one here means a row reached
        // storage by some other path. Not memoised: a node on a cycle has no
        // answer to remember.
        if self.on_path.contains(policy_id) {
            reasons.push(Reason::AggregationCycle {
                policy_id: policy_id.to_owned(),
            });
            return Decision::Indeterminate;
        }

        self.visited += 1;
        if self.visited > self.budget.max_nodes || self.on_path.len() >= self.budget.max_depth {
            reasons.push(Reason::AggregationTooLarge {
                policy_id: policy_id.to_owned(),
            });
            return Decision::Indeterminate;
        }

        let Some(stored) = self.set.get(policy_id) else {
            reasons.push(Reason::DanglingCondition {
                policy_id: policy_id.to_owned(),
                condition: policy_id.to_owned(),
            });
            return Decision::Indeterminate;
        };
        let policy = match stored {
            StoredPolicy::Read(policy) => policy,
            StoredPolicy::Unreadable { policy_id } => {
                reasons.push(Reason::Quarantined {
                    policy_id: policy_id.clone(),
                });
                return Decision::Indeterminate;
            }
        };

        // A policy confined to an organization, read as a condition rather than
        // as a candidate, is not silent: dropping it would shrink the set its
        // parent folds, and a condition that vanishes from a unanimous fold is
        // a permission that grants where it refused.
        if !placed(policy, self.request.membership) {
            reasons.push(Reason::Confined {
                policy_id: policy_id.to_owned(),
            });
            return Decision::Indeterminate;
        }

        // Copied out before the walk borrows itself. The facts are one value
        // for the whole decision, so every policy in the fold reads the same
        // caller whatever order the graph is descended in.
        let request = self.request;
        let patterns = self.set.patterns();

        self.on_path.insert(policy_id.to_owned());
        let answer = rule::decide(policy, &request, patterns, reasons, |reasons| {
            self.conditions(policy, reasons)
        });
        let answer = apply(policy.terms.logic, answer);
        self.on_path.remove(policy_id);

        self.answered.insert(policy_id.to_owned(), answer);
        answer
    }

    /// What the policies this one is built on answer, folded under its own
    /// strategy.
    fn conditions(&mut self, policy: &PolicyModel, reasons: &mut Vec<Reason>) -> Decision {
        if policy.terms.policies.is_empty() {
            reasons.push(Reason::EmptyBinding {
                policy_id: policy.policy_id.clone(),
                kind: policy.policy_type(),
            });
            return Decision::Indeterminate;
        }

        let outcomes: Vec<Decision> = policy
            .terms
            .policies
            .iter()
            .map(|condition| self.evaluate(condition, reasons))
            .collect();
        fold(policy.terms.decision, &outcomes)
    }
}

/// Whether the caller stands where the policy is confined to.
///
/// A policy the write path narrowed to one organization has to be silent for
/// everybody else, whatever it decides on. An organization that could not be
/// established places nobody, so it places nobody here either.
pub(crate) fn placed(policy: &PolicyModel, membership: Membership<'_>) -> bool {
    match (&policy.org_id, membership) {
        (None, _) => true,
        (Some(confined), Membership::In { org_id }) => confined == org_id,
        (Some(_), Membership::RealmWide) | (Some(_), Membership::Unknown) => false,
    }
}

/// Whether a policy is a permission that covers this resource and verb.
///
/// Every kind named, so a twelfth one has to say whether it is a candidate.
/// Left to a catch-all it would answer that it is not, and a permission kind
/// added later would protect nothing while looking as though it did.
pub(crate) fn governs(
    stored: &StoredPolicy,
    target: &Target<'_>,
    membership: Membership<'_>,
    reasons: &mut Vec<Reason>,
) -> Applicability {
    let policy = match stored {
        StoredPolicy::Read(policy) => policy,
        // Fail closed. A row nobody can read may be the permission that would
        // have refused, so it withholds an answer rather than disappearing.
        StoredPolicy::Unreadable { policy_id } => {
            reasons.push(Reason::Quarantined {
                policy_id: policy_id.clone(),
            });
            return Applicability::Undecided;
        }
    };

    match (&policy.org_id, membership) {
        (Some(_), Membership::Unknown) => {
            reasons.push(Reason::Confined {
                policy_id: policy.policy_id.clone(),
            });
            return Applicability::Undecided;
        }
        // A permission about another organization's business is about something
        // else, exactly as a permission about another resource is.
        (Some(confined), Membership::In { org_id }) if confined != org_id => {
            return Applicability::Silent;
        }
        (Some(_), Membership::RealmWide) => return Applicability::Silent,
        (Some(_), Membership::In { .. }) | (None, _) => {}
    }

    match &policy.terms.rule {
        PolicyRule::ScopePermission { resource_type } => {
            if !names(policy, target, resource_type) {
                return Applicability::Silent;
            }
            // The kind is defined by the verbs it names, so naming none is a
            // binding that cascaded away rather than a permission over every
            // verb. It withholds, and it is confined to its own resources, so
            // it cannot withhold an answer about anything else.
            if policy.terms.scopes.is_empty() {
                reasons.push(Reason::EmptyBinding {
                    policy_id: policy.policy_id.clone(),
                    kind: policy.policy_type(),
                });
                return Applicability::Undecided;
            }
            if policy
                .terms
                .scopes
                .iter()
                .any(|scope| scope == target.scope_id)
            {
                Applicability::Governs
            } else {
                Applicability::Silent
            }
        }
        // Every verb on the resources it names. It binds no scopes at all, so
        // an empty list here means what it has always meant and cannot be
        // produced by a deletion elsewhere.
        PolicyRule::ResourcePermission { resource_type } => {
            if names(policy, target, resource_type) {
                Applicability::Governs
            } else {
                Applicability::Silent
            }
        }
        PolicyRule::Role { .. }
        | PolicyRule::Group { .. }
        | PolicyRule::User { .. }
        | PolicyRule::Client { .. }
        | PolicyRule::ClientScope { .. }
        | PolicyRule::Time(_)
        | PolicyRule::Regex { .. }
        | PolicyRule::Attribute { .. }
        | PolicyRule::Aggregated => Applicability::Silent,
    }
}

/// Whether the permission names this resource, or the type it is of.
///
/// A blank type names nothing. A permission that named neither would apply to
/// nothing, and a reader that took that for everything would make it the widest
/// grant in the realm.
fn names(policy: &PolicyModel, target: &Target<'_>, resource_type: &str) -> bool {
    policy
        .terms
        .resources
        .iter()
        .any(|resource| resource == target.resource_id)
        || (!resource_type.trim().is_empty() && resource_type == target.resource_type)
}
