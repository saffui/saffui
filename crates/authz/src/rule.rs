use std::collections::BTreeSet;

use models::entities::authz::{Decision, FactSource, PolicyModel, PolicyRule, PolicyType};

use crate::compare;
use crate::fold::holds;
use crate::policies::Patterns;
use crate::request::{Caller, Request, Resolved};
use crate::verdict::Reason;
use crate::window;

/// One policy's own answer, before its logic is applied to it.
///
/// The three kinds that decide from other policies are handed a closure rather
/// than reaching for the set themselves, so the walking, its budget and its
/// cycle guard live in one place and this file stays a table of predicates.
pub(crate) fn decide(
    policy: &PolicyModel,
    request: &Request<'_>,
    patterns: &Patterns<'_>,
    reasons: &mut Vec<Reason>,
    conditions: impl FnOnce(&mut Vec<Reason>) -> Decision,
) -> Decision {
    let id = policy.policy_id.as_str();

    match &policy.terms.rule {
        PolicyRule::Role { roles } => among(id, roles, request.roles, PolicyType::Role, reasons),
        PolicyRule::Group { groups } => {
            among(id, groups, request.groups, PolicyType::Group, reasons)
        }
        PolicyRule::User { users } => {
            if let Some(answer) = empty(id, users, PolicyType::User, reasons) {
                return answer;
            }
            match request.caller {
                Caller::User { user_id, .. } => holds(users.iter().any(|named| named == user_id)),
                // A client is established, and it is definitively none of these
                // users. An answer, so "anybody but these three" admits it.
                Caller::Client { .. } => holds(false),
            }
        }
        PolicyRule::Client { clients } => {
            if let Some(answer) = empty(id, clients, PolicyType::Client, reasons) {
                return answer;
            }
            match request.caller.presented() {
                Some(presented) => holds(clients.iter().any(|named| named == presented.client_id)),
                None => unable(
                    reasons,
                    Reason::NoPresenter {
                        policy_id: id.to_owned(),
                    },
                ),
            }
        }
        PolicyRule::ClientScope { client_scopes } => {
            if let Some(answer) = empty(id, client_scopes, PolicyType::ClientScope, reasons) {
                return answer;
            }
            match request.caller.presented() {
                Some(presented) => match presented.client_scopes.known() {
                    Some(held) => holds(client_scopes.iter().any(|named| held.contains(named))),
                    None => unable(
                        reasons,
                        Reason::SourceUnavailable {
                            policy_id: id.to_owned(),
                            source: FactSource::Token,
                        },
                    ),
                },
                None => unable(
                    reasons,
                    Reason::NoPresenter {
                        policy_id: id.to_owned(),
                    },
                ),
            }
        }
        PolicyRule::Time(window) => {
            if let Some(defect) = window.defect() {
                return unable(
                    reasons,
                    Reason::WindowUnusable {
                        policy_id: id.to_owned(),
                        defect,
                    },
                );
            }
            match window::within(window, request.now) {
                Some(inside) => holds(inside),
                None => unable(
                    reasons,
                    Reason::InstantUnplaceable {
                        policy_id: id.to_owned(),
                    },
                ),
            }
        }
        PolicyRule::Regex {
            target_claim,
            target_regex,
        } => {
            let Some(pattern) = patterns.get(target_regex) else {
                return unable(
                    reasons,
                    Reason::PatternUnusable {
                        policy_id: id.to_owned(),
                    },
                );
            };
            let Some(claims) = request.token_claims.known() else {
                return unable(
                    reasons,
                    Reason::SourceUnavailable {
                        policy_id: id.to_owned(),
                        source: FactSource::Token,
                    },
                );
            };
            let Some(value) = claims.get(target_claim) else {
                return unable(
                    reasons,
                    Reason::ClaimAbsent {
                        policy_id: id.to_owned(),
                        claim: target_claim.clone(),
                    },
                );
            };
            // A pattern is matched against text. A number rendered into text to
            // be matched would be matched against a rendering nobody chose.
            let Some(text) = value.as_str() else {
                return unable(
                    reasons,
                    Reason::Uncomparable {
                        policy_id: id.to_owned(),
                    },
                );
            };
            // Unanchored, because the anchors are the author's vocabulary and
            // adding them here would change what every stored pattern means.
            holds(pattern.is_match(text))
        }
        PolicyRule::Attribute { left, test } => {
            compare::attribute(id, left, test, request, reasons)
        }
        // These three decide from what they are built on, and the two
        // permissions are never anything's condition, so the schema keeps them
        // out of a fold they are not the subject of.
        PolicyRule::Aggregated
        | PolicyRule::ScopePermission { .. }
        | PolicyRule::ResourcePermission { .. } => conditions(reasons),
    }
}

/// Whether the caller holds any of the identifiers named.
fn among(
    policy_id: &str,
    named: &[String],
    facts: Resolved<'_, BTreeSet<String>>,
    kind: PolicyType,
    reasons: &mut Vec<Reason>,
) -> Decision {
    if let Some(answer) = empty(policy_id, named, kind, reasons) {
        return answer;
    }
    let Some(held) = facts.known() else {
        return unable(
            reasons,
            Reason::SubjectFactsUnknown {
                policy_id: policy_id.to_owned(),
                kind,
            },
        );
    };
    holds(named.iter().any(|name| held.contains(name)))
}

/// A kind that decides by naming things, naming none.
///
/// Refused where it is written, and answered here too. The binding rows cascade
/// when what they name is deleted, so a policy that named one role comes back
/// naming none without anybody having written it that way. Answering that the
/// caller matched none of them would make a vanished binding invertible into a
/// grant for everybody.
fn empty(
    policy_id: &str,
    named: &[String],
    kind: PolicyType,
    reasons: &mut Vec<Reason>,
) -> Option<Decision> {
    named.is_empty().then(|| {
        unable(
            reasons,
            Reason::EmptyBinding {
                policy_id: policy_id.to_owned(),
                kind,
            },
        )
    })
}

fn unable(reasons: &mut Vec<Reason>, reason: Reason) -> Decision {
    reasons.push(reason);
    Decision::Indeterminate
}
