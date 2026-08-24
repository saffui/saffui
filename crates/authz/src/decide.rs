use models::entities::authz::{
    Decision, PolicyEnforcementMode, ReportedDecision, ResourceServerModel,
};

use crate::fold::fold;
use crate::policies::{Applicability, Evaluable, Walk, governs};
use crate::request::{Declared, Request, Target};
use crate::verdict::{Reason, Verdict, conclude};

/// What one named policy answers about a caller.
///
/// The administrative surface, and it reports nothing: it hands back what the
/// evaluation reached, third value included, because an administrator trying a
/// rule needs to see that it could not be evaluated rather than a refusal
/// standing in for one. No enforcement mode is read here, since nothing is
/// being enforced.
pub fn policy(
    set: &Evaluable<'_>,
    policy_id: &str,
    request: Request<'_>,
) -> (Decision, Vec<Reason>) {
    let mut reasons = Vec::new();
    let mut walk = Walk::new(set, request);
    let decision = walk.evaluate(policy_id, &mut reasons);
    (decision, reasons)
}

/// Whether this caller may do this to this.
///
/// The resource is already resolved: a `Target` cannot be built for a resource
/// nothing answers to, so a call about an unknown resource never reaches a
/// policy. What is checked here is the verb, then which permissions govern the
/// pair, then what they answer under the application's own strategy.
pub fn permission(
    server: &ResourceServerModel,
    set: &Evaluable<'_>,
    target: Target<'_>,
    request: Request<'_>,
) -> Verdict {
    // Before anything reads the mode. A mode is a property of the application
    // that owns the resource, so a caller naming one application and a resource
    // of another would otherwise have the named one's mode applied to somebody
    // else's resource: name a permissive or disabled application, and its mode
    // answers for a resource it does not protect.
    if server.server_id != target.server_id {
        return Verdict {
            reported: ReportedDecision::Deny,
            computed: Decision::Deny,
            reasons: vec![Reason::NotThisApplication {
                server_id: server.server_id.clone(),
                resource_id: target.resource_id.to_owned(),
            }],
        };
    }

    conclude(server.enforcement_mode, || {
        let mut reasons = Vec::new();

        // The verbs a resource declares are what may be done to it. Declaring
        // none is an answer and means none; not having read them is not an
        // answer and may not be read as either.
        match target.declared_scopes {
            Declared::NotLoaded => {
                reasons.push(Reason::VerbsNotLoaded {
                    resource_id: target.resource_id.to_owned(),
                });
                return (Decision::Indeterminate, reasons);
            }
            Declared::Verbs(declared) => {
                if !declared.contains(target.scope_id) {
                    reasons.push(Reason::VerbNotDeclared {
                        resource_id: target.resource_id.to_owned(),
                        scope_id: target.scope_id.to_owned(),
                    });
                    return (Decision::Deny, reasons);
                }
            }
        }

        let mut walk = Walk::new(set, request);
        let mut candidates = Vec::new();
        for stored in set.all() {
            match governs(stored, &target, request.membership, &mut reasons) {
                Applicability::Silent => {}
                Applicability::Undecided => candidates.push(Decision::Indeterminate),
                Applicability::Governs => {
                    candidates.push(walk.evaluate(stored.policy_id(), &mut reasons));
                }
            }
        }

        // Nothing protects this pair. The fold answers refuse for an empty set
        // anyway; this says which empty set it was, since a request nobody
        // wrote a permission for and a request every permission refused are the
        // same answer and different problems.
        if candidates.is_empty() {
            reasons.push(Reason::NothingGoverns {
                resource_id: target.resource_id.to_owned(),
                scope_id: target.scope_id.to_owned(),
            });
        }

        (fold(server.decision_strategy, &candidates), reasons)
    })
}

/// The modes, named here so a reader of this file sees what the two entry
/// points do and do not decide.
///
/// `permission` reads the mode once, through `conclude`. `policy` reads none,
/// because a test of a rule is not an enforcement of it.
const _: fn(PolicyEnforcementMode) = |_mode| {};
