//! Where a question about a caller becomes an answer.
//!
//! One door. Every protected surface asks here, and what it asks about is a
//! nature, matched exhaustively with no catch-all arm. A nature added without
//! an engine does not compile, which is the difference between a surface nobody
//! wired up and a surface that refuses everything in silence: the second reads
//! as a working guard for as long as nobody tests it.
//!
//! The facts are gathered once, from the store and from what the request
//! established, and handed to an engine that cannot reach either. What comes
//! back is recorded before it is returned, on every path, because a decision
//! nobody can find afterwards is a decision nobody can audit.

use authz::{Caller, Declared, Evaluable, Membership, Presented, Request, Resolved, Through};
use chrono::Utc;
use deadpool_postgres::Transaction;
use models::entities::attributes::AttributesMap;
use models::entities::authz::{
    AuthzDecisionRecord, Decision, ReportedDecision, ResourceServerModel,
};
use std::collections::BTreeSet;
use store::providers::{authz_policies, authz_surface, organizations, roles};

use crate::context::{Acting, Context};

/// What is being acted on.
///
/// One arm per protected surface. The dispatch below names every one of them,
/// so adding a surface is a compile error here rather than a question that
/// quietly answers no.
#[derive(Debug, Clone, Copy)]
pub enum Resource<'a> {
    /// One named policy, against this caller. The administrative surface: it
    /// tests a rule and enforces nothing.
    Policy {
        server_id: &'a str,
        policy_id: &'a str,
    },
    /// May this caller do this to this? The surface a protected application
    /// asks on behalf of somebody using it.
    Permission {
        server_id: &'a str,
        resource: &'a str,
        scope: &'a str,
    },
    /// An object governed by relationships rather than by policies. Its engine
    /// is not built, and the arm below says so.
    Relationship {
        object_type: &'a str,
        object_id: &'a str,
    },
}

impl Resource<'_> {
    /// What the journal's `resource_kind` column takes.
    fn kind(&self) -> &'static str {
        match self {
            Self::Policy { .. } => "policy",
            Self::Permission { .. } => "permission",
            Self::Relationship { .. } => "relationship",
        }
    }

    /// Which one, where there is one to name.
    fn reference(&self) -> Option<String> {
        match self {
            Self::Policy { policy_id, .. } => Some((*policy_id).to_owned()),
            Self::Permission {
                resource, scope, ..
            } => Some(format!("{resource}#{scope}")),
            Self::Relationship {
                object_type,
                object_id,
            } => Some(format!("{object_type}:{object_id}")),
        }
    }
}

/// What was decided, and what the caller is told.
///
/// Two answers and not one, kept apart all the way out. What the caller hears
/// has two values because there is no third answer to give somebody; what the
/// evaluation reached has three, and a permissive application reporting a
/// permit over a refusal is exactly the case an auditor is looking for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub reported: ReportedDecision,
    pub computed: Decision,
    pub detail: serde_json::Value,
}

impl Answer {
    pub fn permitted(&self) -> bool {
        self.reported == ReportedDecision::Permit
    }
}

/// One question, with everything needed to answer it and to write it down.
///
/// The identifier is the caller's to mint. Nothing here can: an instant is
/// shared by every decision one request makes, so two decisions would carry one
/// identifier and be one record where there should be two. The layer that knows
/// the request is the layer that can tell them apart.
#[derive(Debug, Clone, Copy)]
pub struct Question<'a> {
    pub resource: Resource<'a>,
    /// A stable verb, as the record keeps it.
    pub action: &'a str,
    /// Unique per decision, minted by the caller.
    pub decision_id: &'a str,
    pub trace_id: Option<&'a str>,
}

/// Why a decision could not be reached at all.
///
/// Distinct from a refusal. A question that could not be asked and a question
/// answered no are different events, and only the second one is a decision.
///
/// Failing to record is fatal here, which is a position rather than an
/// oversight. The record goes into the transaction the decision was asked in,
/// so a refused insert does not merely go unrecorded: it poisons the
/// transaction, and everything after it fails regardless. Answering yes on the
/// way out of a transaction that cannot commit would be answering about work
/// that never happened. Surviving it means giving the journal a connection of
/// its own, which is a change to how this layer reaches the database.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unanswerable {
    #[error("the store could not be read")]
    Unreadable,
    #[error("the decision could not be recorded")]
    Unrecorded,
}

/// Decide, and record what was decided.
pub async fn decide(
    transaction: &Transaction<'_>,
    context: &Context,
    question: Question<'_>,
) -> Result<Answer, Unanswerable> {
    let started = Utc::now();
    let facts = gather(transaction, context).await?;

    let answer = match question.resource {
        Resource::Policy {
            server_id,
            policy_id,
        } => tested(transaction, context, &facts, server_id, policy_id).await?,
        Resource::Permission {
            server_id,
            resource,
            scope,
        } => enforced(transaction, context, &facts, server_id, resource, scope).await?,
        // Named, not forgotten. When the engine lands this arm calls it, and
        // until then the record says the question reached a surface nothing
        // answers rather than a caller being refused on the merits.
        Resource::Relationship { .. } => Answer {
            reported: ReportedDecision::Deny,
            computed: Decision::Indeterminate,
            detail: serde_json::json!({ "reasons": [{ "reason": "no-engine" }] }),
        },
    };

    record(
        transaction,
        context,
        &question,
        &answer,
        (Utc::now() - started)
            .num_microseconds()
            .unwrap_or(0)
            .max(0),
    )
    .await?;

    Ok(answer)
}

/// Everything the store says about this caller, owned so a borrowed request can
/// be built from it.
///
/// Gathered once per decision. Read per engine, two engines in one request
/// could see two callers, which is the shape the context exists to prevent one
/// layer up.
///
/// `acting` is a set of one on purpose. The engine asks its confinement
/// question against the organizations a caller belongs to, and a caller may
/// belong to several; this hands it the one the caller said it was acting
/// within, confirmed against the store. That is narrower, and narrower is the
/// safe direction: an unplaced confined policy is silent as a permission and
/// withholds as a condition, and neither of those grants.
struct Facts {
    roles: BTreeSet<String>,
    groups: BTreeSet<String>,
    attributes: AttributesMap,
    /// The organization the caller acts within, as a set of one.
    acting: BTreeSet<String>,
}

async fn gather(transaction: &Transaction<'_>, context: &Context) -> Result<Facts, Unanswerable> {
    let subject = context.principal.id();

    let mut roles: BTreeSet<String> = roles::effective_roles(transaction, subject)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .into_iter()
        .map(|role| role.role_id)
        .collect();

    // The same confinement the admin plane applies: a grant made inside an
    // organization counts there and nowhere else.
    if let Acting::In { org_id } = &context.acting {
        roles.extend(
            organizations::roles_of_member(transaction, org_id, subject)
                .await
                .map_err(|_| Unanswerable::Unreadable)?
                .into_iter()
                .map(|role| role.role_id),
        );
    }

    let groups = roles::groups_of(transaction, subject)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
        .into_iter()
        .collect();

    let acting = match &context.acting {
        Acting::In { org_id } => BTreeSet::from([org_id.clone()]),
        Acting::RealmWide => BTreeSet::new(),
    };

    Ok(Facts {
        roles,
        groups,
        acting,
        attributes: context
            .principal
            .user()
            .attributes
            .clone()
            .unwrap_or_default(),
    })
}

/// The question, as the engine reads it.
fn asked<'a>(context: &'a Context, facts: &'a Facts) -> Request<'a> {
    Request {
        caller: Caller::User {
            user_id: context.principal.id(),
            through: match context.presenter.as_deref() {
                Some(client_id) => Through::Client(Presented {
                    client_id,
                    // Nothing resolves a token's scope names to identifiers yet.
                    // Said to be unread rather than handed over empty, since an
                    // empty set is a token carrying none, which is an answer.
                    client_scopes: Resolved::Unknown,
                }),
                None => Through::Unestablished,
            },
        },
        roles: Resolved::Known(&facts.roles),
        groups: Resolved::Known(&facts.groups),
        // Nothing projects a token's claims into facts yet. Said to be unread
        // rather than handed over empty, because a rule reading a claim must be
        // unevaluable and not answered no.
        token_claims: Resolved::Unknown,
        subject_attributes: Resolved::Known(&facts.attributes),
        membership: match &context.acting {
            Acting::In { .. } => Membership::In(&facts.acting),
            Acting::RealmWide => Membership::RealmWide,
        },
        now: context.now,
    }
}

/// One named policy, tested against this caller.
async fn tested(
    transaction: &Transaction<'_>,
    context: &Context,
    facts: &Facts,
    server_id: &str,
    policy_id: &str,
) -> Result<Answer, Unanswerable> {
    let stored = authz_policies::list_for_server(transaction, server_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?;
    let set = Evaluable::index(&stored);

    let (computed, reasons) = authz::policy(&set, policy_id, asked(context, facts));

    Ok(Answer {
        // A test reports what it reached. An administrator trying a rule needs
        // to see that it could not be evaluated, not a refusal standing in.
        reported: match computed {
            Decision::Permit => ReportedDecision::Permit,
            Decision::Deny | Decision::Indeterminate => ReportedDecision::Deny,
        },
        computed,
        detail: serde_json::json!({ "reasons": reasons }),
    })
}

/// May this caller do this to this?
async fn enforced(
    transaction: &Transaction<'_>,
    context: &Context,
    facts: &Facts,
    server_id: &str,
    resource_id: &str,
    scope_id: &str,
) -> Result<Answer, Unanswerable> {
    let Some(server) = authz_surface::load_server(transaction, server_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
    else {
        return Ok(nothing_to_protect("no-such-application"));
    };

    // Resolved before the mode is read. An application that evaluates nothing
    // still does not answer yes about a resource nobody protects.
    let Some(resource) = authz_surface::load_resource(transaction, resource_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?
    else {
        return Ok(nothing_to_protect("no-such-resource"));
    };

    let declared: BTreeSet<String> = resource
        .scopes
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let stored = authz_policies::list_for_server(transaction, server_id)
        .await
        .map_err(|_| Unanswerable::Unreadable)?;
    let set = Evaluable::index(&stored);

    let verdict = authz::permission(
        &server,
        &set,
        authz::Target {
            server_id: &resource.server_id,
            resource_id: &resource.resource_id,
            resource_type: &resource.resource_type,
            scope_id,
            declared_scopes: match resource.scopes {
                Some(_) => Declared::Verbs(&declared),
                None => Declared::NotLoaded,
            },
        },
        asked(context, facts),
    );

    Ok(Answer {
        reported: verdict.reported,
        computed: verdict.computed,
        detail: serde_json::json!({
            "reasons": verdict.reasons,
            "enforcement": enforcement(&server),
        }),
    })
}

fn enforcement(server: &ResourceServerModel) -> &'static str {
    server.enforcement_mode.as_str()
}

/// A question about something nothing protects.
///
/// Refused without reading an enforcement mode, because the mode belongs to an
/// application and there is none, or to a resource it does not have.
fn nothing_to_protect(reason: &'static str) -> Answer {
    Answer {
        reported: ReportedDecision::Deny,
        computed: Decision::Deny,
        detail: serde_json::json!({ "reasons": [{ "reason": reason }] }),
    }
}

/// Write down what was decided.
///
/// On every path. A decision returned and not recorded is one nobody can
/// replay, and the two an auditor looks for are exactly the ones where the
/// answer given and the answer reached differ.
async fn record(
    transaction: &Transaction<'_>,
    context: &Context,
    question: &Question<'_>,
    answer: &Answer,
    duration_us: i64,
) -> Result<(), Unanswerable> {
    let record = AuthzDecisionRecord {
        decision_id: question.decision_id.to_owned(),
        tenant: context.tenant.tenant.clone(),
        realm_id: context.tenant.realm_id.clone(),
        subject_type: context.principal.kind().to_owned(),
        subject_id: context.principal.id().to_owned(),
        resource_kind: question.resource.kind().to_owned(),
        resource_ref: question.resource.reference(),
        action: question.action.to_owned(),
        reported: answer.reported,
        computed: answer.computed,
        detail: answer.detail.clone(),
        duration_us,
        trace_id: question.trace_id.map(str::to_owned),
        occurred_at_millis: None,
    };

    authz_policies::record(transaction, &record)
        .await
        .map_err(|_| Unanswerable::Unrecorded)
}
