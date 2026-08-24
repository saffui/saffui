use authz::{Caller, Declared, Evaluable, Membership, Presented, Request, Resolved, Through};
use chrono::Utc;
use deadpool_postgres::{Pool, Transaction};
use models::entities::attributes::AttributesMap;
use models::entities::authz::{
    AuthzDecisionRecord, Decision, ReportedDecision, ResourceServerModel,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use store::providers::{authz_policies, authz_surface, organizations, roles};
use store::tenancy::{Tenancy, TenantContext};

use crate::context::{Acting, Context};
use crate::rebac;

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
    /// An object governed by relationships rather than by policies.
    ///
    /// The relation is part of what is being asked about, beside the object,
    /// for the reason the scope is part of a permission question: what may be
    /// done is half of it, and a verb arriving as free text somewhere else is a
    /// verb nothing checks against what the schema declares.
    Relationship {
        object_type: &'a str,
        object_id: &'a str,
        relation: &'a str,
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
                relation,
            } => Some(format!("{object_type}:{object_id}#{relation}")),
        }
    }
}

/// What was decided, and what the caller is told. Two answers, since a
/// permissive application reporting a permit over a refusal is the case an
/// auditor looks for.
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
/// The identifier is the caller's to mint: an instant is shared by every
/// decision one request makes, so two would be one record.
#[derive(Debug, Clone, Copy)]
pub struct Question<'a> {
    pub resource: Resource<'a>,
    /// A stable verb, as the record keeps it.
    pub action: &'a str,
    /// Unique per decision, minted by the caller.
    pub decision_id: &'a str,
    pub trace_id: Option<&'a str>,
}

/// Where decisions are written down, on connections of its own.
///
/// Written into the caller's transaction a failed append poisons it, so an
/// audit outage becomes a service outage. One that misses is counted instead.
#[derive(Clone)]
pub struct Journal {
    pool: Pool,
    tenancy: Tenancy,
    missed: Arc<AtomicU64>,
}

impl Journal {
    pub fn new(pool: Pool, tenancy: Tenancy) -> Self {
        Self {
            pool,
            tenancy,
            missed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many decisions were reached and not written down.
    pub fn missed(&self) -> u64 {
        self.missed.load(Ordering::Relaxed)
    }

    async fn append(&self, tenant: &TenantContext, record: &AuthzDecisionRecord) -> bool {
        let landed = async {
            let mut connection = self.pool.get().await.ok()?;
            let transaction = self
                .tenancy
                .transaction(&mut connection, tenant)
                .await
                .ok()?;
            authz_policies::record(&transaction, record).await.ok()?;
            transaction.commit().await.ok()
        }
        .await
        .is_some();

        if !landed {
            self.missed.fetch_add(1, Ordering::Relaxed);
        }
        landed
    }
}

/// Why a decision could not be reached at all.
///
/// Distinct from a refusal. A question that could not be asked and a question
/// answered no are different events, and only the second one is a decision.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unanswerable {
    #[error("the store could not be read")]
    Unreadable,
    /// A refusal reported as a permit, and not written down: the only place
    /// such a refusal exists.
    #[error("a masked refusal could not be recorded")]
    Unrecorded,
}

/// Decide, and record what was decided.
pub async fn decide(
    transaction: &Transaction<'_>,
    journal: &Journal,
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
        Resource::Relationship {
            object_type,
            object_id,
            relation,
        } => related(transaction, context, object_type, object_id, relation).await?,
    };

    record(
        journal,
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
/// be built from it. Gathered once, since two engines reading their own would
/// see two callers.
///
/// `acting` is a set of one: the organization the caller said it was acting
/// within, which is narrower than everything it belongs to, and narrow is the
/// safe direction.
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

/// Does this caller stand in this relation to this object?
///
/// The engine next door: neither it nor a policy can overrule the other, since
/// neither is ever asked the other's question. Every way the walk fails to
/// reach an answer is `Indeterminate`, never a refusal.
async fn related(
    transaction: &Transaction<'_>,
    context: &Context,
    object_type: &str,
    object_id: &str,
    relation: &str,
) -> Result<Answer, Unanswerable> {
    let schema = match rebac::schema_of(transaction).await {
        Ok(schema) => schema,
        Err(why) => return Ok(unwalkable(&why)),
    };

    let walked = rebac::check(
        transaction,
        &schema,
        rebac::Object {
            object_type,
            object_id,
        },
        relation,
        rebac::Subject {
            subject_type: context.principal.kind(),
            subject_id: context.principal.id(),
        },
        rebac::CHECK,
    )
    .await;

    Ok(match walked {
        Ok(true) => Answer {
            reported: ReportedDecision::Permit,
            computed: Decision::Permit,
            detail: serde_json::json!({ "reasons": [] }),
        },
        Ok(false) => Answer {
            reported: ReportedDecision::Deny,
            computed: Decision::Deny,
            detail: serde_json::json!({ "reasons": [{ "reason": "unrelated" }] }),
        },
        Err(why) => unwalkable(&why),
    })
}

/// A walk that reached no answer, recorded as one.
fn unwalkable(why: &rebac::Unwalkable) -> Answer {
    Answer {
        reported: ReportedDecision::Deny,
        computed: Decision::Indeterminate,
        detail: serde_json::json!({
            "reasons": [{ "reason": why.slug(), "says": why.to_string() }]
        }),
    }
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

/// A question about something nothing protects, refused without reading an
/// enforcement mode: the mode belongs to an application that is not there.
fn nothing_to_protect(reason: &'static str) -> Answer {
    Answer {
        reported: ReportedDecision::Deny,
        computed: Decision::Deny,
        detail: serde_json::json!({ "reasons": [{ "reason": reason }] }),
    }
}

/// Write down what was decided, on every path.
async fn record(
    journal: &Journal,
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

    if journal.append(&context.tenant, &record).await {
        return Ok(());
    }

    if answer.reported == ReportedDecision::Permit && answer.computed != Decision::Permit {
        return Err(Unanswerable::Unrecorded);
    }
    Ok(())
}
