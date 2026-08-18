//! What a policy decides, what it decides on, and what was decided.
//!
//! The write path is where a policy is made sound. A constraint reads one row,
//! so it can hold that a rule names its own kind and that no binding hangs from
//! a kind that would not read it, and it cannot hold that a role policy names a
//! role, that a permission has a condition, that a pattern compiles, or that an
//! aggregation does not lead back to where it started. Each of those is a
//! property of the whole shape, and each is refused here.
//!
//! What that buys is on the read side. By the time an evaluator meets a policy,
//! the answer it owes is a decision, and every one of these faults would have
//! to be answered with one. A permission with no condition can only refuse, and
//! refusing for want of a condition is indistinguishable from refusing because a
//! condition said no.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use commons::pattern;
use commons::walk::{self, Budget};
use deadpool_postgres::Transaction;
use models::entities::authz::{
    AuthzDecisionRecord, Decision, PolicyModel, PolicyRule, PolicyTerms, PolicyType,
    ReportedDecision, StoredPolicy,
};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const POLICY_COLUMNS: &str = "tenant, realm_id, policy_id, server_id, org_id, name, description, \
                              policy_type, rule, decision, logic, policy_owner, created_by, \
                              created_at, updated_by, updated_at, version";

const DECISION_COLUMNS: &str = "tenant, realm_id, decision_id, subject_type, subject_id, \
                                resource_kind, resource_ref, action, reported, computed, detail, \
                                duration_us, trace_id, occurred_at";

/// How far the aggregation graph is searched before a write is refused.
///
/// Both ceilings sit far above any policy set written by hand and far below
/// what would hold a connection. Reaching either refuses the write: what is
/// being asked is whether an edge closes a cycle, and not having found one is
/// not the same answer as there not being one.
const GRAPH: Budget = Budget {
    max_depth: 16,
    max_nodes: 1024,
};

/// What the schema cannot see, refused where the whole shape is known.
///
/// Public because it is the same question an administrative endpoint wants
/// answered before it offers to save anything, and asking it twice from two
/// pieces of code is how the two come to disagree.
pub fn validate(terms: &PolicyTerms) -> StoreResult<()> {
    let kind = terms.policy_type();

    // What was given but would not be read. Written, it would be dropped
    // silently, and the administrator would be left with a policy narrower than
    // the one they described.
    if !aggregates(kind) && !terms.policies.is_empty() {
        return Err(StoreError::UnreadBinding {
            kind: kind.as_str(),
            binding: "conditions",
        });
    }
    if !is_permission(kind) && !terms.resources.is_empty() {
        return Err(StoreError::UnreadBinding {
            kind: kind.as_str(),
            binding: "resources",
        });
    }
    // Scopes belong to the one kind defined by them. A resource permission that
    // could bind them would have two meanings for an empty list, since the
    // binding rows cascade: the verbs it was written to cover, and every verb
    // there is once somebody deletes the last one it named.
    if kind != PolicyType::ScopePermission && !terms.scopes.is_empty() {
        return Err(StoreError::UnreadBinding {
            kind: kind.as_str(),
            binding: "scopes",
        });
    }

    match &terms.rule {
        PolicyRule::Role { roles } => at_least_one("role", roles),
        PolicyRule::Group { groups, .. } => at_least_one("group", groups),
        PolicyRule::User { users } => at_least_one("user", users),
        PolicyRule::Client { clients } => at_least_one("client", clients),
        PolicyRule::ClientScope { client_scopes } => at_least_one("client scope", client_scopes),
        // A comparison carries its own terms and is legible to the schema as
        // the document it is stored as.
        PolicyRule::Attribute { .. } => Ok(()),
        // A window is not. What the schema cannot see is whether any instant
        // could satisfy it, and one that none could is a grant in waiting.
        PolicyRule::Time(window) => match window.defect() {
            Some(defect) => Err(StoreError::UnusableWindow { defect }),
            None => Ok(()),
        },
        // Compiled once, here. A decision that compiled it would pay for it per
        // request and would meet a bad pattern with a decision to make.
        PolicyRule::Regex { target_regex, .. } => {
            pattern::compile(target_regex)?;
            Ok(())
        }
        PolicyRule::Aggregated => at_least_one("aggregated", &terms.policies),
        PolicyRule::ScopePermission { resource_type } => {
            permission_applies(terms, resource_type)?;
            at_least_one("scope permission", &terms.scopes)
        }
        PolicyRule::ResourcePermission { resource_type } => {
            permission_applies(terms, resource_type)
        }
    }
}

/// Record a policy, and everything it is bound to.
///
/// One transaction, so a policy and its bindings arrive together. A row written
/// without its bindings is a policy that names nothing, which is the shape
/// [`validate`] exists to refuse.
pub async fn create(transaction: &Transaction<'_>, policy: &PolicyModel) -> StoreResult<()> {
    validate(&policy.terms)?;
    let conditions = resolve_conditions(transaction, policy).await?;
    refuse_cycles(transaction, policy).await?;

    // The document as the model writes it, members and all. The binding rows
    // beside it are what the database keeps in step with the rest of the realm;
    // this stays the record of what was asked for.
    let rule = serde_json::to_value(&policy.terms.rule).map_err(|_| StoreError::Backend)?;
    let kind = policy.policy_type();

    let set = WriteSet::insert(vec![
        col("tenant", &policy.metadata.tenant),
        col("realm_id", &policy.realm_id),
        col("policy_id", &policy.policy_id),
        col("server_id", &policy.server_id),
        col("org_id", &policy.org_id),
        col("name", &policy.terms.name),
        col("description", &policy.terms.description),
        col("policy_type", &kind),
        col("rule", &rule),
        col("decision", &policy.terms.decision),
        col("logic", &policy.terms.logic),
        col("policy_owner", &policy.terms.policy_owner),
        col("created_by", &policy.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("policies", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;

    bind_members(transaction, policy, &conditions).await
}

/// One policy of this application.
pub async fn load(
    transaction: &Transaction<'_>,
    server_id: &str,
    policy_id: &str,
) -> StoreResult<Option<StoredPolicy>> {
    let statement =
        format!("SELECT {POLICY_COLUMNS} FROM policies WHERE server_id = $1 AND policy_id = $2");
    let rows = transaction
        .query(statement.as_str(), &[&server_id, &policy_id])
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(assemble(transaction, server_id, rows).await?.pop())
}

/// Every policy of one application, by name.
///
/// A row that will not decode comes back named rather than dropped, and does
/// not take the rest of the list with it. Dropping it would make a policy
/// nobody can read look like a policy nobody wrote, and under a strategy where
/// one permit is enough those two are the difference between refusing and
/// permitting.
pub async fn list_for_server(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> StoreResult<Vec<StoredPolicy>> {
    let statement =
        format!("SELECT {POLICY_COLUMNS} FROM policies WHERE server_id = $1 ORDER BY name ASC");
    let rows = transaction
        .query(statement.as_str(), &[&server_id])
        .await
        .map_err(|_| StoreError::Backend)?;

    assemble(transaction, server_id, rows).await
}

/// Rewrite a policy and everything it is bound to.
///
/// The bindings are replaced rather than added to. A policy is the set it
/// names, and an update that only ever added would leave no way to take a role
/// back out through the door it was put in by.
///
/// The kind is not one of the things an update may change. Every binding hangs
/// from it, so a policy that changed kind would be a different policy wearing
/// the same identifier, and everything conditioned on it would follow the
/// change without anybody asking for it.
pub async fn update(transaction: &Transaction<'_>, policy: &PolicyModel) -> StoreResult<bool> {
    validate(&policy.terms)?;

    let Some(stored) = kind_of(transaction, &policy.server_id, &policy.policy_id).await? else {
        return Ok(false);
    };
    if stored != policy.policy_type() {
        return Err(StoreError::PolicyKindChanged);
    }
    let conditions = resolve_conditions(transaction, policy).await?;
    refuse_cycles(transaction, policy).await?;

    let rule = serde_json::to_value(&policy.terms.rule).map_err(|_| StoreError::Backend)?;
    let set = WriteSet::update(
        vec![
            col("org_id", &policy.org_id),
            col("name", &policy.terms.name),
            col("description", &policy.terms.description),
            col("rule", &rule),
            col("decision", &policy.terms.decision),
            col("logic", &policy.terms.logic),
            col("policy_owner", &policy.terms.policy_owner),
            col("updated_by", &policy.metadata.updated_by),
        ],
        vec![col("policy_id", &policy.policy_id)],
    );

    // The stamp and the version are the statement's, not the caller's: one
    // clock, and a version nobody can hand in a second opinion on.
    let statement = statement::update("policies", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );

    transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;

    unbind(transaction, &policy.policy_id).await?;
    bind_members(transaction, policy, &conditions).await?;
    Ok(true)
}

/// Drop every binding of one policy, whatever kind it is.
///
/// Named table by table rather than swept, because there is no one table to
/// sweep: each kind's members live where that kind reads them.
async fn unbind(transaction: &Transaction<'_>, policy_id: &str) -> StoreResult<()> {
    for table in [
        "policies_roles",
        "policies_groups",
        "policies_users",
        "policies_clients",
        "policies_client_scopes",
        "policies_resources",
        "policies_scopes",
        "policies_policies",
    ] {
        transaction
            .execute(
                format!("DELETE FROM {table} WHERE policy_id = $1").as_str(),
                &[&policy_id],
            )
            .await
            .map_err(|_| StoreError::Backend)?;
    }
    Ok(())
}

/// Remove a policy, and say whether there was one to remove.
///
/// A policy something is conditioned on is refused rather than left to the
/// constraint, so the caller is told what is in the way and the transaction it
/// asked in is still usable. Removing it would leave a parent requiring one
/// condition where it required two, and nothing to show the other was there.
pub async fn delete(transaction: &Transaction<'_>, policy_id: &str) -> StoreResult<bool> {
    if is_a_condition(transaction, policy_id).await? {
        return Err(StoreError::PolicyIsACondition {
            policy_id: policy_id.to_owned(),
        });
    }

    let removed = transaction
        .execute("DELETE FROM policies WHERE policy_id = $1", &[&policy_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Drop every aggregation edge of one application.
///
/// What anything removing a whole application calls first. A condition cannot
/// be deleted from under the policy that reads it, and a cascade takes the rows
/// in whatever order it reaches them, so the edges go before the rows the
/// constraint is about.
pub async fn unbind_server(transaction: &Transaction<'_>, server_id: &str) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM policies_policies WHERE server_id = $1",
            &[&server_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Whether anything is conditioned on this policy.
async fn is_a_condition(transaction: &Transaction<'_>, policy_id: &str) -> StoreResult<bool> {
    Ok(transaction
        .query_opt(
            "SELECT 1 FROM policies_policies WHERE associated_policy_id = $1 LIMIT 1",
            &[&policy_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .is_some())
}

/// Record what was decided.
///
/// Both outcomes, always. What the caller was told and what the evaluation
/// reached are the same on an ordinary decision and differ on the two that
/// matter: a permissive server reporting a permit over a denial, and a policy
/// that could not be evaluated at all.
pub async fn record(
    transaction: &Transaction<'_>,
    decision: &AuthzDecisionRecord,
) -> StoreResult<()> {
    let reported = decision.reported.as_str();
    let computed = decision.computed.as_str();

    let set = WriteSet::insert(vec![
        col("tenant", &decision.tenant),
        col("realm_id", &decision.realm_id),
        col("decision_id", &decision.decision_id),
        col("subject_type", &decision.subject_type),
        col("subject_id", &decision.subject_id),
        col("resource_kind", &decision.resource_kind),
        col("resource_ref", &decision.resource_ref),
        col("action", &decision.action),
        col("reported", &reported),
        col("computed", &computed),
        col("detail", &decision.detail),
        col("duration_us", &decision.duration_us),
        col("trace_id", &decision.trace_id),
    ]);

    transaction
        .execute(
            statement::insert("authz_decisions", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The most recent decisions of this realm, newest first.
///
/// A row that will not decode fails the read, unlike a policy that will not.
/// The difference is what the answer is for: an evaluation continues without a
/// policy it cannot read and says so in its own record, while an audit that
/// quietly skipped a line would be an audit that reads as complete.
pub async fn recent(
    transaction: &Transaction<'_>,
    limit: i64,
) -> StoreResult<Vec<AuthzDecisionRecord>> {
    let statement = format!(
        "SELECT {DECISION_COLUMNS} FROM authz_decisions ORDER BY occurred_at DESC LIMIT $1"
    );
    transaction
        .query(statement.as_str(), &[&limit])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_decision)
        .collect()
}

/// Decisions whose reported answer is not what was computed.
///
/// The two an auditor is looking for, in one read: a denial the caller never
/// saw, and an evaluation that reached no answer.
pub async fn disagreements(
    transaction: &Transaction<'_>,
    limit: i64,
) -> StoreResult<Vec<AuthzDecisionRecord>> {
    let statement = format!(
        "SELECT {DECISION_COLUMNS} FROM authz_decisions WHERE reported <> computed \
         ORDER BY occurred_at DESC LIMIT $1"
    );
    transaction
        .query(statement.as_str(), &[&limit])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_decision)
        .collect()
}

/// Whether a kind is one that decides from other policies.
fn aggregates(kind: PolicyType) -> bool {
    matches!(
        kind,
        PolicyType::Aggregated | PolicyType::ScopePermission | PolicyType::ResourcePermission
    )
}

/// Whether a kind is one that applies to part of a surface.
fn is_permission(kind: PolicyType) -> bool {
    matches!(
        kind,
        PolicyType::ScopePermission | PolicyType::ResourcePermission
    )
}

fn at_least_one(kind: &'static str, members: &[String]) -> StoreResult<()> {
    if members.is_empty() {
        return Err(StoreError::EmptyPolicy { kind });
    }
    Ok(())
}

/// A permission has something to decide with, and something to decide about.
fn permission_applies(terms: &PolicyTerms, resource_type: &str) -> StoreResult<()> {
    if terms.policies.is_empty() {
        return Err(StoreError::UnconditionalPermission);
    }
    if terms.resources.is_empty() && resource_type.trim().is_empty() {
        return Err(StoreError::UnappliedPermission);
    }
    Ok(())
}

/// Write each kind's members into the table that reads them.
///
/// Every arm named, with no catch-all. A twelfth kind does not compile until it
/// has said here where its members go, which is the difference between adding a
/// kind and adding one whose bindings quietly go nowhere.
async fn bind_members(
    transaction: &Transaction<'_>,
    policy: &PolicyModel,
    conditions: &[(String, PolicyType)],
) -> StoreResult<()> {
    let terms = &policy.terms;

    match &terms.rule {
        PolicyRule::Role { roles } => {
            bind(transaction, policy, "policies_roles", "role_id", roles).await?
        }
        PolicyRule::Group { groups, .. } => {
            bind(transaction, policy, "policies_groups", "group_id", groups).await?
        }
        PolicyRule::User { users } => {
            bind(transaction, policy, "policies_users", "user_id", users).await?
        }
        PolicyRule::Client { clients } => {
            bind(
                transaction,
                policy,
                "policies_clients",
                "client_id",
                clients,
            )
            .await?
        }
        PolicyRule::ClientScope { client_scopes } => {
            bind(
                transaction,
                policy,
                "policies_client_scopes",
                "client_scope_id",
                client_scopes,
            )
            .await?
        }
        // These decide from what the document already holds.
        PolicyRule::Time(_) | PolicyRule::Regex { .. } | PolicyRule::Attribute { .. } => {}
        // And this one from the conditions written below, which it shares with
        // the permissions.
        PolicyRule::Aggregated => {}
        PolicyRule::ScopePermission { .. } | PolicyRule::ResourcePermission { .. } => {
            bind(
                transaction,
                policy,
                "policies_resources",
                "resource_id",
                &terms.resources,
            )
            .await?;
            bind(
                transaction,
                policy,
                "policies_scopes",
                "scope_id",
                &terms.scopes,
            )
            .await?;
        }
    }

    for (condition, condition_kind) in conditions {
        aggregate(transaction, policy, condition, *condition_kind).await?;
    }
    Ok(())
}

/// Write one kind's members into one table.
///
/// The table and the column are compile time strings from the match above, so
/// what is formatted into the statement never came from a caller. The kind
/// travels with each row, which is what the composite foreign key keys on.
///
/// One statement for the whole set rather than one per member: a policy is
/// written with everything it names, and a round trip per name is a cost that
/// grows with how carefully somebody described their realm.
async fn bind(
    transaction: &Transaction<'_>,
    policy: &PolicyModel,
    table: &'static str,
    column: &'static str,
    members: &[String],
) -> StoreResult<()> {
    if members.is_empty() {
        return Ok(());
    }

    let kind = policy.policy_type();
    let statement = format!(
        "INSERT INTO {table} (tenant, realm_id, server_id, policy_id, policy_type, {column}) \
         SELECT current_setting('saffui.current_tenant', true), \
                current_setting('saffui.current_realm', true), $1, $2, $3, member \
         FROM unnest($4::text[]) AS member"
    );

    transaction
        .execute(
            statement.as_str(),
            &[&policy.server_id, &policy.policy_id, &kind, &members],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Condition one policy on another.
///
/// The condition's own kind is read and written with the edge, because that is
/// what the foreign key points at: a condition cannot change kind while
/// something is conditioned on it, and a permission cannot be one.
async fn aggregate(
    transaction: &Transaction<'_>,
    policy: &PolicyModel,
    condition: &str,
    condition_kind: PolicyType,
) -> StoreResult<()> {
    let kind = policy.policy_type();

    transaction
        .execute(
            "INSERT INTO policies_policies (tenant, realm_id, server_id, policy_id, \
                 policy_type, associated_policy_id, associated_type) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5",
            &[
                &policy.server_id,
                &policy.policy_id,
                &kind,
                &condition,
                &condition_kind,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The kind of every condition, resolved before anything is written.
///
/// A condition nothing answers to stops the write here rather than after the
/// row has landed. Left to the binding statement, what survives a refusal would
/// depend on the caller rolling back, and one that committed anyway would keep
/// an aggregate with no conditions, which is the shape [`validate`] refuses.
async fn resolve_conditions(
    transaction: &Transaction<'_>,
    policy: &PolicyModel,
) -> StoreResult<Vec<(String, PolicyType)>> {
    if !aggregates(policy.policy_type()) {
        return Ok(Vec::new());
    }

    let mut resolved = Vec::with_capacity(policy.terms.policies.len());
    for condition in &policy.terms.policies {
        let Some(kind) = kind_of(transaction, &policy.server_id, condition).await? else {
            return Err(StoreError::NotFound {
                asked: condition.clone(),
            });
        };
        resolved.push((condition.clone(), kind));
    }
    Ok(resolved)
}

/// Refuse an aggregation that leads back to where it started.
///
/// The table's own constraint catches the single cycle one row shows, a policy
/// conditioned on itself. Anything longer is only visible from the whole graph,
/// which is read once here and walked under a budget rather than followed by
/// recursion with nothing to stop it.
async fn refuse_cycles(transaction: &Transaction<'_>, policy: &PolicyModel) -> StoreResult<()> {
    if policy.terms.policies.is_empty() {
        return Ok(());
    }

    let edges = aggregation_edges(transaction, &policy.server_id).await?;
    let successors = |node: &str| edges.get(node).cloned().unwrap_or_default();

    for condition in &policy.terms.policies {
        // The row being written is not in the graph yet, so the edge that would
        // close the shortest cycle is checked here rather than walked to.
        if condition == &policy.policy_id
            || walk::reaches(condition, &policy.policy_id, successors, GRAPH)?
        {
            return Err(StoreError::PolicyCycle {
                policy: policy.policy_id.clone(),
                condition: condition.clone(),
            });
        }
    }
    Ok(())
}

/// Every aggregation edge of one application.
async fn aggregation_edges(
    transaction: &Transaction<'_>,
    server_id: &str,
) -> StoreResult<BTreeMap<String, Vec<String>>> {
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();

    let rows = transaction
        .query(
            "SELECT policy_id, associated_policy_id FROM policies_policies WHERE server_id = $1",
            &[&server_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    for row in rows {
        edges
            .entry(row.get("policy_id"))
            .or_default()
            .push(row.get("associated_policy_id"));
    }
    Ok(edges)
}

/// What kind one policy is, without reading the rest of it.
async fn kind_of(
    transaction: &Transaction<'_>,
    server_id: &str,
    policy_id: &str,
) -> StoreResult<Option<PolicyType>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT policy_type FROM policies WHERE server_id = $1 AND policy_id = $2",
            &[&server_id, &policy_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    // A kind this build cannot name is not a missing policy, and conditioning
    // on something unreadable is not a write to complete quietly.
    row.try_get("policy_type")
        .map(Some)
        .map_err(|_| StoreError::Backend)
}

/// What each policy of a set is bound to.
///
/// Eight statements whatever the count, rather than one per policy per table.
/// The bindings of a whole application are what one evaluation reads, so a
/// query per row would make a decision cost more the more carefully somebody
/// described their realm.
struct Bound {
    roles: HashMap<String, Vec<String>>,
    groups: HashMap<String, Vec<String>>,
    users: HashMap<String, Vec<String>>,
    clients: HashMap<String, Vec<String>>,
    client_scopes: HashMap<String, Vec<String>>,
    resources: HashMap<String, Vec<String>>,
    scopes: HashMap<String, Vec<String>>,
    policies: HashMap<String, Vec<String>>,
}

impl Bound {
    fn of(bindings: &HashMap<String, Vec<String>>, policy_id: &str) -> Vec<String> {
        bindings.get(policy_id).cloned().unwrap_or_default()
    }
}

async fn assemble(
    transaction: &Transaction<'_>,
    server_id: &str,
    rows: Vec<Row>,
) -> StoreResult<Vec<StoredPolicy>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = rows.iter().map(|row| row.get("policy_id")).collect();

    let bound = Bound {
        roles: members(transaction, server_id, &ids, "policies_roles", "role_id").await?,
        groups: members(transaction, server_id, &ids, "policies_groups", "group_id").await?,
        users: members(transaction, server_id, &ids, "policies_users", "user_id").await?,
        clients: members(
            transaction,
            server_id,
            &ids,
            "policies_clients",
            "client_id",
        )
        .await?,
        client_scopes: members(
            transaction,
            server_id,
            &ids,
            "policies_client_scopes",
            "client_scope_id",
        )
        .await?,
        resources: members(
            transaction,
            server_id,
            &ids,
            "policies_resources",
            "resource_id",
        )
        .await?,
        scopes: members(transaction, server_id, &ids, "policies_scopes", "scope_id").await?,
        policies: members(
            transaction,
            server_id,
            &ids,
            "policies_policies",
            "associated_policy_id",
        )
        .await?,
    };

    Ok(rows
        .into_iter()
        .map(|row| read_policy(row, &bound))
        .collect())
}

/// One binding table, for a set of policies.
async fn members(
    transaction: &Transaction<'_>,
    server_id: &str,
    policy_ids: &[String],
    table: &'static str,
    column: &'static str,
) -> StoreResult<HashMap<String, Vec<String>>> {
    let statement = format!(
        "SELECT policy_id, {column} AS member FROM {table} \
         WHERE server_id = $1 AND policy_id = ANY($2) ORDER BY {column} ASC"
    );

    let mut bindings: HashMap<String, Vec<String>> = HashMap::new();
    for row in transaction
        .query(statement.as_str(), &[&server_id, &policy_ids])
        .await
        .map_err(|_| StoreError::Backend)?
    {
        bindings
            .entry(row.get("policy_id"))
            .or_default()
            .push(row.get("member"));
    }
    Ok(bindings)
}

fn read_policy(row: Row, bound: &Bound) -> StoredPolicy {
    let policy_id: String = row.get("policy_id");

    // The discriminant first, and with `try_get`. It is the column an older
    // build meets when a newer one has added a kind, and reading it with `get`
    // would answer that with a panic in the middle of an evaluation.
    if row.try_get::<_, PolicyType>("policy_type").is_err() {
        return StoredPolicy::Unreadable { policy_id };
    }
    let Ok(document) = row.try_get::<_, serde_json::Value>("rule") else {
        return StoredPolicy::Unreadable { policy_id };
    };
    let Ok(rule) = serde_json::from_value::<PolicyRule>(document) else {
        return StoredPolicy::Unreadable { policy_id };
    };

    let terms = PolicyTerms {
        name: row.get("name"),
        description: row.get("description"),
        decision: row.get("decision"),
        logic: row.get("logic"),
        policy_owner: row.get("policy_owner"),
        policies: Bound::of(&bound.policies, &policy_id),
        resources: Bound::of(&bound.resources, &policy_id),
        scopes: Bound::of(&bound.scopes, &policy_id),
        rule: rebind(rule, bound, &policy_id),
    };

    StoredPolicy::Read(PolicyModel {
        policy_id,
        server_id: row.get("server_id"),
        realm_id: row.get("realm_id"),
        org_id: row.get("org_id"),
        terms,
        metadata: audit(&row),
    })
}

/// Take the members from the rows rather than from the document.
///
/// Both hold them. The document is what was written; the binding rows are what
/// still exists, since removing a role from the realm takes its binding with it
/// and leaves the document naming it. A reader is given what exists, and the
/// document stays the record of what was asked for.
fn rebind(rule: PolicyRule, bound: &Bound, policy_id: &str) -> PolicyRule {
    match rule {
        PolicyRule::Role { .. } => PolicyRule::Role {
            roles: Bound::of(&bound.roles, policy_id),
        },
        PolicyRule::Group { .. } => PolicyRule::Group {
            groups: Bound::of(&bound.groups, policy_id),
        },
        PolicyRule::User { .. } => PolicyRule::User {
            users: Bound::of(&bound.users, policy_id),
        },
        PolicyRule::Client { .. } => PolicyRule::Client {
            clients: Bound::of(&bound.clients, policy_id),
        },
        PolicyRule::ClientScope { .. } => PolicyRule::ClientScope {
            client_scopes: Bound::of(&bound.client_scopes, policy_id),
        },
        // Nothing these name is a row of its own, so the document is all there
        // is to read. Named rather than left to a catch-all, so a kind added
        // later has to say which of the two it is.
        rule @ (PolicyRule::Time(_)
        | PolicyRule::Regex { .. }
        | PolicyRule::Attribute { .. }
        | PolicyRule::Aggregated
        | PolicyRule::ScopePermission { .. }
        | PolicyRule::ResourcePermission { .. }) => rule,
    }
}

fn read_decision(row: Row) -> StoreResult<AuthzDecisionRecord> {
    let reported: String = row.get("reported");
    let computed: String = row.get("computed");
    let occurred_at: DateTime<Utc> = row.get("occurred_at");

    Ok(AuthzDecisionRecord {
        decision_id: row.get("decision_id"),
        tenant: row.get("tenant"),
        realm_id: row.get("realm_id"),
        subject_type: row.get("subject_type"),
        subject_id: row.get("subject_id"),
        resource_kind: row.get("resource_kind"),
        resource_ref: row.get("resource_ref"),
        action: row.get("action"),
        reported: ReportedDecision::from_str(&reported).map_err(|_| StoreError::Backend)?,
        computed: Decision::from_str(&computed).map_err(|_| StoreError::Backend)?,
        detail: row.get("detail"),
        duration_us: row.get("duration_us"),
        trace_id: row.get("trace_id"),
        occurred_at_millis: Some(occurred_at.timestamp_millis()),
    })
}

fn audit(row: &Row) -> models::auditable::AuditableModel {
    models::auditable::AuditableModel {
        tenant: row.get("tenant"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::entities::authz::{
        Comparison, DecisionLogic, DecisionStrategy, FactSource, Operand, TimeWindow, WindowDefect,
    };

    fn terms(rule: PolicyRule) -> PolicyTerms {
        PolicyTerms {
            name: "policy".to_owned(),
            description: String::new(),
            decision: DecisionStrategy::Unanimous,
            logic: DecisionLogic::Positive,
            policy_owner: "ada".to_owned(),
            policies: Vec::new(),
            resources: Vec::new(),
            scopes: Vec::new(),
            rule,
        }
    }

    /// One shape per kind that is meant to pass, and the count is checked
    /// against the vocabulary. A kind added without a sound shape here fails
    /// this test rather than arriving with nothing exercising its write path.
    fn sound() -> Vec<PolicyTerms> {
        vec![
            terms(PolicyRule::Role {
                roles: vec!["editor".to_owned()],
            }),
            terms(PolicyRule::Group {
                groups: vec!["staff".to_owned()],
            }),
            terms(PolicyRule::User {
                users: vec!["ada".to_owned()],
            }),
            terms(PolicyRule::Client {
                clients: vec!["app".to_owned()],
            }),
            terms(PolicyRule::ClientScope {
                client_scopes: vec!["profile".to_owned()],
            }),
            terms(PolicyRule::Time(TimeWindow {
                hour: Some(9),
                hour_end: Some(18),
                ..TimeWindow::default()
            })),
            terms(PolicyRule::Regex {
                target_claim: "email".to_owned(),
                target_regex: r"^.+@example\.test$".to_owned(),
            }),
            terms(PolicyRule::Attribute {
                left: Operand::Claim {
                    source: FactSource::Token,
                    name: "tier".to_owned(),
                },
                test: Comparison::Present,
            }),
            PolicyTerms {
                policies: vec!["condition".to_owned()],
                ..terms(PolicyRule::Aggregated)
            },
            PolicyTerms {
                policies: vec!["condition".to_owned()],
                resources: vec!["doc".to_owned()],
                scopes: vec!["read".to_owned()],
                ..terms(PolicyRule::ScopePermission {
                    resource_type: String::new(),
                })
            },
            PolicyTerms {
                policies: vec!["condition".to_owned()],
                resources: vec!["doc".to_owned()],
                ..terms(PolicyRule::ResourcePermission {
                    resource_type: String::new(),
                })
            },
        ]
    }

    #[test]
    fn every_kind_has_a_shape_that_is_accepted() {
        let shapes = sound();
        let mut kinds: Vec<PolicyType> = shapes.iter().map(PolicyTerms::policy_type).collect();
        kinds.sort_by_key(|kind| kind.as_str());
        kinds.dedup();

        assert_eq!(
            kinds.len(),
            PolicyType::ALL.len(),
            "a kind has no shape here that the write path accepts"
        );
        for terms in &shapes {
            assert_eq!(
                validate(terms),
                Ok(()),
                "{:?} was refused",
                terms.policy_type()
            );
        }
    }

    /// A policy of a kind that decides by naming things, naming none. It matches
    /// nobody, and under negative logic a policy that matches nobody grants to
    /// everybody.
    #[test]
    fn a_policy_that_names_nobody_is_refused() {
        for rule in [
            PolicyRule::Role { roles: Vec::new() },
            PolicyRule::Group { groups: Vec::new() },
            PolicyRule::User { users: Vec::new() },
            PolicyRule::Client {
                clients: Vec::new(),
            },
            PolicyRule::ClientScope {
                client_scopes: Vec::new(),
            },
            PolicyRule::Aggregated,
        ] {
            let kind = rule.policy_type();
            assert!(
                matches!(validate(&terms(rule)), Err(StoreError::EmptyPolicy { .. })),
                "an empty {kind:?} policy was accepted"
            );
        }
    }

    /// A permission with nothing to decide with could only ever refuse, and a
    /// refusal for want of a condition reads the same as one a condition made.
    #[test]
    fn a_permission_with_no_condition_is_refused() {
        let permission = PolicyTerms {
            resources: vec!["doc".to_owned()],
            ..terms(PolicyRule::ResourcePermission {
                resource_type: "urn:doc".to_owned(),
            })
        };
        assert_eq!(
            validate(&permission),
            Err(StoreError::UnconditionalPermission)
        );
    }

    /// A permission that names neither a resource nor a type of one applies to
    /// nothing. What makes it worth refusing is the reading it invites: that
    /// applying to nothing means applying to everything.
    #[test]
    fn a_permission_that_applies_to_nothing_is_refused() {
        let permission = PolicyTerms {
            policies: vec!["condition".to_owned()],
            ..terms(PolicyRule::ResourcePermission {
                resource_type: "   ".to_owned(),
            })
        };
        assert_eq!(validate(&permission), Err(StoreError::UnappliedPermission));

        // And a type on its own is enough: the resources of that type are what
        // it applies to, whether or not any exist yet.
        let by_type = PolicyTerms {
            policies: vec!["condition".to_owned()],
            ..terms(PolicyRule::ResourcePermission {
                resource_type: "urn:doc".to_owned(),
            })
        };
        assert_eq!(validate(&by_type), Ok(()));
    }

    /// A scope permission decides about verbs, so one that names no verb is the
    /// same defect under another name.
    #[test]
    fn a_scope_permission_that_names_no_verb_is_refused() {
        let permission = PolicyTerms {
            policies: vec!["condition".to_owned()],
            resources: vec!["doc".to_owned()],
            ..terms(PolicyRule::ScopePermission {
                resource_type: String::new(),
            })
        };
        assert!(matches!(
            validate(&permission),
            Err(StoreError::EmptyPolicy { .. })
        ));
    }

    /// Bindings only three kinds read, given to a kind that does not. Written,
    /// they would go nowhere and the administrator would keep a policy narrower
    /// than the one they described.
    #[test]
    fn a_binding_no_kind_would_read_is_refused() {
        let conditioned = PolicyTerms {
            policies: vec!["condition".to_owned()],
            ..terms(PolicyRule::Role {
                roles: vec!["editor".to_owned()],
            })
        };
        assert_eq!(
            validate(&conditioned),
            Err(StoreError::UnreadBinding {
                kind: "role",
                binding: "conditions",
            })
        );

        let applied = PolicyTerms {
            resources: vec!["doc".to_owned()],
            ..terms(PolicyRule::Aggregated)
        };
        assert_eq!(
            validate(&applied),
            Err(StoreError::UnreadBinding {
                kind: "aggregated",
                binding: "resources",
            })
        );
    }

    /// Only the kind defined by the verbs it names may bind them. A resource
    /// permission that could would have two meanings for an empty list, since
    /// the rows cascade: the verbs it was written to cover, and every verb
    /// there is once somebody deletes the last one it named.
    #[test]
    fn only_the_kind_defined_by_verbs_binds_them() {
        let over_reaching = PolicyTerms {
            policies: vec!["condition".to_owned()],
            resources: vec!["doc".to_owned()],
            scopes: vec!["read".to_owned()],
            ..terms(PolicyRule::ResourcePermission {
                resource_type: String::new(),
            })
        };
        assert_eq!(
            validate(&over_reaching),
            Err(StoreError::UnreadBinding {
                kind: "resource-permission",
                binding: "scopes",
            })
        );
    }

    /// A window no instant can satisfy is not a policy that never grants. Under
    /// negative logic it is one that always does.
    #[test]
    fn a_window_no_instant_could_satisfy_is_refused() {
        let unusable = [
            (TimeWindow::default(), WindowDefect::Unbounded),
            (
                TimeWindow {
                    hour: Some(9),
                    ..TimeWindow::default()
                },
                WindowDefect::HalfOpen,
            ),
            (
                TimeWindow {
                    hour: Some(17),
                    hour_end: Some(9),
                    ..TimeWindow::default()
                },
                WindowDefect::Inverted,
            ),
            (
                TimeWindow {
                    month: Some(0),
                    month_end: Some(12),
                    ..TimeWindow::default()
                },
                WindowDefect::OutOfRange,
            ),
            (
                TimeWindow {
                    month: Some(2),
                    month_end: Some(2),
                    day_of_month: Some(30),
                    day_of_month_end: Some(31),
                    ..TimeWindow::default()
                },
                WindowDefect::NoSuchDate,
            ),
        ];

        for (window, defect) in unusable {
            assert_eq!(
                validate(&terms(PolicyRule::Time(window))),
                Err(StoreError::UnusableWindow { defect }),
                "{window:?}"
            );
        }

        // And one that names a bound with no end on the side that has none is
        // still written: a policy in force from a date is an ordinary thing.
        let from_a_date = TimeWindow {
            not_before: Some(1_760_000_000),
            ..TimeWindow::default()
        };
        assert_eq!(validate(&terms(PolicyRule::Time(from_a_date))), Ok(()));
    }

    /// The pattern is compiled where it is written. A decision that compiled it
    /// would meet a bad one with an answer already owed.
    #[test]
    fn a_pattern_is_compiled_where_it_is_written() {
        let broken = terms(PolicyRule::Regex {
            target_claim: "email".to_owned(),
            target_regex: "([a-z".to_owned(),
        });
        assert!(matches!(validate(&broken), Err(StoreError::BadPattern(_))));

        let enormous = terms(PolicyRule::Regex {
            target_claim: "email".to_owned(),
            target_regex: "a".repeat(commons::pattern::MAX_PATTERN_LEN + 1),
        });
        assert!(matches!(
            validate(&enormous),
            Err(StoreError::BadPattern(_))
        ));
    }
}
