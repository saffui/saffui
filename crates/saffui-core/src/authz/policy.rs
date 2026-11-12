//! Policies: what a client that guards resources lets a subject do with
//! them, read from the subject, the resource and the instant. A policy
//! permits or denies when its conditions hold, says nothing when they do
//! not, and says that it cannot tell when one of them cannot be read. A
//! policy that cannot tell never permits.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::admin::AdminCaller;
use super::roles::{describe_actor, is_role_name};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::claims::rules::is_policy_attribute;
use crate::clients::{is_unshowable, read_named_client};
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::instant::read_instant;
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

/// How many conditions a policy holds at most.
pub const MAX_CONDITIONS: usize = 32;
/// How many policies one client keeps at most.
pub const MAX_POLICIES_PER_CLIENT: u32 = 200;
/// How many of them one action on one type of resource has at most: what a
/// question reads and weighs.
pub const MAX_APPLICABLE_POLICIES: usize = 16;
/// The largest integer a policy holds: every reader of JSON reads it exactly.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;
/// The longest document of conditions, in bytes.
pub const MAX_CONDITIONS_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Permit,
    Deny,
}

impl Effect {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Permit => "permit",
            Self::Deny => "deny",
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Permit, Self::Deny]
            .into_iter()
            .find(|effect| effect.name() == text)
    }
}

/// Whether every condition must hold, or one is enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Combine {
    All,
    Any,
}

impl Combine {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Any => "any",
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [Self::All, Self::Any]
            .into_iter()
            .find(|combine| combine.name() == text)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub id: Uuid,
    /// The client that guards the resources.
    pub client_id: String,
    pub name: String,
    pub resource_type: String,
    pub action: String,
    pub effect: Effect,
    pub combine: Combine,
    /// The conditions as they were written, read at each decision: a
    /// document that no longer reads leaves its policy unable to tell.
    pub conditions: Value,
    pub created_at: OffsetDateTime,
}

/// What a subject attribute names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectAttribute {
    /// The identifier of the person, or of the client that acts as itself.
    Id,
    Username,
    Email,
    EmailVerified,
    /// The client the token of the subject was issued to.
    ClientId,
    /// The scopes of the token, as a list.
    Scope,
    /// An attribute an administrator wrote of the person, by its name: one
    /// of those that start with `policy.`, and no other.
    Attribute(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Operand {
    Subject(SubjectAttribute),
    /// An attribute the client says the resource has.
    Resource(String),
    Value(Value),
}

/// Ten operators, and no negation: a policy that denies says no.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    In,
    Gt,
    Gte,
    Lt,
    Lte,
    /// Whether the left operand is there at all. The one operator that
    /// answers on what is missing.
    Present,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// The subject holds this role now.
    Role(Uuid),
    /// The subject is a member of this group now.
    Group(Uuid),
    Attribute {
        left: Operand,
        operator: Operator,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        right: Option<Operand>,
    },
    /// The instant of the question is at or after the first bound and
    /// before the second. Instants are written in RFC 3339.
    Time {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_before: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_on_or_after: Option<String>,
    },
}

/// What is known of a subject at the instant of a question.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectFacts {
    pub id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub roles: Vec<Uuid>,
    pub groups: Vec<Uuid>,
    /// What an administrator wrote of the person. Empty for a client.
    pub attributes: Map<String, Value>,
}

impl SubjectFacts {
    fn read(&self, attribute: &SubjectAttribute) -> Option<Value> {
        match attribute {
            SubjectAttribute::Id => Some(json!(self.id)),
            SubjectAttribute::Username => self.username.as_ref().map(|name| json!(name)),
            SubjectAttribute::Email => self.email.as_ref().map(|email| json!(email)),
            SubjectAttribute::EmailVerified => self.email_verified.map(Value::Bool),
            SubjectAttribute::ClientId => Some(json!(self.client_id)),
            SubjectAttribute::Scope => Some(json!(self.scopes)),
            // Refused at the reading too: a policy kept before the rule reads nothing.
            SubjectAttribute::Attribute(name) => self
                .attributes
                .get(name)
                .filter(|_| is_policy_attribute(name))
                .cloned(),
        }
    }
}

/// What a decision reads from.
pub struct Facts<'a> {
    pub subject: &'a SubjectFacts,
    pub resource: &'a Map<String, Value>,
    pub now: OffsetDateTime,
}

/// Whether a condition holds. Three answers: what cannot be read is not
/// taken for a no.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    Holds,
    Fails,
    Unknown,
}

impl Truth {
    fn of(holds: bool) -> Self {
        if holds { Self::Holds } else { Self::Fails }
    }
}

fn read_operand(operand: &Operand, facts: &Facts<'_>) -> Option<Value> {
    match operand {
        Operand::Subject(attribute) => facts.subject.read(attribute),
        Operand::Resource(name) => facts
            .resource
            .get(name)
            .filter(|value| !value.is_null())
            .cloned(),
        Operand::Value(value) => Some(value.clone()),
    }
}

/// Whether two values are the same. Two numbers are the same when they are
/// worth the same, whatever their writing: 100 and 100.0 are one.
fn is_same_value(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(one), Value::Number(other)) if one.is_f64() || other.is_f64() => one
            .as_f64()
            .zip(other.as_f64())
            .is_some_and(|(one, other)| one.partial_cmp(&other) == Some(std::cmp::Ordering::Equal)),
        _ => left == right,
    }
}

fn compare(operator: Operator, left: Option<Value>, right: Option<Value>) -> Truth {
    if operator == Operator::Present {
        return Truth::of(left.is_some());
    }
    let (Some(left), Some(right)) = (left, right) else {
        return Truth::Unknown;
    };
    let texts = || left.as_str().zip(right.as_str());
    let numbers = || left.as_f64().zip(right.as_f64());
    let answer = match operator {
        Operator::Equals => Some(is_same_value(&left, &right)),
        Operator::Contains => texts().map(|(whole, part)| whole.contains(part)),
        Operator::StartsWith => texts().map(|(whole, part)| whole.starts_with(part)),
        Operator::EndsWith => texts().map(|(whole, part)| whole.ends_with(part)),
        Operator::In => match (&left, right.as_array()) {
            (Value::String(_) | Value::Number(_) | Value::Bool(_), Some(list)) => {
                Some(list.iter().any(|item| is_same_value(item, &left)))
            }
            _ => None,
        },
        Operator::Gt => numbers().map(|(one, other)| one > other),
        Operator::Gte => numbers().map(|(one, other)| one >= other),
        Operator::Lt => numbers().map(|(one, other)| one < other),
        Operator::Lte => numbers().map(|(one, other)| one <= other),
        Operator::Present => None,
    };
    answer.map_or(Truth::Unknown, Truth::of)
}

fn read_bound(text: Option<&String>) -> Result<Option<OffsetDateTime>, ()> {
    text.map(|text| read_instant(text).ok_or(())).transpose()
}

#[must_use]
pub fn evaluate_condition(condition: &Condition, facts: &Facts<'_>) -> Truth {
    match condition {
        Condition::Role(role) => Truth::of(facts.subject.roles.contains(role)),
        Condition::Group(group) => Truth::of(facts.subject.groups.contains(group)),
        Condition::Attribute {
            left,
            operator,
            right,
        } => compare(
            *operator,
            read_operand(left, facts),
            right.as_ref().and_then(|right| read_operand(right, facts)),
        ),
        Condition::Time {
            not_before,
            not_on_or_after,
        } => match (
            read_bound(not_before.as_ref()),
            read_bound(not_on_or_after.as_ref()),
        ) {
            (Ok(from), Ok(until)) => Truth::of(
                from.is_none_or(|from| from <= facts.now)
                    && until.is_none_or(|until| facts.now < until),
            ),
            _ => Truth::Unknown,
        },
    }
}

/// What one policy says of a question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOutcome {
    Applies(Effect),
    NotApplicable,
    Undecided,
}

/// Reads the conditions of a policy, as written.
///
/// # Errors
///
/// Fails when the document is not a list of conditions this version reads.
pub fn read_conditions(document: &Value) -> Result<Vec<Condition>, Failure> {
    Vec::<Condition>::deserialize(document).map_err(|_| Failure::new(ErrorCode::PolicyInvalid))
}

/// A policy and its conditions, read once for a question: conditions that
/// no longer read leave the policy unable to tell.
pub struct ReadPolicy<'a> {
    pub policy: &'a Policy,
    pub conditions: Option<Vec<Condition>>,
}

impl<'a> ReadPolicy<'a> {
    #[must_use]
    pub fn read(policy: &'a Policy) -> Self {
        Self {
            policy,
            conditions: read_conditions(&policy.conditions).ok(),
        }
    }

    /// Whether a condition reads an attribute written of the person.
    #[must_use]
    pub fn reads_person_attributes(&self) -> bool {
        let is_attribute =
            |operand: &Operand| matches!(operand, Operand::Subject(SubjectAttribute::Attribute(_)));
        self.conditions.iter().flatten().any(|condition| {
            matches!(condition, Condition::Attribute { left, right, .. }
                if is_attribute(left) || right.as_ref().is_some_and(is_attribute))
        })
    }
}

#[must_use]
pub fn evaluate_policy(read: &ReadPolicy<'_>, facts: &Facts<'_>) -> PolicyOutcome {
    let policy = read.policy;
    let Some(conditions) = &read.conditions else {
        return PolicyOutcome::Undecided;
    };
    if conditions.is_empty() {
        return PolicyOutcome::Undecided;
    }
    let truths = conditions
        .iter()
        .map(|condition| evaluate_condition(condition, facts));
    let mut unknown = false;
    let decisive = match policy.combine {
        Combine::All => Truth::Fails,
        Combine::Any => Truth::Holds,
    };
    for truth in truths {
        if truth == decisive {
            return if decisive == Truth::Holds {
                PolicyOutcome::Applies(policy.effect)
            } else {
                PolicyOutcome::NotApplicable
            };
        }
        unknown |= truth == Truth::Unknown;
    }
    if unknown {
        PolicyOutcome::Undecided
    } else if decisive == Truth::Holds {
        PolicyOutcome::NotApplicable
    } else {
        PolicyOutcome::Applies(policy.effect)
    }
}

/// What the policies of a question say together. A denial wins over
/// everything, a policy that cannot tell over a permission, and nothing
/// applicable is a denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyVerdict {
    Permit(String),
    Deny(String),
    Undecided(String),
    NoPolicy,
}

#[must_use]
pub fn weigh_policies(policies: &[ReadPolicy<'_>], facts: &Facts<'_>) -> PolicyVerdict {
    let mut permitted = None;
    let mut undecided = None;
    for read in policies {
        let policy = read.policy;
        match evaluate_policy(read, facts) {
            PolicyOutcome::Applies(Effect::Deny) => {
                return PolicyVerdict::Deny(policy.name.clone());
            }
            PolicyOutcome::Applies(Effect::Permit) => {
                permitted.get_or_insert_with(|| policy.name.clone());
            }
            PolicyOutcome::Undecided => {
                undecided.get_or_insert_with(|| policy.name.clone());
            }
            PolicyOutcome::NotApplicable => {}
        }
    }
    match (undecided, permitted) {
        (Some(name), _) => PolicyVerdict::Undecided(name),
        (None, Some(name)) => PolicyVerdict::Permit(name),
        (None, None) => PolicyVerdict::NoPolicy,
    }
}

fn is_attribute_name(text: &str) -> bool {
    is_role_name(text)
}

/// Whether a value stores and reads back as it was written: integers a
/// reader of JSON reads exactly, text that can be shown, and so all the way
/// down.
fn is_storable_value(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) => true,
        Value::Number(number) => number
            .as_i64()
            .is_some_and(|whole| whole.abs() <= MAX_SAFE_INTEGER),
        Value::String(text) => !text.chars().any(is_unshowable),
        Value::Array(items) => items.iter().all(is_storable_value),
        Value::Object(members) => members
            .iter()
            .all(|(key, item)| !key.chars().any(is_unshowable) && is_storable_value(item)),
    }
}

/// Refuses conditions that could never be decided, or not as they were
/// written: too many or none, an operand an operator does not take, a value
/// that does not store as it reads, a bound that does not read, a role of
/// another client, a role or a group the realm does not have.
async fn check_conditions(
    work: &mut dyn UnitOfWork,
    client_id: &str,
    conditions: &[Condition],
) -> Result<(), Failure> {
    let invalid = || Failure::new(ErrorCode::PolicyInvalid);
    if conditions.is_empty() || conditions.len() > MAX_CONDITIONS {
        return Err(invalid());
    }
    let (mut roles, mut groups) = (Vec::new(), Vec::new());
    for condition in conditions {
        match condition {
            Condition::Role(role) => roles.push(*role),
            Condition::Group(group) => groups.push(*group),
            Condition::Attribute {
                left,
                operator,
                right,
            } => {
                let named = |operand: &Operand| match operand {
                    Operand::Resource(name) => is_attribute_name(name),
                    Operand::Subject(SubjectAttribute::Attribute(name)) => {
                        is_policy_attribute(name)
                    }
                    Operand::Subject(_) => true,
                    Operand::Value(value) => is_storable_value(value),
                };
                let arity = (*operator == Operator::Present) == right.is_none();
                if !arity || !named(left) || !right.as_ref().is_none_or(named) {
                    return Err(invalid());
                }
            }
            Condition::Time {
                not_before,
                not_on_or_after,
            } => {
                let (Ok(from), Ok(until)) = (
                    read_bound(not_before.as_ref()),
                    read_bound(not_on_or_after.as_ref()),
                ) else {
                    return Err(invalid());
                };
                let ordered = match (from, until) {
                    (None, None) => false,
                    (Some(from), Some(until)) => from < until,
                    _ => true,
                };
                if !ordered {
                    return Err(invalid());
                }
            }
        }
    }
    // Each kind read once, however many conditions name it.
    roles.sort_unstable();
    roles.dedup();
    groups.sort_unstable();
    groups.dedup();
    if !roles.is_empty() {
        // A role of the realm, or of the client that writes the policy: the
        // role of another client is said to it alone.
        let admitted = work
            .read_roles(&roles)
            .await?
            .iter()
            .filter(|role| {
                role.client_id
                    .as_deref()
                    .is_none_or(|owner| owner == client_id)
            })
            .count();
        if admitted != roles.len() {
            return Err(invalid());
        }
    }
    if !groups.is_empty() && work.read_groups(&groups).await?.len() != groups.len() {
        return Err(invalid());
    }
    Ok(())
}

pub struct NewPolicy<'a> {
    pub client_id: &'a str,
    pub name: &'a str,
    pub resource_type: &'a str,
    pub action: &'a str,
    pub effect: Effect,
    pub combine: Combine,
    pub conditions: &'a Value,
}

/// Writes a policy of a client that guards resources.
///
/// # Errors
///
/// Returns [`ErrorCode::PolicyInvalid`] for a name, a type, an action or
/// conditions that cannot be read or decided, or past the number of
/// policies a client keeps, [`ErrorCode::ClientNotFound`],
/// [`ErrorCode::PolicyNameTaken`], or the storage failure.
pub async fn create_policy(
    app: &App,
    caller: &AdminCaller,
    wanted: NewPolicy<'_>,
) -> Result<Policy, Failure> {
    let invalid = || Failure::new(ErrorCode::PolicyInvalid);
    let named = [wanted.name, wanted.resource_type, wanted.action];
    if !named.iter().all(|text| is_role_name(text))
        || wanted.conditions.to_string().len() > MAX_CONDITIONS_BYTES
    {
        return Err(invalid());
    }
    let conditions = read_conditions(wanted.conditions)?;
    let mut work = app.storage.begin(caller.scope).await?;
    // Checked and written under the lock of the definitions: a schema, a
    // role or a group that changes meanwhile waits for this policy to be kept.
    work.lock_definitions().await?;
    if read_named_client(work.as_mut(), wanted.client_id)
        .await?
        .is_none()
    {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    check_conditions(work.as_mut(), wanted.client_id, &conditions).await?;
    // A type the schema of relations defines is decided by its relations: a
    // policy written for it would never be read.
    let decided_by_relations = work
        .read_relation_schema()
        .await?
        .and_then(|stored| stored.open())
        .is_some_and(|schema| schema.types.contains_key(wanted.resource_type));
    if decided_by_relations {
        return Err(Failure::new(ErrorCode::ResourceTypeTaken));
    }
    // Counted under the lock: two writers do not both find room.
    let kept = work
        .count_policies(wanted.client_id, MAX_POLICIES_PER_CLIENT)
        .await?;
    if kept >= u64::from(MAX_POLICIES_PER_CLIENT) {
        return Err(invalid());
    }
    let applicable = work
        .list_applicable_policies(wanted.client_id, wanted.resource_type, wanted.action)
        .await?;
    if applicable.len() >= MAX_APPLICABLE_POLICIES {
        return Err(invalid());
    }
    let policy = Policy {
        id: mint_id(app)?,
        client_id: wanted.client_id.to_owned(),
        name: wanted.name.to_owned(),
        resource_type: wanted.resource_type.to_owned(),
        action: wanted.action.to_owned(),
        effect: wanted.effect,
        combine: wanted.combine,
        // Kept as this version writes it, unknown parts left out.
        conditions: serde_json::to_value(&conditions).map_err(|_| invalid())?,
        created_at: app.now(),
    };
    if !work.insert_policy(&policy).await? {
        return Err(Failure::new(ErrorCode::PolicyNameTaken));
    }
    // A policy is never changed: this event is what it was.
    let told = json!({
        "action": policy.action,
        "actor": describe_actor(caller),
        "client_id": policy.client_id,
        "combine": policy.combine.name(),
        "conditions": policy.conditions,
        "effect": policy.effect.name(),
        "name": policy.name,
        "policy_id": policy.id.to_string(),
        "resource_type": policy.resource_type,
    });
    record_event(app, work.as_mut(), EventKind::PolicyCreated, told).await?;
    work.commit().await?;
    Ok(policy)
}

/// Lists the policies of a client, by name.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientNotFound`], or the storage failure.
pub async fn list_policies(
    app: &App,
    scope: RealmScope,
    client_id: &str,
) -> Result<Vec<Policy>, Failure> {
    let mut work = app.storage.begin(scope).await?;
    if read_named_client(work.as_mut(), client_id).await?.is_none() {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    Ok(work.list_policies(client_id).await?)
}

/// Removes a policy of a client.
///
/// # Errors
///
/// Returns [`ErrorCode::PolicyNotFound`], or the storage failure.
pub async fn delete_policy(
    app: &App,
    caller: &AdminCaller,
    client_id: &str,
    policy: Uuid,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_policy(client_id, policy).await? {
        return Err(Failure::new(ErrorCode::PolicyNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "client_id": client_id,
        "policy_id": policy.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::PolicyDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        Combine, Effect, Facts, NewPolicy, Policy, PolicyOutcome, PolicyVerdict, ReadPolicy,
        SubjectFacts, Truth, create_policy, delete_policy, evaluate_condition, evaluate_policy,
        list_policies, read_conditions, weigh_policies,
    };
    use crate::authz::capability::Capability;
    use crate::authz::relations::{SchemaRefusal, write_relation_schema};
    use crate::authz::roles::{
        NewGroup, NewRole, create_group, create_role, delete_group, delete_role,
    };
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    const APPROVER: Uuid = Uuid::from_u128(1);

    fn ada() -> SubjectFacts {
        SubjectFacts {
            id: "ada-id".to_owned(),
            username: Some("ada".to_owned()),
            email: None,
            email_verified: Some(true),
            client_id: "portal".to_owned(),
            scopes: vec!["openid".to_owned(), "invoices".to_owned()],
            roles: vec![APPROVER],
            groups: Vec::new(),
            attributes: json!({
                "policy.department": ["research", "audit"],
                "policy.level": "senior",
                "level": "senior",
            })
            .as_object()
            .cloned()
            .unwrap_or_default(),
        }
    }

    fn noon() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_268_800).expect("an instant")
    }

    fn ask(condition: &Value, resource: &Value) -> Truth {
        let condition = read_conditions(&json!([condition]))
            .expect("a condition")
            .remove(0);
        let subject = ada();
        let resource: Map<String, Value> = resource.as_object().cloned().unwrap_or_default();
        let facts = Facts {
            subject: &subject,
            resource: &resource,
            now: noon(),
        };
        evaluate_condition(&condition, &facts)
    }

    fn attribute(left: &Value, operator: &str, right: Option<Value>) -> Value {
        let mut written = json!({ "attribute": { "left": left, "operator": operator } });
        if let Some(right) = right {
            written["attribute"]["right"] = right;
        }
        written
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table of answers, read from top to bottom"
    )]
    fn an_attribute_that_cannot_be_read_is_unknown_and_only_present_says_no_to_it() {
        let invoice = json!({ "owner": "ada-id", "amount": 120, "currency": "XOF" });
        let owner = || json!({ "resource": "owner" });
        let id = || json!({ "subject": "id" });

        assert_eq!(
            ask(&attribute(&owner(), "equals", Some(id())), &invoice),
            Truth::Holds
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "resource": "amount" }),
                    "gt",
                    Some(json!({ "value": 100 }))
                ),
                &invoice
            ),
            Truth::Holds
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "resource": "amount" }),
                    "lte",
                    Some(json!({ "value": 100 }))
                ),
                &invoice
            ),
            Truth::Fails
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "resource": "amount" }),
                    "equals",
                    Some(json!({ "value": "120" }))
                ),
                &invoice
            ),
            Truth::Fails,
            "a number is not the text of a number"
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "resource": "currency" }),
                    "gt",
                    Some(json!({ "value": 1 }))
                ),
                &invoice
            ),
            Truth::Unknown,
            "a text compared as a number cannot be told"
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "resource": "region" }),
                    "equals",
                    Some(json!({ "value": "west" }))
                ),
                &invoice
            ),
            Truth::Unknown
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "subject": "email" }),
                    "ends_with",
                    Some(json!({ "value": "@example.org" }))
                ),
                &invoice
            ),
            Truth::Unknown
        );
        assert_eq!(
            ask(
                &attribute(&json!({ "resource": "region" }), "present", None),
                &invoice
            ),
            Truth::Fails
        );
        assert_eq!(
            ask(&attribute(&owner(), "present", None), &invoice),
            Truth::Holds
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "value": "invoices" }),
                    "in",
                    Some(json!({ "subject": "scope" }))
                ),
                &invoice
            ),
            Truth::Holds
        );
        assert_eq!(
            ask(
                &attribute(
                    &json!({ "resource": "currency" }),
                    "starts_with",
                    Some(json!({ "value": "XO" }))
                ),
                &invoice
            ),
            Truth::Holds
        );
    }

    #[test]
    fn a_policy_reads_the_attributes_whose_name_starts_with_policy_and_no_other() {
        let read = |name: &str| json!({ "subject": { "attribute": name } });
        let none = json!({});

        assert_eq!(
            ask(
                &attribute(
                    &json!({ "value": "audit" }),
                    "in",
                    Some(read("policy.department"))
                ),
                &none
            ),
            Truth::Holds,
            "a value among those of a list the person holds"
        );
        assert_eq!(
            ask(
                &attribute(
                    &read("policy.level"),
                    "equals",
                    Some(json!({ "value": "junior" }))
                ),
                &none
            ),
            Truth::Fails
        );
        assert_eq!(
            ask(
                &attribute(&read("policy.clearance"), "present", None),
                &none
            ),
            Truth::Fails,
            "an attribute the person does not hold"
        );
        assert_eq!(
            ask(
                &attribute(&read("level"), "equals", Some(json!({ "value": "senior" }))),
                &none
            ),
            Truth::Unknown,
            "held, but outside the space: whoever writes people could have written it"
        );

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let write = |name: &str| {
            let conditions = json!([attribute(&read(name), "present", None)]);
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id: "billing",
                    name: "readers",
                    resource_type: "invoice",
                    action: "approve",
                    effect: Effect::Permit,
                    combine: Combine::All,
                    conditions: &conditions,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };
        assert_eq!(write("level"), Err(ErrorCode::PolicyInvalid));
        assert_eq!(write("policy."), Err(ErrorCode::PolicyInvalid));
        assert_eq!(write("policy.level"), Ok(()));
    }

    #[test]
    fn a_role_a_group_and_a_window_of_time_are_read_from_the_subject_and_the_instant() {
        let none = json!({});

        assert_eq!(ask(&json!({ "role": APPROVER }), &none), Truth::Holds);
        assert_eq!(
            ask(&json!({ "role": Uuid::from_u128(2) }), &none),
            Truth::Fails
        );
        assert_eq!(
            ask(&json!({ "group": Uuid::from_u128(3) }), &none),
            Truth::Fails
        );
        assert_eq!(
            ask(
                &json!({ "time": { "not_before": "2026-01-01T12:00:00Z", "not_on_or_after": "2026-01-01T13:00:00Z" } }),
                &none
            ),
            Truth::Holds,
            "the first bound is in, the second is out"
        );
        assert_eq!(
            ask(
                &json!({ "time": { "not_on_or_after": "2026-01-01T12:00:00Z" } }),
                &none
            ),
            Truth::Fails
        );
        assert_eq!(
            ask(&json!({ "time": { "not_before": "noon" } }), &none),
            Truth::Unknown
        );
    }

    fn policy(name: &str, effect: Effect, combine: Combine, conditions: Value) -> Policy {
        Policy {
            id: Uuid::nil(),
            client_id: "billing".to_owned(),
            name: name.to_owned(),
            resource_type: "invoice".to_owned(),
            action: "approve".to_owned(),
            effect,
            combine,
            conditions,
            created_at: noon(),
        }
    }

    fn weigh(policies: &[Policy], resource: &Value) -> PolicyVerdict {
        let subject = ada();
        let resource: Map<String, Value> = resource.as_object().cloned().unwrap_or_default();
        let facts = Facts {
            subject: &subject,
            resource: &resource,
            now: noon(),
        };
        let read: Vec<ReadPolicy<'_>> = policies.iter().map(ReadPolicy::read).collect();
        weigh_policies(&read, &facts)
    }

    #[test]
    fn all_needs_every_condition_any_needs_one_and_unknown_is_never_a_permission() {
        let subject = ada();
        let resource = Map::new();
        let facts = Facts {
            subject: &subject,
            resource: &resource,
            now: noon(),
        };
        let holds = json!({ "role": APPROVER });
        let fails = json!({ "role": Uuid::from_u128(9) });
        let unknown = attribute(
            &json!({ "resource": "amount" }),
            "gt",
            Some(json!({ "value": 1 })),
        );
        let outcome = |combine, conditions: Value| {
            let written = policy("p", Effect::Permit, combine, conditions);
            evaluate_policy(&ReadPolicy::read(&written), &facts)
        };

        assert_eq!(
            outcome(Combine::All, json!([holds, holds])),
            PolicyOutcome::Applies(Effect::Permit)
        );
        assert_eq!(
            outcome(Combine::All, json!([holds, fails, unknown])),
            PolicyOutcome::NotApplicable
        );
        assert_eq!(
            outcome(Combine::All, json!([holds, unknown])),
            PolicyOutcome::Undecided
        );
        assert_eq!(
            outcome(Combine::Any, json!([fails, unknown, holds])),
            PolicyOutcome::Applies(Effect::Permit)
        );
        assert_eq!(
            outcome(Combine::Any, json!([fails, unknown])),
            PolicyOutcome::Undecided
        );
        assert_eq!(
            outcome(Combine::Any, json!([fails])),
            PolicyOutcome::NotApplicable
        );
        assert_eq!(
            outcome(Combine::All, json!([{ "script": "return true" }])),
            PolicyOutcome::Undecided,
            "a document this version cannot read is set aside, never taken for a yes"
        );
        assert_eq!(outcome(Combine::All, json!([])), PolicyOutcome::Undecided);
    }

    #[test]
    fn a_denial_wins_a_policy_that_cannot_tell_beats_a_permission_and_nothing_is_a_denial() {
        let approver = json!([{ "role": APPROVER }]);
        let large = json!([attribute(
            &json!({ "resource": "amount" }),
            "gt",
            Some(json!({ "value": 1000 }))
        )]);
        let permit = policy("approvers", Effect::Permit, Combine::All, approver);
        let deny_large = policy("large-invoices", Effect::Deny, Combine::All, large);

        let small = json!({ "amount": 120 });
        let huge = json!({ "amount": 5000 });
        let unpriced = json!({});

        assert_eq!(
            weigh(&[permit.clone(), deny_large.clone()], &small),
            PolicyVerdict::Permit("approvers".to_owned())
        );
        assert_eq!(
            weigh(&[permit.clone(), deny_large.clone()], &huge),
            PolicyVerdict::Deny("large-invoices".to_owned())
        );
        assert_eq!(
            weigh(&[permit.clone(), deny_large], &unpriced),
            PolicyVerdict::Undecided("large-invoices".to_owned()),
            "the amount that could forbid is unknown: no permission"
        );
        assert_eq!(weigh(&[], &small), PolicyVerdict::NoPolicy);
        let stranger = policy(
            "strangers",
            Effect::Permit,
            Combine::All,
            json!([{ "role": Uuid::from_u128(5) }]),
        );
        assert_eq!(weigh(&[stranger], &small), PolicyVerdict::NoPolicy);
    }

    #[test]
    fn a_policy_is_written_only_when_every_condition_can_be_decided() {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite, Capability::RoleWrite]);
        let approver = complete(create_role(
            &scenario.app,
            &caller,
            NewRole {
                name: "approver",
                client_id: None,
                description: None,
            },
        ))
        .expect("a role")
        .id;
        let write = |name: &str, client_id: &str, conditions: Value| {
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id,
                    name,
                    resource_type: "invoice",
                    action: "approve",
                    effect: Effect::Permit,
                    combine: Combine::All,
                    conditions: &conditions,
                },
            ))
            .map_err(|failure| failure.code)
        };

        let written =
            write("approvers", "billing", json!([{ "role": approver }])).expect("a policy");
        assert_eq!(written.conditions, json!([{ "role": approver }]));
        for (conditions, why) in [
            (json!([]), "no condition"),
            (
                json!([{ "role": Uuid::from_u128(7) }]),
                "a role the realm does not have",
            ),
            (
                json!([{ "group": Uuid::from_u128(7) }]),
                "a group the realm does not have",
            ),
            (
                json!([attribute(&json!({ "resource": "owner" }), "equals", None)]),
                "an operator without its right side",
            ),
            (
                json!([attribute(
                    &json!({ "resource": "owner" }),
                    "present",
                    Some(json!({ "value": 1 }))
                )]),
                "present takes no right side",
            ),
            (
                json!([attribute(
                    &json!({ "resource": "two words" }),
                    "present",
                    None
                )]),
                "an attribute name",
            ),
            (json!([{ "time": {} }]), "a window without a bound"),
            (
                json!([{ "time": { "not_before": "2026-02-01T00:00:00Z", "not_on_or_after": "2026-01-01T00:00:00Z" } }]),
                "a window that ends before it starts",
            ),
            (
                json!([{ "script": "return true" }]),
                "a kind of condition this version does not have",
            ),
            (
                json!([{ "role": approver, "extra": true }]),
                "an extra member",
            ),
        ] {
            assert_eq!(
                write("other", "billing", conditions),
                Err(ErrorCode::PolicyInvalid),
                "{why}"
            );
        }
        assert_eq!(
            write("approvers", "billing", json!([{ "role": approver }])).map(|policy| policy.id),
            Err(ErrorCode::PolicyNameTaken)
        );
        assert_eq!(
            write("approvers", "nobody", json!([{ "role": approver }])).map(|policy| policy.id),
            Err(ErrorCode::ClientNotFound)
        );

        let listed = complete(list_policies(&scenario.app, scenario.scope, "billing"))
            .expect("the policies");
        assert_eq!(listed, std::slice::from_ref(&written));
        let delete = || {
            complete(delete_policy(&scenario.app, &caller, "billing", written.id))
                .map_err(|failure| failure.code)
        };
        assert_eq!(delete(), Ok(()));
        assert_eq!(delete(), Err(ErrorCode::PolicyNotFound));
    }

    #[test]
    fn two_numbers_are_the_same_when_they_are_worth_the_same() {
        let discount = |value: Value| json!({ "discount": value });
        let equals_a_hundred = attribute(
            &json!({ "resource": "discount" }),
            "equals",
            Some(json!({ "value": 100 })),
        );
        for written in [json!(100), json!(100.0), json!(1e2)] {
            assert_eq!(
                ask(&equals_a_hundred, &discount(written.clone())),
                Truth::Holds,
                "{written}"
            );
        }
        assert_eq!(
            ask(&equals_a_hundred, &discount(json!(100.5))),
            Truth::Fails
        );
        assert_eq!(
            ask(&equals_a_hundred, &discount(json!("100"))),
            Truth::Fails
        );
        let in_list = attribute(
            &json!({ "resource": "discount" }),
            "in",
            Some(json!({ "value": [50, 100] })),
        );
        assert_eq!(ask(&in_list, &discount(json!(100.0))), Truth::Holds);
    }

    #[test]
    fn a_type_is_decided_by_relations_or_by_policies_never_by_both() {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite, Capability::RoleWrite]);
        let approver = complete(create_role(
            &scenario.app,
            &caller,
            NewRole {
                name: "approver",
                client_id: None,
                description: None,
            },
        ))
        .expect("a role")
        .id;
        let write = |resource_type: &str| {
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id: "billing",
                    name: resource_type,
                    resource_type,
                    action: "approve",
                    effect: Effect::Deny,
                    combine: Combine::Any,
                    conditions: &json!([{ "role": approver }]),
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };
        let schema = |source: &str| {
            complete(write_relation_schema(&scenario.app, &caller, source)).map(|_| ())
        };

        assert_eq!(write("invoice"), Ok(()));
        assert_eq!(
            schema("definition user {}\ndefinition invoice {\n  relation approver: user\n}"),
            Err(SchemaRefusal::Failed(crate::error::Failure::new(
                ErrorCode::ResourceTypeTaken
            ))),
            "a policy guards invoices"
        );
        assert_eq!(schema("definition user {}\ndefinition document {}"), Ok(()));
        assert_eq!(
            write("document"),
            Err(ErrorCode::ResourceTypeTaken),
            "the schema decides documents"
        );
        let created = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "policy.created")
            .expect("the event");
        assert_eq!(created["payload"]["resource_type"], "invoice");
        assert_eq!(created["payload"]["action"], "approve");
        assert_eq!(created["payload"]["combine"], "any");

        assert_eq!(
            complete(delete_role(&scenario.app, &caller, approver)).map_err(|failure| failure.code),
            Err(ErrorCode::NamedByPolicy),
            "the denial would stop applying in silence"
        );
    }

    #[test]
    fn a_policy_holds_only_what_stores_as_it_reads_and_the_roles_it_may_name() {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite, Capability::RoleWrite]);
        let role_of = |name: &str, client_id: Option<&str>| {
            complete(create_role(
                &scenario.app,
                &caller,
                NewRole {
                    name,
                    client_id,
                    description: None,
                },
            ))
            .expect("a role")
            .id
        };
        let of_the_realm = role_of("approver", None);
        let of_billing = role_of("clerk", Some("billing"));
        let of_webapp = role_of("editor", Some("webapp"));
        let write = |name: &str, action: &str, conditions: Value| {
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id: "billing",
                    name,
                    resource_type: "invoice",
                    action,
                    effect: Effect::Permit,
                    combine: Combine::Any,
                    conditions: &conditions,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };
        let equals = |value: Value| {
            json!([attribute(
                &json!({ "resource": "amount" }),
                "equals",
                Some(json!({ "value": value }))
            )])
        };

        assert_eq!(
            write("realm-role", "approve", json!([{ "role": of_the_realm }])),
            Ok(())
        );
        assert_eq!(
            write("own-role", "approve", json!([{ "role": of_billing }])),
            Ok(())
        );
        assert_eq!(
            write("other-role", "approve", json!([{ "role": of_webapp }])),
            Err(ErrorCode::PolicyInvalid),
            "the role of webapp is told to webapp alone"
        );
        for (value, why) in [
            (json!(100.5), "a number that is not whole"),
            (
                json!(9_007_199_254_740_992_i64),
                "a whole number past what JSON reads exactly",
            ),
            (json!("turned \u{202e}around"), "text that cannot be shown"),
            (json!({ "nul\u{0}": 1 }), "a key that cannot be shown"),
        ] {
            assert_eq!(
                write("odd", "approve", equals(value)),
                Err(ErrorCode::PolicyInvalid),
                "{why}"
            );
        }
        assert_eq!(
            write("whole", "approve", equals(json!(9_007_199_254_740_991_i64))),
            Ok(())
        );
    }

    #[test]
    fn one_action_on_one_type_takes_sixteen_policies_at_most() {
        use super::MAX_APPLICABLE_POLICIES;

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let present = json!([attribute(&json!({ "resource": "amount" }), "present", None)]);
        let write = |name: &str, action: &str| {
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id: "billing",
                    name,
                    resource_type: "invoice",
                    action,
                    effect: Effect::Deny,
                    combine: Combine::All,
                    conditions: &present,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };
        for index in 0..MAX_APPLICABLE_POLICIES {
            assert_eq!(write(&format!("approve-{index}"), "approve"), Ok(()));
        }
        assert_eq!(write("one-more", "approve"), Err(ErrorCode::PolicyInvalid));
        assert_eq!(write("of-another-action", "read"), Ok(()));
    }

    #[test]
    fn a_policy_holds_so_many_conditions_and_so_many_bytes_and_no_more() {
        use super::{MAX_CONDITIONS, MAX_CONDITIONS_BYTES};

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let write = |name: &str, conditions: &Value| {
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id: "billing",
                    name,
                    resource_type: "invoice",
                    action: name,
                    effect: Effect::Deny,
                    combine: Combine::Any,
                    conditions,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };
        let present = attribute(&json!({ "resource": "amount" }), "present", None);
        let counted = |count: usize| Value::Array(vec![present.clone(); count]);
        // One condition whose value pads the document to `bytes`, as written.
        let sized = |bytes: usize| {
            let mut document = json!([attribute(
                &json!({ "resource": "note" }),
                "equals",
                Some(json!({ "value": "" }))
            )]);
            let padding = bytes - document.to_string().len();
            document[0]["attribute"]["right"]["value"] = json!("x".repeat(padding));
            assert_eq!(document.to_string().len(), bytes);
            document
        };

        assert_eq!(write("full", &counted(MAX_CONDITIONS)), Ok(()));
        assert_eq!(
            write("too-many", &counted(MAX_CONDITIONS + 1)),
            Err(ErrorCode::PolicyInvalid)
        );
        assert_eq!(write("at-bound", &sized(MAX_CONDITIONS_BYTES)), Ok(()));
        assert_eq!(
            write("past-bound", &sized(MAX_CONDITIONS_BYTES + 1)),
            Err(ErrorCode::PolicyInvalid)
        );
    }

    #[test]
    fn a_client_keeps_two_hundred_policies_and_another_client_its_own() {
        use super::MAX_POLICIES_PER_CLIENT;

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let present = json!([attribute(&json!({ "resource": "amount" }), "present", None)]);
        // An action each: no one action fills up first.
        let write = |client_id: &str, index: u32| {
            let name = format!("policy-{index}");
            complete(create_policy(
                &scenario.app,
                &caller,
                NewPolicy {
                    client_id,
                    name: &name,
                    resource_type: "invoice",
                    action: &name,
                    effect: Effect::Deny,
                    combine: Combine::All,
                    conditions: &present,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };

        for index in 0..MAX_POLICIES_PER_CLIENT {
            assert_eq!(write("billing", index), Ok(()), "policy {index}");
        }
        assert_eq!(
            write("billing", MAX_POLICIES_PER_CLIENT),
            Err(ErrorCode::PolicyInvalid)
        );
        assert_eq!(write("webapp", MAX_POLICIES_PER_CLIENT), Ok(()));
    }

    #[test]
    fn a_group_a_policy_names_is_not_removed() {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite, Capability::RoleWrite]);
        let night = complete(create_group(
            &scenario.app,
            &caller,
            NewGroup {
                name: "night-shift",
                description: None,
            },
        ))
        .expect("a group")
        .id;
        complete(create_policy(
            &scenario.app,
            &caller,
            NewPolicy {
                client_id: "billing",
                name: "no-nights",
                resource_type: "invoice",
                action: "approve",
                effect: Effect::Deny,
                combine: Combine::Any,
                conditions: &json!([{ "group": night }]),
            },
        ))
        .expect("a policy");

        assert_eq!(
            complete(delete_group(&scenario.app, &caller, night)).map_err(|failure| failure.code),
            Err(ErrorCode::NamedByPolicy)
        );
    }
}
