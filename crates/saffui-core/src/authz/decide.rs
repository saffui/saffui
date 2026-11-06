//! The one point of decision of a realm: whether a subject may take an
//! action on a resource. A resource of a type the schema of relations
//! defines is decided by the relations kept; any other by the policies of
//! the client that asks. Nothing else decides, and what cannot be decided
//! is refused, with the reason.

use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::grants::{read_held_roles, read_member_groups};
use super::policy::{Facts, PolicyVerdict, SubjectFacts, weigh_policies};
use super::relations::check::{MAX_DURATION, Walk, WalkBudget, walk_relations};
use super::relations::schema::{CompiledSchema, compile_schema};
use super::relations::{ObjectRef, is_object_id, read_compiled_schema};
use super::roles::is_role_name;
use crate::app::App;
use crate::clients::authenticate::authenticate_client;
use crate::clients::read_named_client;
use crate::error::{ErrorCode, Failure};
use crate::login::session::read_live_subject;
use crate::oidc::discovery::name_issuer;
use crate::oidc::errors::OAuthFailure;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::verify_access_token;

/// The type a person is to the schema of relations: `user:<person id>`.
pub const PERSON_TYPE: &str = "user";
/// The type a client that acts as itself is: `client:<client id>`.
pub const CLIENT_TYPE: &str = "client";
/// How large the attributes of a resource may be, written as JSON.
pub const MAX_ATTRIBUTES_BYTES: usize = 8 * 1024;

/// What a client asks of the point of decision.
pub struct DecisionRequest<'a> {
    /// The access token the subject presented to the client.
    pub subject_token: Option<&'a str>,
    pub action: &'a str,
    pub resource_type: &'a str,
    /// The object, for a type the schema of relations defines.
    pub resource_id: Option<&'a str>,
    /// What the client says of the resource, for its policies to read.
    pub attributes: &'a Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Decision {
    /// `permit` or `deny`.
    pub decision: &'static str,
    pub reason: String,
    /// The policy that decided, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

impl Decision {
    fn permit(reason: &str, policy: Option<String>) -> Self {
        Self {
            decision: "permit",
            reason: reason.to_owned(),
            policy,
        }
    }

    fn deny(reason: &str, policy: Option<String>) -> Self {
        Self {
            decision: "deny",
            reason: reason.to_owned(),
            policy,
        }
    }
}

struct Subject {
    /// What the policies read of the subject, its roles and groups aside.
    facts: SubjectFacts,
    object: ObjectRef,
    /// The person, when one presented the token.
    person: Option<Uuid>,
}

/// Reads who presented the token, as they are now. A token that does not
/// verify, a session that ended, a person disabled or a client disabled
/// since is nobody.
async fn read_subject(
    app: &App,
    work: &mut dyn UnitOfWork,
    issuer: &str,
    token: &str,
) -> Result<Option<Subject>, Failure> {
    let claims = match verify_access_token(app, work, issuer, token).await {
        Ok(claims) => claims,
        Err(failure) if failure.code == ErrorCode::TokenInvalid => return Ok(None),
        Err(failure) => return Err(failure),
    };
    let Some(session) = claims.session else {
        let Some(client) = read_named_client(work, &claims.subject)
            .await?
            .filter(|client| client.enabled)
        else {
            return Ok(None);
        };
        return Ok(Some(Subject {
            facts: SubjectFacts {
                id: client.client_id.clone(),
                client_id: claims.client_id,
                scopes: claims.scopes,
                ..SubjectFacts::default()
            },
            object: ObjectRef {
                object_type: CLIENT_TYPE.to_owned(),
                object_id: client.client_id,
            },
            person: None,
        }));
    };
    let Some((_, person)) = read_live_subject(app, work, session).await? else {
        return Ok(None);
    };
    if person.id.to_string() != claims.subject {
        return Ok(None);
    }
    Ok(Some(Subject {
        facts: SubjectFacts {
            id: person.id.to_string(),
            username: Some(person.username),
            email: person.email,
            email_verified: Some(person.email_verified),
            client_id: claims.client_id,
            scopes: claims.scopes,
            ..SubjectFacts::default()
        },
        object: ObjectRef {
            object_type: PERSON_TYPE.to_owned(),
            object_id: person.id.to_string(),
        },
        person: Some(person.id),
    }))
}

/// What the schema of relations is to a type, for the client that asks.
enum SchemaFor {
    /// A schema that cannot be read decides nothing: no type it may define
    /// falls to the policies.
    Unreadable,
    /// The schema defines the type, and the client guards it.
    Relations(CompiledSchema),
    /// The schema does not define the type, or the client does not guard
    /// it. No policy names a type of the schema, so a client that does not
    /// guard one is answered as for a type of nothing, and learns nothing.
    Policies,
}

async fn read_schema_for(
    work: &mut dyn UnitOfWork,
    client_id: &str,
    resource_type: &str,
) -> Result<SchemaFor, Failure> {
    let Some(read) = work.read_guarded_schema(resource_type, client_id).await? else {
        return Ok(SchemaFor::Policies);
    };
    let schema = match read_compiled_schema(&read.compiled) {
        Some(schema) => Some(schema),
        // A form another version wrote: the source is read only then.
        None => work
            .read_relation_schema()
            .await?
            .and_then(|stored| compile_schema(&stored.source).ok()),
    };
    let Some(schema) = schema else {
        return Ok(SchemaFor::Unreadable);
    };
    if !schema.types.contains_key(resource_type) || !read.guarded {
        return Ok(SchemaFor::Policies);
    }
    Ok(SchemaFor::Relations(schema))
}

/// Decides by the relations kept, within the budget of the question.
async fn decide_by_relations(
    app: &App,
    work: &mut dyn UnitOfWork,
    schema: &CompiledSchema,
    request: &DecisionRequest<'_>,
    subject: &ObjectRef,
    budget: WalkBudget<'_>,
) -> Result<Decision, OAuthFailure> {
    let object_id = request
        .resource_id
        .filter(|id| is_object_id(id))
        .ok_or(ErrorCode::RequestInvalid)?;
    if schema
        .find_member(request.resource_type, request.action)
        .is_none()
    {
        return Ok(Decision::deny("relation_unknown", None));
    }
    let object = ObjectRef {
        object_type: request.resource_type.to_owned(),
        object_id: object_id.to_owned(),
    };
    let walk = walk_relations(app, work, schema, &object, request.action, subject, budget)
        .await
        .map_err(Failure::from)?;
    Ok(match walk {
        Walk::Found => Decision::permit("relation", None),
        Walk::NotFound => Decision::deny("no_relation", None),
        Walk::Undecided(limit) => Decision::deny(&format!("undecided_{}", limit.name()), None),
    })
}

/// Decides by the policies of the client that asks. Only they read the
/// roles and the groups of a person, and only the roles of the realm or of
/// that client: a role another client defines tells its policies nothing.
async fn decide_by_policies(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
    request: &DecisionRequest<'_>,
    subject: Subject,
) -> Result<Decision, Failure> {
    let policies = work
        .list_applicable_policies(client_id, request.resource_type, request.action)
        .await?;
    if policies.is_empty() {
        return Ok(Decision::deny("no_policy", None));
    }
    let now = app.now();
    let mut facts = subject.facts;
    if let Some(person) = subject.person {
        let mut roles: Vec<Uuid> = read_held_roles(work, person, now)
            .await?
            .into_iter()
            .filter(|held| {
                held.client_id
                    .as_deref()
                    .is_none_or(|owner| owner == client_id)
            })
            .map(|held| held.role)
            .collect();
        roles.sort_unstable();
        roles.dedup();
        facts.roles = roles;
        facts.groups = read_member_groups(work, person, now).await?;
    }
    let facts = Facts {
        subject: &facts,
        resource: request.attributes,
        now,
    };
    Ok(match weigh_policies(&policies, &facts) {
        PolicyVerdict::Permit(name) => Decision::permit("policy", Some(name)),
        PolicyVerdict::Deny(name) => Decision::deny("policy", Some(name)),
        PolicyVerdict::Undecided(name) => Decision::deny("undecided", Some(name)),
        PolicyVerdict::NoPolicy => Decision::deny("no_policy", None),
    })
}

/// Whether the attributes of a resource are small enough to be read.
fn is_small(attributes: &Map<String, Value>) -> bool {
    serde_json::to_vec(attributes).is_ok_and(|written| written.len() <= MAX_ATTRIBUTES_BYTES)
}

/// Decides whether the subject of a token may take an action on a
/// resource, for a client that authenticates. The facts are read as they
/// are now, never from what the token says beyond who it is for.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientAuthenticationFailed`] for a caller that is
/// not a client with its secret, [`ErrorCode::RequestInvalid`] for a
/// question that cannot be asked, [`ErrorCode::StorageUnavailable`] past
/// the share of the tenant or of the node, [`ErrorCode::HeldTooMany`] for a
/// person with too many roles or groups, or the storage failure. A refusal
/// is not an error: it is an answer.
pub async fn decide(
    app: &App,
    realm: &str,
    client_id: Option<&str>,
    client_secret: Option<Secret>,
    request: DecisionRequest<'_>,
) -> Result<Decision, OAuthFailure> {
    // The budget of a walk runs from the question, its first reads included.
    let deadline = app.now() + MAX_DURATION;
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let (Some(client_id), Some(client_secret)) = (client_id, client_secret) else {
        return Err(ErrorCode::ClientAuthenticationFailed.into());
    };
    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let client = authenticate_client(app, work.as_mut(), client_id, &client_secret).await?;
    let token = request.subject_token.ok_or(ErrorCode::RequestInvalid)?;
    if !is_role_name(request.action)
        || !is_role_name(request.resource_type)
        || !is_small(request.attributes)
    {
        return Err(ErrorCode::RequestInvalid.into());
    }
    // A question holds its connection for all it reads, a walk for up to
    // its whole budget: past the share of its tenant or of the node, it is
    // to be asked again, and the connection goes back at once.
    let Some(share) = app.decision_shares.take(scope.tenant()) else {
        return Err(Failure::new(ErrorCode::StorageUnavailable).into());
    };
    let issuer = name_issuer(&app.settings, &realm_name);
    let Some(subject) = read_subject(app, work.as_mut(), &issuer, token).await? else {
        return Ok(Decision::deny("subject_unknown", None));
    };
    match read_schema_for(work.as_mut(), &client.client_id, request.resource_type).await? {
        SchemaFor::Unreadable => Ok(Decision::deny("schema_unreadable", None)),
        SchemaFor::Relations(schema) => {
            let budget = WalkBudget {
                deadline,
                _share: &share,
            };
            decide_by_relations(
                app,
                work.as_mut(),
                &schema,
                &request,
                &subject.object,
                budget,
            )
            .await
        }
        SchemaFor::Policies => {
            Ok(
                decide_by_policies(app, work.as_mut(), &client.client_id, &request, subject)
                    .await?,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::{Decision, DecisionRequest, decide};
    use crate::authz::admin::AdminCaller;
    use crate::authz::capability::Capability;
    use crate::authz::grants::{GrantTerms, RoleHolder, grant_role};
    use crate::authz::policy::{Combine, Effect, NewPolicy, create_policy};
    use crate::authz::relations::{
        ObjectRef, RelationTuple, SubjectRef, write_relation, write_relation_guard,
        write_relation_schema,
    };
    use crate::authz::roles::{NewRole, create_role};
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::Scenario;
    use crate::secret::Secret;
    use crate::testkit::drive::complete;

    struct Started {
        scenario: Scenario,
        caller: AdminCaller,
        /// The access token `webapp` holds for `ada`.
        token: String,
    }

    impl Started {
        fn open() -> Self {
            let scenario = Scenario::start();
            let caller = scenario.name_operator(&[Capability::PolicyWrite, Capability::RoleWrite]);
            let token = scenario.sign_in("openid").tokens.access_token;
            Self {
                scenario,
                caller,
                token,
            }
        }

        fn ask_as(
            &self,
            secret: Secret,
            token: &str,
            action: &str,
            resource: (&str, Option<&str>),
            attributes: &Value,
        ) -> Result<Decision, OAuthError> {
            let attributes: Map<String, Value> =
                attributes.as_object().cloned().unwrap_or_default();
            complete(decide(
                &self.scenario.app,
                "acme",
                Some("billing"),
                Some(secret),
                DecisionRequest {
                    subject_token: Some(token),
                    action,
                    resource_type: resource.0,
                    resource_id: resource.1,
                    attributes: &attributes,
                },
            ))
            .map_err(|failure| failure.error)
        }

        fn ask(
            &self,
            action: &str,
            resource: (&str, Option<&str>),
            attributes: &Value,
        ) -> Decision {
            self.ask_as(
                self.scenario.copy_service_secret(),
                &self.token,
                action,
                resource,
                attributes,
            )
            .expect("an answer")
        }

        /// Makes `billing`, the client that asks, a guard of a type.
        fn guard(&self, object_type: &str) {
            complete(write_relation_guard(
                &self.scenario.app,
                &self.caller,
                object_type,
                "billing",
            ))
            .expect("a guard");
        }

        fn keep(&self, object: (&str, &str), relation: &str, subject: (&str, &str)) {
            let tuple = RelationTuple {
                object: ObjectRef {
                    object_type: object.0.to_owned(),
                    object_id: object.1.to_owned(),
                },
                relation: relation.to_owned(),
                subject: SubjectRef {
                    object: ObjectRef {
                        object_type: subject.0.to_owned(),
                        object_id: subject.1.to_owned(),
                    },
                    member: None,
                },
            };
            complete(write_relation(&self.scenario.app, &self.caller, &tuple)).expect("a relation");
        }

        fn write_policy(&self, name: &str, client_id: &str, effect: Effect, conditions: &Value) {
            let wanted = NewPolicy {
                client_id,
                name,
                resource_type: "invoice",
                action: "approve",
                effect,
                combine: Combine::All,
                conditions,
            };
            complete(create_policy(&self.scenario.app, &self.caller, wanted)).expect("a policy");
        }
    }

    fn told(decision: &Decision) -> (&str, &str, Option<&str>) {
        (
            decision.decision,
            decision.reason.as_str(),
            decision.policy.as_deref(),
        )
    }

    const SCHEMA: &str = "
        definition user {}
        definition client {}
        definition document {
            relation owner: user
            relation reader: user | client
            permission read = reader + owner
        }
    ";

    #[test]
    fn a_resource_of_a_type_of_the_schema_is_decided_by_the_relations_kept() {
        let started = Started::open();
        complete(write_relation_schema(
            &started.scenario.app,
            &started.caller,
            SCHEMA,
        ))
        .expect("a schema");
        started.guard("document");
        let ada = started.scenario.find_ada().to_string();
        started.keep(("document", "q3"), "owner", ("user", &ada));
        let none = json!({});

        assert_eq!(
            told(&started.ask("read", ("document", Some("q3")), &none)),
            ("permit", "relation", None)
        );
        assert_eq!(
            told(&started.ask("read", ("document", Some("q4")), &none)),
            ("deny", "no_relation", None)
        );
        assert_eq!(
            told(&started.ask("share", ("document", Some("q3")), &none)),
            ("deny", "relation_unknown", None)
        );
        let unnamed = started.ask_as(
            started.scenario.copy_service_secret(),
            &started.token,
            "read",
            ("document", None),
            &none,
        );
        assert_eq!(
            unnamed.map(|decision| decision.decision),
            Err(OAuthError::InvalidRequest)
        );
    }

    #[test]
    fn a_client_acting_as_itself_is_the_subject_client_of_the_schema() {
        let started = Started::open();
        complete(write_relation_schema(
            &started.scenario.app,
            &started.caller,
            SCHEMA,
        ))
        .expect("a schema");
        started.guard("document");
        started.keep(("document", "q3"), "reader", ("client", "operator"));
        let operator_token = complete(crate::testkit::fixtures::create_administrator(
            &started.scenario.app,
            "acme",
            started.scenario.scope,
            "auditor",
            &[Capability::AuditRead],
        ));
        let secret = started.scenario.copy_service_secret();
        let as_auditor = started
            .ask_as(
                secret,
                &operator_token,
                "read",
                ("document", Some("q3")),
                &json!({}),
            )
            .expect("an answer");
        assert_eq!(told(&as_auditor), ("deny", "no_relation", None));
        started.keep(("document", "q3"), "reader", ("client", "auditor"));
        let as_auditor = started
            .ask_as(
                started.scenario.copy_service_secret(),
                &operator_token,
                "read",
                ("document", Some("q3")),
                &json!({}),
            )
            .expect("an answer");
        assert_eq!(told(&as_auditor), ("permit", "relation", None));
    }

    #[test]
    fn any_other_resource_is_decided_by_the_policies_of_the_client_that_asks() {
        let started = Started::open();
        let approver = complete(create_role(
            &started.scenario.app,
            &started.caller,
            NewRole {
                name: "approver",
                client_id: None,
                description: None,
            },
        ))
        .expect("a role")
        .id;
        let small = json!({ "amount": 120 });
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &small)),
            ("deny", "no_policy", None)
        );

        started.write_policy(
            "approvers",
            "billing",
            Effect::Permit,
            &json!([{ "role": approver }]),
        );
        started.write_policy(
            "large-invoices",
            "billing",
            Effect::Deny,
            &json!([{ "attribute": { "left": { "resource": "amount" }, "operator": "gt", "right": { "value": 1000 } } }]),
        );
        started.write_policy(
            "of-the-application",
            "webapp",
            Effect::Permit,
            &json!([{ "attribute": { "left": { "subject": "username" }, "operator": "equals", "right": { "value": "ada" } } }]),
        );
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &small)),
            ("deny", "no_policy", None),
            "ada is not an approver yet, and the policy of webapp, that would permit her, is not read"
        );

        complete(grant_role(
            &started.scenario.app,
            &started.caller,
            approver,
            RoleHolder::Person(started.scenario.find_ada()),
            GrantTerms::default(),
        ))
        .expect("a grant");
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &small)),
            ("permit", "policy", Some("approvers")),
            "the role is read now, not from the token made before it"
        );
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &json!({ "amount": 5000 }))),
            ("deny", "policy", Some("large-invoices"))
        );
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &json!({}))),
            ("deny", "undecided", Some("large-invoices"))
        );
    }

    #[test]
    fn a_token_that_does_not_stand_is_nobody_and_a_caller_must_prove_itself() {
        let started = Started::open();
        let none = json!({});

        let forged = started
            .ask_as(
                started.scenario.copy_service_secret(),
                "not.a.token",
                "approve",
                ("invoice", None),
                &none,
            )
            .expect("an answer");
        assert_eq!(told(&forged), ("deny", "subject_unknown", None));
        started.scenario.storage.end_every_session();
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &none)),
            ("deny", "subject_unknown", None),
            "the session ended: the token stands for nobody"
        );
        let wrong = started.ask_as(
            Secret::new(b"not the secret".to_vec()),
            &started.token,
            "approve",
            ("invoice", None),
            &none,
        );
        assert_eq!(
            wrong.map(|decision| decision.decision),
            Err(OAuthError::InvalidClient)
        );
        let unreadable = started.ask_as(
            started.scenario.copy_service_secret(),
            &started.token,
            "two words",
            ("invoice", None),
            &none,
        );
        assert_eq!(
            unreadable.map(|decision| decision.decision),
            Err(OAuthError::InvalidRequest)
        );
    }

    #[test]
    fn a_question_past_the_share_of_its_tenant_is_to_be_asked_again() {
        use std::sync::Arc;

        use crate::authz::shares::DecisionShares;

        let mut started = Started::open();
        complete(write_relation_schema(
            &started.scenario.app,
            &started.caller,
            "definition user {}\ndefinition document {\n  relation owner: user\n}",
        ))
        .expect("a schema");
        started.guard("document");
        started.scenario.app.decision_shares = Arc::new(DecisionShares::new(0, 0));

        for (action, resource) in [
            ("owner", ("document", Some("q3"))),
            ("approve", ("invoice", None)),
        ] {
            let busy = started.ask_as(
                started.scenario.copy_service_secret(),
                &started.token,
                action,
                resource,
                &json!({}),
            );
            assert_eq!(
                busy.map(|decision| decision.decision),
                Err(OAuthError::TemporarilyUnavailable),
                "a walk or the policies, a question holds a share: {}",
                resource.0
            );
        }
    }

    #[test]
    fn a_type_the_client_does_not_guard_is_answered_as_a_type_of_nothing() {
        let started = Started::open();
        complete(write_relation_schema(
            &started.scenario.app,
            &started.caller,
            SCHEMA,
        ))
        .expect("a schema");
        let ada = started.scenario.find_ada().to_string();
        started.keep(("document", "q3"), "owner", ("user", &ada));
        let none = json!({});

        let unguarded = started.ask("read", ("document", Some("q3")), &none);
        assert_eq!(told(&unguarded), ("deny", "no_policy", None));
        assert_eq!(
            unguarded,
            started.ask("read", ("folder", Some("q3")), &none),
            "billing does not learn that the schema defines a document"
        );
        assert_eq!(
            told(&started.ask("read", ("document", None), &none)),
            ("deny", "no_policy", None),
            "nor is its question read as one of relations"
        );
        started.guard("document");
        assert_eq!(
            told(&started.ask("read", ("document", Some("q3")), &none)),
            ("permit", "relation", None)
        );
    }

    #[test]
    fn the_attributes_of_a_resource_are_bounded() {
        use super::MAX_ATTRIBUTES_BYTES;

        let started = Started::open();
        let large = json!({ "notes": "x".repeat(MAX_ATTRIBUTES_BYTES) });
        let refused = started.ask_as(
            started.scenario.copy_service_secret(),
            &started.token,
            "approve",
            ("invoice", None),
            &large,
        );
        assert_eq!(
            refused.map(|decision| decision.decision),
            Err(OAuthError::InvalidRequest)
        );
        let fits = json!({ "notes": "x".repeat(MAX_ATTRIBUTES_BYTES - 64) });
        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &fits)),
            ("deny", "no_policy", None)
        );
    }

    #[test]
    fn a_role_another_client_defines_tells_the_policies_of_billing_nothing() {
        use crate::authz::policy::Policy;
        use crate::ids::mint_id;

        let started = Started::open();
        let of_webapp = complete(create_role(
            &started.scenario.app,
            &started.caller,
            NewRole {
                name: "approver",
                client_id: Some("webapp"),
                description: None,
            },
        ))
        .expect("a role")
        .id;
        complete(grant_role(
            &started.scenario.app,
            &started.caller,
            of_webapp,
            RoleHolder::Person(started.scenario.find_ada()),
            GrantTerms::default(),
        ))
        .expect("a grant");
        // Written past the checks of a policy, as an older version may have.
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            let policy = Policy {
                id: mint_id(&started.scenario.app).expect("an identifier"),
                client_id: "billing".to_owned(),
                name: "approvers".to_owned(),
                resource_type: "invoice".to_owned(),
                action: "approve".to_owned(),
                effect: Effect::Permit,
                combine: Combine::All,
                conditions: json!([{ "role": of_webapp }]),
                created_at: started.scenario.app.now(),
            };
            assert_eq!(work.insert_policy(&policy).await, Ok(true));
            work.commit().await.expect("a commit");
        });

        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &json!({}))),
            ("deny", "no_policy", None),
            "the role ada holds of webapp is not read for billing"
        );
    }

    #[test]
    fn a_person_in_too_many_groups_is_refused_by_name() {
        use crate::authz::grants::{Grant, MAX_HELD, Membership};
        use crate::authz::roles::Group;
        use crate::ids::mint_id;

        let started = Started::open();
        started.write_policy(
            "named-ada",
            "billing",
            Effect::Permit,
            &json!([{ "attribute": { "left": { "subject": "username" }, "operator": "equals", "right": { "value": "ada" } } }]),
        );
        let now = started.scenario.app.now();
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            for index in 0..=MAX_HELD {
                let group = Group {
                    id: mint_id(&started.scenario.app).expect("an identifier"),
                    name: format!("group-{index}"),
                    description: None,
                    created_at: now,
                };
                assert_eq!(work.insert_group(&group).await, Ok(true));
                let membership = Membership {
                    group: group.id,
                    person: started.scenario.find_ada(),
                    grant: Grant {
                        valid_from: now,
                        valid_until: None,
                        granted_by: "operator".to_owned(),
                        reason: None,
                        granted_at: now,
                    },
                };
                work.write_membership(&membership)
                    .await
                    .expect("a membership");
            }
            work.commit().await.expect("a commit");
        });

        let refused = started.ask_as(
            started.scenario.copy_service_secret(),
            &started.token,
            "approve",
            ("invoice", None),
            &json!({}),
        );
        assert_eq!(
            refused.map(|decision| decision.decision),
            Err(OAuthError::InvalidRequest)
        );
    }

    #[test]
    fn a_schema_that_cannot_be_read_decides_nothing_and_nothing_falls_to_the_policies() {
        use crate::authz::relations::StoredSchema;

        let started = Started::open();
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            let unreadable = StoredSchema {
                source: "definition user {".to_owned(),
                compiled: json!({ "version": 0, "types": {} }),
                written_at: started.scenario.app.now(),
            };
            work.write_relation_schema(&unreadable, &[])
                .await
                .expect("a schema");
            work.commit().await.expect("a commit");
        });

        let told = started.ask("approve", ("invoice", None), &json!({}));
        assert_eq!(
            (told.decision, told.reason.as_str()),
            ("deny", "schema_unreadable")
        );
    }

    #[test]
    fn a_compiled_form_another_version_wrote_is_compiled_again_from_its_source() {
        use crate::authz::relations::schema::compile_schema;
        use crate::authz::relations::{StoredSchema, list_admitted_relations};

        let started = Started::open();
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            let older = StoredSchema {
                source: SCHEMA.to_owned(),
                compiled: json!({ "version": 0, "types": {} }),
                written_at: started.scenario.app.now(),
            };
            // The kinds it admits, as the version that wrote it keeps them.
            let admitted = list_admitted_relations(&compile_schema(SCHEMA).expect("a schema"));
            work.write_relation_schema(&older, &admitted)
                .await
                .expect("a schema");
            work.commit().await.expect("a commit");
        });
        started.guard("document");
        let ada = started.scenario.find_ada().to_string();
        started.keep(("document", "q3"), "owner", ("user", &ada));

        assert_eq!(
            told(&started.ask("read", ("document", Some("q3")), &json!({}))),
            ("permit", "relation", None)
        );
    }

    #[test]
    fn a_guard_left_on_a_type_the_schema_no_longer_defines_lets_its_policies_decide() {
        let started = Started::open();
        let schema = |source: &str| {
            complete(write_relation_schema(
                &started.scenario.app,
                &started.caller,
                source,
            ))
            .expect("a schema")
        };
        schema("definition user {}\ndefinition invoice {\n  relation approver: user\n}");
        started.guard("invoice");
        schema("definition user {}");
        started.write_policy(
            "named-ada",
            "billing",
            Effect::Permit,
            &json!([{ "attribute": { "left": { "subject": "username" }, "operator": "equals", "right": { "value": "ada" } } }]),
        );

        assert_eq!(
            told(&started.ask("approve", ("invoice", None), &json!({}))),
            ("permit", "policy", Some("named-ada")),
            "the type went with the schema, the guard stayed: the policies decide"
        );
    }
}
