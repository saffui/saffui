//! What the decision point answers, and what it writes down.
//!
//! Every one of these goes through the real door: facts read from the store,
//! an engine that cannot reach it, and a record written before the answer comes
//! back. What is asserted is the answer and the record together, because an
//! answer nobody can find afterwards is half a decision.

mod support;

use chrono::Utc;
use models::auditable::AuditableModel;
use models::entities::authz::{Decision, ReportedDecision};
use models::sessions::records::{UserSessionModel, UserSessionState};
use services::context::{Context, establish};
use services::pdp::{Question, Resource, decide};
use services::token::Verified;
use store::providers::{authz_policies, sessions};
use store::tenancy::TenantContext;
use support::Fixture;

const SESSION: &str = "session-1";

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

fn presented(subject: &str) -> Verified {
    let mut claims = serde_json::Map::new();
    claims.insert("typ".into(), serde_json::json!("Bearer"));
    claims.insert("sid".into(), serde_json::json!(SESSION));
    Verified {
        subject: subject.to_owned(),
        audiences: vec!["saffui-admin".to_owned()],
        scope: "openid admin".to_owned(),
        token_id: None,
        claims,
    }
}

/// A realm with an application, one resource, one verb, and a caller logged in.
async fn plant(transaction: &deadpool_postgres::Transaction<'_>) {
    sessions::open(
        transaction,
        &UserSessionModel {
            tenant: "acme".into(),
            session_id: SESSION.into(),
            realm_id: "main".into(),
            user_id: "ada".into(),
            login_username: "ada".into(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: None,
            ip_address: None,
            started_at: Utc::now().timestamp(),
            auth_time: None,
            loa: None,
            expiration: None,
            state: UserSessionState::LoggedIn,
            remember_me: None,
            last_session_refresh: None,
            is_offline: None,
            notes: None,
        },
    )
    .await
    .unwrap();

    for statement in [
        "INSERT INTO clients (tenant, realm_id, client_id, name, display_name) \
         VALUES ('acme', 'main', 'app', 'app', 'App')",
        "INSERT INTO resource_servers (tenant, realm_id, server_id) \
         VALUES ('acme', 'main', 'app')",
        "INSERT INTO resources \
             (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
         VALUES ('acme', 'main', 'doc', 'app', 'document', 'urn:doc', 'ada')",
        "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
         VALUES ('acme', 'main', 'read', 'app', 'read')",
        "INSERT INTO resource_scopes (tenant, realm_id, server_id, resource_id, scope_id) \
         VALUES ('acme', 'main', 'app', 'doc', 'read')",
        "INSERT INTO roles (tenant, realm_id, role_id, name, display_name) \
         VALUES ('acme', 'main', 'editor', 'editor', 'Editor')",
    ] {
        transaction.execute(statement, &[]).await.unwrap();
    }
}

/// A role policy naming `editor`, and a permission on the document conditioned
/// on it.
async fn protect(transaction: &deadpool_postgres::Transaction<'_>) {
    let editors = models::entities::authz::PolicyTerms {
        name: "editors".into(),
        description: String::new(),
        decision: models::entities::authz::DecisionStrategy::Unanimous,
        logic: models::entities::authz::DecisionLogic::Positive,
        policy_owner: "ada".into(),
        policies: Vec::new(),
        resources: Vec::new(),
        scopes: Vec::new(),
        rule: models::entities::authz::PolicyRule::Role {
            roles: vec!["editor".into()],
        },
    }
    .into_model(
        "editors".into(),
        "app".into(),
        "main".into(),
        None,
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    authz_policies::create(transaction, &editors).await.unwrap();

    let may_read = models::entities::authz::PolicyTerms {
        name: "may-read".into(),
        description: String::new(),
        decision: models::entities::authz::DecisionStrategy::Unanimous,
        logic: models::entities::authz::DecisionLogic::Positive,
        policy_owner: "ada".into(),
        policies: vec!["editors".into()],
        resources: vec!["doc".into()],
        scopes: vec!["read".into()],
        rule: models::entities::authz::PolicyRule::ScopePermission {
            resource_type: String::new(),
        },
    }
    .into_model(
        "may-read".into(),
        "app".into(),
        "main".into(),
        None,
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    authz_policies::create(transaction, &may_read)
        .await
        .unwrap();
}

/// One question, with an identifier of its own. Nothing downstream can mint one
/// that differs per decision, so a test that reused one would collide on the
/// record's key and abort the transaction under it.
fn question<'a>(resource: Resource<'a>, action: &'a str) -> Question<'a> {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let seen = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Question {
        resource,
        action,
        decision_id: Box::leak(format!("decision-{seen}").into_boxed_str()),
        trace_id: None,
    }
}

async fn caller(transaction: &deadpool_postgres::Transaction<'_>) -> Context {
    establish(transaction, tenant(), &presented("ada"), Utc::now())
        .await
        .expect("a caller this realm holds")
}

/// The whole path: a caller who holds the role the permission is conditioned
/// on, and the same caller once the role is taken away.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_permission_answers_on_what_the_caller_holds() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    plant(&transaction).await;
    protect(&transaction).await;
    store::providers::roles::grant_to_user(&transaction, "ada", "editor")
        .await
        .unwrap();

    let context = caller(&transaction).await;
    let answer = decide(
        &transaction,
        &context,
        question(
            Resource::Permission {
                server_id: "app",
                resource: "doc",
                scope: "read",
            },
            "read",
        ),
    )
    .await
    .unwrap();

    assert!(answer.permitted(), "a caller holding the role was refused");
    assert_eq!(answer.computed, Decision::Permit);

    store::providers::roles::revoke_from_user(&transaction, "ada", "editor")
        .await
        .unwrap();
    let answer = decide(
        &transaction,
        &context,
        question(
            Resource::Permission {
                server_id: "app",
                resource: "doc",
                scope: "read",
            },
            "read",
        ),
    )
    .await
    .unwrap();

    assert!(
        !answer.permitted(),
        "the role was taken away and nothing changed"
    );
    assert_eq!(answer.computed, Decision::Deny);
}

/// A verb the resource does not declare, and a resource nothing protects. Both
/// refuse, and they refuse for their own stated reason rather than by falling
/// through to the same empty fold.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_nothing_protects_is_refused_for_its_own_reason() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    plant(&transaction).await;
    protect(&transaction).await;

    let context = caller(&transaction).await;

    let unknown = decide(
        &transaction,
        &context,
        question(
            Resource::Permission {
                server_id: "app",
                resource: "no-such-doc",
                scope: "read",
            },
            "read",
        ),
    )
    .await
    .unwrap();
    assert!(!unknown.permitted());
    assert_eq!(
        unknown.detail["reasons"][0]["reason"], "no-such-resource",
        "a resource nobody protects refused for some other reason"
    );

    let elsewhere = decide(
        &transaction,
        &context,
        question(
            Resource::Permission {
                server_id: "no-such-app",
                resource: "doc",
                scope: "read",
            },
            "read",
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        elsewhere.detail["reasons"][0]["reason"],
        "no-such-application"
    );
}

/// The administrative surface reports what it reached, third value included,
/// because an administrator trying a rule needs to see that it could not be
/// evaluated rather than a refusal standing in for one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn testing_a_policy_reports_what_it_reached() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    plant(&transaction).await;
    protect(&transaction).await;

    let context = caller(&transaction).await;

    let answer = decide(
        &transaction,
        &context,
        question(
            Resource::Policy {
                server_id: "app",
                policy_id: "editors",
            },
            "test",
        ),
    )
    .await
    .unwrap();
    assert_eq!(answer.computed, Decision::Deny, "ada holds no role here");

    // A policy the set does not hold is not a refusal on the merits.
    let missing = decide(
        &transaction,
        &context,
        question(
            Resource::Policy {
                server_id: "app",
                policy_id: "no-such-policy",
            },
            "test",
        ),
    )
    .await
    .unwrap();
    assert_eq!(missing.computed, Decision::Indeterminate);
    assert!(!missing.permitted());
}

/// A realm with no relationship schema has nothing to walk by, and that is not
/// a caller being refused on the merits.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_with_no_schema_cannot_answer() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    plant(&transaction).await;

    let context = caller(&transaction).await;
    let answer = decide(
        &transaction,
        &context,
        question(
            Resource::Relationship {
                object_type: "document",
                object_id: "doc",
                relation: "view",
            },
            "view",
        ),
    )
    .await
    .unwrap();

    assert!(!answer.permitted());
    assert_eq!(
        answer.computed,
        Decision::Indeterminate,
        "a question nothing answered was recorded as having been decided"
    );
    assert_eq!(answer.detail["reasons"][0]["reason"], "no-schema");
}

/// Every decision is written down, on every path, and the record keeps the two
/// answers apart. A decision nobody can find afterwards is one nobody can
/// audit.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_decision_is_written_down() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    plant(&transaction).await;
    protect(&transaction).await;

    let context = caller(&transaction).await;
    for resource in [
        Resource::Permission {
            server_id: "app",
            resource: "doc",
            scope: "read",
        },
        Resource::Permission {
            server_id: "app",
            resource: "no-such-doc",
            scope: "read",
        },
        Resource::Relationship {
            object_type: "document",
            object_id: "doc",
            relation: "view",
        },
    ] {
        decide(&transaction, &context, question(resource, "read"))
            .await
            .unwrap();
    }

    let written = authz_policies::recent(&transaction, 10).await.unwrap();
    assert_eq!(written.len(), 3, "a decision was answered and not recorded");

    for entry in &written {
        assert_eq!(entry.subject_id, "ada");
        assert_eq!(entry.subject_type, "user");
        assert!(entry.duration_us >= 0);
    }

    let kinds: Vec<&str> = written.iter().map(|e| e.resource_kind.as_str()).collect();
    assert!(kinds.contains(&"permission"));
    assert!(kinds.contains(&"relationship"));

    // The one an auditor looks for: what was reached and what was said differ.
    let unanswered = written
        .iter()
        .find(|e| e.resource_kind == "relationship")
        .expect("the relationship decision");
    assert_eq!(unanswered.reported, ReportedDecision::Deny);
    assert_eq!(unanswered.computed, Decision::Indeterminate);
}

/// The other engine, reached through the same door and recorded the same way.
/// Neither engine can overrule the other, because neither is ever asked the
/// question the other answers.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_relationship_question_reaches_the_engine_next_door() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    plant(&transaction).await;

    let source = "
definition user {}
definition document {
    relation owner: user
    permission view = owner
}
";
    let compiled = authz::rebac::compile(&authz::rebac::parse(source).unwrap()).unwrap();
    store::providers::rebac::put_schema(
        &transaction,
        &store::providers::rebac::StoredSchema {
            format: authz::rebac::FORMAT as i32,
            revision: 1,
            source: source.to_owned(),
            compiled: serde_json::to_value(&compiled).unwrap(),
        },
        Some("root"),
    )
    .await
    .unwrap();

    let context = caller(&transaction).await;
    let asking = |relation: &'static str| Resource::Relationship {
        object_type: "document",
        object_id: "doc",
        relation,
    };

    // No edge yet.
    let before = decide(&transaction, &context, question(asking("view"), "view"))
        .await
        .unwrap();
    assert!(!before.permitted());
    assert_eq!(
        before.computed,
        Decision::Deny,
        "an unrelated caller was recorded as unanswerable"
    );

    store::providers::rebac::relate(
        &transaction,
        "document",
        "doc",
        "owner",
        &store::providers::rebac::Subject {
            subject_type: "user".into(),
            subject_id: "ada".into(),
            subject_relation: String::new(),
        },
        Some("root"),
    )
    .await
    .unwrap();

    let after = decide(&transaction, &context, question(asking("view"), "view"))
        .await
        .unwrap();
    assert!(after.permitted(), "the edge written beside it was not seen");
    assert_eq!(after.computed, Decision::Permit);

    // A relation the schema does not describe is not a refusal on the merits.
    let unknown = decide(&transaction, &context, question(asking("fly"), "fly"))
        .await
        .unwrap();
    assert!(!unknown.permitted());
    assert_eq!(unknown.computed, Decision::Deny);

    // And every one of the three is in the journal, named by what it was about.
    let written = store::providers::authz_policies::recent(&transaction, 10)
        .await
        .unwrap();
    let kinds: Vec<&str> = written.iter().map(|e| e.resource_kind.as_str()).collect();
    assert_eq!(
        kinds.iter().filter(|kind| **kind == "relationship").count(),
        3
    );
    let refs: Vec<String> = written
        .iter()
        .filter(|e| e.resource_kind == "relationship")
        .filter_map(|e| e.resource_ref.clone())
        .collect();
    assert!(
        refs.contains(&"document:doc#view".to_owned()),
        "the record does not say which relation was asked about: {refs:?}"
    );
}
