//! What a policy decides, and what the schema refuses to let it become.

mod support;

use models::auditable::AuditableModel;
use models::entities::authz::{
    AuthzDecisionRecord, Decision, DecisionLogic, DecisionStrategy, PolicyModel, PolicyRule,
    PolicyTerms, ReportedDecision, StoredPolicy,
};
use store::error::StoreError;
use store::providers::authz_policies;
use store::tenancy::TenantContext;
use support::Fixture;

/// A policy of this realm's one application, with nothing bound to it.
fn terms(name: &str, rule: PolicyRule) -> PolicyTerms {
    PolicyTerms {
        name: name.to_owned(),
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

fn stored(id: &str, terms: PolicyTerms) -> PolicyModel {
    terms.into_model(
        id.to_owned(),
        "app".to_owned(),
        "main".to_owned(),
        None,
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    )
}

/// An aggregate over the conditions it names.
fn aggregate(id: &str, conditions: &[&str]) -> PolicyModel {
    stored(
        id,
        PolicyTerms {
            policies: conditions.iter().map(|id| (*id).to_owned()).collect(),
            ..terms(id, PolicyRule::Aggregated)
        },
    )
}

fn read(policy: StoredPolicy) -> PolicyModel {
    match policy {
        StoredPolicy::Read(policy) => policy,
        StoredPolicy::Unreadable { policy_id } => {
            panic!("{policy_id} came back as a row nothing could read")
        }
    }
}

/// A server, a resource and a scope to bind to.
async fn plant_surface(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    for statement in [
        "INSERT INTO resource_servers (tenant, realm_id, server_id) \
         VALUES ('acme', 'main', 'app')",
        "INSERT INTO resources \
             (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
         VALUES ('acme', 'main', 'doc', 'app', 'document', 'urn:doc', 'ada')",
        "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
         VALUES ('acme', 'main', 'read', 'app', 'read')",
        "INSERT INTO roles (tenant, realm_id, role_id, name, display_name) \
         VALUES ('acme', 'main', 'editor', 'editor', 'Editor')",
    ] {
        transaction.execute(statement, &[]).await.unwrap();
    }
    transaction.commit().await.unwrap();
    drop(connection);
}

fn policy(id: &str, kind: &str, rule: &str) -> String {
    format!(
        "INSERT INTO policies \
             (tenant, realm_id, policy_id, server_id, name, policy_type, rule, policy_owner) \
         VALUES ('acme', 'main', '{id}', 'app', '{id}', '{kind}', '{rule}'::jsonb, 'ada')"
    )
}

/// The tag inside the rule and the column beside it cannot disagree.
///
/// One check, and adding an arm never edits it. Transcribing the arms into
/// columns would put the enumeration in two places that have to change together.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_policy_names_its_own_kind() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let cases = [
        (
            policy(
                "agreeing",
                "role",
                r#"{"policy_type":"role","roles":["editor"]}"#,
            ),
            true,
            "a policy whose tag matches its column was refused",
        ),
        (
            policy(
                "lying",
                "role",
                r#"{"policy_type":"time","not_before":"0"}"#,
            ),
            false,
            "a policy carried a rule of another kind than it declares",
        ),
        (
            policy("untagged", "role", r#"{"roles":["editor"]}"#),
            false,
            "a policy carried a rule that names no kind",
        ),
        (
            policy("not-a-document", "role", r#"["role"]"#),
            false,
            "a rule was allowed to be something other than a document",
        ),
    ];

    for (statement, allowed, what) in cases {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let outcome = transaction.execute(statement.as_str(), &[]).await;
        let refused = outcome.is_err();
        drop(transaction);
        drop(connection);
        assert_eq!(!refused, allowed, "{what}");
    }
}

/// A binding cannot hang from a kind that would never read it.
///
/// A row of groups under a policy that decides on roles is a binding nothing
/// reads, and without the kind in the key it is also a binding nothing refuses.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_binding_hangs_only_from_the_kind_that_reads_it() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            policy(
                "by-role",
                "role",
                r#"{"policy_type":"role","roles":["editor"]}"#,
            )
            .as_str(),
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO policies_roles \
                 (tenant, realm_id, server_id, policy_id, policy_type, role_id) \
             VALUES ('acme', 'main', 'app', 'by-role', 'role', 'editor')",
            &[],
        )
        .await
        .unwrap();
    // The group has to exist, or the refusal below would come from the foreign
    // key to it rather than from the kind, and the test would pass whatever the
    // kind constraint said.
    transaction
        .execute(
            "INSERT INTO groups (tenant, realm_id, group_id, name, display_name) \
             VALUES ('acme', 'main', 'staff', 'staff', 'Staff')",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    // The same policy, given a binding of a kind it does not read.
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    let refused = transaction
        .execute(
            "INSERT INTO policies_groups \
                 (tenant, realm_id, server_id, policy_id, policy_type, group_id) \
             VALUES ('acme', 'main', 'app', 'by-role', 'role', 'staff')",
            &[],
        )
        .await
        .is_err();
    drop(transaction);
    drop(connection);
    assert!(
        refused,
        "a policy deciding on roles was given a group binding"
    );
}

/// A policy that has bindings cannot change what it decides on, because the
/// kind travels in the foreign key those bindings hold.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_bound_policy_cannot_change_its_kind() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            policy(
                "by-role",
                "role",
                r#"{"policy_type":"role","roles":["editor"]}"#,
            )
            .as_str(),
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO policies_roles \
                 (tenant, realm_id, server_id, policy_id, policy_type, role_id) \
             VALUES ('acme', 'main', 'app', 'by-role', 'role', 'editor')",
            &[],
        )
        .await
        .unwrap();

    assert!(
        transaction
            .execute(
                "UPDATE policies SET policy_type = 'time', \
                 rule = '{\"policy_type\":\"time\"}'::jsonb WHERE policy_id = 'by-role'",
                &[],
            )
            .await
            .is_err(),
        "a policy with bindings changed what it decides on"
    );
}

/// Only three kinds aggregate, a permission is never a condition, and nothing
/// is its own condition.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn aggregation_refuses_what_would_not_terminate_or_be_read() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    for statement in [
        policy("group-of", "aggregated", r#"{"policy_type":"aggregated"}"#),
        policy(
            "by-role",
            "role",
            r#"{"policy_type":"role","roles":["editor"]}"#,
        ),
        policy(
            "may-read",
            "scope-permission",
            r#"{"policy_type":"scope-permission","resource_type":"urn:doc"}"#,
        ),
    ] {
        transaction.execute(statement.as_str(), &[]).await.unwrap();
    }
    // An aggregate over a condition is the legitimate case.
    transaction
        .execute(
            "INSERT INTO policies_policies \
                 (tenant, realm_id, server_id, policy_id, policy_type, \
                  associated_policy_id, associated_type) \
             VALUES ('acme', 'main', 'app', 'group-of', 'aggregated', 'by-role', 'role')",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let cases = [
        (
            "INSERT INTO policies_policies \
                 (tenant, realm_id, server_id, policy_id, policy_type, \
                  associated_policy_id, associated_type) \
             VALUES ('acme', 'main', 'app', 'by-role', 'role', 'group-of', 'aggregated')",
            "a policy that decides on roles was given conditions to aggregate",
        ),
        (
            "INSERT INTO policies_policies \
                 (tenant, realm_id, server_id, policy_id, policy_type, \
                  associated_policy_id, associated_type) \
             VALUES ('acme', 'main', 'app', 'group-of', 'aggregated', 'may-read', \
                     'scope-permission')",
            "a permission was made the condition of another policy",
        ),
        (
            "INSERT INTO policies_policies \
                 (tenant, realm_id, server_id, policy_id, policy_type, \
                  associated_policy_id, associated_type) \
             VALUES ('acme', 'main', 'app', 'group-of', 'aggregated', 'group-of', \
                     'aggregated')",
            "a policy was made its own condition",
        ),
    ];

    for (statement, what) in cases {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let refused = transaction.execute(statement, &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// A permission reaches the resources of its own application and no other's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_permission_reaches_its_own_application() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            policy(
                "may-read",
                "resource-permission",
                r#"{"policy_type":"resource-permission","resource_type":"urn:doc"}"#,
            )
            .as_str(),
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO policies_resources \
                 (tenant, realm_id, server_id, policy_id, policy_type, resource_id) \
             VALUES ('acme', 'main', 'app', 'may-read', 'resource-permission', 'doc')",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    // A condition, given resources to apply to.
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            policy(
                "by-role",
                "role",
                r#"{"policy_type":"role","roles":["editor"]}"#,
            )
            .as_str(),
            &[],
        )
        .await
        .unwrap();
    let refused = transaction
        .execute(
            "INSERT INTO policies_resources \
                 (tenant, realm_id, server_id, policy_id, policy_type, resource_id) \
             VALUES ('acme', 'main', 'app', 'by-role', 'role', 'doc')",
            &[],
        )
        .await
        .is_err();
    drop(transaction);
    drop(connection);
    assert!(
        refused,
        "a condition was bound to resources it would never read"
    );
}

/// Narrowing a policy to an organization and then removing the organization
/// removes the policy, rather than widening it back to the realm.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn removing_the_organization_removes_what_was_confined_to_it() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO organizations (tenant, realm_id, org_id, name, display_name) \
             VALUES ('acme', 'main', 'customer-x', 'customer-x', 'Customer X')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO policies \
                 (tenant, realm_id, policy_id, server_id, org_id, name, policy_type, rule, \
                  policy_owner) \
             VALUES ('acme', 'main', 'confined', 'app', 'customer-x', 'confined', 'role', \
                     '{\"policy_type\":\"role\",\"roles\":[\"editor\"]}'::jsonb, 'ada')",
            &[],
        )
        .await
        .unwrap();

    transaction
        .execute("DELETE FROM organizations WHERE org_id = 'customer-x'", &[])
        .await
        .unwrap();

    let left: i64 = transaction
        .query_one(
            "SELECT count(*) FROM policies WHERE policy_id = 'confined'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        left, 0,
        "a policy confined to an organization outlived it, widened to the realm"
    );
}

/// The log records what the caller was told and what was actually reached,
/// because a permissive server reports a permit over a denial and an
/// unevaluable policy is neither.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_log_keeps_the_answer_apart_from_the_outcome() {
    let fixture = Fixture::with_user_and_client().await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO authz_decisions \
                 (tenant, realm_id, decision_id, subject_type, subject_id, resource_kind, \
                  action, reported, computed, detail, duration_us) \
             VALUES ('acme', 'main', 'masked', 'user', 'ada', 'resource', 'read', \
                     'permit', 'deny', '{}'::jsonb, 120)",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO authz_decisions \
                 (tenant, realm_id, decision_id, subject_type, subject_id, resource_kind, \
                  action, reported, computed, detail, duration_us) \
             VALUES ('acme', 'main', 'unevaluable', 'user', 'ada', 'resource', 'read', \
                     'deny', 'indeterminate', '{}'::jsonb, 90)",
            &[],
        )
        .await
        .unwrap();

    let disagreements: i64 = transaction
        .query_one(
            "SELECT count(*) FROM authz_decisions WHERE reported <> computed",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(disagreements, 2);

    // Nobody is told a third thing.
    assert!(
        transaction
            .execute(
                "INSERT INTO authz_decisions \
                     (tenant, realm_id, decision_id, subject_type, subject_id, resource_kind, \
                      action, reported, computed, detail, duration_us) \
                 VALUES ('acme', 'main', 'told-maybe', 'user', 'ada', 'resource', 'read', \
                         'indeterminate', 'indeterminate', '{}'::jsonb, 5)",
                &[],
            )
            .await
            .is_err(),
        "a caller was recorded as having been told the answer was undecided"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn policies_are_not_visible_from_another_realm() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            policy(
                "by-role",
                "role",
                r#"{"policy_type":"role","roles":["editor"]}"#,
            )
            .as_str(),
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    let seen: i64 = transaction
        .query_one("SELECT count(*) FROM policies", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0, "another realm read this realm's policies");
}

/// A policy names what the realm still holds, not what it held when it was
/// written. The document keeps the second answer, which is why the two are not
/// the same read.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_policy_answers_with_what_still_exists() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO roles (tenant, realm_id, role_id, name, display_name) \
             VALUES ('acme', 'main', 'viewer', 'viewer', 'Viewer')",
            &[],
        )
        .await
        .unwrap();

    authz_policies::create(
        &transaction,
        &stored(
            "editors",
            terms(
                "editors",
                PolicyRule::Role {
                    roles: vec!["viewer".to_owned(), "editor".to_owned()],
                },
            ),
        ),
    )
    .await
    .unwrap();

    let loaded = read(
        authz_policies::load(&transaction, "app", "editors")
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        loaded.terms.rule,
        PolicyRule::Role {
            roles: vec!["editor".to_owned(), "viewer".to_owned()]
        },
        "the members did not come back from the rows the database keeps"
    );
    assert_eq!(loaded.org_id, None);
    assert_eq!(loaded.metadata.created_by.as_deref(), Some("root"));

    transaction
        .execute("DELETE FROM roles WHERE role_id = 'viewer'", &[])
        .await
        .unwrap();

    let after = read(
        authz_policies::load(&transaction, "app", "editors")
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        after.terms.rule,
        PolicyRule::Role {
            roles: vec!["editor".to_owned()]
        },
        "a policy still named a role the realm no longer has"
    );

    // And the document is untouched, so what was asked for is still on record.
    let written: serde_json::Value = transaction
        .query_one("SELECT rule FROM policies WHERE policy_id = 'editors'", &[])
        .await
        .unwrap()
        .get("rule");
    assert_eq!(
        written["roles"],
        serde_json::json!(["viewer", "editor"]),
        "the record of what was asked for was rewritten by a deletion elsewhere"
    );
}

/// The one cycle a row shows is the table's to refuse. A longer one is only
/// visible from the whole graph, and it is refused before the edge lands.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_condition_that_leads_back_is_refused() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    for leaf in ["leaf", "twig"] {
        authz_policies::create(
            &transaction,
            &stored(
                leaf,
                terms(
                    leaf,
                    PolicyRule::Role {
                        roles: vec!["editor".to_owned()],
                    },
                ),
            ),
        )
        .await
        .unwrap();
    }
    for (id, conditions) in [
        ("first", vec!["leaf"]),
        ("second", vec!["first"]),
        ("third", vec!["second"]),
    ] {
        authz_policies::create(&transaction, &aggregate(id, &conditions))
            .await
            .unwrap();
    }

    // Three edges away and back again. Nothing in one row shows it.
    assert_eq!(
        authz_policies::update(&transaction, &aggregate("first", &["third"])).await,
        Err(StoreError::PolicyCycle {
            policy: "first".to_owned(),
            condition: "third".to_owned(),
        })
    );

    // The short one is refused by the same walk, so the two are one rule.
    assert!(matches!(
        authz_policies::update(&transaction, &aggregate("first", &["first"])).await,
        Err(StoreError::PolicyCycle { .. })
    ));

    // A refusal leaves the graph as it was, and the transaction usable.
    let untouched = read(
        authz_policies::load(&transaction, "app", "first")
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(untouched.terms.policies, vec!["leaf".to_owned()]);

    // And nothing here is a blanket refusal: an aggregation that leads nowhere
    // near where it started is written.
    assert!(
        authz_policies::update(&transaction, &aggregate("first", &["leaf", "twig"]))
            .await
            .unwrap()
    );
    let widened = read(
        authz_policies::load(&transaction, "app", "first")
            .await
            .unwrap()
            .unwrap(),
    );
    assert_eq!(
        widened.terms.policies,
        vec!["leaf".to_owned(), "twig".to_owned()],
        "an update added to the conditions instead of replacing them"
    );
}

/// Everything the write path refuses is refused before it writes, so a refusal
/// leaves nothing behind and does not abort the transaction it was asked in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_is_refused_is_refused_before_anything_is_written() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let unconditional = stored(
        "grant",
        PolicyTerms {
            resources: vec!["doc".to_owned()],
            ..terms(
                "grant",
                PolicyRule::ResourcePermission {
                    resource_type: "urn:doc".to_owned(),
                },
            )
        },
    );
    assert_eq!(
        authz_policies::create(&transaction, &unconditional).await,
        Err(StoreError::UnconditionalPermission)
    );

    let broken = stored(
        "by-mail",
        terms(
            "by-mail",
            PolicyRule::Regex {
                target_claim: "email".to_owned(),
                target_regex: "([a-z".to_owned(),
            },
        ),
    );
    assert!(matches!(
        authz_policies::create(&transaction, &broken).await,
        Err(StoreError::BadPattern(_))
    ));

    let ghost = aggregate("built-on-air", &["no-such-policy"]);
    assert_eq!(
        authz_policies::create(&transaction, &ghost).await,
        Err(StoreError::NotFound {
            asked: "no-such-policy".to_owned(),
        })
    );

    // Nothing landed, including the row the aggregate would have written before
    // it reached its conditions.
    assert!(
        authz_policies::list_for_server(&transaction, "app")
            .await
            .unwrap()
            .is_empty(),
        "a refused write left a policy behind"
    );

    // And the transaction still works, which is what refusing before writing
    // buys: no statement was sent for the database to abort it over.
    authz_policies::create(
        &transaction,
        &stored(
            "by-mail",
            terms(
                "by-mail",
                PolicyRule::Regex {
                    target_claim: "email".to_owned(),
                    target_regex: r"^.+@example\.test$".to_owned(),
                },
            ),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        authz_policies::list_for_server(&transaction, "app")
            .await
            .unwrap()
            .len(),
        1
    );
}

/// A policy nobody can read is named and quarantined. Dropping it would make it
/// look like a policy nobody wrote, and under a strategy where one permit is
/// enough those two are the difference between refusing and permitting.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_row_nothing_can_read_is_named_and_the_rest_survive() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    authz_policies::create(
        &transaction,
        &stored(
            "editors",
            terms(
                "editors",
                PolicyRule::Role {
                    roles: vec!["editor".to_owned()],
                },
            ),
        ),
    )
    .await
    .unwrap();

    // Tagged as the kind it claims, so the constraint that reads the tag is
    // satisfied, and carrying none of what that kind is made of.
    transaction
        .execute(&policy("adrift", "role", r#"{"policy_type": "role"}"#), &[])
        .await
        .unwrap();

    let listed = authz_policies::list_for_server(&transaction, "app")
        .await
        .unwrap();
    assert_eq!(listed.len(), 2, "a row that would not decode took the list");

    let names: Vec<&str> = listed.iter().map(StoredPolicy::policy_id).collect();
    assert_eq!(names, vec!["adrift", "editors"]);
    assert!(matches!(listed[0], StoredPolicy::Unreadable { .. }));
    assert!(matches!(listed[1], StoredPolicy::Read(_)));

    assert!(matches!(
        authz_policies::load(&transaction, "app", "adrift")
            .await
            .unwrap(),
        Some(StoredPolicy::Unreadable { .. })
    ));
}

/// What a caller was told and what the evaluation reached, kept apart on the
/// way in and on the way out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_decision_keeps_both_answers_through_the_round_trip() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let record = |id: &str, reported, computed| AuthzDecisionRecord {
        decision_id: id.to_owned(),
        tenant: "acme".to_owned(),
        realm_id: "main".to_owned(),
        subject_type: "user".to_owned(),
        subject_id: "ada".to_owned(),
        resource_kind: "resource".to_owned(),
        resource_ref: Some("doc".to_owned()),
        action: "read".to_owned(),
        reported,
        computed,
        detail: serde_json::json!({"claims": {"tier": "gold"}}),
        duration_us: 1_200,
        trace_id: Some("trace-1".to_owned()),
        occurred_at_millis: None,
    };

    for entry in [
        record("plain", ReportedDecision::Permit, Decision::Permit),
        // A permissive server telling the caller yes over a denial.
        record("masked", ReportedDecision::Permit, Decision::Deny),
        // And an evaluation that reached no answer at all.
        record(
            "unanswered",
            ReportedDecision::Deny,
            Decision::Indeterminate,
        ),
    ] {
        authz_policies::record(&transaction, &entry).await.unwrap();
    }

    // The order is not asserted: these share one transaction, so `now()` gives
    // them one timestamp and a sort on it decides nothing.
    let all = authz_policies::recent(&transaction, 10).await.unwrap();
    assert_eq!(all.len(), 3);

    let plain = all
        .iter()
        .find(|entry| entry.decision_id == "plain")
        .expect("the ordinary decision");
    assert_eq!(plain.reported, ReportedDecision::Permit);
    assert_eq!(plain.computed, Decision::Permit);
    assert_eq!(plain.detail["claims"]["tier"], "gold");
    assert_eq!(plain.duration_us, 1_200);
    assert!(plain.occurred_at_millis.is_some());

    let mut disagreed: Vec<String> = authz_policies::disagreements(&transaction, 10)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.decision_id)
        .collect();
    disagreed.sort();
    assert_eq!(
        disagreed,
        vec!["masked".to_owned(), "unanswered".to_owned()],
        "the two an auditor looks for are not what the read returned"
    );
}

/// A policy is what it decides on. Changing that under the same identifier
/// would take everything conditioned on it along without anyone asking.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_policy_does_not_change_what_it_decides_on() {
    let fixture = Fixture::with_user_and_client().await;
    plant_surface(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    authz_policies::create(
        &transaction,
        &stored(
            "editors",
            terms(
                "editors",
                PolicyRule::Role {
                    roles: vec!["editor".to_owned()],
                },
            ),
        ),
    )
    .await
    .unwrap();

    assert_eq!(
        authz_policies::update(&transaction, &aggregate("editors", &["editors"])).await,
        Err(StoreError::PolicyKindChanged)
    );

    assert!(
        !authz_policies::update(
            &transaction,
            &stored(
                "nobody",
                terms(
                    "nobody",
                    PolicyRule::Role {
                        roles: vec!["editor".to_owned()],
                    },
                ),
            ),
        )
        .await
        .unwrap(),
        "a policy that is not there was reported as updated"
    );

    assert!(
        authz_policies::delete(&transaction, "editors")
            .await
            .unwrap()
    );
    assert!(
        !authz_policies::delete(&transaction, "editors")
            .await
            .unwrap()
    );
}
