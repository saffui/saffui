//! What a policy decides, and what the schema refuses to let it become.

mod support;

use store::tenancy::TenantContext;
use support::Fixture;

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
/// This is the defect the reference ships: a row of groups under a policy that
/// decides on roles, which nothing reads and nothing refuses.
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
