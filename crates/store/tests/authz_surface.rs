//! The surface a protected application exposes, against a database.

mod support;

use store::tenancy::TenantContext;
use support::Fixture;

/// Plant a server on the client the fixture already has.
async fn plant_server(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO resource_servers (tenant, realm_id, server_id) \
             VALUES ('acme', 'main', 'app')",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
}

/// A server is a client that has a surface, so it cannot be one that is not.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_server_is_a_client_of_the_realm() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        transaction
            .execute(
                "INSERT INTO resource_servers (tenant, realm_id, server_id) \
                 VALUES ('acme', 'main', 'no-such-client')",
                &[],
            )
            .await
            .is_err(),
        "a resource server was created for a client that does not exist"
    );
}

/// The binding carries the server on both sides, so the pair cannot be made of
/// two rows that are each valid and together nonsense.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_resource_cannot_declare_another_server_s_scope() {
    let fixture = Fixture::with_user_and_client().await;
    plant_server(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // A second client, and a second server on it.
    transaction
        .execute(
            "INSERT INTO clients (tenant, realm_id, client_id, name, display_name) \
             VALUES ('acme', 'main', 'other', 'other', 'Other')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO resource_servers (tenant, realm_id, server_id) \
             VALUES ('acme', 'main', 'other')",
            &[],
        )
        .await
        .unwrap();

    transaction
        .execute(
            "INSERT INTO resources \
                 (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
             VALUES ('acme', 'main', 'doc', 'app', 'document', 'urn:doc', 'ada')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
             VALUES ('acme', 'main', 'read-elsewhere', 'other', 'read')",
            &[],
        )
        .await
        .unwrap();

    assert!(
        transaction
            .execute(
                "INSERT INTO resource_scopes (tenant, realm_id, server_id, resource_id, scope_id) \
                 VALUES ('acme', 'main', 'app', 'doc', 'read-elsewhere')",
                &[],
            )
            .await
            .is_err(),
        "a resource declared a verb belonging to another server"
    );
}

/// A name answers for one resource within a server, and for one scope.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_name_answers_once_per_server() {
    let fixture = Fixture::with_user_and_client().await;
    plant_server(&fixture).await;

    let cases = [
        (
            "INSERT INTO resources \
                 (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
             VALUES ('acme', 'main', 'first', 'app', 'document', 'urn:doc', 'ada')",
            "INSERT INTO resources \
                 (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
             VALUES ('acme', 'main', 'second', 'app', 'document', 'urn:doc', 'ada')",
            "two resources of one server answer to one name",
        ),
        (
            "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
             VALUES ('acme', 'main', 'first', 'app', 'read')",
            "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
             VALUES ('acme', 'main', 'second', 'app', 'read')",
            "two scopes of one server answer to one name",
        ),
    ];

    for (first, second, what) in cases {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        transaction.execute(first, &[]).await.unwrap();
        let refused = transaction.execute(second, &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// The configuration is a bounded map, the same rule the login envelope carries.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_resource_configuration_is_a_bounded_map() {
    let fixture = Fixture::with_user_and_client().await;
    plant_server(&fixture).await;

    let big = "x".repeat(5000);
    let cases = [
        (
            "'\"a string\"'::jsonb".to_owned(),
            "the configuration was allowed to be something other than a map",
        ),
        (
            format!("jsonb_build_object('stashed', '{big}')"),
            "the configuration was allowed to grow without a ceiling",
        ),
    ];

    for (index, (configs, what)) in cases.iter().enumerate() {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let statement = format!(
            "INSERT INTO resources \
                 (tenant, realm_id, resource_id, server_id, name, resource_type, \
                  resource_owner, configs) \
             VALUES ('acme', 'main', 'bad-{index}', 'app', 'bad-{index}', 'urn:doc', \
                     'ada', {configs})"
        );
        let refused = transaction.execute(statement.as_str(), &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// Removing the client removes the surface it exposed.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn removing_the_client_takes_the_surface() {
    let fixture = Fixture::with_user_and_client().await;
    plant_server(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO resources \
                 (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
             VALUES ('acme', 'main', 'doc', 'app', 'document', 'urn:doc', 'ada')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO scopes (tenant, realm_id, scope_id, server_id, name) \
             VALUES ('acme', 'main', 'read', 'app', 'read')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO resource_scopes (tenant, realm_id, server_id, resource_id, scope_id) \
             VALUES ('acme', 'main', 'app', 'doc', 'read')",
            &[],
        )
        .await
        .unwrap();

    transaction
        .execute("DELETE FROM clients WHERE client_id = 'app'", &[])
        .await
        .unwrap();

    for table in ["resource_servers", "resources", "scopes", "resource_scopes"] {
        let left: i64 = transaction
            .query_one(format!("SELECT count(*) FROM {table}").as_str(), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(left, 0, "{table} outlived the client that exposed it");
    }
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_surface_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user_and_client().await;
    plant_server(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO resources \
                 (tenant, realm_id, resource_id, server_id, name, resource_type, resource_owner) \
             VALUES ('acme', 'main', 'doc', 'app', 'document', 'urn:doc', 'ada')",
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
    for table in ["resource_servers", "resources"] {
        let seen: i64 = transaction
            .query_one(format!("SELECT count(*) FROM {table}").as_str(), &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(seen, 0, "another realm read {table}");
    }
}
