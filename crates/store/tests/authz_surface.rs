mod support;

use models::auditable::AuditableModel;
use models::entities::authz::{
    DecisionStrategy, PolicyEnforcementMode, ResourceModel, ResourceMutationModel,
    ResourceServerModel, ResourceServerMutationModel, ScopeModel, ScopeMutationModel,
};
use store::providers::authz_surface;
use store::tenancy::TenantContext;
use support::Fixture;

fn meta() -> AuditableModel {
    AuditableModel::from_creator("acme".to_owned(), "root".to_owned())
}

fn server(id: &str) -> ResourceServerModel {
    ResourceServerMutationModel {
        enforcement_mode: PolicyEnforcementMode::Enforcing,
        decision_strategy: DecisionStrategy::Unanimous,
        remote_resource_management: false,
        user_managed_access: false,
    }
    .into_model(id.to_owned(), "main".to_owned(), meta())
}

fn resource(id: &str, kind: &str) -> ResourceModel {
    ResourceMutationModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        description: String::new(),
        resource_uris: vec![format!("/{id}")],
        resource_type: kind.to_owned(),
        resource_owner: "app".to_owned(),
        user_managed_access: false,
        configs: None,
    }
    .into_model(id.to_owned(), "app".to_owned(), "main".to_owned(), meta())
}

fn scope(id: &str) -> ScopeModel {
    ScopeMutationModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        description: String::new(),
    }
    .into_model(id.to_owned(), "app".to_owned(), "main".to_owned(), meta())
}

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

/// A resource that declares nothing and a resource whose verbs were not read
/// are different answers, and the provider only ever gives the first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_resource_answers_with_the_verbs_it_declares() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    authz_surface::create_server(&transaction, &server("app"))
        .await
        .unwrap();
    authz_surface::create_scope(&transaction, &scope("read"))
        .await
        .unwrap();
    authz_surface::create_scope(&transaction, &scope("write"))
        .await
        .unwrap();
    authz_surface::create_resource(&transaction, &resource("doc", "urn:doc"))
        .await
        .unwrap();

    let bare = authz_surface::load_resource(&transaction, "doc")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        bare.scopes.as_deref(),
        Some(&[][..]),
        "a resource declaring nothing came back as one whose verbs were not read"
    );

    // Declared out of order, so the order they come back in is the read's and
    // not the order they were written in.
    authz_surface::declare_scope(&transaction, "app", "doc", "write")
        .await
        .unwrap();
    authz_surface::declare_scope(&transaction, "app", "doc", "read")
        .await
        .unwrap();
    authz_surface::declare_scope(&transaction, "app", "doc", "read")
        .await
        .unwrap();

    let loaded = authz_surface::load_resource(&transaction, "doc")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        loaded.scopes.as_deref(),
        Some(&["read".to_owned(), "write".to_owned()][..]),
        "declaring a verb twice declared it twice"
    );

    assert!(
        authz_surface::undeclare_scope(&transaction, "doc", "write")
            .await
            .unwrap()
    );
    assert!(
        !authz_surface::undeclare_scope(&transaction, "doc", "write")
            .await
            .unwrap(),
        "a verb was taken back off a resource that no longer declared it"
    );
}

/// What a permission naming a type applies to, read as one answer rather than
/// filtered by the caller.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_surface_answers_by_type() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    authz_surface::create_server(&transaction, &server("app"))
        .await
        .unwrap();
    authz_surface::create_scope(&transaction, &scope("read"))
        .await
        .unwrap();
    for (id, kind) in [
        ("memo", "urn:doc"),
        ("note", "urn:note"),
        ("doc", "urn:doc"),
    ] {
        authz_surface::create_resource(&transaction, &resource(id, kind))
            .await
            .unwrap();
    }
    authz_surface::declare_scope(&transaction, "app", "memo", "read")
        .await
        .unwrap();

    let documents = authz_surface::resources_of_type(&transaction, "app", "urn:doc")
        .await
        .unwrap();
    let named: Vec<&str> = documents
        .iter()
        .map(|resource| resource.resource_id.as_str())
        .collect();
    assert_eq!(named, vec!["doc", "memo"]);

    // Every one of them carries its own verbs, so a listing is not a shape a
    // caller has to go back and fill in one resource at a time.
    assert_eq!(documents[0].scopes.as_deref(), Some(&[][..]));
    assert_eq!(
        documents[1].scopes.as_deref(),
        Some(&["read".to_owned()][..])
    );

    assert_eq!(
        authz_surface::resources_of_server(&transaction, "app")
            .await
            .unwrap()
            .len(),
        3
    );
    assert!(
        authz_surface::resources_of_type(&transaction, "app", "urn:nothing")
            .await
            .unwrap()
            .is_empty(),
        "a type nothing answers to came back with resources"
    );
}

/// Rolling a policy out permissively changes what the server does with an
/// answer, not what it protects.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn changing_the_mode_leaves_the_surface_alone() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    authz_surface::create_server(&transaction, &server("app"))
        .await
        .unwrap();
    authz_surface::create_scope(&transaction, &scope("read"))
        .await
        .unwrap();
    authz_surface::create_resource(&transaction, &resource("doc", "urn:doc"))
        .await
        .unwrap();
    authz_surface::declare_scope(&transaction, "app", "doc", "read")
        .await
        .unwrap();

    let rolled_out = ResourceServerModel {
        enforcement_mode: PolicyEnforcementMode::Permissive,
        decision_strategy: DecisionStrategy::Affirmative,
        metadata: AuditableModel::from_updater("acme".to_owned(), "ada".to_owned()),
        ..server("app")
    };
    assert!(
        authz_surface::set_server_mode(&transaction, &rolled_out)
            .await
            .unwrap()
    );

    let loaded = authz_surface::load_server(&transaction, "app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.enforcement_mode, PolicyEnforcementMode::Permissive);
    assert_eq!(loaded.decision_strategy, DecisionStrategy::Affirmative);
    assert_eq!(loaded.metadata.version, 2);
    assert_eq!(loaded.metadata.updated_by.as_deref(), Some("ada"));
    assert_eq!(
        loaded.metadata.created_by.as_deref(),
        Some("root"),
        "an update overwrote who created the row"
    );

    assert_eq!(
        authz_surface::load_resource(&transaction, "doc")
            .await
            .unwrap()
            .unwrap()
            .scopes
            .as_deref(),
        Some(&["read".to_owned()][..])
    );
}

/// Taking a surface away stops an application being protected. It does not take
/// the application with it, which is a different act with a different reach.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn taking_the_surface_away_leaves_the_client() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    authz_surface::create_server(&transaction, &server("app"))
        .await
        .unwrap();
    authz_surface::create_scope(&transaction, &scope("read"))
        .await
        .unwrap();
    authz_surface::create_resource(&transaction, &resource("doc", "urn:doc"))
        .await
        .unwrap();
    authz_surface::declare_scope(&transaction, "app", "doc", "read")
        .await
        .unwrap();

    assert!(
        authz_surface::delete_server(&transaction, "app")
            .await
            .unwrap()
    );
    assert!(
        !authz_surface::delete_server(&transaction, "app")
            .await
            .unwrap()
    );

    assert!(
        authz_surface::load_resource(&transaction, "doc")
            .await
            .unwrap()
            .is_none(),
        "a resource outlived the surface it belonged to"
    );
    assert!(
        authz_surface::load_scope(&transaction, "read")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store::providers::clients::load(&transaction, "app")
            .await
            .unwrap()
            .is_some(),
        "removing a surface removed the client under it"
    );
}
