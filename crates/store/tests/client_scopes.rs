mod support;

use models::auditable::AuditableModel;
use models::entities::authz::RoleMutationModel;
use models::entities::client::{
    ClientScopeModel, ClientScopeMutationModel, Protocol, ProtocolMapperModel,
    ProtocolMapperMutationModel,
};
use store::providers::{client_scopes, roles};
use store::tenancy::TenantContext;
use support::Fixture;

fn metadata() -> AuditableModel {
    AuditableModel::from_creator("acme".to_owned(), "root".to_owned())
}

fn scope(id: &str, name: &str, default_scope: bool) -> ClientScopeModel {
    ClientScopeMutationModel {
        name: name.to_owned(),
        description: String::new(),
        protocol: Protocol::OpenId,
        default_scope: Some(default_scope),
        configs: None,
    }
    .into_model(id.to_owned(), "main".to_owned(), metadata())
}

fn mapper(id: &str, name: &str) -> ProtocolMapperModel {
    ProtocolMapperMutationModel {
        name: name.to_owned(),
        protocol: Protocol::OpenId,
        mapper_type: "oidc-usermodel-property-mapper".to_owned(),
        configs: None,
    }
    .into_model(id.to_owned(), "main".to_owned(), metadata())
}

fn role(id: &str, client_id: Option<&str>) -> models::entities::authz::RoleModel {
    RoleMutationModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        description: String::new(),
        client_id: client_id.map(str::to_owned),
        admin_actions: None,
    }
    .into_model(id.to_owned(), "main".to_owned(), metadata())
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_holds_the_scopes_it_was_given() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    client_scopes::create_scope(&transaction, &scope("scope-1", "profile", true))
        .await
        .unwrap();
    client_scopes::create_scope(&transaction, &scope("scope-2", "address", false))
        .await
        .unwrap();

    client_scopes::attach_scope(&transaction, "app", "scope-1", false)
        .await
        .unwrap();
    client_scopes::attach_scope(&transaction, "app", "scope-2", true)
        .await
        .unwrap();
    // Attaching again corrects how it is held rather than adding a second row.
    client_scopes::attach_scope(&transaction, "app", "scope-2", false)
        .await
        .unwrap();

    let held = client_scopes::scopes_of_client(&transaction, "app")
        .await
        .unwrap();
    assert_eq!(
        held.iter()
            .map(|(s, _)| s.name.as_str())
            .collect::<Vec<_>>(),
        vec!["address", "profile"],
        "the scopes are ordered by name"
    );
    assert!(
        held.iter().all(|(_, optional)| !optional),
        "the second attachment did not correct how the scope is held"
    );

    assert!(
        client_scopes::detach_scope(&transaction, "app", "scope-2")
            .await
            .unwrap()
    );
    assert!(
        !client_scopes::detach_scope(&transaction, "app", "scope-2")
            .await
            .unwrap()
    );
    assert_eq!(
        client_scopes::scopes_of_client(&transaction, "app")
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The write half the plane leans on: listing, finding by the name a request
/// would spell, rewriting, and removal that answers whether anything was there.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_is_rewritten_and_removed_over_the_store() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    client_scopes::create_scope(&transaction, &scope("scope-1", "profile", true))
        .await
        .unwrap();
    client_scopes::create_scope(&transaction, &scope("scope-2", "address", false))
        .await
        .unwrap();

    let listed = client_scopes::list_scopes(&transaction).await.unwrap();
    assert_eq!(
        listed.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        vec!["address", "profile"]
    );

    // The name means something within its protocol, and nothing outside it.
    assert!(
        client_scopes::load_scope_by_name(&transaction, Protocol::OpenId, "profile")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        client_scopes::load_scope_by_name(&transaction, Protocol::Docker, "profile")
            .await
            .unwrap()
            .is_none()
    );

    let mut rewritten = scope("scope-1", "person", false);
    rewritten.description = "what a person shows".to_owned();
    assert!(
        client_scopes::update_scope(&transaction, &rewritten)
            .await
            .unwrap()
    );
    let read_back = client_scopes::load_scope(&transaction, "scope-1")
        .await
        .unwrap()
        .expect("the rewritten scope");
    assert_eq!(read_back.name, "person");
    assert_eq!(read_back.default_scope, Some(false));
    assert!(read_back.metadata.version > 1, "the rewrite left no trace");

    let ghost = scope("scope-9", "nothing", false);
    assert!(
        !client_scopes::update_scope(&transaction, &ghost)
            .await
            .unwrap()
    );

    // Held by a client, the scope reads as attached; released, it does not.
    client_scopes::attach_scope(&transaction, "app", "scope-1", false)
        .await
        .unwrap();
    assert!(
        client_scopes::scope_still_attached(&transaction, "scope-1")
            .await
            .unwrap()
    );
    client_scopes::detach_scope(&transaction, "app", "scope-1")
        .await
        .unwrap();
    assert!(
        !client_scopes::scope_still_attached(&transaction, "scope-1")
            .await
            .unwrap()
    );

    assert!(
        client_scopes::delete_scope(&transaction, "scope-1")
            .await
            .unwrap()
    );
    assert!(
        client_scopes::load_scope(&transaction, "scope-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !client_scopes::delete_scope(&transaction, "scope-1")
            .await
            .unwrap()
    );
}

/// A mapper reached twice is one rule.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_mapper_reached_by_two_routes_is_one_rule() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    for (id, name) in [("mapper-1", "zulu"), ("mapper-2", "alpha")] {
        client_scopes::create_mapper(&transaction, &mapper(id, name))
            .await
            .unwrap();
    }
    for (id, name) in [("scope-1", "profile"), ("scope-2", "email")] {
        client_scopes::create_scope(&transaction, &scope(id, name, false))
            .await
            .unwrap();
    }

    // Attached to the client directly, and reached through two scopes it holds.
    client_scopes::attach_mapper_to_client(&transaction, "app", "mapper-1")
        .await
        .unwrap();
    client_scopes::attach_mapper_to_scope(&transaction, "scope-1", "mapper-1")
        .await
        .unwrap();
    client_scopes::attach_mapper_to_scope(&transaction, "scope-2", "mapper-1")
        .await
        .unwrap();
    client_scopes::attach_mapper_to_scope(&transaction, "scope-2", "mapper-2")
        .await
        .unwrap();
    for scope_id in ["scope-1", "scope-2"] {
        client_scopes::attach_scope(&transaction, "app", scope_id, false)
            .await
            .unwrap();
    }

    let applying: Vec<String> = client_scopes::mappers_for_client(&transaction, "app")
        .await
        .unwrap()
        .into_iter()
        .map(|m| m.name)
        .collect();
    assert_eq!(
        applying,
        vec!["alpha".to_owned(), "zulu".to_owned()],
        "a mapper reached three ways appeared more than once, or the order is not stated"
    );
}

/// Two clients may each define a role of the same name, and the rows say which
/// client owns which.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn two_clients_may_each_own_a_role_of_the_same_name() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // A second client to own the homonymous role.
    transaction
        .execute(
            "INSERT INTO clients (tenant, realm_id, client_id, name, display_name) \
             VALUES ('acme', 'main', 'mobile', 'mobile', 'Mobile')",
            &[],
        )
        .await
        .unwrap();

    let mut app_admin = role("app-admin", Some("app"));
    app_admin.name = "admin".to_owned();
    let mut mobile_admin = role("mobile-admin", Some("mobile"));
    mobile_admin.name = "admin".to_owned();

    roles::create(&transaction, &app_admin).await.unwrap();
    roles::create(&transaction, &mobile_admin)
        .await
        .expect("a second client could not own a role of the same name");

    let realm_admin = role("realm-admin", None);
    roles::create(&transaction, &realm_admin).await.unwrap();

    let owner: Option<String> = transaction
        .query_one(
            "SELECT client_id FROM roles WHERE role_id = 'app-admin'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(owner.as_deref(), Some("app"));

    let loaded = roles::load(&transaction, "realm-admin")
        .await
        .unwrap()
        .unwrap();
    assert!(!loaded.is_client_role());
    assert_eq!(loaded.client_id, None);
}

/// The realm keeps one role of a given name for itself.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realm_keeps_one_role_of_each_name() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let mut first = role("first", None);
    first.name = "auditor".to_owned();
    let mut second = role("second", None);
    second.name = "auditor".to_owned();

    roles::create(&transaction, &first).await.unwrap();
    assert!(
        roles::create(&transaction, &second).await.is_err(),
        "the realm took two roles of one name"
    );
}

/// A scope grants roles, and they come back in a stated order.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_grants_the_roles_attached_to_it() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    client_scopes::create_scope(&transaction, &scope("scope-1", "profile", false))
        .await
        .unwrap();
    for id in ["zulu", "alpha"] {
        roles::create(&transaction, &role(id, None)).await.unwrap();
        client_scopes::attach_role_to_scope(&transaction, "scope-1", id)
            .await
            .unwrap();
    }
    // Attaching again attaches once.
    client_scopes::attach_role_to_scope(&transaction, "scope-1", "zulu")
        .await
        .unwrap();

    assert_eq!(
        client_scopes::roles_of_scope(&transaction, "scope-1")
            .await
            .unwrap(),
        vec!["alpha".to_owned(), "zulu".to_owned()]
    );
}

/// A new client is given the scopes the realm marks as default, and only those.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_default_scopes_are_offered_to_a_new_client() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    client_scopes::create_scope(&transaction, &scope("scope-1", "profile", true))
        .await
        .unwrap();
    client_scopes::create_scope(&transaction, &scope("scope-2", "address", false))
        .await
        .unwrap();
    client_scopes::create_scope(&transaction, &scope("scope-3", "email", true))
        .await
        .unwrap();

    let offered: Vec<String> = client_scopes::default_scopes(&transaction, Protocol::OpenId)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(offered, vec!["email".to_owned(), "profile".to_owned()]);
}

/// One scope answers to a name within a protocol.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_scope_answers_to_a_name() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    client_scopes::create_scope(&transaction, &scope("scope-1", "profile", false))
        .await
        .unwrap();
    assert!(
        client_scopes::create_scope(&transaction, &scope("scope-2", "profile", false))
            .await
            .is_err(),
        "two scopes answer to one name in one protocol"
    );
}

/// A role that claims a client must name one that exists, and a role that names
/// none must not claim to belong to a client.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_flag_and_the_owner_cannot_disagree() {
    let fixture = Fixture::with_user_and_client().await;

    let cases = [
        (
            "INSERT INTO roles (tenant, realm_id, role_id, name, display_name, \
                                is_client_role, client_id) \
             VALUES ('acme', 'main', 'bad-1', 'bad-1', 'bad', true, NULL)",
            "a role claimed a client owns it and named none",
        ),
        (
            "INSERT INTO roles (tenant, realm_id, role_id, name, display_name, \
                                is_client_role, client_id) \
             VALUES ('acme', 'main', 'bad-2', 'bad-2', 'bad', false, 'app')",
            "a role named its owner and claimed the realm owns it",
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

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    client_scopes::create_scope(&transaction, &scope("scope-1", "profile", true))
        .await
        .unwrap();
    client_scopes::attach_scope(&transaction, "app", "scope-1", false)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        client_scopes::load_scope(&transaction, "scope-1")
            .await
            .unwrap()
            .is_none(),
        "another realm read the scope"
    );
    assert!(
        client_scopes::default_scopes(&transaction, Protocol::OpenId)
            .await
            .unwrap()
            .is_empty(),
        "another realm was offered the scope"
    );
    assert!(
        client_scopes::scopes_of_client(&transaction, "app")
            .await
            .unwrap()
            .is_empty(),
        "another realm read the attachment"
    );
    // Read directly, because the join above is filtered by the scope's own
    // policy and would come back empty whatever the attachment's policy said.
    let attachments: i64 = transaction
        .query_one("SELECT count(*) FROM clients_client_scopes", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        attachments, 0,
        "another realm read the attachments themselves"
    );
}
