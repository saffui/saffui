mod support;

use models::auditable::AuditableModel;
use models::entities::authz::{AdminAction, GroupModel, GroupMutationModel, RoleMutationModel};
use store::providers::roles;
use store::tenancy::TenantContext;
use support::Fixture;

fn role(id: &str, permissions: Option<Vec<AdminAction>>) -> models::entities::authz::RoleModel {
    named(id, id, permissions)
}

fn named(
    id: &str,
    name: &str,
    permissions: Option<Vec<AdminAction>>,
) -> models::entities::authz::RoleModel {
    RoleMutationModel {
        name: name.to_owned(),
        description: String::new(),
        display_name: id.to_owned(),
        client_id: None,
        admin_actions: permissions,
    }
    .into_model(
        id.to_owned(),
        "main".to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    )
}

fn group(id: &str, is_default: bool) -> GroupModel {
    GroupMutationModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        description: String::new(),
        is_default,
        parent_id: None,
    }
    .into_model(
        id.to_owned(),
        "main".to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    )
}

/// A role's grant survives the round trip as the capabilities it names, and a
/// capability nobody declared does not come back at all.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_grant_comes_back_as_the_capabilities_it_names() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    roles::create(
        &transaction,
        &role(
            "auditor",
            Some(vec![AdminAction::ConsentRead, AdminAction::UserRead]),
        ),
    )
    .await
    .unwrap();

    let loaded = roles::load(&transaction, "auditor").await.unwrap().unwrap();
    assert_eq!(
        loaded.admin_actions,
        Some(vec![AdminAction::ConsentRead, AdminAction::UserRead])
    );
    assert!(!loaded.is_client_role());
    assert_eq!(
        loaded.client_id, None,
        "a realm role named a client that owns it"
    );
    assert_eq!(loaded.metadata.tenant, "acme");

    // A capability nobody declared, planted directly, does not decode onto a
    // role: the catalogue lives in the build, so this is where it is enforced.
    transaction
        .execute(
            "UPDATE roles SET admin_actions = '[\"realm:*\"]'::jsonb WHERE role_id = $1",
            &[&"auditor"],
        )
        .await
        .unwrap();
    let smuggled = roles::load(&transaction, "auditor").await.unwrap().unwrap();
    assert_eq!(
        smuggled.admin_actions, None,
        "a capability the plane never declared reached a role"
    );
    transaction.commit().await.unwrap();
}

/// A role held directly and a role held through a group are one answer, and a
/// role held both ways appears once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_role_a_user_holds_is_one_answer() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // Identifiers ascend, names do not: ordering by one is visibly not the other.
    for (id, name) in [("role-1", "zulu"), ("role-2", "alpha"), ("role-3", "mike")] {
        roles::create(&transaction, &named(id, name, None))
            .await
            .unwrap();
    }
    roles::create_group(&transaction, &group("engineering", false))
        .await
        .unwrap();

    roles::grant_to_user(&transaction, "ada", "role-1")
        .await
        .unwrap();
    roles::grant_to_user(&transaction, "ada", "role-3")
        .await
        .unwrap();
    roles::grant_to_group(&transaction, "engineering", "role-2")
        .await
        .unwrap();
    roles::grant_to_group(&transaction, "engineering", "role-3")
        .await
        .unwrap();
    roles::add_to_group(&transaction, "ada", "engineering")
        .await
        .unwrap();

    let held = roles::effective_roles(&transaction, "ada").await.unwrap();
    let names: Vec<&str> = held.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["alpha", "mike", "zulu"],
        "ordered by name, which is neither the write order nor the identifier order"
    );

    // And the join carries one row per grant, so a role held both ways is one
    // grant of each kind rather than two of one.
    let direct: i64 = transaction
        .query_one(
            "SELECT count(*) FROM users_roles WHERE user_id = $1 AND role_id = $2",
            &[&"ada", &"role-3"],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(direct, 1);
    transaction.commit().await.unwrap();
}

/// Granting twice is not a second grant. A caller reconciling a set would
/// otherwise have to decide what it already did from an error message.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn granting_twice_grants_once() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    roles::create(&transaction, &role("reader", None))
        .await
        .unwrap();
    roles::grant_to_user(&transaction, "ada", "reader")
        .await
        .unwrap();
    roles::grant_to_user(&transaction, "ada", "reader")
        .await
        .expect("granting again is not an error");

    assert_eq!(
        roles::effective_roles(&transaction, "ada")
            .await
            .unwrap()
            .len(),
        1
    );

    // One row in the join, not two rows collapsed into one answer.
    let recorded: i64 = transaction
        .query_one(
            "SELECT count(*) FROM users_roles WHERE user_id = $1",
            &[&"ada"],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recorded, 1, "the second grant was recorded as another row");

    assert!(
        roles::revoke_from_user(&transaction, "ada", "reader")
            .await
            .unwrap()
    );
    assert!(
        !roles::revoke_from_user(&transaction, "ada", "reader")
            .await
            .unwrap(),
        "revoking what is not held reports that nothing changed"
    );
    assert!(
        roles::effective_roles(&transaction, "ada")
            .await
            .unwrap()
            .is_empty()
    );
    transaction.commit().await.unwrap();
}

/// Removing a role takes every grant of it with it. Left behind, a grant names a
/// role nothing can resolve, and whoever reads it decides what that means.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn removing_a_role_takes_its_grants() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    roles::create(&transaction, &role("temporary", None))
        .await
        .unwrap();
    roles::create_group(&transaction, &group("engineering", false))
        .await
        .unwrap();
    roles::grant_to_user(&transaction, "ada", "temporary")
        .await
        .unwrap();
    roles::grant_to_group(&transaction, "engineering", "temporary")
        .await
        .unwrap();
    roles::add_to_group(&transaction, "ada", "engineering")
        .await
        .unwrap();

    assert_eq!(
        roles::effective_roles(&transaction, "ada")
            .await
            .unwrap()
            .len(),
        1
    );

    // One row in the join, not two rows collapsed into one answer.
    let recorded: i64 = transaction
        .query_one(
            "SELECT count(*) FROM users_roles WHERE user_id = $1",
            &[&"ada"],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(recorded, 1, "the second grant was recorded as another row");
    assert!(roles::delete(&transaction, "temporary").await.unwrap());
    assert!(
        roles::effective_roles(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "a grant outlived the role it named"
    );
    transaction.commit().await.unwrap();
}

/// A subject's groups come back by identifier, direct membership only, ordered.
/// A group policy reads exactly this, so a subject in none answers empty rather
/// than unknown.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_answers_with_the_groups_it_belongs_to() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        roles::groups_of(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "a subject in no group was not read as one that belongs to none"
    );

    for id in ["staff", "board"] {
        roles::create_group(&transaction, &group(id, false))
            .await
            .unwrap();
        roles::add_to_group(&transaction, "ada", id).await.unwrap();
    }
    roles::add_to_group(&transaction, "ada", "staff")
        .await
        .expect("joining a group again is not an error");

    assert_eq!(
        roles::groups_of(&transaction, "ada").await.unwrap(),
        vec!["board".to_owned(), "staff".to_owned()],
        "the groups are the ones joined, ordered by identifier, each once"
    );
}

/// The groups a new user joins without anyone adding them are the ones that say
/// so, and nothing else.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_default_groups_are_joined_by_default() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    roles::create_group(&transaction, &group("everyone", true))
        .await
        .unwrap();
    roles::create_group(&transaction, &group("engineering", false))
        .await
        .unwrap();
    roles::create_group(&transaction, &group("all-staff", true))
        .await
        .unwrap();

    let defaults = roles::default_groups(&transaction).await.unwrap();
    let names: Vec<&str> = defaults.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["all-staff", "everyone"]);
    assert!(defaults.iter().all(|g| g.is_default));

    assert!(
        !roles::load_group(&transaction, "engineering")
            .await
            .unwrap()
            .expect("it exists")
            .is_default
    );
    transaction.commit().await.unwrap();
}

/// A grant cannot name a role in another realm, and the join carries the keys
/// that stop it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_grant_cannot_reach_another_realm() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    roles::create(&transaction, &role("reader", None))
        .await
        .unwrap();
    roles::grant_to_user(&transaction, "ada", "reader")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    // A role identifier is not a way past the rules.
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(roles::load(&transaction, "reader").await.unwrap().is_none());
    assert!(
        roles::effective_roles(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "another realm read a user's grants"
    );
    assert!(
        roles::grant_to_user(&transaction, "ada", "reader")
            .await
            .is_err(),
        "a grant was written into a realm that holds neither side of it"
    );
}
