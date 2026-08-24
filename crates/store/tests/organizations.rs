mod support;

use models::auditable::AuditableModel;
use models::entities::authz::RoleMutationModel;
use models::entities::organization::{
    OrgMembershipType, OrganizationMemberModel, OrganizationModel, OrganizationMutationModel,
};
use models::entities::realm::RealmCreateModel;
use store::providers::{organizations, realms, roles};
use store::tenancy::TenantContext;
use support::Fixture;

fn org(id: &str, realm: &str) -> OrganizationModel {
    OrganizationMutationModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        description: String::new(),
        enabled: true,
        redirect_url: Some("https://x.example".to_owned()),
        attributes: None,
    }
    .into_model(
        id.to_owned(),
        realm.to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    )
}

fn member(org_id: &str, user_id: &str, kind: OrgMembershipType) -> OrganizationMemberModel {
    OrganizationMemberModel {
        realm_id: "main".to_owned(),
        org_id: org_id.to_owned(),
        user_id: user_id.to_owned(),
        membership_type: kind,
        roles: Vec::new(),
        joined_at: None,
        metadata: AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    }
}

/// Plant a second realm of the same tenant, so a boundary test crosses a realm
/// that exists rather than one that does not.
async fn second_realm(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
        .await;
    let realm = RealmCreateModel {
        name: "other".into(),
        display_name: "Other".into(),
        enabled: true,
    }
    .into_model(
        "other".into(),
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    realms::create(&transaction, &realm).await.unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_organization_comes_back_as_it_was_written() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();

    let loaded = organizations::load(&transaction, "customer-x")
        .await
        .unwrap()
        .expect("the organization was not found where it was written");
    assert_eq!(loaded.name, "customer-x");
    assert_eq!(loaded.redirect_url.as_deref(), Some("https://x.example"));
    assert!(loaded.enabled);
    assert_eq!(loaded.metadata.tenant, "acme");
    assert!(
        loaded.domains.is_empty(),
        "a plain load answered with domains it was not asked for"
    );
}

/// A claim is someone saying they own a mail domain. Routing on that alone
/// would hand the domain's users to whoever asked first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_claim_does_not_route_until_it_is_proven() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    organizations::claim_domain(&transaction, "customer-x", "x.example", "challenge-token")
        .await
        .unwrap();

    assert!(
        organizations::by_domain(&transaction, "x.example")
            .await
            .unwrap()
            .is_none(),
        "an unproven claim routed a login"
    );
    let claimed = organizations::domains(&transaction, "customer-x")
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].name, "x.example");
    assert!(!claimed[0].verified);

    assert_eq!(
        organizations::pending_challenge(&transaction, "x.example")
            .await
            .unwrap()
            .as_deref(),
        Some("challenge-token"),
        "a pending claim lost the challenge it waits on"
    );

    assert!(
        organizations::verify_domain(&transaction, "x.example")
            .await
            .unwrap()
    );
    assert!(
        organizations::pending_challenge(&transaction, "x.example")
            .await
            .unwrap()
            .is_none(),
        "the challenge outlived the proof it was for"
    );
    assert_eq!(
        organizations::by_domain(&transaction, "x.example")
            .await
            .unwrap()
            .expect("a proven claim did not route")
            .org_id,
        "customer-x"
    );
    assert!(
        organizations::domains(&transaction, "customer-x")
            .await
            .unwrap()[0]
            .verified,
        "the claim reads as unproven after it was proven"
    );

    // Proving it again changes nothing, so a caller cannot move the time by
    // asking twice.
    assert!(
        !organizations::verify_domain(&transaction, "x.example")
            .await
            .unwrap()
    );
}

/// Discovery reads one row per domain, so two claims would make the answer
/// depend on which was found first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_domain_answers_for_one_organization() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    organizations::create(&transaction, &org("customer-y", "main"))
        .await
        .unwrap();
    organizations::claim_domain(
        &transaction,
        "customer-x",
        "shared.example",
        "challenge-token",
    )
    .await
    .unwrap();

    assert!(
        organizations::claim_domain(
            &transaction,
            "customer-y",
            "shared.example",
            "challenge-token"
        )
        .await
        .is_err(),
        "two organizations of one realm hold the same domain"
    );
}

/// The claim is scoped to the realm and no wider. A domain unique across the
/// deployment would have one tenant's claim refused by another's, which reports
/// a customer that tenant cannot otherwise see.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_same_domain_may_be_claimed_in_another_realm() {
    let fixture = Fixture::with_user().await;
    second_realm(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    organizations::claim_domain(
        &transaction,
        "customer-x",
        "shared.example",
        "challenge-token",
    )
    .await
    .unwrap();
    organizations::verify_domain(&transaction, "shared.example")
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    organizations::create(&transaction, &org("customer-z", "other"))
        .await
        .unwrap();
    organizations::claim_domain(
        &transaction,
        "customer-z",
        "shared.example",
        "challenge-token",
    )
    .await
    .expect("a realm was refused a domain another realm holds");
    organizations::verify_domain(&transaction, "shared.example")
        .await
        .unwrap();

    assert_eq!(
        organizations::by_domain(&transaction, "shared.example")
            .await
            .unwrap()
            .expect("the domain routed nowhere in this realm")
            .org_id,
        "customer-z",
        "the domain routed to the other realm's organization"
    );
}

/// A domain is matched against an address, and addresses arrive in whatever case
/// the sender typed. One casing is stored so one comparison answers.
///
/// In its own transaction: a refused write aborts the one it was made in, and
/// every later statement then fails for that reason instead of its own.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_domain_is_stored_in_one_casing() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    assert!(
        organizations::claim_domain(
            &transaction,
            "customer-x",
            "Mixed.Example",
            "challenge-token"
        )
        .await
        .is_err(),
        "a domain was stored in a casing no lookup will match"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_member_comes_back_with_the_roles_it_holds() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    for id in ["writer", "auditor"] {
        let role = RoleMutationModel {
            name: id.to_owned(),
            display_name: id.to_owned(),
            description: String::new(),
            client_id: None,
            admin_actions: None,
        }
        .into_model(
            id.to_owned(),
            "main".to_owned(),
            AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
        );
        roles::create(&transaction, &role).await.unwrap();
    }

    organizations::add_member(
        &transaction,
        &member("customer-x", "ada", OrgMembershipType::Managed),
    )
    .await
    .unwrap();
    organizations::grant_role(&transaction, "customer-x", "ada", "writer")
        .await
        .unwrap();
    organizations::grant_role(&transaction, "customer-x", "ada", "auditor")
        .await
        .unwrap();
    organizations::grant_role(&transaction, "customer-x", "ada", "writer")
        .await
        .expect("granting again is not an error");
    organizations::add_member(
        &transaction,
        &member("customer-x", "ada", OrgMembershipType::Managed),
    )
    .await
    .expect("adding an existing member again is not an error");

    let members = organizations::members(&transaction, "customer-x")
        .await
        .unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].user_id, "ada");
    assert_eq!(members[0].membership_type, OrgMembershipType::Managed);
    assert_eq!(
        members[0].roles,
        vec!["auditor".to_owned(), "writer".to_owned()],
        "the roles are the ones granted, ordered, and each once"
    );
    assert!(members[0].joined_at.is_some());
}

/// Belonging again is not belonging twice.
/// A role granted inside an organization is held there and nowhere else. The
/// realm wide read must not see it: counted there it would answer for every
/// other organization and for the realm itself, which is a grant nobody wrote.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_role_granted_in_an_organization_is_not_held_across_the_realm() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    for id in ["auditor", "everywhere"] {
        let role = RoleMutationModel {
            name: id.to_owned(),
            display_name: id.to_owned(),
            description: String::new(),
            client_id: None,
            admin_actions: None,
        }
        .into_model(
            id.to_owned(),
            "main".to_owned(),
            AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
        );
        roles::create(&transaction, &role).await.unwrap();
    }

    organizations::add_member(
        &transaction,
        &member("customer-x", "ada", OrgMembershipType::Managed),
    )
    .await
    .unwrap();
    organizations::grant_role(&transaction, "customer-x", "ada", "auditor")
        .await
        .unwrap();
    roles::grant_to_user(&transaction, "ada", "everywhere")
        .await
        .unwrap();

    let held: Vec<String> = roles::effective_roles(&transaction, "ada")
        .await
        .unwrap()
        .into_iter()
        .map(|role| role.role_id)
        .collect();
    assert_eq!(
        held,
        vec!["everywhere".to_owned()],
        "a role granted only inside an organization was held across the realm"
    );

    let inside: Vec<String> = organizations::roles_of_member(&transaction, "customer-x", "ada")
        .await
        .unwrap()
        .into_iter()
        .map(|role| role.role_id)
        .collect();
    assert_eq!(
        inside,
        vec!["auditor".to_owned()],
        "the grant written inside the organization was read by nothing"
    );

    assert!(
        organizations::roles_of_member(&transaction, "customer-x", "nobody")
            .await
            .unwrap()
            .is_empty()
    );
}

/// A subject's organizations are the reverse of a member listing, on the index
/// that exists for it. A subject in none comes back empty, which a decision
/// reads as a realm level caller rather than as an unknown one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_answers_with_the_organizations_it_belongs_to() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        organizations::of_member(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "a subject in no organization was not read as a realm level caller"
    );

    for org_id in ["north", "east"] {
        organizations::create(&transaction, &org(org_id, "main"))
            .await
            .unwrap();
        organizations::add_member(
            &transaction,
            &member(org_id, "ada", OrgMembershipType::Managed),
        )
        .await
        .unwrap();
    }

    assert_eq!(
        organizations::of_member(&transaction, "ada").await.unwrap(),
        vec!["east".to_owned(), "north".to_owned()],
        "the organizations are the ones joined, ordered by identifier"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_second_add_corrects_how_a_member_belongs() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();

    // An import restores the day it started rather than stamping today.
    let restored = chrono::Utc::now() - chrono::Duration::days(400);
    let mut first = member("customer-x", "ada", OrgMembershipType::Managed);
    first.joined_at = Some(restored);
    organizations::add_member(&transaction, &first)
        .await
        .unwrap();

    organizations::add_member(
        &transaction,
        &member("customer-x", "ada", OrgMembershipType::Unmanaged),
    )
    .await
    .unwrap();

    let members = organizations::members(&transaction, "customer-x")
        .await
        .unwrap();
    assert_eq!(members.len(), 1, "the second add made a second membership");
    assert_eq!(
        members[0].membership_type,
        OrgMembershipType::Unmanaged,
        "the way they belong was not corrected"
    );
    assert_eq!(
        members[0].joined_at.map(|at| at.timestamp()),
        Some(restored.timestamp()),
        "the day it started was replaced by the day it was corrected"
    );
}

/// The two states of a claim are exclusive, and the schema is what says so.
///
/// Written as raw statements because the provider cannot express either wrong
/// state, and a constraint nothing can reach is a constraint nobody checks.
/// Each attempt gets its own transaction: a refused write aborts the one it was
/// made in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_claim_is_pending_or_proven_and_never_both() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    for (challenge, verified_at, what) in [
        (
            None,
            None,
            "a claim that is neither pending nor proven was recorded",
        ),
        (
            Some("token"),
            Some("now()"),
            "a claim was recorded as pending and proven at once",
        ),
    ] {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let statement = format!(
            "INSERT INTO organization_domains \
                 (tenant, realm_id, org_id, domain, challenge, verified_at) \
             VALUES ('acme', 'main', 'customer-x', 'both.example', {}, {})",
            challenge.map_or("NULL".to_owned(), |c| format!("'{c}'")),
            verified_at.unwrap_or("NULL"),
        );
        let refused = transaction.execute(statement.as_str(), &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn removing_an_organization_takes_what_hung_from_it() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    organizations::claim_domain(&transaction, "customer-x", "x.example", "challenge-token")
        .await
        .unwrap();
    organizations::add_member(
        &transaction,
        &member("customer-x", "ada", OrgMembershipType::Unmanaged),
    )
    .await
    .unwrap();

    assert!(
        organizations::delete(&transaction, "customer-x")
            .await
            .unwrap()
    );
    assert!(
        organizations::domains(&transaction, "customer-x")
            .await
            .unwrap()
            .is_empty(),
        "a domain outlived the organization that claimed it"
    );
    assert!(
        organizations::members(&transaction, "customer-x")
            .await
            .unwrap()
            .is_empty(),
        "a membership outlived its organization"
    );
    assert!(
        !organizations::delete(&transaction, "customer-x")
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_organization_is_not_visible_from_another_realm() {
    let fixture = Fixture::with_user().await;
    second_realm(&fixture).await;

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    organizations::create(&transaction, &org("customer-x", "main"))
        .await
        .unwrap();
    organizations::claim_domain(&transaction, "customer-x", "x.example", "challenge-token")
        .await
        .unwrap();
    organizations::verify_domain(&transaction, "x.example")
        .await
        .unwrap();
    organizations::add_member(
        &transaction,
        &member("customer-x", "ada", OrgMembershipType::Managed),
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        organizations::load(&transaction, "customer-x")
            .await
            .unwrap()
            .is_none(),
        "another realm of the same tenant read the organization"
    );
    assert!(
        organizations::by_domain(&transaction, "x.example")
            .await
            .unwrap()
            .is_none(),
        "another realm routed on a domain it does not hold"
    );
    assert!(
        organizations::domains(&transaction, "customer-x")
            .await
            .unwrap()
            .is_empty(),
        "another realm read the claims"
    );
    assert!(
        organizations::members(&transaction, "customer-x")
            .await
            .unwrap()
            .is_empty(),
        "another realm read who belongs"
    );
}
