//! What a request establishes about its caller, against a real schema.
//!
//! Every one of these arranges exactly one thing to be wrong, because the whole
//! point of the type is that a caller the realm no longer stands behind is a
//! refusal here rather than an absence something downstream has to interpret.

mod support;

use chrono::{Duration, Utc};
use models::auditable::AuditableModel;
use models::entities::organization::{OrgMembershipType, OrganizationMemberModel};
use models::entities::user::UserCreateModel;
use services::context::{Acting, NotEstablished, Principal, establish};
use services::token::Verified;
use store::providers::{organizations, users};
use store::tenancy::TenantContext;
use support::Fixture;

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

/// A token that carried nothing but a subject. Each test edits the one claim it
/// is about, so nothing else can be the reason it passed or failed.
fn presented(subject: &str) -> Verified {
    Verified {
        subject: subject.to_owned(),
        audiences: vec!["saffui-admin".to_owned()],
        scope: "openid admin".to_owned(),
        token_id: None,
        claims: serde_json::Map::new(),
    }
}

fn org(id: &str) -> models::entities::organization::OrganizationModel {
    models::entities::organization::OrganizationModel {
        org_id: id.to_owned(),
        realm_id: "main".to_owned(),
        name: id.to_owned(),
        display_name: id.to_owned(),
        description: String::new(),
        enabled: true,
        domains: Vec::new(),
        redirect_url: None,
        attributes: None,
        metadata: AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    }
}

fn member(org_id: &str, user_id: &str) -> OrganizationMemberModel {
    OrganizationMemberModel {
        realm_id: "main".to_owned(),
        org_id: org_id.to_owned(),
        user_id: user_id.to_owned(),
        membership_type: OrgMembershipType::Managed,
        roles: Vec::new(),
        joined_at: None,
        metadata: AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    }
}

/// The ordinary case, asserted first so every refusal below is the arranged one
/// rather than the fixture failing for its own reasons.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_the_realm_holds_is_established() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let context = establish(&transaction, tenant(), &presented("ada"), Utc::now())
        .await
        .expect("a caller this realm holds");

    assert_eq!(context.principal.id(), "ada");
    assert_eq!(context.principal.kind(), "user");
    assert_eq!(
        context.acting,
        Acting::RealmWide,
        "a caller naming no organization was confined to one"
    );
    assert_eq!(context.presenter, None);
    assert_eq!(context.tenant.realm_id, "main");
}

/// A subject the realm does not hold and one it has switched off are different
/// refusals: one is a typo, the other is somebody having been offboarded.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_subject_the_realm_will_not_stand_behind_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    assert_eq!(
        establish(&transaction, tenant(), &presented("nobody"), Utc::now())
            .await
            .expect_err("a subject nothing holds"),
        NotEstablished::NoSuchSubject
    );

    let offboarded = UserCreateModel {
        user_name: "bob".into(),
        enabled: false,
        email: "bob@example.test".into(),
        email_verified: Some(true),
        phone_number: None,
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
    }
    .into_model(
        "bob".into(),
        "main".into(),
        AuditableModel::from_creator("acme".into(), "root".into()),
    );
    users::create(&transaction, &offboarded).await.unwrap();

    assert_eq!(
        establish(&transaction, tenant(), &presented("bob"), Utc::now())
            .await
            .expect_err("a disabled subject"),
        NotEstablished::Disabled,
        "an offboarded subject was established, and would have kept every role"
    );
}

/// The bulk lever: everything minted for a subject before a cut stops working,
/// however long after the cut it is presented.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_minted_before_the_cut_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let now = Utc::now();
    let cut = now.timestamp();
    let mut user = users::load(&transaction, "ada").await.unwrap().unwrap();
    user.not_before = Some(cut);
    user.metadata = AuditableModel::from_updater("acme".into(), "root".into());
    users::update(&transaction, &user).await.unwrap();

    let mut stale = presented("ada");
    stale
        .claims
        .insert("iat".into(), serde_json::json!(cut - 60));
    assert_eq!(
        establish(&transaction, tenant(), &stale, now)
            .await
            .expect_err("a token minted before the cut"),
        NotEstablished::Superseded
    );

    let mut fresh = presented("ada");
    fresh
        .claims
        .insert("iat".into(), serde_json::json!(cut + 60));
    assert!(
        establish(&transaction, tenant(), &fresh, now + Duration::days(30))
            .await
            .is_ok(),
        "a token minted after the cut was refused, so the cut is being read as an expiry"
    );
}

/// The claim names which organization, and the store says whether that is true.
/// Neither half is enough: without the claim a subject in two organizations is
/// ambiguous, and without the check the claim is a caller choosing its own
/// confinement.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_organization_is_claimed_and_then_confirmed() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    for id in ["north", "east"] {
        organizations::create(&transaction, &org(id)).await.unwrap();
    }
    organizations::add_member(&transaction, &member("north", "ada"))
        .await
        .unwrap();

    let mut inside = presented("ada");
    inside
        .claims
        .insert("org_id".into(), serde_json::json!("north"));
    let context = establish(&transaction, tenant(), &inside, Utc::now())
        .await
        .expect("a member of the organization it names");
    assert_eq!(
        context.acting,
        Acting::In {
            org_id: "north".to_owned()
        }
    );

    let mut elsewhere = presented("ada");
    elsewhere
        .claims
        .insert("org_id".into(), serde_json::json!("east"));
    assert_eq!(
        establish(&transaction, tenant(), &elsewhere, Utc::now())
            .await
            .expect_err("an organization the subject does not belong to"),
        NotEstablished::NotAMember,
        "a caller confined itself to an organization it is not in"
    );
}

/// A client acting for itself is a principal, and it belongs to no
/// organization, so claiming one is claiming something that cannot be true.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_client_acting_for_itself_belongs_to_no_organization() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let context = establish(&transaction, tenant(), &presented("app"), Utc::now())
        .await
        .expect("a client this realm holds");
    assert!(matches!(context.principal, Principal::Client(_)));
    assert_eq!(context.principal.kind(), "client");
    assert_eq!(context.acting, Acting::RealmWide);

    let mut claiming = presented("app");
    claiming
        .claims
        .insert("org_id".into(), serde_json::json!("north"));
    assert_eq!(
        establish(&transaction, tenant(), &claiming, Utc::now())
            .await
            .expect_err("a client claiming a membership"),
        NotEstablished::NotAMember
    );
}

/// The client that obtained the token travels with the context, so the plane
/// does not read it out of the token a second time.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_client_that_asked_for_the_token_is_carried() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let mut through = presented("ada");
    through
        .claims
        .insert("azp".into(), serde_json::json!("saffui-console"));

    let context = establish(&transaction, tenant(), &through, Utc::now())
        .await
        .unwrap();
    assert_eq!(context.presenter.as_deref(), Some("saffui-console"));
}
