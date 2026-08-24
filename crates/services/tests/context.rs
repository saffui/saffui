mod support;

use chrono::{Duration, Utc};
use models::auditable::AuditableModel;
use models::entities::organization::{OrgMembershipType, OrganizationMemberModel};
use models::entities::user::UserCreateModel;
use models::sessions::records::{UserSessionModel, UserSessionState};
use services::context::{Acting, NotEstablished, establish};
use services::token::Verified;
use store::providers::{organizations, sessions, users};
use store::tenancy::TenantContext;
use support::Fixture;

fn tenant() -> TenantContext {
    TenantContext::new("acme", "main")
}

/// The login every token here was minted for.
const SESSION: &str = "session-1";

/// An access token bound to a login. Each test edits the one claim it is about,
/// so nothing else can be the reason it passed or failed.
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

/// A login, open, for the subject the tokens name.
fn login(session_id: &str, user_id: &str) -> UserSessionModel {
    UserSessionModel {
        browser_state: None,
        tenant: "acme".to_owned(),
        session_id: session_id.to_owned(),
        realm_id: "main".to_owned(),
        user_id: user_id.to_owned(),
        login_username: user_id.to_owned(),
        broker_session_id: None,
        broker_user_id: None,
        auth_method: None,
        ip_address: None,
        user_agent: None,
        started_at: Utc::now().timestamp(),
        auth_time: None,
        loa: None,
        expiration: None,
        state: UserSessionState::LoggedIn,
        remember_me: None,
        last_session_refresh: None,
        is_offline: None,
        notes: None,
    }
}

/// Plant the login the tokens are bound to.
async fn open_login(transaction: &deadpool_postgres::Transaction<'_>, user_id: &str) {
    sessions::open(transaction, &login(SESSION, user_id))
        .await
        .unwrap();
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
    open_login(&transaction, "ada").await;

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

    open_login(&transaction, "ada").await;

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

    open_login(&transaction, "ada").await;
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

/// Only an access token bound to a login gets in, and each of the three that
/// are not is turned away for being what it is rather than by failing some
/// later lookup. A refusal that happens by accident is one that disappears the
/// day the code downstream changes.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_an_access_token_bound_to_a_login_gets_in() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    open_login(&transaction, "ada").await;

    // A refresh token and an identity token are minted for other purposes and
    // would otherwise pass everything a bearer passes.
    for kind in ["Refresh", "ID"] {
        let mut other = presented("ada");
        other.claims.insert("typ".into(), serde_json::json!(kind));
        assert_eq!(
            establish(&transaction, tenant(), &other, Utc::now())
                .await
                .expect_err("a token minted for another purpose"),
            NotEstablished::NotAnAccessToken,
            "a {kind} token reached the plane"
        );
    }

    // A token minted for a machine carries no login, so there is nothing a
    // logout could ever close.
    let mut machine = presented("app");
    machine.claims.remove("sid");
    assert_eq!(
        establish(&transaction, tenant(), &machine, Utc::now())
            .await
            .expect_err("a token with no login behind it"),
        NotEstablished::NotAnAccessToken
    );
}

/// The lever the other three miss. An expiry cannot be brought forward, a
/// withdrawal names one token, and switching an account off ends every login it
/// has: this ends the one that was ended.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_whose_login_has_ended_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;
    open_login(&transaction, "ada").await;

    assert!(
        establish(&transaction, tenant(), &presented("ada"), Utc::now())
            .await
            .is_ok(),
        "the open login was refused, so what follows proves nothing"
    );

    // Three of the four states are not a login. The one that never confirmed is
    // neither usable nor provably ended, which is the case that must not read
    // as usable.
    for ended in [
        UserSessionState::LoggedOut,
        UserSessionState::LoggingOut,
        UserSessionState::LoggingOutUnconfirmed,
    ] {
        sessions::set_state(&transaction, SESSION, ended)
            .await
            .unwrap();
        assert_eq!(
            establish(&transaction, tenant(), &presented("ada"), Utc::now())
                .await
                .expect_err("a login that is not open"),
            NotEstablished::LoggedOut,
            "{ended:?} read as an open login"
        );
    }

    // And a login this realm never had.
    sessions::set_state(&transaction, SESSION, UserSessionState::LoggedIn)
        .await
        .unwrap();
    let mut elsewhere = presented("ada");
    elsewhere
        .claims
        .insert("sid".into(), serde_json::json!("never-opened"));
    assert_eq!(
        establish(&transaction, tenant(), &elsewhere, Utc::now())
            .await
            .expect_err("a login nothing opened"),
        NotEstablished::LoggedOut
    );
}

/// An identifier on its own is only a string. A live login belonging to
/// somebody else would be a way in for anyone who learned its identifier.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_belonging_to_somebody_else_is_not_a_way_in() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    let bob = UserCreateModel {
        user_name: "bob".into(),
        enabled: true,
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
    users::create(&transaction, &bob).await.unwrap();
    open_login(&transaction, "bob").await;

    assert_eq!(
        establish(&transaction, tenant(), &presented("ada"), Utc::now())
            .await
            .expect_err("ada presenting bob's login"),
        NotEstablished::LoggedOut,
        "one subject rode in on another's login"
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

    open_login(&transaction, "ada").await;

    let mut through = presented("ada");
    through
        .claims
        .insert("azp".into(), serde_json::json!("saffui-console"));

    let context = establish(&transaction, tenant(), &through, Utc::now())
        .await
        .unwrap();
    assert_eq!(context.presenter.as_deref(), Some("saffui-console"));
}

/// The cut has to survive the shape a real token carries. `set_issued_at` writes
/// `iat` as a fraction, `as_i64` reads a fraction as nothing, and the fallback
/// was the instant of the question, so every cut in the past passed. The test
/// above never caught it because it wrote the claim by hand, as an integer.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_cut_reads_the_instant_a_minted_token_actually_carries() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture.scoped(&mut connection, &tenant()).await;

    open_login(&transaction, "ada").await;

    let now = Utc::now();
    let cut = now.timestamp();
    let mut user = users::load(&transaction, "ada").await.unwrap().unwrap();
    user.not_before = Some(cut);
    user.metadata = AuditableModel::from_updater("acme".into(), "root".into());
    users::update(&transaction, &user).await.unwrap();

    let mut payload = crypto::jose::jwt::JwtPayload::new();
    payload.set_issued_at(
        &(std::time::UNIX_EPOCH + std::time::Duration::from_secs((cut - 60) as u64)),
    );
    let minted = payload.claim("iat").unwrap().clone();
    assert!(
        minted.as_i64().is_none(),
        "the claim a minted token carries is no longer a fraction, so this test \
         is asserting the wrong thing"
    );

    let mut stale = presented("ada");
    stale.claims.insert("iat".into(), minted);
    assert_eq!(
        establish(&transaction, tenant(), &stale, now)
            .await
            .expect_err("a token minted before the cut, as a real one states it"),
        NotEstablished::Superseded
    );

    // And a token that states nothing at all is refused rather than judged
    // against the clock, which is what let every past cut through.
    let mut silent = presented("ada");
    silent.claims.remove("iat");
    assert_eq!(
        establish(&transaction, tenant(), &silent, now)
            .await
            .expect_err("a token stating no instant cannot be judged against a cut"),
        NotEstablished::Superseded
    );
}
