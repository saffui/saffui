mod support;

use models::auditable::AuditableModel;
use models::entities::realm::RealmCreateModel;
use models::entities::tenant::TenantCreateModel;
use store::error::StoreError;
use store::providers::{realms, tenants};
use store::tenancy::{TenantContext, resolve};
use support::Fixture;

/// Plant a second tenant holding a realm of the same name, which is what makes
/// a name ambiguous rather than merely taken.
async fn rival_tenant(fixture: &Fixture, tenant_id: &str, realm_name: &str, region: Option<&str>) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::tenant_wide(tenant_id))
        .await;

    let tenant: models::entities::tenant::TenantModel = TenantCreateModel {
        tenant_id: tenant_id.into(),
        display_name: tenant_id.into(),
        region: region.map(str::to_owned),
        limits: None,
        created_by: Some("root".into()),
    }
    .into();
    tenants::create(&transaction, &tenant).await.unwrap();

    let realm = RealmCreateModel {
        name: realm_name.into(),
        display_name: realm_name.into(),
        enabled: true,
    }
    .into_model(
        format!("{tenant_id}-realm"),
        AuditableModel::from_creator(tenant_id.to_owned(), "root".into()),
    );
    realms::create(&transaction, &realm).await.unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
}

/// The reason these functions exist, asserted rather than explained.
///
/// The application role reads nothing from `realms` on its own: the policies
/// match nothing until the settings are written, and the settings are written
/// from what the resolver returns. Reading the answer under the rules is
/// impossible by construction, and the function is the way out.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_resolver_answers_what_the_rules_keep() {
    let fixture = Fixture::with_user().await;
    let connection = fixture.connection().await;

    let direct: i64 = connection
        .query_one("SELECT count(*) FROM realms", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        direct, 0,
        "an ungoverned connection read the table the resolver exists for"
    );

    let resolved = resolve::realm_by_name(&connection, "main")
        .await
        .expect("the resolver found nothing");
    assert_eq!(resolved.tenant, "acme");
    assert_eq!(resolved.realm_id, "main");
}

/// The tenant comes off the row that was found. Nothing in the request says it,
/// which is what stops a caller naming any tenant and having the realm looked
/// up inside it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_carries_its_tenant_and_its_residency_back() {
    let fixture = Fixture::with_user().await;
    rival_tenant(&fixture, "globex", "elsewhere", Some("eu-west")).await;
    let connection = fixture.connection().await;

    let resolved = resolve::realm_by_name(&connection, "elsewhere")
        .await
        .unwrap();
    assert_eq!(resolved.tenant, "globex");
    assert_eq!(resolved.realm_id, "globex-realm");
    assert_eq!(
        resolved.region.as_deref(),
        Some("eu-west"),
        "the residency pin did not come back, so nothing can refuse an off region request"
    );
}

/// Two answers is a refusal, not a choice.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_name_two_tenants_use_is_refused() {
    let fixture = Fixture::with_user().await;
    rival_tenant(&fixture, "globex", "main", None).await;
    let connection = fixture.connection().await;

    match resolve::realm_by_name(&connection, "main").await {
        Err(StoreError::Ambiguous { asked, count }) => {
            assert_eq!(asked, "main");
            assert_eq!(count, 2);
        }
        other => panic!("an ambiguous name resolved to {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_name_nobody_uses_is_not_found() {
    let fixture = Fixture::with_user().await;
    let connection = fixture.connection().await;

    match resolve::realm_by_name(&connection, "absent").await {
        Err(StoreError::NotFound { asked }) => assert_eq!(asked, "absent"),
        other => panic!("a name nobody uses resolved to {other:?}"),
    }
}

/// A disabled realm answers nothing. Resolving it would let a login start in a
/// realm an operator has turned off, and be refused deeper in with less to say.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_disabled_realm_does_not_answer() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "UPDATE realms SET enabled = false WHERE realm_id = 'main'",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let connection = fixture.connection().await;
    assert!(
        matches!(
            resolve::realm_by_name(&connection, "main").await,
            Err(StoreError::NotFound { .. })
        ),
        "a realm an operator turned off still answered"
    );
}

/// A token names the realm and not the tenant.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_is_found_by_the_identifier_a_token_carries() {
    let fixture = Fixture::with_user().await;
    let connection = fixture.connection().await;

    let resolved = resolve::realm_by_id(&connection, "main").await.unwrap();
    assert_eq!(resolved.tenant, "acme");

    assert!(matches!(
        resolve::realm_by_id(&connection, "absent").await,
        Err(StoreError::NotFound { .. })
    ));
}

/// A cookie carries a session identifier and no realm.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_session_resolves_the_realm_it_belongs_to() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO user_sessions \
                 (tenant, realm_id, session_id, user_id, login_username, state, started_at) \
             VALUES ('acme', 'main', 'session-1', 'ada', 'ada', 'logged-in', \
                     extract(epoch FROM now())::bigint)",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let connection = fixture.connection().await;
    let resolved = resolve::user_session(&connection, "session-1")
        .await
        .unwrap();
    assert_eq!(resolved.tenant, "acme");
    assert_eq!(resolved.realm_id, "main");
}

/// The application role may call the resolvers and may not become the role that
/// owns them, so what it can read through them is all it can read.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_application_role_only_borrows_the_answer() {
    let fixture = Fixture::with_user().await;
    let connection = fixture.connection().await;

    let bypasses: bool = connection
        .query_one(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!bypasses, "the application role bypasses the rules itself");

    let member: bool = connection
        .query_one(
            "SELECT pg_has_role(current_user, 'saffui_resolver', 'member')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!member, "the application role can become the resolver");
}
