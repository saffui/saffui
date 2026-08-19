//! What the providers do under the rules, against a database.

use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider};
use deadpool_postgres::{Manager, Pool};
use models::auditable::AuditableModel;
use models::entities::acr::AcrLoaMap;
use models::entities::attributes::AttributeValue;
use models::entities::keys::{JweAlgorithm, JweEncryption};
use models::entities::realm::{PasswordPolicy, RealmCreateModel, RealmModel};
use models::entities::tenant::{TenantCreateModel, TenantLimits, TenantModel, TenantState};
use models::paging::PagingParams;
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use std::collections::HashMap;

use crypto::provider::SignAlg;
use store::providers::{realms, tenants};
use store::query::list_query::ListQuery;
use store::schema::migrations;
use store::tenancy::{Tenancy, TenantContext};
use tokio_postgres::{Config, NoTls};

static DATABASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn owner_config() -> Config {
    std::env::var("SAFFUI_TEST_PG")
        .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
        .parse()
        .expect("SAFFUI_TEST_PG is a connection string")
}

async fn pool() -> Pool {
    let (owner, connection) = owner_config().connect(NoTls).await.expect("the owner");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    owner
        .batch_execute(
            "DROP SCHEMA public CASCADE; CREATE SCHEMA public; \
             GRANT ALL ON SCHEMA public TO CURRENT_USER;",
        )
        .await
        .expect("the database resets");

    let provider = OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider");
    MigrationRunner::new(migrations())
        .run(&owner_config(), &PgConnector::disabled(), provider.digest())
        .await
        .expect("the schema applies");
    owner
        .batch_execute("ALTER ROLE saffui_app LOGIN PASSWORD 'saffui_app_test'")
        .await
        .expect("the role gets a password");

    let mut app = owner_config();
    app.user("saffui_app").password("saffui_app_test");
    Pool::builder(Manager::new(app, NoTls))
        .max_size(4)
        .build()
        .expect("a pool")
}

fn tenant(id: &str) -> TenantModel {
    TenantCreateModel {
        tenant_id: id.to_owned(),
        display_name: id.to_owned(),
        region: None,
        limits: Some(TenantLimits {
            max_realms: Some(10),
            ..Default::default()
        }),
        created_by: Some("root".to_owned()),
    }
    .into()
}

fn realm(tenant: &str, id: &str) -> RealmModel {
    RealmCreateModel {
        name: id.to_owned(),
        display_name: id.to_owned(),
        enabled: true,
    }
    .into_model(
        id.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), "root".to_owned()),
    )
}

/// Plant a tenant and its realms, each under its own scope.
async fn plant(pool: &Pool, tenancy: &Tenancy, name: &str, realm_ids: &[&str]) {
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(name))
        .await
        .unwrap();

    tenants::create(&transaction, &tenant(name)).await.unwrap();
    for realm_id in realm_ids {
        realms::create(&transaction, &realm(name, realm_id))
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

/// A tenant reads itself back, with everything it was written with.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_tenant_reads_itself_back() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &["one"]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let loaded = tenants::load(&transaction)
        .await
        .unwrap()
        .expect("its own tenant");
    assert_eq!(loaded.tenant_id, "acme");
    assert_eq!(loaded.state, TenantState::Active);
    assert_eq!(
        loaded.limits.expect("the ceilings survived").max_realms,
        Some(10),
        "the limits went through the wire and came back"
    );
    assert_eq!(loaded.version, 1);
    assert!(loaded.created_at.is_some(), "the column default stamped it");

    assert!(tenants::exists(&transaction).await.unwrap());
    assert_eq!(tenants::count_realms(&transaction).await.unwrap(), 1);
    transaction.commit().await.unwrap();
}

/// Another tenant's row is nothing rather than theirs, and its realms do not
/// count towards this one's ceiling.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn another_tenant_reads_as_nothing() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &["one", "two"]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("globex"))
        .await
        .unwrap();

    assert!(tenants::load(&transaction).await.unwrap().is_none());
    assert!(!tenants::exists(&transaction).await.unwrap());
    assert_eq!(
        tenants::count_realms(&transaction).await.unwrap(),
        0,
        "another tenant's realms counted towards this one's ceiling"
    );
    assert!(
        realms::load(&transaction, "one").await.unwrap().is_none(),
        "a realm identifier is not a way past the rules"
    );
    assert!(
        !realms::name_taken(&transaction, "one").await.unwrap(),
        "a name taken elsewhere is free here"
    );
    transaction.commit().await.unwrap();
}

/// A model naming another tenant is refused by the rules rather than written
/// under a name nobody would look for it by.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_model_naming_another_tenant_is_refused() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &[]).await;
    plant(&pool, &tenancy, "globex", &[]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    assert!(
        realms::create(&transaction, &realm("globex", "planted"))
            .await
            .is_err(),
        "a realm was written under a tenant this transaction is not for"
    );
}

/// A page is bounded and its total counts the same set, not the page.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_page_is_bounded_and_its_total_is_not() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &["a", "b", "c", "d", "e"]).await;
    plant(&pool, &tenancy, "globex", &["x", "y"]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let window = PagingParams {
        first: Some(0),
        max: Some(2),
        ..Default::default()
    }
    .window()
    .unwrap();

    let page = realms::list(&transaction, &ListQuery::new(window), true)
        .await
        .unwrap();

    assert_eq!(
        page.items.len(),
        2,
        "the page is the size that was asked for"
    );
    assert_eq!(
        page.total,
        Some(5),
        "the total counts the tenant's realms, not the page and not everyone's"
    );
    assert!(page.may_have_more());

    // And without asking, the total is absent rather than a number nobody paid
    // for.
    let unasked = realms::list(&transaction, &ListQuery::new(window), false)
        .await
        .unwrap();
    assert_eq!(unasked.total, None);
    transaction.commit().await.unwrap();
}

/// Changing a state bumps the version from the stored value rather than from
/// whatever the writer last read.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_state_change_bumps_the_stored_version() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant(&pool, &tenancy, "acme", &[]).await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    assert!(
        tenants::set_state(&transaction, TenantState::Suspended, "root")
            .await
            .unwrap()
    );
    let loaded = tenants::load(&transaction).await.unwrap().unwrap();
    assert_eq!(loaded.state, TenantState::Suspended);
    assert_eq!(loaded.version, 2);
    assert_eq!(loaded.updated_by.as_deref(), Some("root"));
    assert!(loaded.updated_at.is_some());
    transaction.commit().await.unwrap();

    // A tenant that is not there is not an error, and says nothing changed.
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("nobody"))
        .await
        .unwrap();
    assert!(
        !tenants::set_state(&transaction, TenantState::Archived, "root")
            .await
            .unwrap(),
        "a state was changed on a tenant this transaction cannot see"
    );
    transaction.commit().await.unwrap();
}

use models::entities::client::{ClientCreateModel, ClientSecret, JweRegistration};
use models::entities::user::{UserCreateModel, UserModel};
use store::providers::{clients, users};

fn user(tenant: &str, realm: &str, id: &str) -> UserModel {
    UserCreateModel {
        user_name: id.to_owned(),
        enabled: true,
        email: format!("{id}@example.test"),
        email_verified: Some(true),
        phone_number: Some(format!("+3312345{id}")),
        phone_number_verified: None,
        required_actions: None,
        not_before: None,
        user_storage: None,
        attributes: None,
        is_service_account: None,
        service_account_client_link: None,
    }
    .into_model(
        id.to_owned(),
        realm.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), "root".to_owned()),
    )
}

/// Plant a tenant, a realm, and whatever lives in it.
/// A pool guard stays borrowed until it leaves scope, and shadowing it does not
/// release it. A test that takes more of them in a row than the pool holds waits
/// on one that is never coming back, so each is dropped once its transaction has
/// committed.
async fn plant_realm(pool: &Pool, tenancy: &Tenancy, name: &str, realm_id: &str) {
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide(name))
        .await
        .unwrap();
    tenants::create(&transaction, &tenant(name)).await.unwrap();
    realms::create(&transaction, &realm(name, realm_id))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// A user is found by every identifier a login may arrive with, and only inside
/// their own realm.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_user_is_found_by_what_a_login_arrives_with() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant_realm(&pool, &tenancy, "acme", "main").await;
    plant_realm(&pool, &tenancy, "globex", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    users::create(&transaction, &user("acme", "main", "ada"))
        .await
        .unwrap();

    for found in [
        users::load(&transaction, "ada").await.unwrap(),
        users::load_by_name(&transaction, "ada").await.unwrap(),
        users::load_by_email(&transaction, "ada@example.test")
            .await
            .unwrap(),
        users::load_by_phone(&transaction, "+3312345ada")
            .await
            .unwrap(),
    ] {
        let found = found.expect("every identifier resolves the same user");
        assert_eq!(found.user_id, "ada");
        assert_eq!(found.realm_id, "main");
        assert_eq!(found.metadata.tenant, "acme");
        assert!(found.enabled);
    }

    assert!(users::name_taken(&transaction, "ada").await.unwrap());
    assert!(
        users::email_taken(&transaction, "ada@example.test")
            .await
            .unwrap()
    );
    assert_eq!(users::count(&transaction).await.unwrap(), 1);
    transaction.commit().await.unwrap();

    // The same name in another tenant's realm is a different user, and free.
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("globex", "main"))
        .await
        .unwrap();
    assert!(users::load(&transaction, "ada").await.unwrap().is_none());
    assert!(!users::name_taken(&transaction, "ada").await.unwrap());
    assert_eq!(users::count(&transaction).await.unwrap(), 0);
    transaction.commit().await.unwrap();
}

/// An update writes what it carries and never the identifiers or the name: a
/// realm's users are addressed by those, so moving one would be a different user
/// wearing the same row.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_update_never_moves_a_user() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant_realm(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    users::create(&transaction, &user("acme", "main", "ada"))
        .await
        .unwrap();

    let mut changed = user("acme", "main", "ada");
    changed.user_name = "someone-else".to_owned();
    changed.email = "moved@example.test".to_owned();
    changed.enabled = false;
    changed.metadata.updated_by = Some("root".to_owned());

    assert!(users::update(&transaction, &changed).await.unwrap());

    let loaded = users::load(&transaction, "ada").await.unwrap().unwrap();
    assert_eq!(loaded.email, "moved@example.test");
    assert!(!loaded.enabled);
    assert_eq!(
        loaded.metadata.version, 2,
        "the statement bumped the stored version"
    );
    assert_eq!(loaded.metadata.updated_by.as_deref(), Some("root"));
    assert_eq!(
        loaded.user_name, "ada",
        "an update renamed the user it was written over"
    );
    transaction.commit().await.unwrap();
}

/// A client is loaded without what authenticates it, and reaching that is its
/// own call.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_loaded_client_carries_no_credential() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant_realm(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();

    let mut client = ClientCreateModel {
        name: "app".into(),
        display_name: "App".into(),
        description: String::new(),
        enabled: Some(true),
    }
    .into_model(
        "app".to_owned(),
        "main".to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    );
    client.secret = Some(ClientSecret::new("s3cr3t-value".to_owned()));
    clients::create(&transaction, &client).await.unwrap();

    let loaded = clients::load(&transaction, "app").await.unwrap().unwrap();
    assert_eq!(loaded.client_id, "app");
    assert_eq!(
        loaded.secret, None,
        "a plain load carried the credential that authenticates the client"
    );
    assert_eq!(loaded.registration_token, None);

    let secret = clients::load_secret(&transaction, "app")
        .await
        .unwrap()
        .expect("the deliberate call reaches it");
    assert_eq!(secret.expose(), "s3cr3t-value");

    assert!(clients::exists(&transaction, "app").await.unwrap());
    assert!(!clients::exists(&transaction, "nobody").await.unwrap());
    assert!(
        clients::load_secret(&transaction, "nobody")
            .await
            .unwrap()
            .is_none()
    );
    transaction.commit().await.unwrap();
}

/// Rotating a secret stamps when it happened, because a secret whose age nothing
/// can read is one nobody can decide to replace.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn rotating_a_secret_stamps_when_it_happened() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant_realm(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();

    let client = ClientCreateModel {
        name: "app".into(),
        display_name: "App".into(),
        description: String::new(),
        enabled: Some(true),
    }
    .into_model(
        "app".to_owned(),
        "main".to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    );
    clients::create(&transaction, &client).await.unwrap();

    let before = clients::load(&transaction, "app").await.unwrap().unwrap();
    assert_eq!(before.secret_created_at, None, "it was minted without one");

    assert!(
        clients::rotate_secret(
            &transaction,
            "app",
            &ClientSecret::new("fresh".into()),
            None
        )
        .await
        .unwrap()
    );

    let after = clients::load(&transaction, "app").await.unwrap().unwrap();
    assert!(after.secret_created_at.is_some(), "the rotation stamped it");
    assert_eq!(after.metadata.version, 2);
    assert_eq!(
        clients::load_secret(&transaction, "app")
            .await
            .unwrap()
            .unwrap()
            .expose(),
        "fresh"
    );

    assert!(
        !clients::rotate_secret(&transaction, "nobody", &ClientSecret::new("x".into()), None)
            .await
            .unwrap(),
        "a secret was rotated on a client this transaction cannot see"
    );
    transaction.commit().await.unwrap();
}

use models::entities::credentials::{
    CredentialModel, CredentialSecret, CredentialType, OtpAlgorithm, OtpCredentialData,
    OtpParameters,
};
use store::providers::credentials;

fn otp_credential(tenant: &str, realm: &str, id: &str, priority: i64) -> CredentialModel {
    CredentialModel {
        priority,
        ..CredentialModel::otp(
            id.to_owned(),
            realm.to_owned(),
            "ada".to_owned(),
            CredentialSecret::new("JBSWY3DPEHPK3PXP".to_owned()),
            OtpAlgorithm::Sha1,
            OtpParameters::totp_default(),
            AuditableModel::from_creator(tenant.to_owned(), "ada".to_owned()),
        )
    }
}

fn password(tenant: &str, realm: &str, id: &str, priority: i64) -> CredentialModel {
    CredentialModel {
        credential_id: id.to_owned(),
        realm_id: realm.to_owned(),
        user_id: "ada".to_owned(),
        credential_type: CredentialType::Password,
        user_label: None,
        secret: CredentialSecret::new("$argon2id$stored".to_owned()),
        otp: None,
        priority,
        metadata: AuditableModel::from_creator(tenant.to_owned(), "ada".to_owned()),
    }
}

async fn realm_with_user(pool: &Pool, tenancy: &Tenancy, name: &str, realm_id: &str) {
    plant_realm(pool, tenancy, name, realm_id).await;
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new(name, realm_id))
        .await
        .unwrap();
    users::create(&transaction, &user(name, realm_id, "ada"))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// Credentials come back in the order they are tried, and the order is the
/// statement's rather than whatever the rows happened to arrive in.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn credentials_come_back_in_the_order_they_are_tried() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    realm_with_user(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();

    // Written out of order on purpose.
    credentials::create(&transaction, &otp_credential("acme", "main", "second", 20))
        .await
        .unwrap();
    credentials::create(&transaction, &password("acme", "main", "first", 10))
        .await
        .unwrap();
    credentials::create(&transaction, &password("acme", "main", "also-first", 10))
        .await
        .unwrap();

    let held = credentials::load_for_user(&transaction, "ada")
        .await
        .unwrap();
    let order: Vec<&str> = held.iter().map(|c| c.credential_id.as_str()).collect();
    assert_eq!(
        order,
        vec!["also-first", "first", "second"],
        "a tie is broken by identifier, so the answer does not move between reads"
    );

    let passwords =
        credentials::load_for_user_of_type(&transaction, "ada", CredentialType::Password)
            .await
            .unwrap();
    assert_eq!(passwords.len(), 2);
    assert!(
        passwords
            .iter()
            .all(|c| c.credential_type == CredentialType::Password)
    );
    transaction.commit().await.unwrap();
}

/// The parameters survive the round trip as one value, and the priority reads
/// back as the whole number it was written as.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_parameters_and_the_rank_survive_the_round_trip() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    realm_with_user(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    credentials::create(&transaction, &otp_credential("acme", "main", "totp-1", 5))
        .await
        .unwrap();

    let loaded = credentials::load(&transaction, "totp-1")
        .await
        .unwrap()
        .expect("its own credential");

    assert_eq!(loaded.credential_type, CredentialType::Totp);
    assert_eq!(
        loaded.priority, 5,
        "the rank is read back as a whole number"
    );
    assert_eq!(loaded.secret.expose(), "JBSWY3DPEHPK3PXP");

    let otp = loaded.otp.expect("a time based credential carries its own");
    assert_eq!(otp.algorithm, OtpAlgorithm::Sha1);
    assert_eq!(otp.parameters, OtpParameters::totp_default());
    transaction.commit().await.unwrap();
}

/// A credential's parameters match its kind, and the database says so. A time
/// based one with none cannot produce a code, and a password with some describes
/// a way of checking it that nothing implements.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_parameters_have_to_match_the_kind() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    realm_with_user(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();

    let mut bare_otp = otp_credential("acme", "main", "bare", 0);
    bare_otp.otp = None;
    assert!(
        credentials::create(&transaction, &bare_otp).await.is_err(),
        "a time based credential was written with no parameters"
    );
}

/// Replacing what verifies a credential replaces its parameters with it.
///
/// A password rehashed at a new cost and stored beside the old parameters is one
/// nothing can verify.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn replacing_the_secret_replaces_its_parameters() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    realm_with_user(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    credentials::create(&transaction, &otp_credential("acme", "main", "totp-1", 0))
        .await
        .unwrap();

    let stronger = OtpCredentialData {
        algorithm: OtpAlgorithm::Sha256,
        parameters: OtpParameters::totp(8, 60).unwrap(),
    };
    assert!(
        credentials::replace_secret(
            &transaction,
            "totp-1",
            &CredentialSecret::new("NEWSECRET".to_owned()),
            Some(&stronger),
            "ada",
        )
        .await
        .unwrap()
    );

    let loaded = credentials::load(&transaction, "totp-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded.secret.expose(), "NEWSECRET");
    assert_eq!(loaded.otp, Some(stronger), "the parameters moved with it");
    assert_eq!(loaded.metadata.version, 2);

    assert!(
        !credentials::replace_secret(
            &transaction,
            "nobody",
            &CredentialSecret::new("x".to_owned()),
            None,
            "ada",
        )
        .await
        .unwrap(),
        "a secret was replaced on a credential this transaction cannot see"
    );
    transaction.commit().await.unwrap();
}

/// Which kinds a user holds is answerable without any of the material, which is
/// what a redacted restore needs to know what has to be enrolled again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_kinds_held_are_answerable_without_the_material() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    realm_with_user(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();

    assert!(
        credentials::kinds_held(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "a user who holds nothing"
    );

    credentials::create(&transaction, &password("acme", "main", "pw", 0))
        .await
        .unwrap();
    credentials::create(&transaction, &otp_credential("acme", "main", "totp", 10))
        .await
        .unwrap();
    credentials::create(&transaction, &password("acme", "main", "old-pw", 20))
        .await
        .unwrap();

    let kinds = credentials::kinds_held(&transaction, "ada").await.unwrap();
    assert_eq!(
        kinds.len(),
        2,
        "each kind once, however many of it are held: {kinds:?}"
    );
    assert!(kinds.contains(&CredentialType::Password));
    assert!(kinds.contains(&CredentialType::Totp));

    // And removing one of a kind does not remove the kind.
    assert!(credentials::delete(&transaction, "pw").await.unwrap());
    assert!(
        credentials::kinds_held(&transaction, "ada")
            .await
            .unwrap()
            .contains(&CredentialType::Password)
    );
    assert!(!credentials::delete(&transaction, "pw").await.unwrap());
    transaction.commit().await.unwrap();
}

/// A realm's credentials are invisible from another realm, and removing a user
/// takes theirs with them.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn credentials_belong_to_their_realm_and_to_their_user() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    realm_with_user(&pool, &tenancy, "acme", "main").await;
    realm_with_user(&pool, &tenancy, "globex", "main").await;

    // A second realm under the same tenant, so the read half of the rule is
    // exercised and not only the tenant half.
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();
    realms::create(&transaction, &realm("acme", "other"))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    credentials::create(&transaction, &password("acme", "main", "pw", 0))
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    // Another realm of the same tenant sees none of them. Crossing tenants
    // would be isolated by the tenant alone, so it proves only half the rule.
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "other"))
        .await
        .unwrap();
    assert!(
        credentials::load(&transaction, "pw")
            .await
            .unwrap()
            .is_none(),
        "a realm read another realm's credentials inside the same tenant"
    );
    assert!(
        credentials::load_for_user(&transaction, "ada")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        credentials::kinds_held(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "nor the kinds they hold"
    );
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("globex", "main"))
        .await
        .unwrap();
    assert!(
        credentials::load(&transaction, "pw")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        credentials::load_for_user(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "another realm's user of the same name carries none of theirs"
    );
    transaction.commit().await.unwrap();

    // Removing the user removes what they held.
    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    assert!(users::delete(&transaction, "ada").await.unwrap());
    assert!(
        credentials::load(&transaction, "pw")
            .await
            .unwrap()
            .is_none(),
        "a credential outlived the user it belonged to"
    );
    transaction.commit().await.unwrap();
}

/// Every rule a realm has must survive being written and read back. They are set
/// after creation, which names what a realm is and nothing about how it behaves,
/// so a read that drops them leaves an operator setting a five minute access
/// token and getting whatever a constant elsewhere says, forever, with no error.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realms_rules_survive_being_written_and_read_back() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant_realm(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::tenant_wide("acme"))
        .await
        .unwrap();

    let mut settings = realms::load(&transaction, "main").await.unwrap().unwrap();
    settings.access_token_lifespan = Some(300);
    settings.action_tokens_lifespan = Some(600);
    settings.access_code_lifespan = Some(60);
    settings.access_code_lifespan_user_action = Some(120);
    settings.access_code_lifespan_login = Some(1_800);
    settings.revoke_refresh_token = Some(true);
    settings.refresh_token_max_reuse = Some(2);
    settings.not_before = Some(1_700_000_000);
    settings.remember_me = Some(true);
    settings.verify_email = Some(true);
    settings.acr_loa_map = Some(AcrLoaMap::from_pairs([("password", 1), ("mfa", 2)]));
    settings.password_policy = Some(PasswordPolicy {
        min_length: Some(12),
        ..PasswordPolicy::default()
    });
    settings.attributes = Some(HashMap::from([(
        "brand".to_owned(),
        AttributeValue::Str("acme".to_owned()),
    )]));

    assert!(realms::update(&transaction, &settings).await.unwrap());

    let read_back = realms::load(&transaction, "main").await.unwrap().unwrap();
    assert_eq!(read_back.access_token_lifespan, Some(300));
    assert_eq!(read_back.action_tokens_lifespan, Some(600));
    assert_eq!(read_back.access_code_lifespan, Some(60));
    assert_eq!(read_back.access_code_lifespan_user_action, Some(120));
    assert_eq!(read_back.access_code_lifespan_login, Some(1_800));
    assert_eq!(read_back.revoke_refresh_token, Some(true));
    assert_eq!(read_back.refresh_token_max_reuse, Some(2));
    assert_eq!(read_back.not_before, Some(1_700_000_000));
    assert_eq!(read_back.remember_me, Some(true));
    assert_eq!(read_back.verify_email, Some(true));
    assert_eq!(read_back.acr_loa_map, settings.acr_loa_map);
    assert_eq!(read_back.password_policy, settings.password_policy);
    assert_eq!(read_back.attributes, settings.attributes);

    assert!(
        !realms::update(&transaction, &realm("acme", "nobody"))
            .await
            .unwrap(),
        "a realm that does not exist takes no settings"
    );
    transaction.commit().await.unwrap();
}

/// Same for a client, and the encryption pair is the case worth naming: the two
/// columns hold one registration, and reading them as two independent options
/// would let the half written state back into a model built to make it
/// unrepresentable.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_clients_registrations_survive_being_written_and_read_back() {
    let _turn = DATABASE.lock().await;
    let pool = pool().await;
    let tenancy = Tenancy::unpinned();
    plant_realm(&pool, &tenancy, "acme", "main").await;

    let mut connection = pool.get().await.unwrap();
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();

    let client = ClientCreateModel {
        name: "app".into(),
        display_name: "App".into(),
        description: String::new(),
        enabled: Some(true),
    }
    .into_model(
        "app".to_owned(),
        "main".to_owned(),
        AuditableModel::from_creator("acme".to_owned(), "root".to_owned()),
    );
    clients::create(&transaction, &client).await.unwrap();

    let mut registered = clients::load(&transaction, "app").await.unwrap().unwrap();
    registered.redirect_uris = Some(vec!["https://app.example/cb".to_owned()]);
    registered.post_logout_redirect_uris = Some(vec!["https://app.example/bye".to_owned()]);
    registered.web_origins = Some(vec!["https://app.example".to_owned()]);
    registered.root_url = Some("https://app.example".to_owned());
    registered.id_token_signed_response_alg = Some(SignAlg::Es256);
    registered.userinfo_signed_response_alg = Some(SignAlg::Rs512);
    registered.id_token_encryption = Some(JweRegistration::new(
        JweAlgorithm::RsaOaep256,
        Some(JweEncryption::A256Gcm),
    ));
    // No `enc` named, so the registration takes the specified default and the
    // read must bring back the pair rather than the half that was written.
    registered.userinfo_encryption = Some(JweRegistration::new(JweAlgorithm::EcdhEs, None));
    registered.full_scope_allowed = Some(false);
    registered.consent_required = Some(true);
    registered.direct_access_grants_enabled = Some(true);
    registered.standard_flow_enabled = Some(true);
    registered.implicit_flow_enabled = Some(false);
    registered.service_account_enabled = Some(true);
    registered.not_before = Some(1_700_000_000);
    registered.configs = Some(HashMap::from([("tier".to_owned(), AttributeValue::Int(2))]));

    assert!(clients::update(&transaction, &registered).await.unwrap());

    let read_back = clients::load(&transaction, "app").await.unwrap().unwrap();
    assert_eq!(read_back.redirect_uris, registered.redirect_uris);
    assert_eq!(
        read_back.post_logout_redirect_uris,
        registered.post_logout_redirect_uris
    );
    assert_eq!(read_back.web_origins, registered.web_origins);
    assert_eq!(read_back.root_url, registered.root_url);
    assert_eq!(read_back.id_token_signed_response_alg, Some(SignAlg::Es256));
    assert_eq!(read_back.userinfo_signed_response_alg, Some(SignAlg::Rs512));
    assert_eq!(read_back.request_object_signing_alg, None);
    assert_eq!(
        read_back.id_token_encryption,
        registered.id_token_encryption
    );
    assert_eq!(
        read_back.userinfo_encryption,
        Some(JweRegistration {
            alg: JweAlgorithm::EcdhEs,
            enc: JweEncryption::DEFAULT,
        })
    );
    assert_eq!(read_back.request_object_encryption, None);

    assert_eq!(read_back.full_scope_allowed, Some(false));
    assert_eq!(read_back.consent_required, Some(true));
    assert_eq!(read_back.direct_access_grants_enabled, Some(true));
    assert_eq!(read_back.standard_flow_enabled, Some(true));
    assert_eq!(read_back.implicit_flow_enabled, Some(false));
    assert_eq!(read_back.service_account_enabled, Some(true));
    assert_eq!(read_back.not_before, Some(1_700_000_000));
    assert_eq!(read_back.configs, registered.configs);
    assert_eq!(
        read_back.secret, None,
        "a settings edit is not how a credential is reached"
    );
    transaction.commit().await.unwrap();

    // The half written state is unrepresentable on both sides, and the schema is
    // where that is actually held: the model can only refuse to describe it, the
    // check refuses to store it whatever wrote the row. Its own transaction,
    // because a refused statement aborts the one it was issued in.
    let transaction = tenancy
        .transaction(&mut connection, &TenantContext::new("acme", "main"))
        .await
        .unwrap();
    assert!(
        transaction
            .execute(
                "UPDATE clients SET userinfo_encryption_enc = NULL WHERE client_id = 'app'",
                &[],
            )
            .await
            .is_err(),
        "a content encryption was dropped from under the algorithm it goes with"
    );
}
