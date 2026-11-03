//! What every storage adapter must do, written once and played on the double
//! and on Postgres: they must answer alike.

use uuid::Uuid;

use crate::app::App;
use crate::audit::canonical::canonicalize;
use crate::audit::verify::{ChainVerdict, verify_chain};
use crate::ids::mint_id;
use crate::ports::storage::StorageError;
use crate::tenancy::{Realm, RealmId, RealmName, RealmScope, Tenant, TenantId};

fn describe_realm(app: &App, name: &str) -> (Tenant, Realm, RealmScope) {
    let tenant = Tenant {
        id: TenantId::from_uuid(mint_id(app).expect("an identifier")),
        name: format!("Tenant of {name}"),
        created_at: app.now(),
    };
    let realm = Realm {
        id: RealmId::from_uuid(mint_id(app).expect("an identifier")),
        tenant: tenant.id,
        name: RealmName::parse(name).expect("a realm name"),
        enabled: true,
        created_at: app.now(),
    };
    let scope = RealmScope::bind(tenant.id, realm.id);
    (tenant, realm, scope)
}

/// Plays the tenancy contract on the storage `app` is wired on.
///
/// # Panics
///
/// Panics at the first answer that breaks the contract.
pub async fn check_tenancy_contract(app: &App) {
    let (realm, scope) = check_what_a_unit_of_work_keeps(app).await;
    check_that_a_realm_name_is_taken_once(app, &realm).await;
    check_that_a_unit_of_work_stays_in_its_scope(app, realm, scope).await;
}

async fn check_what_a_unit_of_work_keeps(app: &App) -> (Realm, RealmScope) {
    let storage = &app.storage;
    let (tenant, realm, scope) = describe_realm(app, "contract-one");

    // An abandoned unit of work leaves nothing.
    {
        let mut abandoned = storage.begin(scope).await.expect("a unit of work");
        abandoned.insert_tenant(&tenant).await.expect("a tenant");
        abandoned.insert_realm(&realm).await.expect("a realm");
    }
    assert_eq!(
        storage.locate_realm(&realm.name).await,
        Ok(None),
        "what an abandoned unit of work wrote is gone"
    );

    // A committed one is read back, equal to what was written.
    let mut work = storage.begin(scope).await.expect("a unit of work");
    work.insert_tenant(&tenant).await.expect("a tenant");
    work.insert_realm(&realm).await.expect("a realm");
    assert_eq!(
        work.read_realm().await,
        Ok(Some(realm.clone())),
        "a unit of work reads what it wrote"
    );
    work.commit().await.expect("a commit");

    let mut later = storage.begin(scope).await.expect("a unit of work");
    assert_eq!(later.read_realm().await, Ok(Some(realm.clone())));
    drop(later);

    let located = storage
        .locate_realm(&realm.name)
        .await
        .expect("the directory answers")
        .expect("the realm is listed");
    assert_eq!(
        (located.tenant, located.realm, located.enabled),
        (tenant.id, realm.id, true)
    );
    let nobody = RealmName::parse("contract-nobody").expect("a realm name");
    assert_eq!(storage.locate_realm(&nobody).await, Ok(None));

    // A realm is written once: its identifier is taken.
    let mut twice = storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        twice
            .insert_realm(&Realm {
                name: RealmName::parse("contract-twice").expect("a realm name"),
                ..realm.clone()
            })
            .await,
        Err(StorageError::Failed),
        "a realm whose identifier exists is refused"
    );
    drop(twice);
    (realm, scope)
}

async fn check_that_a_realm_name_is_taken_once(app: &App, realm: &Realm) {
    let storage = &app.storage;
    // A name designates one realm, across every tenant.
    let (other_tenant, mut same_name, other_scope) = describe_realm(app, "contract-two");
    same_name.name = realm.name.clone();
    let mut refused = storage.begin(other_scope).await.expect("a unit of work");
    refused
        .insert_tenant(&other_tenant)
        .await
        .expect("a tenant");
    assert_eq!(
        refused.insert_realm(&same_name).await,
        Err(StorageError::Taken("realm name"))
    );
    assert_eq!(
        refused.commit().await,
        Err(StorageError::Failed),
        "a unit of work that met a refusal commits nothing"
    );
    let mut again = storage.begin(other_scope).await.expect("a unit of work");
    assert_eq!(
        again.insert_tenant(&other_tenant).await,
        Ok(()),
        "the tenant written before the refusal was not kept"
    );
}

async fn check_that_a_unit_of_work_stays_in_its_scope(app: &App, realm: Realm, scope: RealmScope) {
    let storage = &app.storage;
    // A unit of work reads its own realm and no other.
    let (second_tenant, second_realm, second_scope) = describe_realm(app, "contract-two");
    let mut work = storage.begin(second_scope).await.expect("a unit of work");
    work.insert_tenant(&second_tenant).await.expect("a tenant");
    work.insert_realm(&second_realm).await.expect("a realm");
    work.commit().await.expect("a commit");
    let mut first = storage.begin(scope).await.expect("a unit of work");
    assert_eq!(first.read_realm().await, Ok(Some(realm)));
    drop(first);
    let mut second = storage.begin(second_scope).await.expect("a unit of work");
    assert_eq!(second.read_realm().await, Ok(Some(second_realm)));
    drop(second);

    // Nothing is written outside the scope a unit of work is bound to. Each
    // stray row differs from the scope by one key alone, where nothing else
    // would refuse it.
    let (fresh_tenant, fresh_realm, fresh_scope) = describe_realm(app, "contract-fresh");
    let (stray_tenant, stray_realm, _stray_scope) = describe_realm(app, "contract-stray");
    let mut fresh = storage.begin(fresh_scope).await.expect("a unit of work");
    assert_eq!(
        fresh.insert_tenant(&stray_tenant).await,
        Err(StorageError::Failed),
        "a tenant other than the one of the scope is refused"
    );
    assert_eq!(
        fresh.commit().await,
        Err(StorageError::Failed),
        "a refusal of the store ends the unit of work, as one of the database does"
    );
    let mut fresh = storage.begin(fresh_scope).await.expect("a unit of work");
    fresh.insert_tenant(&fresh_tenant).await.expect("a tenant");
    let other_realm_of_the_tenant = Realm {
        tenant: fresh_tenant.id,
        ..stray_realm
    };
    assert_eq!(
        fresh.insert_realm(&other_realm_of_the_tenant).await,
        Err(StorageError::Failed),
        "a realm other than the one of the scope is refused"
    );
    let the_realm_under_another_tenant = Realm {
        tenant: scope.tenant(),
        ..fresh_realm
    };
    assert_eq!(
        fresh.insert_realm(&the_realm_under_another_tenant).await,
        Err(StorageError::Failed),
        "the realm of the scope under another tenant is refused"
    );
}

/// Plays the audit contract on the storage `app` is wired on. The digester
/// of `app` must be the one the storage links its chains with.
///
/// The counts are taken from the chain as the realm left it: whatever its
/// creation recorded, the contract asks only for what follows.
///
/// # Panics
///
/// Panics at the first answer that breaks the contract.
pub async fn check_audit_contract(app: &App) {
    let (scope, created) = check_that_appends_are_kept_once_committed(app).await;
    check_that_the_chain_is_read_in_order(app, scope, created).await;
    check_that_a_snapshot_appends_nothing(app, scope, created).await;
    check_that_an_envelope_of_another_scope_is_refused(app, scope, created).await;
}

/// A canonical envelope for `tenant` and `realm`, as an adapter receives it.
fn write_envelope(app: &App, tenant: Uuid, realm: Uuid) -> Vec<u8> {
    use serde_json::json;

    canonicalize(&json!({
        "id": mint_id(app).expect("an identifier").to_string(),
        "tenant_id": tenant.to_string(),
        "realm_id": realm.to_string(),
        "kind": "realm.created",
        "ts": "2026-01-01T00:00:00Z",
        "payload": {},
    }))
    .expect("a canonical form")
}

async fn read_events_in_chain(app: &App, scope: RealmScope) -> i64 {
    match verify_chain(app, scope).await {
        Ok(ChainVerdict::Intact { events }) => events,
        other => panic!("the chain is intact: {other:?}"),
    }
}

async fn check_that_appends_are_kept_once_committed(app: &App) -> (RealmScope, i64) {
    use serde_json::json;

    use crate::audit::EventKind;
    use crate::audit::append::record_event;
    use crate::tenancy::realm::{NewRealm, provision_first_realm};

    let provisioned = provision_first_realm(
        app,
        NewRealm {
            tenant_name: "Audited",
            realm_name: "contract-audit",
        },
    )
    .await
    .expect("a realm");
    let scope = RealmScope::bind(provisioned.tenant.id, provisioned.realm.id);
    let created = read_events_in_chain(app, scope).await;

    for round in 0..3 {
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        record_event(
            app,
            work.as_mut(),
            EventKind::RealmCreated,
            json!({ "round": round }),
        )
        .await
        .expect("an event");
        work.commit().await.expect("a commit");
    }
    assert_eq!(read_events_in_chain(app, scope).await, created + 3);

    // An event recorded by an abandoned unit of work is not in the chain.
    {
        let mut abandoned = app.storage.begin(scope).await.expect("a unit of work");
        record_event(
            app,
            abandoned.as_mut(),
            EventKind::RealmCreated,
            json!({ "round": "lost" }),
        )
        .await
        .expect("an event");
    }
    assert_eq!(read_events_in_chain(app, scope).await, created + 3);
    (scope, created)
}

async fn check_that_the_chain_is_read_in_order(app: &App, scope: RealmScope, created: i64) {
    use crate::audit::GENESIS_HASH;
    use crate::audit::store::ChainedEvent;

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let whole = work.read_audit_events(0, 100).await.expect("a page");
    assert_eq!(whole[0].previous_hash, GENESIS_HASH);
    let first_two = work.read_audit_events(created, 2).await.expect("a page");
    let rest = work
        .read_audit_events(created + 2, 10)
        .await
        .expect("a page");
    let numbers =
        |page: &[ChainedEvent]| -> Vec<i64> { page.iter().map(|event| event.seq).collect() };
    assert_eq!(numbers(&first_two), [created + 1, created + 2]);
    assert_eq!(numbers(&rest), [created + 3]);
    assert_eq!(first_two[1].previous_hash, first_two[0].hash);
    assert_eq!(rest[0].previous_hash, first_two[1].hash);
    let head = work
        .read_audit_head()
        .await
        .expect("a head")
        .expect("a chain");
    assert_eq!((head.seq, &head.hash), (created + 3, &rest[0].hash));
}

async fn check_that_a_snapshot_appends_nothing(app: &App, scope: RealmScope, created: i64) {
    let mut snapshot = app.storage.begin_snapshot(scope).await.expect("a snapshot");
    let head = snapshot
        .read_audit_head()
        .await
        .expect("a head")
        .expect("a chain");
    assert_eq!(head.seq, created + 3, "a snapshot reads");

    let event = write_envelope(app, scope.tenant().as_uuid(), scope.realm().as_uuid());
    assert!(snapshot.append_audit_event(&event).await.is_err());
    assert_eq!(snapshot.commit().await, Err(StorageError::Failed));
    assert_eq!(read_events_in_chain(app, scope).await, created + 3);
}

async fn check_that_an_envelope_of_another_scope_is_refused(
    app: &App,
    scope: RealmScope,
    created: i64,
) {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let stranger = mint_id(app).expect("an identifier");

    let foreign = write_envelope(app, stranger, scope.realm().as_uuid());
    assert!(work.append_audit_event(&foreign).await.is_err());
    assert_eq!(
        work.commit().await,
        Err(StorageError::Failed),
        "the refusal ended the unit of work"
    );
    assert_eq!(read_events_in_chain(app, scope).await, created + 3);
}

/// Plays the key contract on the storage `app` is wired on.
///
/// # Panics
///
/// Panics at the first answer that breaks the contract.
pub async fn check_keys_contract(app: &App) {
    use crate::keys::SIGNING_KEY_PURPOSE;
    use crate::keys::jwks::{open_signing_key, publish_key_set};
    use crate::ports::crypto::{SealPlace, SignatureAlgorithm};
    use crate::tenancy::realm::{NewRealm, provision_first_realm};

    let provisioned = provision_first_realm(
        app,
        NewRealm {
            tenant_name: "Keyed",
            realm_name: "contract-keys",
        },
    )
    .await
    .expect("a realm");
    let scope = RealmScope::bind(provisioned.tenant.id, provisioned.realm.id);

    // A realm is born with its data key and one signing key.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let data_key = work
        .read_data_key()
        .await
        .expect("a read")
        .expect("a data key");
    assert_eq!(data_key.generation, 1);
    let keys = work.list_signing_keys().await.expect("the keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].algorithm, SignatureAlgorithm::Es256);
    assert_eq!(keys[0].public_jwk["kid"], keys[0].key_id.as_str());

    // What is published is the public half, and the private half opens
    // where it is stored.
    let published = publish_key_set(app, scope).await.expect("a key set");
    assert_eq!(published.keys, [keys[0].public_jwk.clone()]);
    let (key, _private_key) = open_signing_key(app, work.as_mut(), SignatureAlgorithm::Es256)
        .await
        .expect("the signing key");
    assert_eq!(key, keys[0]);

    // The sealed key opens for its own row only.
    let elsewhere = SealPlace {
        tenant: scope.tenant().as_uuid(),
        realm: scope.realm().as_uuid(),
        purpose: SIGNING_KEY_PURPOSE,
        row: mint_id(app).expect("an identifier"),
    };
    assert!(
        app.sealer
            .open(&data_key, &elsewhere, &key.sealed_private_key)
            .is_err(),
        "a sealed key moved to another row does not open"
    );

    // A generation of the data key is written once, and so is a key.
    assert!(work.insert_data_key(&data_key).await.is_err());
    drop(work);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert!(work.insert_signing_key(&keys[0]).await.is_err());
    drop(work);

    // A newer generation is the one read.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let newer = app
        .sealer
        .make_data_key(scope.tenant().as_uuid(), scope.realm().as_uuid(), 2)
        .expect("a data key");
    work.insert_data_key(&newer)
        .await
        .expect("a second generation");
    assert_eq!(work.read_data_key().await, Ok(Some(newer)));
}

/// Plays the clients contract on the storage `app` is wired on.
///
/// # Panics
///
/// Panics at the first answer that breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_clients_contract(app: &App) {
    use crate::clients::Client;
    use crate::tenancy::realm::{NewRealm, provision_first_realm};

    let mut scopes = Vec::new();
    for realm_name in ["contract-clients", "contract-clients-2"] {
        let provisioned = provision_first_realm(
            app,
            NewRealm {
                tenant_name: "Clients",
                realm_name,
            },
        )
        .await
        .expect("a realm");
        scopes.push(RealmScope::bind(
            provisioned.tenant.id,
            provisioned.realm.id,
        ));
    }
    let client = Client {
        id: mint_id(app).expect("an identifier"),
        client_id: "billing".to_owned(),
        name: "Billing".to_owned(),
        secret_digest: Some(vec![7; 32]),
        allows_client_credentials: true,
        allows_authorization_code: false,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["invoices:read".to_owned(), "invoices:write".to_owned()],
        capabilities: vec![
            crate::authz::capability::Capability::ClientRead,
            crate::authz::capability::Capability::AuditRead,
        ],
        enabled: true,
        created_at: app.now(),
    };

    // A client is read back as it was written, by its identifier.
    let mut work = app.storage.begin(scopes[0]).await.expect("a unit of work");
    work.insert_client(&client).await.expect("a client");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scopes[0]).await.expect("a unit of work");
    assert_eq!(work.read_client("billing").await, Ok(Some(client.clone())));
    assert_eq!(work.read_client("nobody").await, Ok(None));

    // An application without a secret is read back as it was written too.
    let application = Client {
        id: mint_id(app).expect("an identifier"),
        client_id: "webapp".to_owned(),
        secret_digest: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec!["https://app.example.org/callback".to_owned()],
        post_logout_redirect_uris: vec!["https://app.example.org/goodbye".to_owned()],
        capabilities: Vec::new(),
        ..client.clone()
    };
    work.insert_client(&application)
        .await
        .expect("an application");
    assert_eq!(
        work.read_client("webapp").await,
        Ok(Some(application.clone()))
    );

    // An identifier is taken once in its realm, and free in every other.
    let again = Client {
        id: mint_id(app).expect("an identifier"),
        ..client.clone()
    };
    assert_eq!(
        work.insert_client(&again).await,
        Err(StorageError::Taken("client identifier"))
    );
    drop(work);
    let mut work = app.storage.begin(scopes[1]).await.expect("a unit of work");
    assert_eq!(work.read_client("billing").await, Ok(None));
    work.insert_client(&again)
        .await
        .expect("the same identifier in another realm");
    work.commit().await.expect("a commit");

    // A list runs in the order of the identifiers, cut by its window, and
    // its count is the size of the realm, not of the page.
    let mut work = app.storage.begin(scopes[0]).await.expect("a unit of work");
    for client_id in ["ledger", "audit-bot"] {
        let other = Client {
            id: mint_id(app).expect("an identifier"),
            client_id: client_id.to_owned(),
            ..client.clone()
        };
        work.insert_client(&other).await.expect("a client");
    }
    let window = |first, max| crate::clients::store::ListWindow { first, max };
    let named = |clients: Vec<Client>| -> Vec<String> {
        clients.into_iter().map(|client| client.client_id).collect()
    };
    assert_eq!(
        work.list_clients(window(0, 10)).await.map(named),
        Ok(vec![
            "audit-bot".to_owned(),
            "billing".to_owned(),
            "ledger".to_owned()
        ])
    );
    assert_eq!(
        work.list_clients(window(1, 1)).await.map(named),
        Ok(vec!["billing".to_owned()])
    );
    assert_eq!(work.count_clients().await, Ok(3));
}

/// What every storage must answer of the people of a realm.
///
/// # Panics
///
/// Panics at the first answer the contract does not allow.
pub async fn check_persons_contract(app: &App) {
    use crate::clients::store::ListWindow;
    use crate::directory::Person;
    use crate::testkit::fixtures::create_realm;

    let scope = create_realm(app, "contract-persons").await;
    let other = create_realm(app, "contract-persons-other").await;
    let now = app.now();
    let describe = |username: &str, email: Option<&str>| Person {
        id: mint_id(app).expect("an identifier"),
        username: username.to_owned(),
        email: email.map(str::to_owned),
        email_verified: false,
        display_name: Some("Ada".to_owned()),
        enabled: true,
        created_at: now,
    };

    // People: read back equal, by identifier and by name, in their realm only.
    let ada = describe("ada", Some("ada@example.org"));
    let bob = describe("bob", None);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_person(&ada).await.expect("a person");
    work.insert_person(&bob)
        .await
        .expect("a person without an address");
    work.insert_person(&describe("carol", None))
        .await
        .expect("a second person without an address");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_person(ada.id).await, Ok(Some(ada.clone())));
    assert_eq!(
        work.read_person_by_username("bob").await,
        Ok(Some(bob.clone()))
    );
    assert_eq!(work.read_person_by_username("nobody").await, Ok(None));
    assert_eq!(work.count_persons().await, Ok(3));
    let listed = work
        .list_persons(ListWindow { first: 1, max: 5 })
        .await
        .expect("a page");
    let names: Vec<&str> = listed
        .iter()
        .map(|person| person.username.as_str())
        .collect();
    assert_eq!(names, ["bob", "carol"]);
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_person(ada.id).await, Ok(None));
    elsewhere
        .insert_person(&describe("ada", Some("ada@example.org")))
        .await
        .expect("the same name and address, elsewhere");
    elsewhere.commit().await.expect("a commit");

    // A name and an address are each taken once per realm.
    assert_eq!(
        work.insert_person(&describe("ada", None)).await,
        Err(StorageError::Taken("username"))
    );
    drop(work);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.insert_person(&describe("dave", Some("ada@example.org")))
            .await,
        Err(StorageError::Taken("email"))
    );
    drop(work);

    // A password is kept for its person, and read in its realm only.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_password(ada.id).await, Ok(None));
    work.insert_password(ada.id, "$first", now)
        .await
        .expect("a password");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.read_password(ada.id).await,
        Ok(Some("$first".to_owned()))
    );
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_password(ada.id).await, Ok(None));
}

/// What every storage must answer of sessions and of the counters of the brake.
///
/// # Panics
///
/// Panics at the first answer the contract does not allow.
pub async fn check_sign_in_contract(app: &App) {
    use time::Duration;

    use crate::login::session::{Session, SessionState};
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-sign-in").await;
    let other = create_realm(app, "contract-sign-in-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();

    // A session is read back equal, in its realm only.
    let session = Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![3; 32],
        state: SessionState::Active,
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.read_session(session.id).await,
        Ok(Some(session.clone()))
    );
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_session(session.id).await, Ok(None));

    // The brake: counts add up per digest, and only from the window asked for.
    let (digest, another) = ([5_u8; 32], [6_u8; 32]);
    let earlier = now - Duration::minutes(10);
    work.record_login_failure(&digest, now)
        .await
        .expect("a failure");
    work.record_login_failure(&digest, now)
        .await
        .expect("a failure");
    work.record_login_failure(&digest, earlier)
        .await
        .expect("an older failure");
    work.record_login_failure(&another, now)
        .await
        .expect("a failure of another name");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.count_login_failures(&digest, now).await, Ok(2));
    assert_eq!(work.count_login_failures(&digest, earlier).await, Ok(3));
    assert_eq!(work.count_login_failures(&[9; 32], earlier).await, Ok(0));
    assert_eq!(
        elsewhere.count_login_failures(&digest, earlier).await,
        Ok(0),
        "a counter is kept per realm"
    );

    // A counter is forgotten whole, and only that one.
    work.forget_login_failures(&digest)
        .await
        .expect("a forgotten counter");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.count_login_failures(&digest, earlier).await, Ok(0));
    assert_eq!(work.count_login_failures(&another, earlier).await, Ok(1));
}

/// What every storage must answer of the authorization code flow: requests
/// that wait, codes, and sessions that end.
///
/// # Panics
///
/// Panics at the first answer the contract does not allow.
pub async fn check_codes_contract(app: &App) {
    use time::Duration;

    use crate::login::session::{Session, SessionState};
    use crate::oidc::code::PendingAuthorization;
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-codes").await;
    let other = create_realm(app, "contract-codes-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();

    // A session ends once, and is kept ended.
    let session = Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![3; 32],
        state: SessionState::Active,
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    assert_eq!(work.end_session(session.id).await, Ok(true));
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.end_session(session.id).await,
        Ok(false),
        "an ended session is not ended twice"
    );
    let ended = work
        .read_session(session.id)
        .await
        .expect("a read")
        .expect("the session is kept");
    assert_eq!(ended.state, SessionState::Ended);

    // A request is read until it expires, and taken once.
    let pending = PendingAuthorization {
        id: mint_id(app).expect("an identifier"),
        browser_digest: vec![4; 32],
        client_id: "webapp".to_owned(),
        redirect_uri: "https://app.example.org/cb".to_owned(),
        scopes: vec!["openid".to_owned()],
        state: Some("state".to_owned()),
        nonce: None,
        code_challenge: "challenge".to_owned(),
        expires_at: now + Duration::minutes(10),
        expected_person: Some(ada.id),
    };
    work.insert_pending_authorization(&pending)
        .await
        .expect("a pending request");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.read_pending_authorization(pending.id, now).await,
        Ok(Some(pending.clone()))
    );
    let later = now + Duration::minutes(11);
    assert_eq!(
        work.read_pending_authorization(pending.id, later).await,
        Ok(None)
    );
    assert_eq!(
        work.take_pending_authorization(pending.id, later).await,
        Ok(None),
        "an expired request is not taken"
    );
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.take_pending_authorization(pending.id, now).await,
        Ok(None)
    );
    assert_eq!(
        work.take_pending_authorization(pending.id, now).await,
        Ok(Some(pending.clone()))
    );
    assert_eq!(
        work.take_pending_authorization(pending.id, now).await,
        Ok(None)
    );

    work.commit().await.expect("a commit");
    check_that_a_code_is_spent_once(app, scope, other, &session).await;
}

/// A code is spent once, and not after it expired. A spent code is kept, so
/// that an exchange that comes after can be told.
async fn check_that_a_code_is_spent_once(
    app: &App,
    scope: RealmScope,
    other: RealmScope,
    session: &crate::login::session::Session,
) {
    use time::Duration;

    use crate::oidc::code::AuthorizationCode;

    let now = app.now();
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let code = AuthorizationCode {
        code_digest: vec![8; 32],
        client_id: "webapp".to_owned(),
        person: session.person,
        session: session.id,
        redirect_uri: "https://app.example.org/cb".to_owned(),
        scopes: vec!["openid".to_owned()],
        nonce: Some("nonce".to_owned()),
        code_challenge: "challenge".to_owned(),
        authenticated_at: now,
        expires_at: now + Duration::minutes(1),
    };
    work.insert_authorization_code(&code).await.expect("a code");
    assert_eq!(
        work.spend_authorization_code(&code.code_digest, now + Duration::minutes(2))
            .await,
        Ok(None)
    );
    assert_eq!(
        work.mark_code_replayed(&code.code_digest, "webapp", now)
            .await,
        Ok(None),
        "a code not spent yet is not a replay"
    );
    assert_eq!(
        work.spend_authorization_code(&code.code_digest, now).await,
        Ok(Some(code.clone()))
    );
    assert_eq!(
        work.spend_authorization_code(&code.code_digest, now).await,
        Ok(None)
    );
    work.commit().await.expect("a commit");
    check_what_a_replayed_code_finds(app, scope, other, &code, session).await;
}

/// A spent code tells what it obtained, to its own client and in its realm
/// only. Once marked as presented again, it binds nothing more.
async fn check_what_a_replayed_code_finds(
    app: &App,
    scope: RealmScope,
    other: RealmScope,
    code: &crate::oidc::code::AuthorizationCode,
    session: &crate::login::session::Session,
) {
    use crate::oidc::code::ReplayedCode;

    let now = app.now();
    let family = mint_id(app).expect("an identifier");
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.bind_code_family(&code.code_digest, family).await,
        Ok(false)
    );
    assert_eq!(
        elsewhere
            .mark_code_replayed(&code.code_digest, "webapp", now)
            .await,
        Ok(None)
    );
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.bind_code_family(&code.code_digest, family).await,
        Ok(true)
    );
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.mark_code_replayed(&code.code_digest, "another-client", now)
            .await,
        Ok(None)
    );
    let replayed = Some(ReplayedCode {
        person: session.person,
        family: Some(family),
    });
    assert_eq!(
        work.mark_code_replayed(&code.code_digest, "webapp", now)
            .await,
        Ok(replayed.clone())
    );
    assert_eq!(
        work.bind_code_family(&code.code_digest, family).await,
        Ok(false),
        "a code presented again binds nothing more"
    );
    assert_eq!(
        work.mark_code_replayed(&code.code_digest, "webapp", now)
            .await,
        Ok(replayed),
        "a second replay finds the same"
    );
    work.commit().await.expect("a commit");

    // Marked before its exchange finished, a code binds no family.
    let early = crate::oidc::code::AuthorizationCode {
        code_digest: vec![9; 32],
        ..code.clone()
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_authorization_code(&early)
        .await
        .expect("a code");
    assert_eq!(
        work.spend_authorization_code(&early.code_digest, now).await,
        Ok(Some(early.clone()))
    );
    assert_eq!(
        work.mark_code_replayed(&early.code_digest, "webapp", now)
            .await,
        Ok(Some(ReplayedCode {
            person: session.person,
            family: None,
        }))
    );
    assert_eq!(
        work.bind_code_family(&early.code_digest, family).await,
        Ok(false)
    );
}

/// What any storage owes to refresh tokens: a token is spent once, by the
/// client it was issued to, in its realm; a used token stays readable so
/// that a replay can be told; a family and a session are revoked whole.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_refresh_contract(app: &App) {
    use time::Duration;

    use crate::login::session::{Session, SessionState};
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::tokens::store::RefreshToken;

    let scope = create_realm(app, "contract-refresh").await;
    let other = create_realm(app, "contract-refresh-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let open = || Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let (first_session, second_session) = (open(), open());
    let mint = |digest: u8, family: Uuid, session: &Session, lifetime: Duration| RefreshToken {
        token_digest: vec![digest; 32],
        family,
        client_id: "webapp".to_owned(),
        person: ada.id,
        session: session.id,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        issued_at: now,
        expires_at: now + lifetime,
    };
    let family = mint_id(app).expect("an identifier");
    let other_family = mint_id(app).expect("an identifier");
    let first = mint(1, family, &first_session, Duration::minutes(30));
    let second = mint(2, family, &first_session, Duration::minutes(30));
    let stale = mint(3, other_family, &second_session, Duration::seconds(-1));
    let apart = mint(4, other_family, &second_session, Duration::minutes(30));

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&first_session)
        .await
        .expect("a session");
    work.insert_session(&second_session)
        .await
        .expect("a second session");
    for token in [&first, &second, &stale, &apart] {
        work.insert_refresh_token(token).await.expect("a token");
    }
    work.commit().await.expect("a commit");

    // Unknown in another realm: not read, not spent, not revoked.
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.read_refresh_token(&first.token_digest).await,
        Ok(None)
    );
    assert_eq!(
        elsewhere
            .spend_refresh_token(&first.token_digest, "webapp", now)
            .await,
        Ok(None)
    );
    assert_eq!(elsewhere.revoke_refresh_family(family, now).await, Ok(0));
    drop(elsewhere);

    // Read back equal and unused. Not spent by another client, nor once expired.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let stored = work
        .read_refresh_token(&first.token_digest)
        .await
        .expect("a read")
        .expect("the token");
    assert_eq!(stored.token, first);
    assert_eq!((stored.used_at, stored.revoked_at), (None, None));
    assert_eq!(
        work.spend_refresh_token(&first.token_digest, "another-client", now)
            .await,
        Ok(None)
    );
    assert_eq!(
        work.spend_refresh_token(&stale.token_digest, "webapp", now)
            .await,
        Ok(None)
    );

    // Spent once. The used token stays, and says when it was used.
    assert_eq!(
        work.spend_refresh_token(&first.token_digest, "webapp", now)
            .await,
        Ok(Some(first.clone()))
    );
    assert_eq!(
        work.spend_refresh_token(&first.token_digest, "webapp", now)
            .await,
        Ok(None)
    );
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let used = work
        .read_refresh_token(&first.token_digest)
        .await
        .expect("a read")
        .expect("the used token is kept");
    assert_eq!(used.used_at, Some(now));
    assert!(!used.is_live(now));

    // A family is revoked whole, used tokens included, and once.
    assert_eq!(work.revoke_refresh_family(family, now).await, Ok(2));
    assert_eq!(work.revoke_refresh_family(family, now).await, Ok(0));
    assert_eq!(
        work.spend_refresh_token(&second.token_digest, "webapp", now)
            .await,
        Ok(None)
    );
    let untouched = work
        .read_refresh_token(&apart.token_digest)
        .await
        .expect("a read")
        .expect("the token of the other family");
    assert!(untouched.is_live(now));

    // Written into a family once it was revoked, as a rotation in flight
    // does, a token is not spent and reads as revoked.
    let late = mint(6, family, &first_session, Duration::minutes(30));
    work.insert_refresh_token(&late).await.expect("a token");
    assert_eq!(
        work.spend_refresh_token(&late.token_digest, "webapp", now)
            .await,
        Ok(None)
    );
    let late = work
        .read_refresh_token(&late.token_digest)
        .await
        .expect("a read")
        .expect("the late token");
    assert_eq!(late.revoked_at, Some(now));
    assert!(!late.is_live(now));

    // A session takes its tokens with it, and only its own.
    assert_eq!(
        work.revoke_refresh_tokens_of_session(second_session.id, now)
            .await,
        Ok(2)
    );
    assert_eq!(
        work.spend_refresh_token(&apart.token_digest, "webapp", now)
            .await,
        Ok(None)
    );
    work.commit().await.expect("a commit");

    // Abandoned, a spend leaves the token as it was.
    let again = mint(
        5,
        mint_id(app).expect("an identifier"),
        &first_session,
        Duration::minutes(30),
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_refresh_token(&again).await.expect("a token");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.spend_refresh_token(&again.token_digest, "webapp", now)
            .await,
        Ok(Some(again.clone()))
    );
    drop(work);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.spend_refresh_token(&again.token_digest, "webapp", now)
            .await,
        Ok(Some(again))
    );
}

/// What any storage owes to the browsers people signed in from: one is read
/// back in its realm only and until it expires, lives longer when kept
/// again, never changes hands, and a person keeps the few that expire last.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
pub async fn check_known_browsers_contract(app: &App) {
    use time::Duration;

    use crate::login::store::KnownBrowser;
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-browsers").await;
    let other = create_realm(app, "contract-browsers-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let bob = create_person(app, scope, "bob", "correct horse battery").await;
    let now = app.now();
    let browser = |device: u128, person: Uuid, days: i64| KnownBrowser {
        device: Uuid::from_u128(device),
        person,
        expires_at: now + Duration::days(days),
    };

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.remember_browser(&browser(1, ada.id, 10), 2)
        .await
        .expect("a browser");
    work.commit().await.expect("a commit");
    let devices =
        |numbers: &[u128]| -> Vec<Uuid> { numbers.iter().copied().map(Uuid::from_u128).collect() };
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.read_live_browsers(&devices(&[1]), now).await,
        Ok(Vec::new())
    );
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.read_live_browsers(&devices(&[1, 9]), now).await,
        Ok(vec![browser(1, ada.id, 10)])
    );
    assert_eq!(
        work.read_live_browsers(&devices(&[1]), now + Duration::days(10))
            .await,
        Ok(Vec::new()),
        "a browser is believed until it expires, not at that instant"
    );
    // Kept again, it lives longer. Kept for someone else, it does not move.
    work.remember_browser(&browser(1, ada.id, 20), 2)
        .await
        .expect("a browser kept again");
    work.remember_browser(&browser(1, bob.id, 30), 2)
        .await
        .expect("a claim that changes nothing");
    assert_eq!(
        work.read_live_browsers(&devices(&[1]), now).await,
        Ok(vec![browser(1, ada.id, 20)])
    );
    // Of three browsers of ada, the one that expires first is forgotten.
    work.remember_browser(&browser(2, ada.id, 5), 2)
        .await
        .expect("a second browser");
    work.remember_browser(&browser(3, ada.id, 15), 2)
        .await
        .expect("a third browser");
    let mut live = work
        .read_live_browsers(&devices(&[3, 2, 1]), now)
        .await
        .expect("a read");
    live.sort_by_key(|browser| browser.device);
    assert_eq!(live, [browser(1, ada.id, 20), browser(3, ada.id, 15)]);
    work.commit().await.expect("a commit");
}
