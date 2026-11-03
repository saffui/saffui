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
}
