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
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_keys_contract(app: &App) {
    use crate::keys::jwks::{open_signing_key, publish_key_set};
    use crate::keys::{KeyStatus, SIGNING_KEY_PURPOSE, SealedSigningKey};
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
    let (es256, rs256) = (SignatureAlgorithm::Es256, SignatureAlgorithm::Rs256);

    // A realm is born with its data key and an active key of ES256 and of RS256.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let data_key = work
        .read_data_key()
        .await
        .expect("a read")
        .expect("a data key");
    assert_eq!(data_key.generation, 1);
    // Born at one instant: their order says nothing of their algorithm.
    let mut keys = work.list_signing_keys().await.expect("the keys");
    keys.sort_by_key(|key| key.algorithm.name());
    let algorithms: Vec<SignatureAlgorithm> = keys.iter().map(|key| key.algorithm).collect();
    assert_eq!(algorithms, [es256, rs256]);
    assert!(keys.iter().all(|key| key.status == KeyStatus::Active));
    assert_eq!(keys[0].public_jwk["kid"], keys[0].key_id.as_str());
    assert_eq!(work.count_signing_keys().await, Ok(2));
    assert_eq!(
        work.read_signing_key(&keys[1].key_id).await,
        Ok(Some(keys[1].clone()))
    );
    assert_eq!(work.read_signing_key("no-such-kid").await, Ok(None));

    // What is published is the public half, read without any private one:
    // the private halves are read by algorithm, of the active keys alone.
    let published = publish_key_set(app, scope).await.expect("a key set");
    assert_eq!(published.keys.len(), 2);
    for key in &keys {
        assert!(published.keys.contains(&key.public_jwk), "{}", key.key_id);
    }
    let sealed = work
        .read_active_keys(&[es256])
        .await
        .expect("the key that signs");
    assert_eq!(sealed.len(), 1, "one key per algorithm asked");
    assert_eq!(sealed[0].key, keys[0]);
    let (key, _private_key) = open_signing_key(app, work.as_mut(), es256)
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
            .open(&data_key, &elsewhere, &sealed[0].sealed_private_key)
            .is_err(),
        "a sealed key moved to another row does not open"
    );

    // A generation of the data key is written once, and so is a key.
    assert!(work.insert_data_key(&data_key).await.is_err());
    drop(work);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert!(work.insert_signing_key(&sealed[0]).await.is_err());
    drop(work);

    // A newer generation is the one read, and the one the lock returns.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let newer = app
        .sealer
        .make_data_key(scope.tenant().as_uuid(), scope.realm().as_uuid(), 2)
        .expect("a data key");
    work.insert_data_key(&newer)
        .await
        .expect("a second generation");
    assert_eq!(work.read_data_key().await, Ok(Some(newer.clone())));
    assert_eq!(work.lock_signing_keys().await, Ok(Some(newer)));
    drop(work);

    // One key of an algorithm is active at a time.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let second = SealedSigningKey {
        key: crate::keys::SigningKey {
            id: mint_id(app).expect("an identifier"),
            key_id: "second-es256".to_owned(),
            ..keys[0].clone()
        },
        sealed_private_key: sealed[0].sealed_private_key.clone(),
    };
    assert!(
        work.insert_signing_key(&second).await.is_err(),
        "a second active key of ES256 is refused"
    );
    drop(work);

    // A key is retired once, and removed only once retired.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.lock_signing_keys().await.expect("the keys taken");
    assert_eq!(
        work.delete_retired_key(key.id).await,
        Ok(false),
        "an active key stays"
    );
    assert_eq!(work.retire_signing_key(key.id).await, Ok(true));
    assert_eq!(work.retire_signing_key(key.id).await, Ok(false));
    work.insert_signing_key(&second)
        .await
        .expect("a new active key once the first is retired");
    let listed = work.list_signing_keys().await.expect("the keys");
    let status_of = |id| listed.iter().find(|key| key.id == id).map(|key| key.status);
    assert_eq!(status_of(key.id), Some(KeyStatus::Retired));
    assert_eq!(status_of(second.key.id), Some(KeyStatus::Active));
    let signing = work
        .read_active_keys(&[es256, rs256])
        .await
        .expect("the keys that sign");
    let mut signing: Vec<&str> = signing
        .iter()
        .map(|sealed| sealed.key.key_id.as_str())
        .collect();
    signing.sort_unstable();
    let mut expected = [second.key.key_id.as_str(), keys[1].key_id.as_str()];
    expected.sort_unstable();
    assert_eq!(signing, expected, "a retired key is never read to sign");
    assert_eq!(work.delete_retired_key(key.id).await, Ok(true));
    assert_eq!(work.delete_retired_key(key.id).await, Ok(false));
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let mut kept: Vec<String> = work
        .list_signing_keys()
        .await
        .expect("the keys")
        .into_iter()
        .map(|key| key.key_id)
        .collect();
    kept.sort_unstable();
    let mut expected = [keys[1].key_id.clone(), second.key.key_id.clone()];
    expected.sort_unstable();
    assert_eq!(
        kept, expected,
        "the removal was kept, and nothing else went"
    );
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
    use crate::authz::capability::Capability;
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
        requires_consent: false,
        scopes: vec!["invoices:read".to_owned(), "invoices:write".to_owned()],
        capabilities: vec![
            crate::authz::capability::Capability::ClientRead,
            crate::authz::capability::Capability::AuditRead,
        ],
        id_token_signed_response_alg: None,
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
        requires_consent: true,
        capabilities: Vec::new(),
        id_token_signed_response_alg: Some(crate::ports::crypto::SignatureAlgorithm::Ps256),
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

    // What a client may do is replaced whole, for a client that acts as
    // itself only: an application holds no capability.
    let held = [Capability::KeyRead, Capability::KeyWrite];
    assert_eq!(
        work.write_client_capabilities("nobody", &held).await,
        Ok(false)
    );
    assert_eq!(
        work.write_client_capabilities("billing", &held).await,
        Ok(true)
    );
    assert_eq!(
        work.read_client("billing")
            .await
            .map(|client| client.map(|client| client.capabilities)),
        Ok(Some(held.to_vec()))
    );
    work.insert_client(&application)
        .await
        .expect("an application");
    assert!(
        work.write_client_capabilities("webapp", &held)
            .await
            .is_err(),
        "an application is granted no capability"
    );
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

    use crate::login::session::{
        AuthenticationMethod, ReadSession, Session, SessionKind, SessionState,
    };
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-sign-in").await;
    let other = create_realm(app, "contract-sign-in-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();

    // A session is read back equal, in its realm only. An offline one has
    // no secret, and says what it is.
    let session = Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![3; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let offline = Session {
        id: mint_id(app).expect("an identifier"),
        secret_digest: Vec::new(),
        kind: SessionKind::Offline,
        ..session.clone()
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.insert_session(&offline)
        .await
        .expect("an offline session");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for kept in [&session, &offline] {
        assert_eq!(
            work.read_session(kept.id).await,
            Ok(Some(ReadSession {
                session: kept.clone(),
                person_holds_factor: false,
            }))
        );
    }
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

    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
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
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
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
    assert_eq!(ended.session.state, SessionState::Ended);

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
        first_factor: None,
        key_proof: None,
        consent_prompted: true,
        consent_session: None,
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
    let pending = check_that_a_first_factor_is_kept(app, work.as_mut(), pending, ada.id).await;
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

/// Who proved their password is written on a request that still waits,
/// and on no other. Returns the request as it now reads.
async fn check_that_a_first_factor_is_kept(
    app: &App,
    work: &mut dyn crate::ports::storage::UnitOfWork,
    pending: crate::oidc::code::PendingAuthorization,
    person: Uuid,
) -> crate::oidc::code::PendingAuthorization {
    let now = app.now();
    let key_proof = crate::oidc::code::PendingKeyProof {
        state: vec![5; 12],
        options: serde_json::json!({ "challenge": "c" }),
    };
    assert_eq!(
        work.mark_first_factor(pending.id, person, None, pending.expires_at)
            .await,
        Ok(false)
    );
    assert_eq!(
        work.mark_first_factor(mint_id(app).expect("an identifier"), person, None, now)
            .await,
        Ok(false)
    );
    assert_eq!(
        work.mark_first_factor(pending.id, person, Some(&key_proof), now)
            .await,
        Ok(true)
    );
    let pending = crate::oidc::code::PendingAuthorization {
        first_factor: Some(person),
        key_proof: Some(key_proof),
        ..pending
    };
    assert_eq!(
        work.read_pending_authorization(pending.id, now).await,
        Ok(Some(pending.clone()))
    );
    pending
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

/// A spent code tells what it obtained, to its own client, in its realm, and
/// once. Once marked as presented again, it binds nothing more.
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
    assert_eq!(
        work.mark_code_replayed(&code.code_digest, "webapp", now)
            .await,
        Ok(Some(ReplayedCode {
            person: session.person,
            session: session.id,
            family: Some(family),
        }))
    );
    assert_eq!(
        work.bind_code_family(&code.code_digest, family).await,
        Ok(false),
        "a code presented again binds nothing more"
    );
    assert_eq!(
        work.mark_code_replayed(&code.code_digest, "webapp", now)
            .await,
        Ok(None),
        "a second replay finds nothing left to take back"
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
            session: session.id,
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

    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::tokens::store::{EndedFamily, RefreshToken};

    let scope = create_realm(app, "contract-refresh").await;
    let other = create_realm(app, "contract-refresh-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let open = || Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let (first_session, second_session) = (open(), open());
    let offline_session = Session {
        secret_digest: Vec::new(),
        kind: SessionKind::Offline,
        ..open()
    };
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
    let second = RefreshToken {
        issued_at: now + Duration::minutes(1),
        ..mint(2, family, &first_session, Duration::minutes(30))
    };
    let stale = mint(3, other_family, &second_session, Duration::seconds(-1));
    let apart = mint(4, other_family, &second_session, Duration::minutes(30));
    let offline_family = mint_id(app).expect("an identifier");
    let held_offline = mint(8, offline_family, &offline_session, Duration::minutes(30));

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&first_session)
        .await
        .expect("a session");
    work.insert_session(&second_session)
        .await
        .expect("a second session");
    work.insert_session(&offline_session)
        .await
        .expect("an offline session");
    for token in [&first, &second, &stale, &apart, &held_offline] {
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
    assert_eq!(elsewhere.revoke_refresh_family(family, now).await, Ok(None));
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

    // A family is refused as soon as one of its tokens is revoked, and said
    // so once. The browser session it lived in stands; an offline one is
    // ended for its family.
    assert_eq!(
        work.end_offline_session_of_family(family).await,
        Ok(None),
        "a family of a browser session leaves it standing"
    );
    assert_eq!(
        work.revoke_refresh_family(family, now).await,
        Ok(Some(EndedFamily {
            tokens: 2,
            last_issued_at: second.issued_at,
            last_used_at: Some(now),
        })),
        "how many, the latest issued and the latest used"
    );
    assert_eq!(
        work.revoke_refresh_family(family, now).await,
        Ok(None),
        "a family refused already is not revoked again"
    );
    assert_eq!(
        work.end_offline_session_of_family(offline_family).await,
        Ok(Some(offline_session.id))
    );
    assert_eq!(
        work.end_offline_session_of_family(offline_family).await,
        Ok(None),
        "an offline session is ended once"
    );
    assert_eq!(
        work.revoke_refresh_family(offline_family, now).await,
        Ok(Some(EndedFamily {
            tokens: 1,
            last_issued_at: now,
            last_used_at: None,
        }))
    );
    for (session, state) in [
        (&first_session, SessionState::Active),
        (&offline_session, SessionState::Ended),
    ] {
        let read = work
            .read_session(session.id)
            .await
            .expect("a read")
            .expect("the session");
        assert_eq!(read.session.state, state, "{:?}", session.kind);
    }
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
    drop(work);
    check_that_the_oldest_offline_sessions_give_way(app).await;
}

/// Past what a person keeps offline with one client, the oldest of their
/// offline sessions with it give way: none of another client, of a browser,
/// or that expired already, and none twice.
async fn check_that_the_oldest_offline_sessions_give_way(app: &App) {
    use time::Duration;

    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::tokens::store::RefreshToken;

    let scope = create_realm(app, "contract-offline-bound").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let open = |kind: SessionKind, ends_in: Duration| Session {
        id: mint_id(app).expect("an identifier"),
        person: ada.id,
        secret_digest: match kind {
            SessionKind::Browser => vec![7; 32],
            SessionKind::Offline => Vec::new(),
        },
        state: SessionState::Active,
        kind,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + ends_in,
    };
    let held = [
        (open(SessionKind::Offline, Duration::days(1)), "webapp"),
        (open(SessionKind::Offline, Duration::days(2)), "webapp"),
        (open(SessionKind::Offline, Duration::days(3)), "webapp"),
        (open(SessionKind::Offline, Duration::minutes(-1)), "webapp"),
        (open(SessionKind::Browser, Duration::hours(1)), "webapp"),
        (open(SessionKind::Offline, Duration::hours(12)), "portal"),
    ];
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for (digest, (session, client_id)) in (1_u8..).zip(&held) {
        work.insert_session(session).await.expect("a session");
        work.insert_refresh_token(&RefreshToken {
            token_digest: vec![digest; 32],
            family: mint_id(app).expect("an identifier"),
            client_id: (*client_id).to_owned(),
            person: ada.id,
            session: session.id,
            scopes: vec!["openid".to_owned()],
            issued_at: now,
            expires_at: session.expires_at,
        })
        .await
        .expect("a token");
    }
    work.commit().await.expect("a commit");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.end_oldest_offline_sessions(ada.id, "webapp", 2, now)
            .await,
        Ok(vec![held[0].0.id]),
        "the oldest of the three that stand gives way"
    );
    assert_eq!(
        work.end_oldest_offline_sessions(ada.id, "webapp", 2, now)
            .await,
        Ok(Vec::new()),
        "two stand: none gives way"
    );
    for (rank, (session, _)) in held.iter().enumerate() {
        let read = work
            .read_session(session.id)
            .await
            .expect("a read")
            .expect("the session");
        let state = if rank == 0 {
            SessionState::Ended
        } else {
            SessionState::Active
        };
        assert_eq!(read.session.state, state, "session {rank}");
    }
    work.commit().await.expect("a commit");
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

/// The first accepted step confirms the very secret it was judged against,
/// and a confirmed one signs in. A step is accepted once, and never one at
/// or before the last.
async fn check_that_a_step_is_accepted_once(
    work: &mut dyn crate::ports::storage::UnitOfWork,
    person: Uuid,
    judged: &[u8],
    now: time::OffsetDateTime,
) {
    use time::Duration;

    use crate::login::store::TotpUse;

    let (confirm, sign_in) = (TotpUse::Confirmation, TotpUse::SignIn);
    assert_eq!(
        work.accept_totp_step(person, &[1; 24], 10, confirm, now)
            .await,
        Ok(false),
        "the secret was replaced since it was judged"
    );
    assert_eq!(
        work.accept_totp_step(person, judged, 10, sign_in, now)
            .await,
        Ok(false),
        "a secret nobody confirmed signs nobody in"
    );
    assert_eq!(
        work.accept_totp_step(person, judged, 10, confirm, now)
            .await,
        Ok(true)
    );
    assert_eq!(
        work.accept_totp_step(person, judged, 11, confirm, now)
            .await,
        Ok(false),
        "a secret is confirmed once"
    );
    assert_eq!(
        work.accept_totp_step(person, judged, 10, sign_in, now)
            .await,
        Ok(false)
    );
    assert_eq!(
        work.accept_totp_step(person, judged, 9, sign_in, now).await,
        Ok(false)
    );
    let later = now + Duration::seconds(30);
    assert_eq!(
        work.accept_totp_step(person, judged, 11, sign_in, later)
            .await,
        Ok(true)
    );
}

/// The codes of a person who typed one are forgotten only while they are
/// fewer than a bound.
async fn check_that_code_attempts_are_forgotten_below_a_bound(
    work: &mut dyn crate::ports::storage::UnitOfWork,
    person: Uuid,
    now: time::OffsetDateTime,
) {
    assert_eq!(work.count_code_attempt(person, now).await, Ok(2));
    work.clear_code_attempts_below(person, 2)
        .await
        .expect("an answer");
    assert_eq!(
        work.count_code_attempt(person, now).await,
        Ok(3),
        "two codes are not fewer than two: kept"
    );
    work.clear_code_attempts_below(person, 4)
        .await
        .expect("an answer");
    assert_eq!(
        work.count_code_attempt(person, now).await,
        Ok(1),
        "three codes are fewer than four: forgotten"
    );
}

/// Asks twice whether `person` holds a second factor: alone, and with a
/// session of theirs written in `work` and read back.
async fn ask_whether_holder(
    app: &App,
    work: &mut dyn crate::ports::storage::UnitOfWork,
    person: Uuid,
) -> [bool; 2] {
    use time::Duration;

    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};

    let now = app.now();
    let session = Session {
        id: mint_id(app).expect("an identifier"),
        person,
        secret_digest: vec![8; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    work.insert_session(&session).await.expect("a session");
    let read = work
        .read_session(session.id)
        .await
        .expect("a read")
        .expect("the session");
    let alone = work.holds_second_factor(person).await.expect("an answer");
    [alone, read.person_holds_factor]
}

/// What any storage owes to the authenticator of a person: a secret that
/// was never confirmed can be replaced and a confirmed one cannot, a time
/// step is accepted once and never one before it, it is a second factor
/// once confirmed, and nothing of it is reachable from another realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
pub async fn check_authenticators_contract(app: &App) {
    use crate::login::store::{TotpAuthenticator, TotpUse};
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-authenticators").await;
    let other = create_realm(app, "contract-authenticators-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let offer = |secret: u8| TotpAuthenticator {
        person: ada.id,
        sealed_secret: vec![secret; 24],
        confirmed_at: None,
        last_step: None,
        created_at: now,
    };

    let confirm = TotpUse::Confirmation;
    let judged = vec![2_u8; 24];

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_totp(ada.id).await, Ok(None));
    assert_eq!(
        work.accept_totp_step(ada.id, &judged, 10, confirm, now)
            .await,
        Ok(false)
    );
    assert_eq!(work.delete_totp(ada.id).await, Ok(false));

    // A secret nobody confirmed is replaced by the next one.
    assert_eq!(work.write_pending_totp(&offer(1)).await, Ok(true));
    assert_eq!(
        work.write_pending_totp(&offer(2)).await,
        Ok(true),
        "a secret in place of one never confirmed"
    );
    assert_eq!(work.read_totp(ada.id).await, Ok(Some(offer(2))));
    assert_eq!(
        ask_whether_holder(app, work.as_mut(), ada.id).await,
        [false; 2],
        "a secret nobody confirmed is no factor"
    );
    work.commit().await.expect("a commit");

    // Unknown from another realm.
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_totp(ada.id).await, Ok(None));
    assert_eq!(
        elsewhere
            .accept_totp_step(ada.id, &judged, 10, confirm, now)
            .await,
        Ok(false)
    );
    assert_eq!(elsewhere.delete_totp(ada.id).await, Ok(false));
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    check_that_a_step_is_accepted_once(work.as_mut(), ada.id, &judged, now).await;
    let confirmed = work
        .read_totp(ada.id)
        .await
        .expect("a read")
        .expect("the authenticator");
    assert_eq!(
        (confirmed.confirmed_at, confirmed.last_step),
        (Some(now), Some(11)),
        "the instant of the confirmation is the one of the first code"
    );
    assert_eq!(
        ask_whether_holder(app, work.as_mut(), ada.id).await,
        [true; 2]
    );

    // A confirmed authenticator is not replaced.
    assert_eq!(work.write_pending_totp(&offer(3)).await, Ok(false));
    assert_eq!(
        work.read_totp(ada.id)
            .await
            .expect("a read")
            .map(|known| known.sealed_secret),
        Some(vec![2; 24])
    );
    work.commit().await.expect("a commit");

    // Removed, it is gone, and a new one can be offered.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.delete_totp(ada.id).await, Ok(true));
    assert_eq!(work.read_totp(ada.id).await, Ok(None));
    assert_eq!(work.write_pending_totp(&offer(4)).await, Ok(true));
    work.commit().await.expect("a commit");

    // The codes a person typed are counted across units of work, and
    // forgotten all at once.
    for expected in 1..=3 {
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        assert_eq!(work.count_code_attempt(ada.id, now).await, Ok(expected));
        work.commit().await.expect("a commit");
    }
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.clear_code_attempts(ada.id).await.expect("forgotten");
    work.clear_code_attempts(ada.id)
        .await
        .expect("nothing to forget");
    assert_eq!(work.count_code_attempt(ada.id, now).await, Ok(1));
    work.commit().await.expect("a commit");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    check_that_code_attempts_are_forgotten_below_a_bound(work.as_mut(), ada.id, now).await;
    work.commit().await.expect("a commit");
}

/// What any storage owes to the sessions of a person a factor ends: every
/// active one proven by exactly the methods named ends in one go, but the one
/// kept, and their refresh tokens with them; no other, nor any of another realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
pub async fn check_ended_sessions_contract(app: &App) {
    use time::Duration;

    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use crate::testkit::fixtures::{create_person, create_realm};
    use crate::tokens::store::RefreshToken;

    let scope = create_realm(app, "contract-ended-sessions").await;
    let other = create_realm(app, "contract-ended-sessions-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let bob = create_person(app, scope, "bob", "correct horse battery").await;
    let now = app.now();
    let password = [AuthenticationMethod::Password];
    let open = |person: Uuid, methods: &[AuthenticationMethod]| Session {
        id: mint_id(app).expect("an identifier"),
        person,
        secret_digest: vec![9; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: methods.to_vec(),
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    // Many: no number stops the end.
    let opened: Vec<Session> = (0..120).map(|_| open(ada.id, &password)).collect();
    let kept = open(ada.id, &password);
    let proven = open(
        ada.id,
        &[
            AuthenticationMethod::Password,
            AuthenticationMethod::OneTimeCode,
        ],
    );
    let of_bob = open(bob.id, &password);
    let mint = |digest: u8, session: &Session| RefreshToken {
        token_digest: vec![digest; 32],
        family: mint_id(app).expect("an identifier"),
        client_id: "webapp".to_owned(),
        person: session.person,
        session: session.id,
        scopes: vec!["openid".to_owned()],
        issued_at: now,
        expires_at: now + Duration::minutes(30),
    };
    let tokens = [
        mint(1, &opened[0]),
        mint(2, &opened[0]),
        mint(3, &opened[119]),
        mint(4, &kept),
        mint(5, &of_bob),
    ];

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for session in opened.iter().chain([&kept, &proven, &of_bob]) {
        work.insert_session(session).await.expect("a session");
    }
    for token in &tokens {
        work.insert_refresh_token(token).await.expect("a token");
    }
    work.commit().await.expect("a commit");

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere
            .end_sessions_proven_only_by(ada.id, &password, None)
            .await,
        Ok(vec![])
    );
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let mut ended = work
        .end_sessions_proven_only_by(ada.id, &password, Some(kept.id))
        .await
        .expect("an end");
    ended.sort_unstable();
    let mut expected: Vec<Uuid> = opened.iter().map(|session| session.id).collect();
    expected.sort_unstable();
    assert_eq!(ended, expected);
    assert_eq!(
        work.revoke_refresh_tokens_of_sessions(&ended, now).await,
        Ok(3),
        "the tokens of the ended sessions, not those of the kept one or of bob"
    );
    assert_eq!(
        work.revoke_refresh_tokens_of_sessions(&ended, now).await,
        Ok(0)
    );
    assert_eq!(
        work.end_sessions_proven_only_by(ada.id, &password, Some(kept.id))
            .await,
        Ok(vec![]),
        "an ended session is not ended twice"
    );
    for (session, state) in [
        (&opened[7], SessionState::Ended),
        (&kept, SessionState::Active),
        (&proven, SessionState::Active),
        (&of_bob, SessionState::Active),
    ] {
        let read = work.read_session(session.id).await.expect("a read");
        assert_eq!(read.map(|read| read.session.state), Some(state));
    }
    work.commit().await.expect("a commit");
}

async fn check_that_a_key_is_a_factor_of_its_person(
    app: &App,
    work: &mut dyn crate::ports::storage::UnitOfWork,
    holder: Uuid,
    other: Uuid,
) {
    assert_eq!(ask_whether_holder(app, work, holder).await, [true; 2]);
    assert_eq!(
        ask_whether_holder(app, work, other).await,
        [false; 2],
        "the keys of someone else are no factor"
    );
}

/// What any storage owes to the security keys of a person: a key is enrolled
/// once in a realm and is a second factor of its person only, a use is kept
/// only against the record it was judged with, an enrollment is taken once
/// and not after it expired, and nothing of it is reachable from another
/// realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
pub async fn check_security_keys_contract(app: &App) {
    use time::Duration;

    use crate::login::store::SecurityKey;
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-security-keys").await;
    let other = create_realm(app, "contract-security-keys-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let bob = create_person(app, scope, "bob", "correct horse battery").await;
    let now = app.now();
    let key = |name: u8, person: Uuid, minutes: i64| SecurityKey {
        credential_id: vec![name; 16],
        person,
        record: vec![name, 0],
        created_at: now + Duration::minutes(minutes),
        last_used_at: None,
    };

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.insert_security_key(&key(2, ada.id, 1)).await, Ok(true));
    assert_eq!(work.insert_security_key(&key(1, ada.id, 0)).await, Ok(true));
    assert_eq!(
        work.insert_security_key(&key(1, bob.id, 2)).await,
        Ok(false),
        "a credential is enrolled once in a realm"
    );
    assert_eq!(
        work.list_security_keys(ada.id).await,
        Ok(vec![key(1, ada.id, 0), key(2, ada.id, 1)]),
        "the oldest first"
    );
    assert_eq!(work.list_security_keys(bob.id).await, Ok(vec![]));
    check_that_a_key_is_a_factor_of_its_person(app, work.as_mut(), ada.id, bob.id).await;

    // A use is kept against the key as it was read, once.
    let moved = [1_u8, 1];
    let judged = key(1, ada.id, 0);
    let stale = SecurityKey {
        record: vec![1, 9],
        ..judged.clone()
    };
    let of_bob = SecurityKey {
        person: bob.id,
        ..judged.clone()
    };
    assert_eq!(
        work.record_key_use(&stale, Some(&moved), now).await,
        Ok(false)
    );
    assert_eq!(
        work.record_key_use(&of_bob, Some(&moved), now).await,
        Ok(false),
        "the key of someone else"
    );
    assert_eq!(
        work.record_key_use(&judged, Some(&moved), now).await,
        Ok(true)
    );
    assert_eq!(
        work.record_key_use(&judged, Some(&moved), now).await,
        Ok(false),
        "of two uses judged against one reading, one is kept"
    );
    let used = work.list_security_keys(ada.id).await.expect("a list");
    assert_eq!(
        (used[0].record.clone(), used[0].last_used_at),
        (moved.to_vec(), Some(now))
    );
    // A key that counts nothing keeps its record: the instant of its last
    // use still tells two uses apart.
    let later = now + Duration::minutes(1);
    let read_once = used[0].clone();
    assert_eq!(work.record_key_use(&read_once, None, later).await, Ok(true));
    assert_eq!(
        work.record_key_use(&read_once, None, later).await,
        Ok(false),
        "of two uses of a key that counts nothing, one is kept"
    );
    work.commit().await.expect("a commit");

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.list_security_keys(ada.id).await, Ok(vec![]));
    assert_eq!(elsewhere.holds_second_factor(ada.id).await, Ok(false));
    assert_eq!(elsewhere.delete_security_keys(ada.id).await, Ok(0));
    drop(elsewhere);

    // An enrollment is replaced by a later start, taken once, and not after
    // it expired.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let soon = now + Duration::minutes(5);
    work.write_key_enrollment(ada.id, b"first", soon)
        .await
        .expect("an enrollment");
    work.write_key_enrollment(ada.id, b"second", soon)
        .await
        .expect("a later start");
    assert_eq!(work.take_key_enrollment(ada.id, soon).await, Ok(None));
    assert_eq!(
        work.take_key_enrollment(ada.id, now).await,
        Ok(Some(b"second".to_vec()))
    );
    assert_eq!(work.take_key_enrollment(ada.id, now).await, Ok(None));
    assert_eq!(work.delete_security_keys(ada.id).await, Ok(2));
    assert_eq!(work.list_security_keys(ada.id).await, Ok(vec![]));
    assert_eq!(work.holds_second_factor(ada.id).await, Ok(false));
    work.commit().await.expect("a commit");
}

/// What any storage owes to roles and groups: a name is taken once per
/// realm or per client, they are listed by name byte for byte, a deletion
/// answers once, and nothing of them is reachable from another realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_roles_contract(app: &App) {
    use crate::authz::roles::{Group, Role};
    use crate::clients::store::ListWindow;
    use crate::testkit::fixtures::{Application, create_realm, register_application};

    let scope = create_realm(app, "contract-roles").await;
    let other = create_realm(app, "contract-roles-other").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(app, scope, portal).await;
    let now = app.now();
    let identify = || mint_id(app).expect("an identifier");
    let make_role = |name: &str, client_id: Option<&str>| Role {
        id: identify(),
        client_id: client_id.map(str::to_owned),
        name: name.to_owned(),
        description: Some("what it lets do".to_owned()),
        created_at: now,
    };
    // Upper case sorts before lower case, byte for byte.
    let (admin, portal_admin, viewer) = (
        make_role("admin", None),
        make_role("admin", Some("portal")),
        make_role("Viewer", None),
    );
    let finance = Group {
        id: identify(),
        name: "finance".to_owned(),
        description: None,
        created_at: now,
    };

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for role in [&admin, &portal_admin, &viewer] {
        assert_eq!(work.insert_role(role).await, Ok(true));
    }
    assert_eq!(work.insert_group(&finance).await, Ok(true));
    assert_eq!(
        work.insert_role(&make_role("admin", Some("portal"))).await,
        Ok(false),
        "a name is taken once per client"
    );
    assert_eq!(
        work.insert_role(&make_role("admin", None)).await,
        Ok(false),
        "and once in the realm"
    );
    let twin = Group {
        id: identify(),
        ..finance.clone()
    };
    assert_eq!(work.insert_group(&twin).await, Ok(false));
    work.commit().await.expect("a commit");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    // By name, byte for byte, then by identifier where names tie.
    let mut ordered = vec![viewer.clone(), admin.clone(), portal_admin.clone()];
    ordered.sort_by(|left, right| (&left.name, left.id).cmp(&(&right.name, right.id)));
    assert_eq!(ordered[0], viewer, "upper case comes first");
    assert_eq!(
        work.list_roles(ListWindow { first: 0, max: 10 }).await,
        Ok(ordered.clone())
    );
    assert_eq!(
        work.list_roles(ListWindow { first: 1, max: 1 }).await,
        Ok(vec![ordered[1].clone()])
    );
    assert_eq!(work.count_roles().await, Ok(3));
    assert_eq!(
        work.read_role(portal_admin.id).await,
        Ok(Some(portal_admin.clone()))
    );
    assert_eq!(work.read_group(finance.id).await, Ok(Some(finance.clone())));
    let by_id = |mut roles: Vec<Role>| {
        roles.sort_by_key(|role| role.id);
        roles
    };
    assert_eq!(
        work.read_roles(&[admin.id, viewer.id, Uuid::from_u128(7)])
            .await
            .map(by_id),
        Ok(by_id(vec![admin.clone(), viewer.clone()])),
        "the roles named that the realm has, in one read"
    );
    assert_eq!(
        work.read_groups(&[finance.id, Uuid::from_u128(7)]).await,
        Ok(vec![finance.clone()])
    );
    assert_eq!(
        work.list_groups(ListWindow { first: 0, max: 10 }).await,
        Ok(vec![finance.clone()])
    );
    assert_eq!(work.count_groups().await, Ok(1));
    drop(work);

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_role(admin.id).await, Ok(None));
    assert_eq!(elsewhere.read_group(finance.id).await, Ok(None));
    assert_eq!(elsewhere.read_roles(&[admin.id]).await, Ok(Vec::new()));
    assert_eq!(elsewhere.read_groups(&[finance.id]).await, Ok(Vec::new()));
    assert_eq!(elsewhere.count_roles().await, Ok(0));
    assert_eq!(elsewhere.count_groups().await, Ok(0));
    assert_eq!(elsewhere.delete_role(admin.id).await, Ok(false));
    assert_eq!(elsewhere.delete_group(finance.id).await, Ok(false));
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.delete_role(admin.id).await, Ok(true));
    assert_eq!(work.delete_role(admin.id).await, Ok(false));
    assert_eq!(work.delete_group(finance.id).await, Ok(true));
    assert_eq!(work.delete_group(finance.id).await, Ok(false));
    assert_eq!(work.count_roles().await, Ok(2));
    work.commit().await.expect("a commit");
}

/// What any storage owes to grants and memberships: a grant replaces the one
/// its holder had, a role is held only while every grant on its way stands
/// and until the first of them ends, what is deleted takes its grants with
/// it, and nothing of it is reachable from another realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_grants_contract(app: &App) {
    use time::Duration;

    use crate::authz::grants::{Grant, HeldRole, Membership, RoleGrant, RoleHolder};
    use crate::authz::roles::{Group, Role};
    use crate::testkit::fixtures::{
        Application, create_person, create_realm, register_application,
    };

    let scope = create_realm(app, "contract-grants").await;
    let other = create_realm(app, "contract-grants-other").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    register_application(app, scope, portal).await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let identify = || mint_id(app).expect("an identifier");
    let make_role = |name: &str, client_id: Option<&str>| Role {
        id: identify(),
        client_id: client_id.map(str::to_owned),
        name: name.to_owned(),
        description: None,
        created_at: now,
    };
    let (admin, portal_admin, viewer) = (
        make_role("admin", None),
        make_role("admin", Some("portal")),
        make_role("Viewer", None),
    );
    let finance = Group {
        id: identify(),
        name: "finance".to_owned(),
        description: None,
        created_at: now,
    };
    let lasting = |until: Option<i64>| Grant {
        valid_from: now,
        valid_until: until.map(|hours| now + Duration::hours(hours)),
        granted_by: "operator".to_owned(),
        reason: Some("audit season".to_owned()),
        granted_at: now,
    };

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for role in [&admin, &portal_admin, &viewer] {
        assert_eq!(work.insert_role(role).await, Ok(true));
    }
    assert_eq!(work.insert_group(&finance).await, Ok(true));

    // Admin given to ada for good, then again for an hour: the second
    // replaces the first. Admin of the portal given to the group for three
    // hours, and ada a member for two. A viewer grant that starts later.
    let direct = |role: &Role, until: Option<i64>| RoleGrant {
        role: role.id,
        holder: RoleHolder::Person(ada.id),
        grant: lasting(until),
    };
    work.write_role_grant(&direct(&admin, None))
        .await
        .expect("a grant");
    work.write_role_grant(&direct(&admin, Some(1)))
        .await
        .expect("the grant again");
    let to_group = RoleGrant {
        role: portal_admin.id,
        holder: RoleHolder::Group(finance.id),
        grant: lasting(Some(3)),
    };
    work.write_role_grant(&to_group).await.expect("a grant");
    let membership = Membership {
        group: finance.id,
        person: ada.id,
        grant: lasting(Some(2)),
    };
    work.write_membership(&membership)
        .await
        .expect("a membership");
    let later = RoleGrant {
        grant: Grant {
            valid_from: now + Duration::minutes(30),
            ..lasting(None)
        },
        ..direct(&viewer, None)
    };
    work.write_role_grant(&later)
        .await
        .expect("a grant for later");
    work.commit().await.expect("a commit");

    let held = |role: &Role, through: Option<Uuid>, until: i64| HeldRole {
        role: role.id,
        client_id: role.client_id.clone(),
        name: role.name.clone(),
        through,
        until: Some(now + Duration::hours(until)),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.list_held_roles(ada.id, now, 10).await,
        Ok(vec![
            held(&admin, None, 1),
            held(&portal_admin, Some(finance.id), 2)
        ]),
        "a way lasts until the first of its grants ends"
    );
    assert_eq!(
        work.list_held_roles(ada.id, now, 1)
            .await
            .map(|held| held.len()),
        Ok(1),
        "as many as asked, whichever ones"
    );
    assert_eq!(
        work.list_held_roles(ada.id, now + Duration::minutes(90), 10)
            .await,
        Ok(vec![
            HeldRole {
                until: None,
                ..held(&viewer, None, 0)
            },
            held(&portal_admin, Some(finance.id), 2),
        ]),
        "admin ended, the viewer grant started"
    );
    assert_eq!(
        work.list_held_roles(ada.id, now + Duration::hours(2), 10)
            .await,
        Ok(vec![HeldRole {
            until: None,
            ..held(&viewer, None, 0)
        }]),
        "the membership ended, and the end is not held"
    );
    drop(work);

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.list_held_roles(ada.id, now, 10).await,
        Ok(Vec::new())
    );
    assert_eq!(
        elsewhere
            .delete_role_grant(admin.id, RoleHolder::Person(ada.id))
            .await,
        Ok(false)
    );
    assert_eq!(
        elsewhere.delete_membership(finance.id, ada.id).await,
        Ok(false)
    );
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.delete_role_grant(viewer.id, RoleHolder::Person(ada.id))
            .await,
        Ok(true)
    );
    assert_eq!(
        work.delete_role_grant(viewer.id, RoleHolder::Person(ada.id))
            .await,
        Ok(false)
    );
    assert_eq!(work.delete_membership(finance.id, ada.id).await, Ok(true));
    assert_eq!(work.delete_membership(finance.id, ada.id).await, Ok(false));
    assert_eq!(
        work.list_held_roles(ada.id, now, 10).await,
        Ok(vec![held(&admin, None, 1)])
    );
    work.write_membership(&membership)
        .await
        .expect("a membership again");
    work.commit().await.expect("a commit");

    // A role deleted takes its grants; a group deleted, its members and grants.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.delete_role(admin.id).await, Ok(true));
    assert_eq!(work.delete_role(admin.id).await, Ok(false));
    assert_eq!(
        work.list_held_roles(ada.id, now, 10).await,
        Ok(vec![held(&portal_admin, Some(finance.id), 2)])
    );
    assert_eq!(work.delete_group(finance.id).await, Ok(true));
    assert_eq!(work.list_held_roles(ada.id, now, 10).await, Ok(Vec::new()));
    assert_eq!(
        work.delete_role_grant(portal_admin.id, RoleHolder::Group(finance.id))
            .await,
        Ok(false)
    );
    work.commit().await.expect("a commit");

    // The other ends a way may have: the grant to the group ends first, the
    // membership has no end, the grant has none. And a role held both ways,
    // the direct way first.
    let bob = create_person(app, scope, "bob", "correct horse battery").await;
    let (auditor, clerk, signer) = (
        make_role("auditor", None),
        make_role("clerk", None),
        make_role("signer", None),
    );
    let make_group = |name: &str| Group {
        id: identify(),
        name: name.to_owned(),
        description: None,
        created_at: now,
    };
    let (early, open_member, open_grant) = (
        make_group("early"),
        make_group("open-member"),
        make_group("open-grant"),
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for role in [&auditor, &clerk, &signer] {
        assert_eq!(work.insert_role(role).await, Ok(true));
    }
    for group in [&early, &open_member, &open_grant] {
        assert_eq!(work.insert_group(group).await, Ok(true));
    }
    let given = |role: &Role, holder: RoleHolder, until: Option<i64>| RoleGrant {
        role: role.id,
        holder,
        grant: lasting(until),
    };
    for grant in [
        given(&auditor, RoleHolder::Person(bob.id), None),
        given(&auditor, RoleHolder::Group(early.id), Some(1)),
        given(&clerk, RoleHolder::Group(open_member.id), Some(3)),
        given(&signer, RoleHolder::Group(open_grant.id), None),
    ] {
        work.write_role_grant(&grant).await.expect("a grant");
    }
    for (group, until) in [
        (&early, Some(2)),
        (&open_member, None),
        (&open_grant, Some(2)),
    ] {
        let membership = Membership {
            group: group.id,
            person: bob.id,
            grant: lasting(until),
        };
        work.write_membership(&membership)
            .await
            .expect("a membership");
    }
    assert_eq!(
        work.list_held_roles(bob.id, now, 10).await,
        Ok(vec![
            HeldRole {
                until: None,
                ..held(&auditor, None, 0)
            },
            held(&auditor, Some(early.id), 1),
            held(&clerk, Some(open_member.id), 3),
            held(&signer, Some(open_grant.id), 2),
        ]),
        "each way ends with the first of its ends, and none is no end"
    );
    work.commit().await.expect("a commit");

    // Names made out of their order, and a way through a group to a name
    // before those given directly: the ways are in the order of the names.
    let cyd = create_person(app, scope, "cyd", "correct horse battery").await;
    let (zulu, mike, alpha) = (
        make_role("zulu", None),
        make_role("mike", None),
        make_role("alpha", None),
    );
    let crew = make_group("crew");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for role in [&zulu, &mike, &alpha] {
        assert_eq!(work.insert_role(role).await, Ok(true));
    }
    assert_eq!(work.insert_group(&crew).await, Ok(true));
    for grant in [
        given(&zulu, RoleHolder::Person(cyd.id), None),
        given(&mike, RoleHolder::Person(cyd.id), None),
        given(&alpha, RoleHolder::Group(crew.id), None),
    ] {
        work.write_role_grant(&grant).await.expect("a grant");
    }
    let membership = Membership {
        group: crew.id,
        person: cyd.id,
        grant: lasting(None),
    };
    work.write_membership(&membership)
        .await
        .expect("a membership");
    let for_good = |role: &Role, through: Option<Uuid>| HeldRole {
        until: None,
        ..held(role, through, 0)
    };
    assert_eq!(
        work.list_held_roles(cyd.id, now, 10).await,
        Ok(vec![
            for_good(&alpha, Some(crew.id)),
            for_good(&mike, None),
            for_good(&zulu, None),
        ]),
        "byte for byte by name, whichever way and whenever made"
    );
    work.commit().await.expect("a commit");
}

/// What any storage owes to the schema of relations and to the relations
/// kept: a schema replaces the one before, and its kinds theirs, a relation
/// is kept once and read back only for its object and relation, in the order
/// of its subjects, and nothing of it is reachable from another realm. A
/// relation the product did not keep goes with the first schema that would
/// admit it, and a form another version wrote is compiled again.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_relations_contract(app: &App) {
    use serde_json::json;

    use crate::authz::relations::schema::AllowedSubject;
    use crate::authz::relations::{
        AdmittedRelation, ObjectRef, RelationAdmission, RelationTuple, StoredSchema, SubjectRef,
    };
    use crate::testkit::fixtures::create_realm;

    let scope = create_realm(app, "contract-relations").await;
    let other = create_realm(app, "contract-relations-other").await;
    let portal = crate::testkit::fixtures::Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: false,
    };
    crate::testkit::fixtures::register_application(app, scope, portal).await;
    let now = app.now();
    let object = |text: &str| {
        let (object_type, object_id) = text.split_once(':').expect("type:id");
        ObjectRef {
            object_type: object_type.to_owned(),
            object_id: object_id.to_owned(),
        }
    };
    let relate = |object_text: &str, relation: &str, subject_text: &str, member: Option<&str>| {
        RelationTuple {
            object: object(object_text),
            relation: relation.to_owned(),
            subject: SubjectRef {
                object: object(subject_text),
                member: member.map(str::to_owned),
            },
        }
    };
    let schema = |source: &str| StoredSchema {
        source: source.to_owned(),
        compiled: json!({ "version": 1, "types": {} }),
        written_at: now,
    };
    let kind = |relation: &str, subject_type: &str, member: Option<&str>| AdmittedRelation {
        object_type: "document".to_owned(),
        relation: relation.to_owned(),
        subject: AllowedSubject {
            object_type: subject_type.to_owned(),
            member: member.map(str::to_owned),
        },
    };

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_relation_schema().await, Ok(None));
    assert_eq!(
        work.read_guarded_schema("document", "portal").await,
        Ok(None)
    );
    let first = [kind("owner", "user", None), kind("reader", "user", None)];
    work.write_relation_schema(&schema("definition first {}"), &first)
        .await
        .expect("a schema");
    let second = [
        kind("owner", "user", None),
        kind("owner", "team", Some("member")),
    ];
    work.write_relation_schema(&schema("definition second {}"), &second)
        .await
        .expect("a schema in place of the first");
    let owner = relate("document:q3", "owner", "user:ada", None);
    let team = relate("document:q3", "owner", "team:core", Some("member"));
    let reader = relate("document:q3", "reader", "user:bob", None);
    assert_eq!(work.insert_relation(&owner, now).await, Ok(true));
    assert_eq!(work.insert_relation(&owner, now).await, Ok(false));
    assert_eq!(work.insert_relation(&team, now).await, Ok(true));
    assert_eq!(work.insert_relation(&reader, now).await, Ok(true));
    work.commit().await.expect("a commit");

    // The kinds follow the schema in place: those of the first went with it.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.admit_relation(&reader).await,
        Ok(RelationAdmission::Refused),
        "a kind the schema no longer admits, kept or not"
    );
    assert_eq!(
        work.admit_relation(&team).await,
        Ok(RelationAdmission::Kept)
    );
    // Each one column away from a kind the schema admits: the member, the
    // type of the subject, the type of the object.
    for tuple in [
        relate("document:q3", "owner", "team:core", None),
        relate("document:q3", "owner", "user:ada", Some("member")),
        relate("folder:q3", "owner", "user:ada", None),
    ] {
        assert_eq!(
            work.admit_relation(&tuple).await,
            Ok(RelationAdmission::Refused),
            "{tuple:?}"
        );
    }
    assert_eq!(
        work.admit_relation(&relate("document:q4", "owner", "user:ada", None))
            .await,
        Ok(RelationAdmission::Taken)
    );
    drop(work);
    // A unit of work that only reads answers what it reads, and cannot hold
    // the definitions.
    let mut snapshot = app.storage.begin_snapshot(scope).await.expect("a snapshot");
    assert_eq!(
        snapshot.admit_relation(&reader).await,
        Ok(RelationAdmission::Refused)
    );
    assert_eq!(
        snapshot.admit_relation(&team).await,
        Ok(RelationAdmission::Kept)
    );
    assert_eq!(
        snapshot
            .admit_relation(&relate("document:q4", "owner", "user:ada", None))
            .await,
        Err(StorageError::Failed)
    );
    drop(snapshot);
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.admit_relation(&owner).await,
        Ok(RelationAdmission::Refused),
        "nor the kinds of another realm"
    );
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.read_relation_schema()
            .await
            .map(|stored| stored.map(|stored| stored.source)),
        Ok(Some("definition second {}".to_owned()))
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q3"), "owner", 10)
            .await,
        Ok(vec![team.subject.clone(), owner.subject.clone()]),
        "by type, then identifier, then member, byte for byte"
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q3"), "owner", 1)
            .await
            .map(|subjects| subjects.len()),
        Ok(1)
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q4"), "owner", 10)
            .await,
        Ok(Vec::new())
    );
    drop(work);

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_relation_schema().await, Ok(None));
    assert_eq!(
        elsewhere
            .list_relation_subjects(&object("document:q3"), "owner", 10)
            .await,
        Ok(Vec::new())
    );
    assert_eq!(elsewhere.delete_relation(&owner).await, Ok(false));
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.delete_relation(&owner).await, Ok(true));
    assert_eq!(work.delete_relation(&owner).await, Ok(false));
    // What a schema admits stays; what none of it names goes, here the reader bob.
    let admitted = |object_type: &str, relation: &str, subject_type: &str, member: Option<&str>| {
        crate::authz::relations::AdmittedRelation {
            object_type: object_type.to_owned(),
            relation: relation.to_owned(),
            subject: crate::authz::relations::schema::AllowedSubject {
                object_type: subject_type.to_owned(),
                member: member.map(str::to_owned),
            },
        }
    };
    assert_eq!(
        work.delete_relations_not_admitted(&[
            admitted("document", "owner", "user", None),
            admitted("document", "owner", "team", Some("member")),
        ])
        .await,
        Ok(1)
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q3"), "reader", 10)
            .await,
        Ok(Vec::new())
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q3"), "owner", 10)
            .await,
        Ok(vec![team.subject.clone()])
    );
    work.commit().await.expect("a commit");

    // Only the kinds withdrawn go: the owners that are users, not the
    // members of a team, nor the readers.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for tuple in [&owner, &reader] {
        assert_eq!(work.insert_relation(tuple, now).await, Ok(true));
    }
    work.commit().await.expect("a commit");
    let users_reading = [admitted("document", "reader", "user", None)];
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.delete_relations_of_kinds(&users_reading).await,
        Ok(0)
    );
    elsewhere.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.delete_relations_of_kinds(&[admitted("document", "owner", "user", None)])
            .await,
        Ok(1)
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q3"), "owner", 10)
            .await,
        Ok(vec![team.subject.clone()])
    );
    assert_eq!(
        work.list_relation_subjects(&object("document:q3"), "reader", 10)
            .await,
        Ok(vec![reader.subject.clone()]),
        "nor what another realm withdrew"
    );
    // Two kinds of one type at once, one of them the members of a team.
    assert_eq!(
        work.delete_relations_of_kinds(&[
            admitted("document", "owner", "team", Some("member")),
            admitted("document", "reader", "user", None),
        ])
        .await,
        Ok(2)
    );
    for relation in ["owner", "reader"] {
        assert_eq!(
            work.list_relation_subjects(&object("document:q3"), relation, 10)
                .await,
            Ok(Vec::new())
        );
    }
    work.commit().await.expect("a commit");

    // A guard is kept once, read for its type and client only, and listed.
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.insert_relation_guard("document", "portal", now).await,
        Ok(true)
    );
    assert_eq!(
        work.insert_relation_guard("document", "portal", now).await,
        Ok(false)
    );
    assert_eq!(
        work.read_guarded_schema("document", "portal")
            .await
            .map(|found| found.map(|found| found.guarded)),
        Ok(Some(true))
    );
    assert_eq!(
        work.read_guarded_schema("folder", "portal")
            .await
            .map(|found| found.map(|found| found.guarded)),
        Ok(Some(false))
    );
    assert_eq!(
        work.read_guarded_schema("document", "portal")
            .await
            .map(|found| found.map(|found| found.compiled)),
        Ok(Some(json!({ "version": 1, "types": {} }))),
        "the compiled form, as it was written"
    );
    assert_eq!(
        work.list_relation_guards("document", 10).await,
        Ok(vec!["portal".to_owned()])
    );
    work.commit().await.expect("a commit");
    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(
        elsewhere.read_guarded_schema("document", "portal").await,
        Ok(None)
    );
    assert_eq!(
        elsewhere.delete_relation_guard("document", "portal").await,
        Ok(false)
    );
    drop(elsewhere);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.delete_relation_guard("document", "portal").await,
        Ok(true)
    );
    assert_eq!(
        work.delete_relation_guard("document", "portal").await,
        Ok(false)
    );
    work.commit().await.expect("a commit");

    check_that_a_schema_sweeps_what_the_product_did_not_keep(app).await;
    check_that_a_form_another_version_wrote_is_compiled_again(app).await;
}

/// A compiled form another version wrote, which this one does not read: its
/// source is compiled again, and serves, where the schema is read and where
/// a question is decided.
async fn check_that_a_form_another_version_wrote_is_compiled_again(app: &App) {
    use serde_json::{Map, json};

    use crate::authz::capability::Capability;
    use crate::authz::decide::{DecisionRequest, decide};
    use crate::authz::relations::schema::compile_schema;
    use crate::authz::relations::{
        ObjectRef, RelationTuple, StoredSchema, SubjectRef, list_admitted_relations,
        read_relation_schema,
    };
    use crate::testkit::fixtures::{create_administrator, create_realm, create_service_client};

    let realm = "contract-older-form";
    let scope = create_realm(app, realm).await;
    let secret = create_service_client(app, scope, "billing", &[]).await;
    let subject_token =
        create_administrator(app, realm, scope, "auditor", &[Capability::AuditRead]).await;
    let source = "definition client {}\ndefinition document {\n  relation reader: client\n}";
    let older = StoredSchema {
        source: source.to_owned(),
        compiled: json!({ "version": 0 }),
        written_at: app.now(),
    };
    let admitted = list_admitted_relations(&compile_schema(source).expect("a schema"));
    let object = |object_type: &str, object_id: &str| ObjectRef {
        object_type: object_type.to_owned(),
        object_id: object_id.to_owned(),
    };
    let reader = RelationTuple {
        object: object("document", "q3"),
        relation: "reader".to_owned(),
        subject: SubjectRef {
            object: object("client", "auditor"),
            member: None,
        },
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.write_relation_schema(&older, &admitted)
        .await
        .expect("a form of another version");
    work.insert_relation_guard("document", "billing", app.now())
        .await
        .expect("a guard");
    assert_eq!(work.insert_relation(&reader, app.now()).await, Ok(true));
    work.commit().await.expect("a commit");

    let read = read_relation_schema(app, scope)
        .await
        .expect("the schema")
        .and_then(|stored| stored.open());
    assert_eq!(
        read.map(|schema| schema.types.into_keys().collect::<Vec<_>>()),
        Some(vec!["client".to_owned(), "document".to_owned()]),
        "the schema is read from its source"
    );
    let attributes = Map::new();
    let asked = decide(
        app,
        realm,
        Some("billing"),
        Some(secret),
        DecisionRequest {
            subject_token: Some(&subject_token),
            action: "reader",
            resource_type: "document",
            resource_id: Some("q3"),
            attributes: &attributes,
        },
    )
    .await;
    assert_eq!(
        asked
            .map(|decision| (decision.decision, decision.reason))
            .map_err(|failure| failure.error),
        Ok(("permit", "relation".to_owned())),
        "the question is decided by the source compiled again"
    );
}

/// A relation kept by hand before any schema, then one of a kind a later
/// schema admits anew: each goes with the schema that would admit it, and
/// what the product kept stays.
async fn check_that_a_schema_sweeps_what_the_product_did_not_keep(app: &App) {
    use crate::authz::admin::authorize_admin_call;
    use crate::authz::capability::Capability;
    use crate::authz::relations::{
        ObjectRef, RelationTuple, SubjectRef, write_relation, write_relation_schema,
    };
    use crate::testkit::fixtures::{create_administrator, create_realm};

    let scope = create_realm(app, "contract-sweep").await;
    let token = create_administrator(
        app,
        "contract-sweep",
        scope,
        "operator",
        &[Capability::PolicyWrite],
    )
    .await;
    let caller = authorize_admin_call(app, "contract-sweep", Some(&token), Capability::PolicyWrite)
        .await
        .expect("an operator");
    let document = ObjectRef {
        object_type: "document".to_owned(),
        object_id: "q1".to_owned(),
    };
    let relate = |relation: &str, user: &str| RelationTuple {
        object: document.clone(),
        relation: relation.to_owned(),
        subject: SubjectRef {
            object: ObjectRef {
                object_type: "user".to_owned(),
                object_id: user.to_owned(),
            },
            member: None,
        },
    };
    let keep_by_hand = |tuple: RelationTuple| async move {
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        assert_eq!(work.insert_relation(&tuple, app.now()).await, Ok(true));
        work.commit().await.expect("a commit");
    };
    let read = |relation: &'static str| {
        let document = document.clone();
        async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.list_relation_subjects(&document, relation, 10)
                .await
                .expect("the subjects")
                .into_iter()
                .map(|subject| subject.object.object_id)
                .collect::<Vec<_>>()
        }
    };
    let readers = "definition user {}\ndefinition document {\n  relation reader: user\n}";
    let owners = "definition user {}\ndefinition document {\n  relation owner: user\n  relation reader: user\n}";

    keep_by_hand(relate("reader", "mallory")).await;
    let written = write_relation_schema(app, &caller, readers).await;
    assert_eq!(written.map(|(_, removed)| removed), Ok(1));
    assert_eq!(read("reader").await, Vec::<String>::new());

    write_relation(app, &caller, &relate("reader", "ada"))
        .await
        .expect("a relation the schema admits");
    keep_by_hand(relate("owner", "mallory")).await;
    let written = write_relation_schema(app, &caller, owners).await;
    assert_eq!(written.map(|(_, removed)| removed), Ok(1));
    assert_eq!(read("owner").await, Vec::<String>::new());
    assert_eq!(read("reader").await, ["ada"]);
}

/// What any storage owes to policies: a name is taken once per client, they
/// are listed by name for their client, and for an action on a type of
/// resource, a deletion answers once, and nothing of them is reachable from
/// another realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one scenario, read from top to bottom"
)]
pub async fn check_policies_contract(app: &App) {
    use serde_json::json;

    use crate::authz::policy::{Combine, Effect, Policy};
    use crate::testkit::fixtures::{Application, create_realm, register_application};

    let scope = create_realm(app, "contract-policies").await;
    let other = create_realm(app, "contract-policies-other").await;
    for client_id in ["billing", "portal"] {
        let application = Application {
            client_id,
            redirect_uri: "https://app.example.org/cb",
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: false,
        };
        register_application(app, scope, application).await;
    }
    let now = app.now();
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let make_policy = |name: &str, client_id: &str, action: &str| Policy {
        id: mint_id(app).expect("an identifier"),
        client_id: client_id.to_owned(),
        name: name.to_owned(),
        resource_type: "invoice".to_owned(),
        action: action.to_owned(),
        effect: Effect::Deny,
        combine: Combine::Any,
        conditions: json!([{ "role": Uuid::from_u128(1) }]),
        created_at: now,
    };
    let (zeta, alpha, read, portal) = (
        make_policy("zeta", "billing", "approve"),
        make_policy("alpha", "billing", "approve"),
        make_policy("readers", "billing", "read"),
        make_policy("alpha", "portal", "approve"),
    );
    for policy in [&zeta, &alpha, &read, &portal] {
        assert_eq!(work.insert_policy(policy).await, Ok(true));
    }
    work.commit().await.expect("a commit");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.insert_policy(&make_policy("alpha", "billing", "read"))
            .await,
        Ok(false),
        "a name is taken once per client"
    );
    drop(work);
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.list_policies("billing").await,
        Ok(vec![alpha.clone(), read.clone(), zeta.clone()])
    );
    assert_eq!(work.count_policies("billing", 10).await, Ok(3));
    assert_eq!(
        work.count_policies("billing", 2).await,
        Ok(2),
        "counted to the bound and no further"
    );
    assert_eq!(
        work.list_applicable_policies("billing", "invoice", "approve")
            .await,
        Ok(vec![alpha.clone(), zeta.clone()])
    );
    assert_eq!(
        work.list_applicable_policies("billing", "receipt", "approve")
            .await,
        Ok(Vec::new())
    );
    assert_eq!(work.delete_policy("portal", alpha.id).await, Ok(false));
    assert_eq!(work.delete_policy("billing", alpha.id).await, Ok(true));
    assert_eq!(work.list_policies("portal").await, Ok(vec![portal.clone()]));
    work.commit().await.expect("a commit");

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let types =
        |names: &[&str]| -> Vec<String> { names.iter().map(|name| (*name).to_owned()).collect() };
    assert_eq!(
        work.has_policy_for_types(&types(&["receipt", "invoice"]))
            .await,
        Ok(true)
    );
    assert_eq!(
        work.has_policy_for_types(&types(&["receipt"])).await,
        Ok(false)
    );
    assert_eq!(
        work.is_named_by_policy("role", Uuid::from_u128(1)).await,
        Ok(true)
    );
    assert_eq!(
        work.is_named_by_policy("group", Uuid::from_u128(1)).await,
        Ok(false)
    );
    let grouped = Policy {
        conditions: json!([{ "group": Uuid::from_u128(9) }]),
        ..make_policy("by-group", "portal", "approve")
    };
    assert_eq!(work.insert_policy(&grouped).await, Ok(true));
    assert_eq!(
        work.is_named_by_policy("group", Uuid::from_u128(9)).await,
        Ok(true)
    );
    assert_eq!(
        work.is_named_by_policy("role", Uuid::from_u128(2)).await,
        Ok(false)
    );
    drop(work);

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.list_policies("billing").await, Ok(Vec::new()));
    assert_eq!(elsewhere.count_policies("billing", 10).await, Ok(0));
    assert_eq!(elsewhere.delete_policy("billing", zeta.id).await, Ok(false));
    assert_eq!(
        elsewhere.has_policy_for_types(&types(&["invoice"])).await,
        Ok(false)
    );
    assert_eq!(
        elsewhere
            .is_named_by_policy("role", Uuid::from_u128(1))
            .await,
        Ok(false)
    );
}

/// What any storage owes to the groups of a person: those they are a member
/// of at an instant, by identifier, and no other.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
pub async fn check_member_groups_contract(app: &App) {
    use time::Duration;

    use crate::authz::grants::{Grant, Membership};
    use crate::authz::roles::Group;
    use crate::testkit::fixtures::{create_person, create_realm};

    let scope = create_realm(app, "contract-member-groups").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let bob = create_person(app, scope, "bob", "correct horse battery").await;
    let now = app.now();
    let make_group = |name: &str| Group {
        id: mint_id(app).expect("an identifier"),
        name: name.to_owned(),
        description: None,
        created_at: now,
    };
    let (night, day, later) = (make_group("night"), make_group("day"), make_group("later"));
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for (group, from, until) in [(&night, 0, Some(1)), (&day, 0, None), (&later, 2, None)] {
        assert_eq!(work.insert_group(group).await, Ok(true));
        work.write_membership(&Membership {
            group: group.id,
            person: ada.id,
            grant: Grant {
                valid_from: now + Duration::hours(from),
                valid_until: until.map(|hours| now + Duration::hours(hours)),
                granted_by: "operator".to_owned(),
                reason: None,
                granted_at: now,
            },
        })
        .await
        .expect("a membership");
    }
    let mut both = vec![night.id, day.id];
    both.sort();
    assert_eq!(
        work.list_member_groups(ada.id, now, 1).await,
        Ok(vec![both[0]]),
        "the first, `most` at most"
    );
    assert_eq!(work.list_member_groups(ada.id, now, 10).await, Ok(both));
    assert_eq!(
        work.list_member_groups(ada.id, now + Duration::hours(1), 10)
            .await,
        Ok(vec![day.id]),
        "a membership ends at its end"
    );
    let mut from_two = vec![day.id, later.id];
    from_two.sort();
    assert_eq!(
        work.list_member_groups(ada.id, now + Duration::hours(2), 10)
            .await,
        Ok(from_two),
        "and starts at its start"
    );
    assert_eq!(
        work.list_member_groups(bob.id, now, 10).await,
        Ok(Vec::new())
    );
    work.commit().await.expect("a commit");
}

/// What any storage owes to consents: kept by person and client, widened in
/// place, in one realm, read with the flag of their client; a request waits
/// for one consent at most; the tokens of a client for a person are revoked
/// together.
///
/// # Panics
///
/// Panics at the first answer that breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one contract, read from top to bottom"
)]
pub async fn check_consents_contract(app: &App) {
    use time::Duration;

    use crate::consent::{Consent, ConsentHold, ConsentTerms, ListedConsent};
    use crate::testkit::fixtures::{
        Application, create_person, create_realm, register_application,
    };

    let scope = create_realm(app, "contract-consents").await;
    let other = create_realm(app, "contract-consents-other").await;
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let bob = create_person(app, scope, "bob", "correct horse battery").await;
    for (client_id, requires_consent) in [("webapp", true), ("portal", true), ("plain", false)] {
        let application = Application {
            client_id,
            redirect_uri: "https://app.example.org/cb",
            post_logout_redirect_uri: None,
            public: true,
            requires_consent,
        };
        register_application(app, scope, application).await;
    }
    let now = app.now();
    let allow = |person: Uuid, client_id: &str, scopes: &[&str]| Consent {
        person,
        client_id: client_id.to_owned(),
        scopes: scopes.iter().map(|&scope| scope.to_owned()).collect(),
        granted_at: now,
    };
    // The name of a client the fixture registers is its identifier.
    let listed = |consent: &Consent| ListedConsent {
        consent: consent.clone(),
        client_name: consent.client_id.clone(),
    };

    let terms = |requires_consent: bool, allowed: Option<&[&str]>| ConsentTerms {
        requires_consent,
        allowed: allowed.map(|scopes| scopes.iter().map(|&scope| scope.to_owned()).collect()),
    };

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_consent(ada.id, "webapp").await, Ok(None));
    assert_eq!(
        work.hold_consent(ada.id, "webapp", ConsentHold::Shared)
            .await,
        Ok(None)
    );
    assert_eq!(
        work.read_consent_terms(ada.id, "webapp").await,
        Ok(Some(terms(true, None))),
        "the flag of the client, and nothing allowed yet"
    );
    assert_eq!(
        work.read_consent_terms(ada.id, "plain").await,
        Ok(Some(terms(false, None)))
    );
    assert_eq!(
        work.read_consent_terms(ada.id, "nobody").await,
        Ok(None),
        "no such client"
    );
    work.add_consent(&allow(ada.id, "webapp", &["openid", "email"]))
        .await
        .expect("a consent");
    let later = now + Duration::minutes(1);
    work.add_consent(&Consent {
        granted_at: later,
        ..allow(ada.id, "webapp", &["profile", "openid"])
    })
    .await
    .expect("a wider consent");
    let wider = Consent {
        granted_at: later,
        ..allow(ada.id, "webapp", &["openid", "email", "profile"])
    };
    assert_eq!(
        work.read_consent(ada.id, "webapp").await,
        Ok(Some(wider.clone())),
        "widened in place: what was allowed keeps its place, the new comes after"
    );
    for hold in [ConsentHold::Shared, ConsentHold::Exclusive] {
        assert_eq!(
            work.hold_consent(ada.id, "webapp", hold).await,
            Ok(Some(wider.scopes.clone())),
            "{hold:?}"
        );
    }
    assert_eq!(
        work.read_consent_terms(ada.id, "webapp").await,
        Ok(Some(terms(true, Some(&["openid", "email", "profile"]))))
    );
    assert_eq!(
        work.read_consent_terms(bob.id, "webapp").await,
        Ok(Some(terms(true, None))),
        "what another person allowed is not read"
    );
    let portal = allow(ada.id, "portal", &["openid"]);
    work.add_consent(&portal).await.expect("a second consent");
    work.add_consent(&allow(bob.id, "webapp", &["openid"]))
        .await
        .expect("a consent of bob");
    assert_eq!(
        work.list_consents(ada.id, 10).await,
        Ok(vec![listed(&portal), listed(&wider)]),
        "by client, with its name, and only those of the person"
    );
    assert_eq!(
        work.list_consents(ada.id, 1).await,
        Ok(vec![listed(&portal)]),
        "`most` at most"
    );
    work.commit().await.expect("a commit");

    for hold in [ConsentHold::Shared, ConsentHold::Exclusive] {
        let mut snapshot = app.storage.begin_snapshot(scope).await.expect("a snapshot");
        assert!(
            snapshot.hold_consent(ada.id, "webapp", hold).await.is_err(),
            "a snapshot holds nothing: {hold:?}"
        );
    }

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.read_consent(ada.id, "webapp").await, Ok(None));
    assert_eq!(
        elsewhere
            .hold_consent(ada.id, "webapp", ConsentHold::Exclusive)
            .await,
        Ok(None)
    );
    assert_eq!(
        elsewhere.read_consent_terms(ada.id, "webapp").await,
        Ok(None)
    );
    assert_eq!(elsewhere.list_consents(ada.id, 10).await, Ok(Vec::new()));
    assert_eq!(elsewhere.delete_consent(ada.id, "webapp").await, Ok(false));
    drop(elsewhere);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.delete_consent(ada.id, "webapp").await, Ok(true));
    assert_eq!(work.delete_consent(ada.id, "webapp").await, Ok(false));
    assert_eq!(
        work.list_consents(ada.id, 10).await,
        Ok(vec![listed(&portal)])
    );
    work.commit().await.expect("a commit");

    check_that_a_request_waits_for_one_consent(app, scope).await;
    check_that_a_client_loses_its_tokens_of_a_person(app, scope, ada.id, bob.id).await;
}

/// A request waits for the consent of one session, written once, and is
/// taken with it.
async fn check_that_a_request_waits_for_one_consent(app: &App, scope: RealmScope) {
    use time::Duration;

    use crate::oidc::code::PendingAuthorization;

    let now = app.now();
    let pending = PendingAuthorization {
        id: mint_id(app).expect("an identifier"),
        browser_digest: vec![4; 32],
        client_id: "webapp".to_owned(),
        redirect_uri: "https://app.example.org/cb".to_owned(),
        scopes: vec!["openid".to_owned()],
        state: None,
        nonce: None,
        code_challenge: "challenge".to_owned(),
        expires_at: now + Duration::minutes(10),
        expected_person: None,
        first_factor: None,
        key_proof: None,
        consent_prompted: false,
        consent_session: None,
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_pending_authorization(&pending)
        .await
        .expect("a pending request");
    let (session, other_session) = (
        mint_id(app).expect("an identifier"),
        mint_id(app).expect("an identifier"),
    );
    assert_eq!(
        work.mark_consent_owed(pending.id, session, pending.expires_at)
            .await,
        Ok(false),
        "not once expired"
    );
    assert_eq!(
        work.mark_consent_owed(pending.id, session, now).await,
        Ok(true)
    );
    assert_eq!(
        work.mark_consent_owed(pending.id, other_session, now).await,
        Ok(false),
        "not twice"
    );
    let waiting = PendingAuthorization {
        consent_session: Some(session),
        ..pending
    };
    assert_eq!(
        work.read_pending_authorization(waiting.id, now).await,
        Ok(Some(waiting.clone()))
    );
    assert_eq!(
        work.take_pending_authorization(waiting.id, now).await,
        Ok(Some(waiting))
    );
    work.commit().await.expect("a commit");
}

/// The live tokens of one client for one person go together, in every
/// session of theirs and no other; each family is counted once, and named
/// within the bound. The offline sessions they lived in end with them.
#[expect(
    clippy::too_many_lines,
    reason = "one contract, read from top to bottom"
)]
async fn check_that_a_client_loses_its_tokens_of_a_person(
    app: &App,
    scope: RealmScope,
    ada: Uuid,
    bob: Uuid,
) {
    use time::Duration;

    use crate::login::session::{AuthenticationMethod, Session, SessionKind, SessionState};
    use crate::tokens::store::{RefreshToken, RevokedFamilies};

    let now = app.now();
    let open = |person: Uuid| Session {
        id: mint_id(app).expect("an identifier"),
        person,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        kind: SessionKind::Browser,
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let offline = |person: Uuid| Session {
        secret_digest: Vec::new(),
        kind: SessionKind::Offline,
        ..open(person)
    };
    let sessions = [open(ada), open(ada), open(bob), offline(ada), offline(ada)];
    let mint = |digest: u8, family: Uuid, client_id: &str, session: &Session| RefreshToken {
        token_digest: vec![digest; 32],
        family,
        client_id: client_id.to_owned(),
        person: session.person,
        session: session.id,
        scopes: vec!["openid".to_owned()],
        issued_at: now,
        expires_at: now + Duration::minutes(30),
    };
    let families: Vec<Uuid> = (0..7)
        .map(|_| mint_id(app).expect("an identifier"))
        .collect();
    let first = mint(1, families[0], "webapp", &sessions[0]);
    let rotated = RefreshToken {
        issued_at: now + Duration::minutes(1),
        ..mint(2, families[0], "webapp", &sessions[0])
    };
    let elsewhere = mint(3, families[1], "webapp", &sessions[1]);
    let of_portal = mint(4, families[2], "portal", &sessions[0]);
    let of_bob = mint(5, families[3], "webapp", &sessions[2]);
    let told_before = mint(6, families[4], "webapp", &sessions[1]);
    let held_offline = mint(8, families[5], "webapp", &sessions[3]);
    let offline_of_portal = mint(9, families[6], "portal", &sessions[4]);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for session in &sessions {
        work.insert_session(session).await.expect("a session");
    }
    for token in [
        &first,
        &elsewhere,
        &of_portal,
        &of_bob,
        &told_before,
        &held_offline,
        &offline_of_portal,
    ] {
        work.insert_refresh_token(token).await.expect("a token");
    }
    work.spend_refresh_token(&first.token_digest, "webapp", now)
        .await
        .expect("a spending")
        .expect("the first token");
    work.insert_refresh_token(&rotated)
        .await
        .expect("a rotation");
    // A family revoked already, and a token written into it after, as a
    // rotation in flight does.
    work.revoke_refresh_family(families[4], now)
        .await
        .expect("a revocation");
    let late = mint(7, families[4], "webapp", &sessions[1]);
    work.insert_refresh_token(&late)
        .await
        .expect("a late token");

    assert_eq!(
        work.revoke_refresh_families_of_client(ada, "webapp", now, 1)
            .await,
        Ok(RevokedFamilies {
            families: 3,
            tokens: 4,
            named: vec![families[0].min(families[1]).min(families[5])],
            offline_sessions: vec![sessions[3].id],
        }),
        "in each session of the person; the tokens the families still held are counted, the \
         family revoked before is left as it was, its late token too; the first family by \
         identifier is named, and no more; the offline session of the client ends, not the \
         one of another"
    );
    assert_eq!(
        work.revoke_refresh_families_of_client(ada, "webapp", now, 1)
            .await,
        Ok(RevokedFamilies {
            families: 0,
            tokens: 0,
            named: Vec::new(),
            offline_sessions: Vec::new(),
        }),
        "what is revoked is not revoked again"
    );
    for (token, live) in [
        (&first, false),
        (&rotated, false),
        (&elsewhere, false),
        (&late, false),
        (&held_offline, false),
        (&of_portal, true),
        (&of_bob, true),
        (&offline_of_portal, true),
    ] {
        let stored = work
            .read_refresh_token(&token.token_digest)
            .await
            .expect("a read")
            .expect("the token");
        assert_eq!(
            stored.revoked_at.is_none(),
            live,
            "token {}",
            token.token_digest[0]
        );
    }
    for (session, state) in [
        (&sessions[0], SessionState::Active),
        (&sessions[3], SessionState::Ended),
        (&sessions[4], SessionState::Active),
    ] {
        let read = work
            .read_session(session.id)
            .await
            .expect("a read")
            .expect("the session");
        assert_eq!(read.session.state, state, "{:?}", session.kind);
    }
    work.commit().await.expect("a commit");
}

/// What any storage owes to the mappers of a client and to the attributes of
/// a person: kept, read back in the byte order of their names, the largest
/// document the rules admit kept as it was written, and nothing reached
/// outside the realm.
///
/// # Panics
///
/// Panics when the storage breaks the contract.
#[expect(
    clippy::too_many_lines,
    reason = "one contract, read from top to bottom"
)]
pub async fn check_claims_contract(app: &App) {
    use serde_json::{Map, json};

    use crate::claims::rules::{MAX_DOCUMENT_BYTES, check_attributes};
    use crate::claims::{ClaimTarget, LockedClient, Mapper, MapperKind, PersonProperty};
    use crate::testkit::fixtures::{
        Application, create_person, create_realm, fill_attributes, register_application,
    };

    let scope = create_realm(app, "contract-claims").await;
    let other = create_realm(app, "contract-claims-other").await;
    for (realm, client_id) in [(scope, "portal"), (scope, "billing"), (other, "portal")] {
        let application = Application {
            client_id,
            redirect_uri: "https://app.example.org/cb",
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: false,
        };
        register_application(app, realm, application).await;
    }
    let ada = create_person(app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let make = |name: &str, client_id: &str, kind: MapperKind| Mapper {
        id: mint_id(app).expect("an identifier"),
        client_id: client_id.to_owned(),
        name: name.to_owned(),
        claim: (!matches!(kind, MapperKind::Audience { .. })).then(|| "a_claim".to_owned()),
        kind,
        targets: vec![ClaimTarget::AccessToken, ClaimTarget::Userinfo],
        scope: Some("billing".to_owned()),
        created_at: now,
    };
    let audience = make(
        "Zeta",
        "portal",
        MapperKind::Audience {
            audience: "https://api.example.org".to_owned(),
        },
    );
    let property = make(
        "alpha",
        "portal",
        MapperKind::Property {
            property: PersonProperty::EmailVerified,
        },
    );
    let of_billing = make("alpha", "billing", MapperKind::FullName);

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let locked = LockedClient {
        scopes: ["openid", "profile", "email", "roles", "offline_access"]
            .map(str::to_owned)
            .to_vec(),
        capabilities: Vec::new(),
    };
    assert_eq!(work.lock_client("portal").await, Ok(Some(locked)));
    assert_eq!(work.lock_client("nobody").await, Ok(None));
    // Written out of the order they are read back in.
    for mapper in [&property, &of_billing, &audience] {
        assert_eq!(work.insert_mapper(mapper).await, Ok(true));
    }
    assert_eq!(
        work.insert_mapper(&Mapper {
            id: mint_id(app).expect("an identifier"),
            ..audience.clone()
        })
        .await,
        Ok(false),
        "a name is taken once per client"
    );
    assert_eq!(
        work.list_mappers("portal").await,
        Ok(vec![audience.clone(), property.clone()]),
        "in the byte order of their names"
    );
    assert_eq!(work.delete_mapper("billing", property.id).await, Ok(false));
    assert_eq!(work.delete_mapper("portal", property.id).await, Ok(true));
    assert_eq!(
        work.list_mappers("portal").await,
        Ok(vec![audience.clone()])
    );

    assert_eq!(
        work.read_person_attributes(ada.id).await,
        Ok(Some(Map::new())),
        "a person starts with no attribute"
    );
    let attributes =
        json!({ "department": ["research"], "given_name": "Ada", "contractor": false });
    let attributes = attributes.as_object().expect("an object");
    assert_eq!(
        work.lock_person_attributes(ada.id).await,
        Ok(Some(Map::new()))
    );
    assert_eq!(
        work.write_person_attributes(ada.id, attributes).await,
        Ok(())
    );
    assert_eq!(
        work.read_person_attributes(ada.id).await,
        Ok(Some(attributes.clone()))
    );
    let nobody = mint_id(app).expect("an identifier");
    assert_eq!(work.read_person_attributes(nobody).await, Ok(None));
    assert_eq!(work.lock_person_attributes(nobody).await, Ok(None));
    work.commit().await.expect("a commit");

    // Measured once, by the rules: the store keeps what they admit.
    let largest = fill_attributes(MAX_DOCUMENT_BYTES);
    assert_eq!(check_attributes(&largest), Ok(()));
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.write_person_attributes(ada.id, &largest).await,
        Ok(()),
        "the largest document the rules admit"
    );
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_person_attributes(ada.id).await, Ok(Some(largest)));
    drop(work);

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    assert_eq!(elsewhere.list_mappers("portal").await, Ok(Vec::new()));
    assert_eq!(
        elsewhere.delete_mapper("portal", audience.id).await,
        Ok(false)
    );
    assert_eq!(elsewhere.lock_client("billing").await, Ok(None));
    assert_eq!(elsewhere.read_person_attributes(ada.id).await, Ok(None));
    assert_eq!(elsewhere.lock_person_attributes(ada.id).await, Ok(None));
}
