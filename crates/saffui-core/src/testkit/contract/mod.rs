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

    use crate::login::session::{AuthenticationMethod, ReadSession, Session, SessionState};
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
        methods: vec![AuthenticationMethod::Password],
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.commit().await.expect("a commit");
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.read_session(session.id).await,
        Ok(Some(ReadSession {
            session: session.clone(),
            person_holds_factor: false,
        }))
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

    use crate::login::session::{AuthenticationMethod, Session, SessionState};
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

    use crate::login::session::{AuthenticationMethod, Session, SessionState};
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
        methods: vec![AuthenticationMethod::Password],
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
    let second = RefreshToken {
        issued_at: now + Duration::minutes(1),
        ..mint(2, family, &first_session, Duration::minutes(30))
    };
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

    // A family is revoked whole, used tokens included, and once.
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
        "nothing is left to revoke"
    );
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

/// Asks twice whether `person` holds a second factor: alone, and with a
/// session of theirs written in `work` and read back.
async fn ask_whether_holder(
    app: &App,
    work: &mut dyn crate::ports::storage::UnitOfWork,
    person: Uuid,
) -> [bool; 2] {
    use time::Duration;

    use crate::login::session::{AuthenticationMethod, Session, SessionState};

    let now = app.now();
    let session = Session {
        id: mint_id(app).expect("an identifier"),
        person,
        secret_digest: vec![8; 32],
        state: SessionState::Active,
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

    use crate::login::session::{AuthenticationMethod, Session, SessionState};
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
