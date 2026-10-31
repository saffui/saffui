//! What every storage adapter must do, written once and played on the double
//! and on Postgres: they must answer alike.

use crate::app::App;
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
    drop(fresh);
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
