//! The keys of a realm are turned over under the lock of its data key: of
//! two rotations at once on two nodes, the second waits for the first, then
//! counts and retires what the first kept. On one node, a tenant makes one
//! key at a time, and the core holds that. Of two removals of one key at once, the
//! second waits for the first, then finds nothing to remove.

use std::future::Future;
use std::sync::Arc;

use pgcore::MAINTENANCE_ROLE;
use pgcore::pool::PoolSettings;
use saffui_core::app::App;
use saffui_core::authz::admin::{AdminCaller, authorize_admin_call};
use saffui_core::authz::capability::Capability;
use saffui_core::error::ErrorCode;
use saffui_core::keys::rotate::{list_realm_keys, remove_retired_key, rotate_signing_key};
use saffui_core::keys::{KeyStatus, MAX_SIGNING_KEYS};
use saffui_core::ports::crypto::SignatureAlgorithm;
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::crypto::WeakSigner;
use saffui_core::testkit::fixtures::{create_administrator, create_realm};

use crate::support::locks::race_two_writers;
use crate::support::{self, connect};

async fn name_operator(app: &App, scope: RealmScope) -> AdminCaller {
    let token = create_administrator(app, "acme", scope, "operator", &[Capability::KeyWrite]).await;
    authorize_admin_call(app, "acme", Some(&token), Capability::KeyWrite)
        .await
        .expect("an operator")
}

/// The same product on the same database, as a second node runs it: what
/// one process holds for its tenants, the other does not see.
fn start_second_node(app: &App) -> App {
    App {
        key_shares: Arc::default(),
        registration_key_shares: Arc::default(),
        ..app.clone()
    }
}

/// Lets the keys be read and not written: a rotation stops at its first
/// write, once it holds the data key.
const KEYS_READ_ONLY: &str = "LOCK TABLE signing_keys IN SHARE MODE";

fn rotate(
    app: &App,
    caller: &AdminCaller,
    algorithm: SignatureAlgorithm,
) -> impl Future<Output = Result<String, ErrorCode>> + Send + 'static {
    let (app, caller) = (app.clone(), caller.clone());
    async move {
        rotate_signing_key(&app, &caller, algorithm)
            .await
            .map(|key| key.key_id)
            .map_err(|failure| failure.code)
    }
}

#[tokio::test]
async fn two_rotations_at_once_leave_one_active_key_of_their_algorithm() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let other = start_second_node(&app);

    let (waited, first, second) = race_two_writers(
        &database,
        KEYS_READ_ONLY,
        rotate(&app, &caller, SignatureAlgorithm::Es256),
        rotate(&other, &caller, SignatureAlgorithm::Es256),
    )
    .await;

    assert!(waited, "the second rotation waits for the first");
    let (first, second) = (
        first.expect("a key"),
        second.expect("a key, after the first"),
    );
    let keys = list_realm_keys(&app, scope).await.expect("the keys");
    let es256: Vec<(&str, KeyStatus)> = keys
        .iter()
        .filter(|key| key.algorithm == SignatureAlgorithm::Es256)
        .map(|key| (key.key_id.as_str(), key.status))
        .collect();
    assert_eq!(es256.len(), 3, "the first key and one for each rotation");
    let active: Vec<&str> = es256
        .iter()
        .filter(|(_, status)| *status == KeyStatus::Active)
        .map(|(kid, _)| *kid)
        .collect();
    assert_eq!(active, [second.as_str()], "the second retired the first's");
    assert!(
        es256.contains(&(first.as_str(), KeyStatus::Retired)),
        "{es256:?}"
    );
}

#[tokio::test]
async fn two_rotations_at_once_with_room_for_one_keep_one() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let held = list_realm_keys(&app, scope).await.expect("the keys").len();
    for _ in held + 1..MAX_SIGNING_KEYS {
        rotate(&app, &caller, SignatureAlgorithm::Es256)
            .await
            .expect("room for one more");
    }

    let other = start_second_node(&app);

    // Of two algorithms: neither retires a key the other would make.
    let (waited, first, second) = race_two_writers(
        &database,
        KEYS_READ_ONLY,
        rotate(&app, &caller, SignatureAlgorithm::Es256),
        rotate(&other, &caller, SignatureAlgorithm::Es384),
    )
    .await;

    assert!(waited, "the second rotation waits for the first");
    assert!(first.is_ok(), "{first:?}");
    assert_eq!(
        second,
        Err(ErrorCode::SigningKeyLimitReached),
        "no room was left"
    );
    let keys = list_realm_keys(&app, scope).await.expect("the keys");
    assert_eq!(keys.len(), MAX_SIGNING_KEYS);
}

fn remove(
    app: &App,
    caller: &AdminCaller,
    key_id: &str,
) -> impl Future<Output = Result<(), ErrorCode>> + Send + 'static {
    let (app, caller, key_id) = (app.clone(), caller.clone(), key_id.to_owned());
    async move {
        remove_retired_key(&app, &caller, &key_id)
            .await
            .map_err(|failure| failure.code)
    }
}

/// The first removal stops on the head of the chain, which it writes right
/// after the key went.
#[tokio::test]
async fn two_removals_of_one_key_at_once_remove_it_once_and_say_so_once() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let first_key = list_realm_keys(&app, scope)
        .await
        .expect("the keys")
        .into_iter()
        .find(|key| key.algorithm == SignatureAlgorithm::Rs256)
        .expect("the first RSA key");
    rotate(&app, &caller, SignatureAlgorithm::Rs256)
        .await
        .expect("a key that retires the first");

    let (waited, first, second) = race_two_writers(
        &database,
        "LOCK TABLE audit_chain_heads IN ACCESS EXCLUSIVE MODE",
        remove(&app, &caller, &first_key.key_id),
        remove(&app, &caller, &first_key.key_id),
    )
    .await;

    assert!(waited, "the second removal waits for the first");
    assert_eq!(first, Ok(()));
    assert_eq!(
        second,
        Err(ErrorCode::KeyNotFound),
        "nothing was left to remove"
    );
    let said: i64 = connect(&database, MAINTENANCE_ROLE)
        .await
        .query_one(
            "SELECT count(*) FROM audit_events WHERE kind = 'key.deleted'",
            &[],
        )
        .await
        .expect("a count")
        .get(0);
    assert_eq!(said, 1, "the chain says the removal once");
}

/// Under the rules of the schema, the serving role retires an active key,
/// then removes it: what a build that no longer signs in its algorithm does.
#[tokio::test]
async fn a_key_this_build_does_not_sign_in_is_retired_then_removed() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let caller = name_operator(&app, scope).await;
    let eddsa = rotate(&app, &caller, SignatureAlgorithm::EdDsa)
        .await
        .expect("a key, made by a build that may");
    let without_eddsa = App {
        signer: Arc::new(WeakSigner::refusing(SignatureAlgorithm::EdDsa)),
        ..app.clone()
    };

    let removed = remove(&without_eddsa, &caller, &eddsa).await;

    assert_eq!(removed, Ok(()));
    let keys = list_realm_keys(&app, scope).await.expect("the keys");
    assert!(keys.iter().all(|key| key.key_id != eddsa));
    let said: Vec<String> = connect(&database, MAINTENANCE_ROLE)
        .await
        .query(
            "SELECT kind FROM audit_events
             WHERE convert_from(envelope, 'UTF8')::jsonb -> 'payload' ->> 'kid' = $1
             ORDER BY seq",
            &[&eddsa],
        )
        .await
        .expect("the chain")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(said, ["key.created", "key.retired", "key.deleted"]);
}
