//! The keys of a realm on Postgres, sealed by the provider under a root key
//! that never reaches the database.

use crypto::envelope::is_sealed;
use pgcore::APP_ROLE;
use saffui_core::app::App;
use saffui_core::error::ErrorCode;
use saffui_core::keys::jwks::open_signing_key;
use saffui_core::ports::crypto::SignatureAlgorithm;
use saffui_core::secret::Secret;
use saffui_core::tenancy::RealmScope;
use tokio_postgres::error::SqlState;

#[path = "support/product.rs"]
mod product;

use product::{ROOT_KEY, connect_as, create_realm, scope_statement, wire_app, wire_on_postgres};

const OWNER: &str = "saffui_owner";

/// Opens the signing key of `scope`, and says what refused it if it does not open.
async fn open_key_of(app: &App, scope: RealmScope) -> Result<Secret, ErrorCode> {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    open_signing_key(app, work.as_mut(), SignatureAlgorithm::Es256)
        .await
        .map(|(_key, private_key)| private_key)
        .map_err(|failure| failure.code)
}

/// Reads one `bytea` column of the realm of `scope`, as the owner of the tables.
async fn read_stored(
    database: &pgcore::testkit::TestDatabase,
    scope: RealmScope,
    sql: &str,
) -> Vec<u8> {
    let owner = connect_as(database, OWNER).await;
    owner
        .batch_execute(&format!("BEGIN; {}", scope_statement(scope)))
        .await
        .expect("a scoped transaction");
    let stored: Vec<u8> = owner.query_one(sql, &[]).await.expect("a row").get(0);
    owner.batch_execute("ROLLBACK").await.expect("a rollback");
    stored
}

#[tokio::test]
async fn a_private_key_is_stored_sealed_and_the_root_key_is_stored_nowhere() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "acme").await;

    let private_key = open_key_of(&app, scope).await.expect("the key opens");
    let sealed = read_stored(
        &database,
        scope,
        "SELECT sealed_private_key FROM signing_keys",
    )
    .await;
    let wrapped = read_stored(&database, scope, "SELECT wrapped FROM realm_data_keys").await;

    assert!(is_sealed(&sealed), "the stored key is an envelope");
    let private = private_key.expose();
    assert!(
        !sealed
            .windows(private.len())
            .any(|window| window == private),
        "the private key is not kept in the clear"
    );
    for stored in [&sealed, &wrapped] {
        assert!(
            !stored
                .windows(ROOT_KEY.len())
                .any(|window| window == ROOT_KEY),
            "the root key is not in the database"
        );
    }
}

#[tokio::test]
async fn a_sealed_key_moved_to_another_realm_does_not_open_there() {
    let (app, database) = wire_on_postgres().await;
    let acme = create_realm(&app, "acme").await;
    let globex = create_realm(&app, "globex").await;
    let moved = read_stored(
        &database,
        acme,
        "SELECT sealed_private_key FROM signing_keys",
    )
    .await;

    let owner = connect_as(&database, OWNER).await;
    owner
        .batch_execute(&format!("BEGIN; {}", scope_statement(globex)))
        .await
        .expect("a scoped transaction");
    owner
        .execute("UPDATE signing_keys SET sealed_private_key = $1", &[&moved])
        .await
        .expect("a hand in the database");
    owner.batch_execute("COMMIT").await.expect("a commit");

    assert_eq!(
        open_key_of(&app, globex).await.map(|_| ()),
        Err(ErrorCode::CryptoUnavailable)
    );
    assert!(
        open_key_of(&app, acme).await.is_ok(),
        "where it was sealed, it still opens"
    );
}

#[tokio::test]
async fn a_data_key_moved_to_another_realm_opens_nothing_there() {
    let (app, database) = wire_on_postgres().await;
    let acme = create_realm(&app, "acme").await;
    let globex = create_realm(&app, "globex").await;
    let moved = read_stored(&database, acme, "SELECT wrapped FROM realm_data_keys").await;

    let owner = connect_as(&database, OWNER).await;
    owner
        .batch_execute(&format!("BEGIN; {}", scope_statement(globex)))
        .await
        .expect("a scoped transaction");
    owner
        .execute("UPDATE realm_data_keys SET wrapped = $1", &[&moved])
        .await
        .expect("a hand in the database");
    owner.batch_execute("COMMIT").await.expect("a commit");

    assert_eq!(
        open_key_of(&app, globex).await.map(|_| ()),
        Err(ErrorCode::CryptoUnavailable)
    );
}

#[tokio::test]
async fn under_another_root_key_no_key_of_a_realm_opens() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "acme").await;

    let elsewhere = wire_app(&database, &Secret::new(vec![8; 32]));

    assert_eq!(
        open_key_of(&elsewhere, scope).await.map(|_| ()),
        Err(ErrorCode::CryptoUnavailable)
    );
}

#[tokio::test]
async fn the_serving_role_cannot_change_or_remove_a_key() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "acme").await;
    let session = connect_as(&database, APP_ROLE).await;

    for statement in [
        "UPDATE signing_keys SET sealed_private_key = sealed_private_key",
        "DELETE FROM signing_keys",
        "UPDATE realm_data_keys SET wrapped = wrapped",
        "DELETE FROM realm_data_keys",
    ] {
        session
            .batch_execute(&format!("BEGIN; {}", scope_statement(scope)))
            .await
            .expect("a scoped transaction");
        let refused = session.batch_execute(statement).await.expect_err(statement);
        assert_eq!(
            refused.code(),
            Some(&SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}"
        );
        session.batch_execute("ROLLBACK").await.expect("a rollback");
    }
}
