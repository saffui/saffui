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

/// Opens the ES256 signing key of `scope`, and says what refused it if it does not open.
async fn open_key_of(app: &App, scope: RealmScope) -> Result<Secret, ErrorCode> {
    open_key_in(app, scope, SignatureAlgorithm::Es256).await
}

async fn open_key_in(
    app: &App,
    scope: RealmScope,
    algorithm: SignatureAlgorithm,
) -> Result<Secret, ErrorCode> {
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    open_signing_key(app, work.as_mut(), algorithm)
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
    let wrapped = read_stored(&database, scope, "SELECT wrapped FROM realm_data_keys").await;

    for algorithm in [SignatureAlgorithm::Es256, SignatureAlgorithm::Rs256] {
        let private_key = open_key_in(&app, scope, algorithm)
            .await
            .expect("the key opens");
        let sealed = read_stored(
            &database,
            scope,
            &format!(
                "SELECT sealed_private_key FROM signing_keys WHERE algorithm = '{}'",
                algorithm.name()
            ),
        )
        .await;

        assert!(
            is_sealed(&sealed),
            "the stored {algorithm:?} key is an envelope"
        );
        let private = private_key.expose();
        assert!(
            !sealed
                .windows(private.len())
                .any(|window| window == private),
            "the private {algorithm:?} key is not kept in the clear"
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
}

#[tokio::test]
async fn a_sealed_key_moved_to_another_realm_does_not_open_there() {
    let (app, database) = wire_on_postgres().await;
    let acme = create_realm(&app, "acme").await;
    let globex = create_realm(&app, "globex").await;
    let moved = read_stored(
        &database,
        acme,
        "SELECT sealed_private_key FROM signing_keys WHERE algorithm = 'ES256'",
    )
    .await;

    let owner = connect_as(&database, OWNER).await;
    owner
        .batch_execute(&format!("BEGIN; {}", scope_statement(globex)))
        .await
        .expect("a scoped transaction");
    owner
        .execute(
            "UPDATE signing_keys SET sealed_private_key = $1 WHERE algorithm = 'ES256'",
            &[&moved],
        )
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

/// Runs `statement` as the serving role in `scope`, and keeps nothing.
async fn run_as_server(
    session: &tokio_postgres::Client,
    scope: RealmScope,
    statement: &str,
) -> Result<u64, Option<SqlState>> {
    session
        .batch_execute(&format!("BEGIN; {}", scope_statement(scope)))
        .await
        .expect("a scoped transaction");
    let ran = session
        .execute(statement, &[])
        .await
        .map_err(|refused| refused.code().cloned());
    session.batch_execute("ROLLBACK").await.expect("a rollback");
    ran
}

#[tokio::test]
async fn the_serving_role_retires_a_key_and_removes_a_retired_one_and_changes_nothing_else() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "acme").await;
    let session = connect_as(&database, APP_ROLE).await;
    let refused = Err(Some(SqlState::INSUFFICIENT_PRIVILEGE));

    for statement in [
        "UPDATE signing_keys SET sealed_private_key = sealed_private_key",
        "UPDATE signing_keys SET kid = kid",
        "UPDATE signing_keys SET algorithm = algorithm",
        "UPDATE signing_keys SET public_jwk = public_jwk",
        "UPDATE realm_data_keys SET wrapped = wrapped",
        "UPDATE realm_data_keys SET generation = generation",
        "DELETE FROM realm_data_keys",
        // Row security: an active key is never written back as active.
        "UPDATE signing_keys SET status = 'active'",
    ] {
        assert_eq!(
            run_as_server(&session, scope, statement).await,
            refused,
            "{statement}"
        );
    }
    assert_eq!(
        run_as_server(&session, scope, "DELETE FROM signing_keys").await,
        Ok(0),
        "an active key is not removed"
    );

    // A key retired stays retired, and only then may it go.
    session
        .batch_execute(&format!(
            "BEGIN; {}; UPDATE signing_keys SET status = 'retired' WHERE algorithm = 'RS256'; COMMIT",
            scope_statement(scope)
        ))
        .await
        .expect("a key retired");
    for (statement, changed) in [
        (
            "UPDATE signing_keys SET status = 'active' WHERE status = 'retired'",
            0,
        ),
        (
            "UPDATE signing_keys SET status = 'retired' WHERE status = 'retired'",
            0,
        ),
        ("DELETE FROM signing_keys WHERE status = 'retired'", 1),
        ("DELETE FROM signing_keys", 1),
    ] {
        assert_eq!(
            run_as_server(&session, scope, statement).await,
            Ok(changed),
            "{statement}"
        );
    }
}

/// The serving role may take the row of a data key, to turn the keys of its
/// realm over one rotation at a time: it may write its realm back as it was,
/// and never another. The other realm is of the same tenant, so that the key
/// of the row would pass and row security alone refuses the move.
#[tokio::test]
async fn the_serving_role_takes_a_data_key_and_moves_none_to_another_realm_of_its_tenant() {
    let (app, database) = wire_on_postgres().await;
    let scope = create_realm(&app, "acme").await;
    let tenant = scope.tenant().as_uuid();
    let other = "00000000-0000-0000-0000-00000000004d";
    connect_as(&database, OWNER)
        .await
        .batch_execute(&format!(
            "BEGIN;
             SELECT set_config('saffui.tenant', '{tenant}', true),
                    set_config('saffui.realm', '{other}', true);
             INSERT INTO realms (tenant_id, realm_id, name, enabled, created_at)
                 VALUES ('{tenant}', '{other}', 'acme-two', true, now());
             COMMIT"
        ))
        .await
        .expect("another realm of the tenant");
    let session = connect_as(&database, APP_ROLE).await;

    assert_eq!(
        run_as_server(
            &session,
            scope,
            &format!("UPDATE realm_data_keys SET realm_id = '{other}'")
        )
        .await,
        Err(Some(SqlState::INSUFFICIENT_PRIVILEGE)),
        "a data key never moves to another realm"
    );
    assert_eq!(
        run_as_server(
            &session,
            scope,
            "UPDATE realm_data_keys SET realm_id = realm_id"
        )
        .await,
        Ok(1),
        "the right a row lock asks for"
    );
}
