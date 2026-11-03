//! The contract of the core, played on Postgres: the adapter must answer as
//! the double does.

use pgcore::pool::PoolSettings;
use saffui_core::testkit::contract::{
    check_clients_contract, check_codes_contract, check_keys_contract, check_persons_contract,
    check_refresh_contract, check_sign_in_contract, check_tenancy_contract,
};

mod support;

#[tokio::test]
async fn postgres_passes_the_tenancy_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_tenancy_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_keys_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_keys_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_clients_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_clients_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_persons_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_persons_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_sign_in_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_sign_in_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_codes_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_codes_contract(&app).await;
}

#[tokio::test]
async fn postgres_passes_the_refresh_contract() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;

    check_refresh_contract(&app).await;
}

/// A rotation still in flight when its family is revoked writes a token the
/// revocation cannot see. The family stands revoked for that token all the
/// same: it is not spent, and reads as revoked.
#[tokio::test]
async fn a_token_written_while_its_family_was_revoked_is_not_spent() {
    use std::time::Duration as Wait;

    use saffui_core::ids::mint_id;
    use saffui_core::login::session::{Session, SessionState};
    use saffui_core::testkit::fixtures::{create_person, create_realm};
    use saffui_core::tokens::store::RefreshToken;
    use time::Duration;

    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "race").await;
    let ada = create_person(&app, scope, "ada", "correct horse battery").await;
    let now = app.now();
    let session = Session {
        id: mint_id(&app).expect("an identifier"),
        person: ada.id,
        secret_digest: vec![7; 32],
        state: SessionState::Active,
        authenticated_at: now,
        expires_at: now + Duration::hours(1),
    };
    let family = mint_id(&app).expect("an identifier");
    let mint = |digest: u8| RefreshToken {
        token_digest: vec![digest; 32],
        family,
        client_id: "webapp".to_owned(),
        person: ada.id,
        session: session.id,
        scopes: vec!["openid".to_owned()],
        issued_at: now,
        expires_at: now + Duration::minutes(30),
    };
    let (first, next) = (mint(1), mint(2));
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_session(&session).await.expect("a session");
    work.insert_refresh_token(&first).await.expect("a token");
    work.commit().await.expect("a commit");

    // The rotation spends the first token and writes the next, uncommitted.
    let mut rotation = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        rotation
            .spend_refresh_token(&first.token_digest, "webapp", now)
            .await,
        Ok(Some(first.clone()))
    );
    rotation.insert_refresh_token(&next).await.expect("a token");
    // The revocation waits on the row the rotation holds.
    let storage = app.storage.clone();
    let revocation = tokio::spawn(async move {
        let mut work = storage.begin(scope).await.expect("a unit of work");
        let revoked = work.revoke_refresh_family(family, now).await;
        work.commit().await.expect("a commit");
        revoked
    });
    tokio::time::sleep(Wait::from_millis(300)).await;
    assert!(
        !revocation.is_finished(),
        "the revocation waits for the rotation"
    );
    rotation.commit().await.expect("a commit");
    assert_eq!(
        revocation.await.expect("the revocation"),
        Ok(1),
        "the revocation sees only the token it waited on"
    );

    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.spend_refresh_token(&next.token_digest, "webapp", now)
            .await,
        Ok(None),
        "the token the rotation wrote is not spent"
    );
    let stored = work
        .read_refresh_token(&next.token_digest)
        .await
        .expect("a read")
        .expect("the token");
    assert!(stored.revoked_at.is_some(), "it reads as revoked");
    assert!(!stored.is_live(now));
}
