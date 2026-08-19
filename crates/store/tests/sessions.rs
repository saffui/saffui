//! What a login leaves behind, against a database.

mod support;

use chrono::{Duration, Utc};
use crypto::provider::CryptoProvider;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use store::providers::one_time_tokens::{self, Owner};
use store::providers::sessions;
use store::tenancy::TenantContext;
use support::{Fixture, provider};

fn session(id: &str, started_at: i64) -> UserSessionModel {
    UserSessionModel {
        tenant: "acme".into(),
        realm_id: "main".into(),
        session_id: id.into(),
        user_id: "ada".into(),
        login_username: "ada".into(),
        broker_session_id: None,
        broker_user_id: None,
        auth_method: Some("password".into()),
        ip_address: Some("198.51.100.7".into()),
        started_at,
        auth_time: Some(started_at),
        loa: Some(1),
        expiration: Some(started_at + 3_600),
        state: UserSessionState::LoggedIn,
        remember_me: Some(false),
        last_session_refresh: None,
        is_offline: Some(false),
        notes: None,
    }
}

fn client_session(id: &str, user_session: &str) -> ClientSessionModel {
    ClientSessionModel {
        tenant: "acme".into(),
        realm_id: "main".into(),
        session_id: id.into(),
        user_session_id: user_session.into(),
        user_id: "ada".into(),
        client_id: "app".into(),
        auth_method: Some("openid-connect".into()),
        redirect_uri: Some("https://app.example/cb".into()),
        started_at: 1_000,
        expiration: Some(4_600),
        notes: None,
        current_refresh_token: Some("rt-s3cr3t".into()),
        current_refresh_token_use_count: Some(0),
        offline: Some(false),
    }
}

/// An authentication moves its instant and its level together. A level raised
/// without the instant attests to a strength reached at a time nothing recorded.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_up_moves_the_instant_and_the_level_together() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    sessions::open(&transaction, &session("s-1", 1_000))
        .await
        .unwrap();

    let opened = sessions::load(&transaction, "s-1").await.unwrap().unwrap();
    assert_eq!(opened.auth_time, Some(1_000));
    assert_eq!(opened.loa, Some(1));
    assert_eq!(opened.state, UserSessionState::LoggedIn);

    assert!(
        sessions::record_authentication(&transaction, "s-1", 5_000, Some(2))
            .await
            .unwrap()
    );

    let stepped = sessions::load(&transaction, "s-1").await.unwrap().unwrap();
    assert_eq!(stepped.auth_time, Some(5_000));
    assert_eq!(stepped.loa, Some(2));
    assert_eq!(
        stepped.started_at, 1_000,
        "the session is still the one that began at nine"
    );

    assert!(
        !sessions::record_authentication(&transaction, "nobody", 6_000, Some(3))
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

/// A client session dies with the login it belongs to. Left behind, it is a
/// refresh token outliving the session that authorised it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn closing_a_login_takes_what_the_clients_got_with_it() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    sessions::open(&transaction, &session("s-1", 1_000))
        .await
        .unwrap();
    sessions::open_client_session(&transaction, &client_session("cs-1", "s-1"))
        .await
        .unwrap();

    assert_eq!(
        sessions::client_sessions_of(&transaction, "s-1")
            .await
            .unwrap()
            .len(),
        1
    );

    assert!(sessions::close(&transaction, "s-1").await.unwrap());
    assert!(
        sessions::client_sessions_of(&transaction, "s-1")
            .await
            .unwrap()
            .is_empty(),
        "a client session outlived the login that authorised it"
    );
    assert!(!sessions::close(&transaction, "s-1").await.unwrap());
    transaction.commit().await.unwrap();
}

/// A loaded client session carries no refresh token, and reaching one brings its
/// use count with it: a token that matches and has been presented before is a
/// replay, and neither half says that alone.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refresh_token_comes_with_how_often_it_was_presented() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    sessions::open(&transaction, &session("s-1", 1_000))
        .await
        .unwrap();
    sessions::open_client_session(&transaction, &client_session("cs-1", "s-1"))
        .await
        .unwrap();

    let loaded = &sessions::client_sessions_of(&transaction, "s-1")
        .await
        .unwrap()[0];
    assert_eq!(
        loaded.current_refresh_token, None,
        "a plain read carried the token the client refreshes with"
    );
    assert_eq!(loaded.current_refresh_token_use_count, Some(0));

    let (token, used) = sessions::refresh_token(&transaction, "cs-1")
        .await
        .unwrap()
        .expect("the deliberate call reaches it");
    assert_eq!(token, "rt-s3cr3t");
    assert_eq!(used, 0, "never presented yet");

    assert_eq!(
        sessions::count_refresh_use(&transaction, "cs-1")
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        sessions::count_refresh_use(&transaction, "cs-1")
            .await
            .unwrap(),
        Some(2),
        "it counts how far a reuse went rather than flagging that one happened"
    );
    assert_eq!(
        sessions::count_refresh_use(&transaction, "nobody")
            .await
            .unwrap(),
        None
    );
    transaction.commit().await.unwrap();
}

/// A token is spent in the statement that checks it.
///
/// Reading it and then deleting it is a window in which two presentations both
/// find it valid, which for a link in a mail is the difference between single
/// use and single use most of the time.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_token_is_spent_once_and_only_by_its_own_value() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let now = Utc::now();
    let owner = Owner {
        tenant: "acme",
        realm_id: "main",
        user_id: "ada",
        purpose: "magic-link",
    };
    one_time_tokens::mint(
        &transaction,
        provider().digest(),
        owner,
        "the-raw-link",
        now + Duration::minutes(10),
    )
    .await
    .unwrap();

    assert!(
        one_time_tokens::outstanding(&transaction, "ada", "magic-link", now)
            .await
            .unwrap()
    );
    assert!(
        !one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "magic-link",
            "guessed",
            now
        )
        .await
        .unwrap(),
        "a value that was not minted spent the token"
    );
    assert!(
        !one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "reset",
            "the-raw-link",
            now
        )
        .await
        .unwrap(),
        "a token for one purpose was spent against another"
    );

    assert!(
        one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "magic-link",
            "the-raw-link",
            now
        )
        .await
        .unwrap()
    );
    assert!(
        !one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "magic-link",
            "the-raw-link",
            now
        )
        .await
        .unwrap(),
        "the same link was accepted twice"
    );
    assert!(
        !one_time_tokens::outstanding(&transaction, "ada", "magic-link", now)
            .await
            .unwrap()
    );
    transaction.commit().await.unwrap();
}

/// Only the digest is stored, one is live per purpose, and an expired one is
/// refused however well it matches.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_newest_and_the_unexpired_is_honoured() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    let now = Utc::now();
    let owner = Owner {
        tenant: "acme",
        realm_id: "main",
        user_id: "ada",
        purpose: "magic-link",
    };

    one_time_tokens::mint(
        &transaction,
        provider().digest(),
        owner,
        "first",
        now + Duration::minutes(10),
    )
    .await
    .unwrap();
    one_time_tokens::mint(
        &transaction,
        provider().digest(),
        owner,
        "second",
        now + Duration::minutes(10),
    )
    .await
    .unwrap();

    assert!(
        !one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "magic-link",
            "first",
            now
        )
        .await
        .unwrap(),
        "asking for a second link left the first one working"
    );
    assert!(
        one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "magic-link",
            "second",
            now
        )
        .await
        .unwrap()
    );

    // The value itself is nowhere in the table.
    one_time_tokens::mint(
        &transaction,
        provider().digest(),
        owner,
        "the-raw-link",
        now + Duration::minutes(10),
    )
    .await
    .unwrap();
    let stored: Vec<u8> = transaction
        .query_one("SELECT token_hash FROM one_time_tokens", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(stored.len(), 32, "a digest and not the value");
    assert_ne!(stored, b"the-raw-link".to_vec());

    // Expired is refused, and swept.
    let later = now + Duration::hours(1);
    assert!(
        !one_time_tokens::spend(
            &transaction,
            provider().digest(),
            "ada",
            "magic-link",
            "the-raw-link",
            later
        )
        .await
        .unwrap(),
        "an expired link was honoured"
    );
    assert_eq!(
        one_time_tokens::drop_expired(&transaction, later)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        one_time_tokens::drop_expired(&transaction, later)
            .await
            .unwrap(),
        0
    );
    transaction.commit().await.unwrap();
}

/// Two guards the provider cannot trip, and something else could.
///
/// The provider always hashes, so it always stores a digest, and the model's
/// state is not optional, so it always writes one. Both constraints exist for
/// whatever writes these rows next, and are checked the only way they can be.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_schema_refuses_what_no_provider_would_write() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // A value where a digest belongs.
    let raw = b"the-raw-link".to_vec();
    assert!(
        transaction
            .execute(
                "INSERT INTO one_time_tokens (tenant, realm_id, user_id, purpose, token_hash, expires_at) \
                 VALUES ('acme', 'main', 'ada', 'magic-link', $1, now() + interval '10 minutes')",
                &[&raw],
            )
            .await
            .is_err(),
        "something other than a digest was stored where one belongs"
    );
    transaction.batch_execute("ROLLBACK; BEGIN").await.unwrap();
    transaction
        .execute(
            "SELECT set_config('saffui.current_tenant', 'acme', true)",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "SELECT set_config('saffui.current_realm', 'main', true)",
            &[],
        )
        .await
        .unwrap();

    // A session with no state, which has to be read as something.
    assert!(
        transaction
            .execute(
                "INSERT INTO user_sessions \
                 (tenant, realm_id, session_id, user_id, login_username, started_at) \
                 VALUES ('acme', 'main', 's-1', 'ada', 'ada', 1000)",
                &[],
            )
            .await
            .is_err(),
        "a session was opened with no state at all"
    );
}

/// A rotation states which token it replaces, so two refreshes racing on one
/// session cannot both land. The loser is told it lost rather than quietly
/// overwriting the winner, which would leave a client holding a token the row
/// no longer names.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_one_of_two_racing_rotations_lands() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    sessions::open(&transaction, &session("s-1", 1_000))
        .await
        .unwrap();
    sessions::open_client_session(&transaction, &client_session("cs-1", "s-1"))
        .await
        .unwrap();
    sessions::count_refresh_use(&transaction, "cs-1")
        .await
        .unwrap();

    assert!(
        sessions::rotate_refresh_token(&transaction, "cs-1", Some("rt-s3cr3t"), "rt-next")
            .await
            .unwrap(),
        "the holder of the current token rotates"
    );

    let (token, used) = sessions::refresh_token(&transaction, "cs-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(token, "rt-next");
    assert_eq!(
        used, 0,
        "the count follows the token it counts, so a successor does not inherit \
         what its predecessor was presented for"
    );

    assert!(
        !sessions::rotate_refresh_token(&transaction, "cs-1", Some("rt-s3cr3t"), "rt-forged")
            .await
            .unwrap(),
        "the second refresh read the same token and must not land on top of the first"
    );
    assert_eq!(
        sessions::refresh_token(&transaction, "cs-1")
            .await
            .unwrap()
            .unwrap()
            .0,
        "rt-next"
    );

    assert!(
        !sessions::rotate_refresh_token(&transaction, "nobody", Some("rt-next"), "rt-x")
            .await
            .unwrap(),
        "a session that does not exist rotates nothing"
    );
    transaction.commit().await.unwrap();
}
