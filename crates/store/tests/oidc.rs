//! Authorization codes, revocations and assertion replay, against a database.

mod support;

use models::entities::oidc::AuthorizationCode;
use store::providers::oidc::{self, Redemption};
use store::tenancy::TenantContext;
use support::Fixture;

fn code(hash: &str) -> AuthorizationCode {
    AuthorizationCode {
        code_hash: hash.to_owned(),
        tenant: "acme".to_owned(),
        realm_id: "main".to_owned(),
        client_id: "app".to_owned(),
        user_id: "ada".to_owned(),
        session_id: "session-1".to_owned(),
        redirect_uri: "https://app.example/callback".to_owned(),
        scope: "openid profile".to_owned(),
        nonce: Some("n-1".to_owned()),
        code_challenge: Some("challenge".to_owned()),
        code_challenge_method: Some("S256".to_owned()),
        auth_time: 1_700_000_000,
        acr: Some("gold".to_owned()),
        org_id: None,
        org_name: None,
        claims: None,
    }
}

fn in_secs(seconds: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(seconds)
}

/// A code needs a session to speak for.
async fn plant_session(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO user_sessions \
                 (tenant, realm_id, session_id, user_id, login_username, state, started_at) \
             VALUES ('acme', 'main', 'session-1', 'ada', 'ada', 'logged-in', \
                     extract(epoch FROM now())::bigint)",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
}

/// Everything /token re-checks is bound to the code rather than looked up
/// again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_carries_what_redemption_must_recheck() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    oidc::mint_code(&transaction, &code("hash-1"), in_secs(60))
        .await
        .unwrap();

    let Redemption::Fresh(spent) = oidc::redeem_code(&transaction, "hash-1").await.unwrap() else {
        panic!("the code was not found");
    };
    assert_eq!(spent.redirect_uri, "https://app.example/callback");
    assert_eq!(spent.code_challenge.as_deref(), Some("challenge"));
    assert_eq!(spent.code_challenge_method.as_deref(), Some("S256"));
    assert_eq!(spent.nonce.as_deref(), Some("n-1"));
    assert_eq!(spent.acr.as_deref(), Some("gold"));
    assert_eq!(spent.auth_time, 1_700_000_000);
    assert_eq!(spent.scope, "openid profile");
}

/// A code is spent by the attempt, not by the attempt succeeding, and a second
/// attempt is told apart from a code that never was: it names what the first
/// bought, so that can be taken back.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_is_spent_once_and_a_replay_names_what_it_bought() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    oidc::mint_code(&transaction, &code("hash-1"), in_secs(60))
        .await
        .unwrap();

    assert!(matches!(
        oidc::redeem_code(&transaction, "hash-1").await.unwrap(),
        Redemption::Fresh(_)
    ));
    oidc::record_issued(
        &transaction,
        "hash-1",
        &["jti-access".into(), "jti-refresh".into()],
    )
    .await
    .unwrap();
    match oidc::redeem_code(&transaction, "hash-1").await.unwrap() {
        Redemption::Reused { issued_token_ids } => {
            assert_eq!(issued_token_ids, vec!["jti-access", "jti-refresh"]);
        }
        other => panic!("a replayed code was not seen as one: {other:?}"),
    }
    assert!(matches!(
        oidc::redeem_code(&transaction, "never-minted")
            .await
            .unwrap(),
        Redemption::Unknown
    ));
}

/// An expired code is not handed back, however often it is tried, and the
/// sweep is what removes it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_expired_code_is_refused_until_swept() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // Planted raw: the schema refuses a code expiring before it was issued, so
    // the provider cannot write one that has already expired.
    transaction
        .execute(
            "INSERT INTO oidc_auth_codes \
                 (tenant, realm_id, code_hash, client_id, user_id, session_id, redirect_uri, \
                  scope, auth_time, issued_at, expires_at) \
             VALUES ('acme', 'main', 'stale', 'app', 'ada', 'session-1', 'https://x', \
                     'openid', 0, now() - interval '10 minutes', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();

    for attempt in ["first", "second"] {
        assert!(
            matches!(
                oidc::redeem_code(&transaction, "stale").await.unwrap(),
                Redemption::Unknown
            ),
            "an expired code was handed back on the {attempt} attempt"
        );
    }
    oidc::drop_expired_codes(&transaction).await.unwrap();
    let left: i64 = transaction
        .query_one(
            "SELECT count(*) FROM oidc_auth_codes WHERE code_hash = 'stale'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(left, 0, "an expired code survived the sweep");
}

/// A challenge and the method that reads it travel together.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_challenge_cannot_stand_without_its_method() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;

    let cases = [
        (
            "'challenge', NULL",
            "a challenge was recorded with no method to read it",
        ),
        (
            "NULL, 'S256'",
            "a method was recorded with no challenge to read",
        ),
    ];

    for (index, (values, what)) in cases.iter().enumerate() {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let statement = format!(
            "INSERT INTO oidc_auth_codes \
                 (tenant, realm_id, code_hash, client_id, user_id, session_id, redirect_uri, \
                  scope, code_challenge, code_challenge_method, auth_time, expires_at) \
             VALUES ('acme', 'main', 'bad-{index}', 'app', 'ada', 'session-1', 'https://x', \
                     'openid', {values}, 0, now() + interval '1 minute')"
        );
        let refused = transaction.execute(statement.as_str(), &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// A code cannot expire before it was issued, which is why the expiry tests
/// plant their rows by hand rather than through the provider.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_cannot_expire_before_it_is_issued() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        transaction
            .execute(
                "INSERT INTO oidc_auth_codes \
                     (tenant, realm_id, code_hash, client_id, user_id, session_id, \
                      redirect_uri, scope, auth_time, issued_at, expires_at) \
                 VALUES ('acme', 'main', 'backwards', 'app', 'ada', 'session-1', \
                         'https://x', 'openid', 0, now(), now() - interval '1 second')",
                &[],
            )
            .await
            .is_err(),
        "a code was minted expiring before it was issued"
    );
}

/// A revocation answers the question asked on every request, until the token
/// would have expired anyway.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_revoked_token_is_refused_until_it_would_have_expired() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(!oidc::is_revoked(&transaction, "token-1").await.unwrap());

    oidc::revoke(&transaction, "token-1", in_secs(300), "logout")
        .await
        .unwrap();
    // Saying it twice says the same thing.
    oidc::revoke(&transaction, "token-1", in_secs(300), "logout")
        .await
        .unwrap();
    assert!(oidc::is_revoked(&transaction, "token-1").await.unwrap());

    // One whose own expiry has passed answers no: it is refused by its expiry
    // already, and a sweep that has not run yet must not change the answer.
    transaction
        .execute(
            "INSERT INTO revoked_tokens (tenant, realm_id, token_id, expires_at) \
             VALUES ('acme', 'main', 'token-old', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();
    assert!(!oidc::is_revoked(&transaction, "token-old").await.unwrap());

    assert_eq!(
        oidc::drop_expired_revocations(&transaction).await.unwrap(),
        1
    );
    assert!(oidc::is_revoked(&transaction, "token-1").await.unwrap());
}

/// The insertion is the check: claiming twice is refused by the key.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_assertion_identifier_is_used_once_per_client() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        oidc::claim_assertion(&transaction, "app", "jti-1", in_secs(60))
            .await
            .unwrap()
    );
    assert!(
        !oidc::claim_assertion(&transaction, "app", "jti-1", in_secs(60))
            .await
            .unwrap(),
        "one assertion authenticated twice"
    );

    // Another client's assertions are its own.
    transaction
        .execute(
            "INSERT INTO clients (tenant, realm_id, client_id, name, display_name) \
             VALUES ('acme', 'main', 'mobile', 'mobile', 'Mobile')",
            &[],
        )
        .await
        .unwrap();
    assert!(
        oidc::claim_assertion(&transaction, "mobile", "jti-1", in_secs(60))
            .await
            .unwrap(),
        "one client's assertion blocked another's"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_expired_is_swept() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    oidc::mint_code(&transaction, &code("live"), in_secs(300))
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO oidc_auth_codes \
                 (tenant, realm_id, code_hash, client_id, user_id, session_id, redirect_uri, \
                  scope, auth_time, issued_at, expires_at) \
             VALUES ('acme', 'main', 'stale', 'app', 'ada', 'session-1', 'https://x', \
                     'openid', 0, now() - interval '10 minutes', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO client_assertion_jtis (tenant, realm_id, client_id, jti_hash, expires_at) \
             VALUES ('acme', 'main', 'app', 'old', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();

    assert_eq!(oidc::drop_expired_codes(&transaction).await.unwrap(), 1);
    assert_eq!(
        oidc::drop_expired_assertions(&transaction).await.unwrap(),
        1
    );
    assert!(matches!(
        oidc::redeem_code(&transaction, "live").await.unwrap(),
        Redemption::Fresh(_)
    ));
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn none_of_it_is_visible_from_another_realm() {
    let fixture = Fixture::with_user_and_client().await;
    plant_session(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    oidc::mint_code(&transaction, &code("hash-1"), in_secs(300))
        .await
        .unwrap();
    oidc::revoke(&transaction, "token-1", in_secs(300), "logout")
        .await
        .unwrap();
    oidc::claim_assertion(&transaction, "app", "jti-1", in_secs(60))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        matches!(
            oidc::redeem_code(&transaction, "hash-1").await.unwrap(),
            Redemption::Unknown
        ),
        "another realm redeemed this realm's code"
    );
    assert!(
        !oidc::is_revoked(&transaction, "token-1").await.unwrap(),
        "another realm read this realm's revocations"
    );
    assert!(
        oidc::claim_assertion(&transaction, "app", "jti-1", in_secs(60))
            .await
            .is_err(),
        "another realm claimed an assertion against a client it cannot see"
    );
}
