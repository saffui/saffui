//! A login in progress, what it has failed at, and what a user may present.

mod support;

use store::providers::login::{self, AuthSession};
use store::providers::webauthn::{self, EnrolledCredential};
use store::tenancy::TenantContext;
use support::Fixture;

fn session(id: &str, seconds: i64) -> AuthSession {
    AuthSession {
        session_id: id.to_owned(),
        client_id: "app".to_owned(),
        flow_id: "flow-1".to_owned(),
        execution_id: None,
        user_id: None,
        redirect_uri: "https://app.example/callback".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(seconds),
        notes: serde_json::json!({}),
    }
}

fn credential(id: &[u8], user: &str, label: &str) -> EnrolledCredential {
    EnrolledCredential {
        credential_id: id.to_vec(),
        user_id: user.to_owned(),
        label: label.to_owned(),
        passkey: serde_json::json!({"kty": "EC", "alg": -7}),
        sign_count: 0,
        last_used_at: None,
    }
}

/// A flow needs somewhere to keep a login while it is still deciding.
async fn plant_flow(fixture: &Fixture) {
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO authentication_flows (tenant, realm_id, flow_id, alias, provider_id) \
             VALUES ('acme', 'main', 'flow-1', 'browser', 'basic-flow')",
            &[],
        )
        .await
        .unwrap();
    transaction
        .execute(
            "INSERT INTO authentication_executions \
                 (tenant, realm_id, execution_id, alias, flow_id, priority, requirement, \
                  authenticator) \
             VALUES ('acme', 'main', 'exec-1', 'cookie', 'flow-1', 10, 'required', 'auth-cookie')",
            &[],
        )
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_is_resumed_until_it_expires() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    login::start(&transaction, &session("login-1", 300))
        .await
        .unwrap();
    let resumed = login::resume(&transaction, "login-1")
        .await
        .unwrap()
        .expect("the login was not found");
    assert_eq!(resumed.client_id, "app");
    assert_eq!(resumed.user_id, None, "a login knows nobody before it asks");
    assert_eq!(resumed.notes, serde_json::json!({}));

    // Planted raw, with its start pushed back too: the provider cannot write one
    // that has already expired, because a login expiring before it starts is a
    // row the schema refuses.
    transaction
        .execute(
            "INSERT INTO auth_sessions \
                 (tenant, realm_id, session_id, client_id, flow_id, redirect_uri, \
                  started_at, expires_at) \
             VALUES ('acme', 'main', 'login-2', 'app', 'flow-1', 'https://x', \
                     now() - interval '10 minutes', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();
    assert!(
        login::resume(&transaction, "login-2")
            .await
            .unwrap()
            .is_none(),
        "an expired login was handed back"
    );

    assert_eq!(login::drop_expired(&transaction).await.unwrap(), 1);
    assert!(
        login::resume(&transaction, "login-1")
            .await
            .unwrap()
            .is_some()
    );
}

/// The notes are merged, so one step does not drop what another wrote.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_step_adds_to_the_notes_without_erasing_them() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    login::start(&transaction, &session("login-1", 300))
        .await
        .unwrap();

    assert!(
        login::record_step(
            &transaction,
            "login-1",
            None,
            Some("exec-1"),
            &serde_json::json!({"attempted": "cookie"}),
        )
        .await
        .unwrap()
    );
    assert!(
        login::record_step(
            &transaction,
            "login-1",
            Some("ada"),
            None,
            &serde_json::json!({"identified_by": "username"}),
        )
        .await
        .unwrap()
    );

    let resumed = login::resume(&transaction, "login-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.user_id.as_deref(), Some("ada"));
    assert_eq!(
        resumed.execution_id.as_deref(),
        Some("exec-1"),
        "the second step cleared where the flow stood"
    );
    assert_eq!(
        resumed.notes,
        serde_json::json!({"attempted": "cookie", "identified_by": "username"}),
        "a step erased what another step wrote"
    );

    assert!(login::finish(&transaction, "login-1").await.unwrap());
    assert!(!login::finish(&transaction, "login-1").await.unwrap());
}

/// The notes are a bounded map, written as a raw statement since the provider
/// takes a value and cannot express either wrong shape.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_notes_are_a_map_and_have_a_ceiling() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;

    let big = "x".repeat(5000);
    let cases = [
        (
            "'\"a string, not a map\"'::jsonb".to_owned(),
            "the notes were allowed to be something other than a map",
        ),
        (
            format!("jsonb_build_object('stashed', '{big}')"),
            "the notes were allowed to grow without a ceiling",
        ),
    ];

    for (index, (notes, what)) in cases.iter().enumerate() {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::new("acme", "main"))
            .await;
        let statement = format!(
            "INSERT INTO auth_sessions \
                 (tenant, realm_id, session_id, client_id, flow_id, redirect_uri, \
                  expires_at, notes) \
             VALUES ('acme', 'main', 'bad-{index}', 'app', 'flow-1', 'https://x', \
                     now() + interval '5 minutes', {notes})"
        );
        let refused = transaction.execute(statement.as_str(), &[]).await.is_err();
        drop(transaction);
        drop(connection);
        assert!(refused, "{what}");
    }
}

/// Counting is one statement, so two failures at once are two.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn failures_are_counted_and_earn_a_lockout() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        login::failures(&transaction, "ada")
            .await
            .unwrap()
            .is_none()
    );

    let first = login::record_failure(&transaction, "ada", 1_000, Some("10.0.0.1"), 3, 60)
        .await
        .unwrap();
    assert_eq!(first.num_failures, 1);
    assert_eq!(
        first.failed_login_not_before, 0,
        "one failure earned a lockout"
    );
    assert_eq!(first.last_ip_failure.as_deref(), Some("10.0.0.1"));

    let second = login::record_failure(&transaction, "ada", 1_010, Some("10.0.0.2"), 3, 60)
        .await
        .unwrap();
    assert_eq!(second.num_failures, 2);
    assert_eq!(second.failed_login_not_before, 0);

    let third = login::record_failure(&transaction, "ada", 1_020, None, 3, 60)
        .await
        .unwrap();
    assert_eq!(third.num_failures, 3);
    assert_eq!(
        third.failed_login_not_before, 1_080,
        "the third failure did not earn the lockout the threshold asks for"
    );
    assert!(third.is_locked_at(1_050));
    assert!(!third.is_locked_at(1_080), "the lock outlived its window");

    // The address is the last one seen, not every one.
    assert_eq!(third.last_ip_failure, None);

    assert!(login::clear_failures(&transaction, "ada").await.unwrap());
    assert!(
        login::failures(&transaction, "ada")
            .await
            .unwrap()
            .is_none()
    );
}

/// A counter that does not advance is a cloned authenticator announcing itself.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_counter_that_does_not_advance_is_refused() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    webauthn::enrol(&transaction, &credential(b"key-1", "ada", "yubikey"))
        .await
        .unwrap();

    assert!(
        webauthn::record_use(&transaction, b"key-1", 5)
            .await
            .unwrap()
    );
    assert!(
        !webauthn::record_use(&transaction, b"key-1", 5)
            .await
            .unwrap(),
        "a repeated counter was accepted"
    );
    assert!(
        !webauthn::record_use(&transaction, b"key-1", 4)
            .await
            .unwrap(),
        "a counter going backwards was accepted"
    );
    assert!(
        webauthn::record_use(&transaction, b"key-1", 6)
            .await
            .unwrap()
    );

    // Zero is what an authenticator keeping no counter reports every time.
    webauthn::enrol(&transaction, &credential(b"key-2", "ada", "phone"))
        .await
        .unwrap();
    assert!(
        webauthn::record_use(&transaction, b"key-2", 0)
            .await
            .unwrap()
    );
    assert!(
        webauthn::record_use(&transaction, b"key-2", 0)
            .await
            .unwrap()
    );

    let held = webauthn::by_id(&transaction, b"key-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(held.sign_count, 6);
    assert!(held.last_used_at.is_some());
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_user_presents_what_they_enrolled() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    // Written in the opposite order to the one expected: enrolled in one
    // transaction they share an instant, so the identifier is what decides.
    for (id, label) in [
        (b"key-2".as_slice(), "phone"),
        (b"key-1".as_slice(), "yubikey"),
    ] {
        webauthn::enrol(&transaction, &credential(id, "ada", label))
            .await
            .unwrap();
    }

    let held = webauthn::of_user(&transaction, "ada").await.unwrap();
    assert_eq!(
        held.iter().map(|c| c.label.as_str()).collect::<Vec<_>>(),
        vec!["yubikey", "phone"],
        "the list is not in a stated order"
    );

    assert!(webauthn::revoke(&transaction, b"key-1").await.unwrap());
    assert!(!webauthn::revoke(&transaction, b"key-1").await.unwrap());
    assert_eq!(
        webauthn::of_user(&transaction, "ada").await.unwrap().len(),
        1
    );
}

/// A login that has expired is finished, whatever it is asked to do next.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_expired_login_does_not_advance() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    transaction
        .execute(
            "INSERT INTO auth_sessions \
                 (tenant, realm_id, session_id, client_id, flow_id, redirect_uri, \
                  started_at, expires_at) \
             VALUES ('acme', 'main', 'stale', 'app', 'flow-1', 'https://x', \
                     now() - interval '10 minutes', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();

    assert!(
        !login::record_step(
            &transaction,
            "stale",
            Some("ada"),
            None,
            &serde_json::json!({})
        )
        .await
        .unwrap(),
        "an expired login was advanced"
    );
}

/// Once a step has said who this is, a later step that says nothing does not
/// unsay it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_later_step_does_not_forget_the_user() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    login::start(&transaction, &session("login-1", 300))
        .await
        .unwrap();

    login::record_step(
        &transaction,
        "login-1",
        Some("ada"),
        None,
        &serde_json::json!({}),
    )
    .await
    .unwrap();
    login::record_step(
        &transaction,
        "login-1",
        None,
        Some("exec-1"),
        &serde_json::json!({"second": "step"}),
    )
    .await
    .unwrap();

    let resumed = login::resume(&transaction, "login-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        resumed.user_id.as_deref(),
        Some("ada"),
        "a step that said nothing about the user unsaid who it was"
    );
}

/// A login cannot expire before it starts, which is the row the expiry tests
/// have to plant by hand.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_cannot_expire_before_it_starts() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    assert!(
        transaction
            .execute(
                "INSERT INTO auth_sessions \
                     (tenant, realm_id, session_id, client_id, flow_id, redirect_uri, \
                      started_at, expires_at) \
                 VALUES ('acme', 'main', 'backwards', 'app', 'flow-1', 'https://x', \
                         now(), now() - interval '1 second')",
                &[],
            )
            .await
            .is_err(),
        "a login was recorded as expiring before it started"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn none_of_it_is_visible_from_another_realm() {
    let fixture = Fixture::with_user_and_client().await;
    plant_flow(&fixture).await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    login::start(&transaction, &session("login-1", 300))
        .await
        .unwrap();
    login::record_failure(&transaction, "ada", 1_000, None, 3, 60)
        .await
        .unwrap();
    webauthn::enrol(&transaction, &credential(b"key-1", "ada", "yubikey"))
        .await
        .unwrap();
    transaction.commit().await.unwrap();
    drop(connection);

    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "other"))
        .await;
    assert!(
        login::resume(&transaction, "login-1")
            .await
            .unwrap()
            .is_none(),
        "another realm resumed this realm's login"
    );
    assert!(
        login::failures(&transaction, "ada")
            .await
            .unwrap()
            .is_none(),
        "another realm read this realm's failures"
    );
    assert!(
        webauthn::by_id(&transaction, b"key-1")
            .await
            .unwrap()
            .is_none(),
        "another realm read this realm's authenticators"
    );
    assert!(
        webauthn::of_user(&transaction, "ada")
            .await
            .unwrap()
            .is_empty(),
        "another realm listed this user's authenticators"
    );
}
