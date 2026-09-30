mod support;

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use store::providers::protocol::presentations::{self, KeptRequest};
use store::tenancy::TenantContext;
use support::Fixture;

fn kept<'a>(
    request_id: &'a str,
    response_kid: &'a str,
    query: &'a Value,
    expires_at: DateTime<Utc>,
) -> KeptRequest<'a> {
    KeptRequest {
        request_id,
        nonce: "n-0S6",
        response_kid,
        response_key: b"sealed",
        query,
        request_object: "signed",
        expires_at,
        created_by: "admin",
        for_login: None,
    }
}

/// A request is served and answerable while it is pending and inside its
/// window, is settled by the first answer and no other, and stays readable by
/// whoever asked until the sweep takes it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_is_settled_once_inside_its_window() {
    let fixture = Fixture::with_user_and_client().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    // Whole seconds, so the column holds the very instants compared below.
    let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time");
    let closes = now + Duration::seconds(300);
    let after = closes + Duration::seconds(1);
    let query = json!({ "credentials": [{ "id": "pid" }] });
    presentations::keep(&transaction, &kept("r1", "k1", &query, closes))
        .await
        .unwrap();

    let served = presentations::pending_request_object(&transaction, "r1", &now)
        .await
        .unwrap();
    assert_eq!(served.as_deref(), Some("signed"));
    for missed in [
        presentations::pending_request_object(&transaction, "r1", &after)
            .await
            .unwrap(),
        presentations::claim_by_response_kid(&transaction, "k1", &after)
            .await
            .unwrap()
            .map(|held| held.request_id),
        presentations::claim_by_request_id(&transaction, "r1", &after)
            .await
            .unwrap()
            .map(|held| held.request_id),
        presentations::claim_by_response_kid(&transaction, "r1", &now)
            .await
            .unwrap()
            .map(|held| held.request_id),
    ] {
        assert_eq!(missed, None);
    }
    let held = presentations::claim_by_response_kid(&transaction, "k1", &now)
        .await
        .unwrap()
        .expect("a pending request");
    assert_eq!(
        (held.request_id.as_str(), held.nonce.as_str()),
        ("r1", "n-0S6")
    );
    assert_eq!(held.response_key, b"sealed");
    assert_eq!(held.query, query);
    assert!(
        presentations::claim_by_request_id(&transaction, "r1", &now)
            .await
            .unwrap()
            .is_some()
    );

    let outcome = json!({ "credentials": [] });
    assert!(
        presentations::settle(&transaction, "r1", "verified", &outcome, None, &now)
            .await
            .unwrap()
    );
    assert!(
        !presentations::settle(&transaction, "r1", "failed", &json!({}), None, &now)
            .await
            .unwrap()
    );
    assert!(
        presentations::claim_by_response_kid(&transaction, "k1", &now)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        presentations::claim_by_request_id(&transaction, "r1", &now)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        presentations::pending_request_object(&transaction, "r1", &now)
            .await
            .unwrap(),
        None
    );
    let standing = presentations::standing(&transaction, "r1")
        .await
        .unwrap()
        .expect("a request");
    assert_eq!(standing.status, "verified");
    assert_eq!(standing.outcome, Some(outcome));
    assert_eq!(standing.answered_at, Some(now));

    assert_eq!(
        presentations::drop_expired(&transaction, closes)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        presentations::drop_expired(&transaction, after)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        presentations::standing(&transaction, "r1").await.unwrap(),
        None
    );

    // Last, since a refused write ends the transaction: a key names one
    // request.
    presentations::keep(&transaction, &kept("r2", "k2", &query, closes))
        .await
        .unwrap();
    assert!(
        presentations::keep(&transaction, &kept("r3", "k2", &query, closes))
            .await
            .is_err()
    );
}

/// A request a login asked for is read by that login alone, and says what it is
/// for; one an administrator asked for is read by no login. A purpose with no
/// login, or a login with no purpose, is refused by the schema.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_asked_for_a_login_is_read_by_that_login_alone() {
    let fixture = Fixture::with_user_and_client().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time");
    let closes = now + Duration::seconds(300);
    let query = json!({ "credentials": [{ "id": "identity" }] });
    let mut for_login = kept("r-login", "k-login", &query, closes);
    for_login.for_login = Some(presentations::ForLogin {
        purpose: "factor",
        login_session: "login-1",
        user_id: Some("u-1"),
    });
    presentations::keep(&transaction, &for_login).await.unwrap();
    presentations::keep(&transaction, &kept("r-admin", "k-admin", &query, closes))
        .await
        .unwrap();

    let held = presentations::claim_by_response_kid(&transaction, "k-login", &now)
        .await
        .unwrap()
        .expect("a pending request");
    assert_eq!(held.purpose.as_deref(), Some("factor"));
    let asked_by_admin = presentations::claim_by_request_id(&transaction, "r-admin", &now)
        .await
        .unwrap()
        .expect("a pending request");
    assert_eq!(asked_by_admin.purpose, None);

    let read = |request_id: &'static str, login: &'static str| {
        let transaction = &transaction;
        async move {
            presentations::standing_for_login(transaction, request_id, login)
                .await
                .unwrap()
                .map(|standing| standing.request_id)
        }
    };
    assert_eq!(read("r-login", "login-1").await.as_deref(), Some("r-login"));
    assert_eq!(read("r-login", "login-2").await, None);
    assert_eq!(read("r-admin", "login-1").await, None);
    let read_by_admin = |request_id: &'static str| {
        let transaction = &transaction;
        async move {
            presentations::standing(transaction, request_id)
                .await
                .unwrap()
                .map(|standing| standing.request_id)
        }
    };
    assert_eq!(read_by_admin("r-admin").await.as_deref(), Some("r-admin"));
    assert_eq!(
        read_by_admin("r-login").await,
        None,
        "an administrator read a login's request"
    );

    let mut unbound = kept("r-half", "k-half", &query, closes);
    unbound.for_login = Some(presentations::ForLogin {
        purpose: "identify",
        login_session: "login-1",
        user_id: Some("u-1"),
    });
    assert!(
        presentations::keep(&transaction, &unbound).await.is_err(),
        "a purpose the schema does not know was kept"
    );
}

/// A sign-in names nobody: its answer is what names the person. The code its
/// answer was handed is kept as a digest and spent once, by the login that
/// asked, while the request lasts.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_sign_in_names_nobody_and_its_code_is_spent_once_by_its_login() {
    let fixture = Fixture::with_user_and_client().await;
    let transaction = fixture.scoped(&TenantContext::new("acme", "main")).await;
    let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time");
    let closes = now + Duration::seconds(300);
    let query = json!({ "credentials": [{ "id": "identity" }] });
    let mut sign_in = kept("r-sign-in", "k-sign-in", &query, closes);
    sign_in.for_login = Some(presentations::ForLogin {
        purpose: "sign-in",
        login_session: "login-1",
        user_id: None,
    });
    presentations::keep(&transaction, &sign_in).await.unwrap();

    let code = "a".repeat(64);
    let other = "b".repeat(64);
    let redeemed = |login: &'static str, presented: &str, at: DateTime<Utc>| {
        let transaction = &transaction;
        let presented = presented.to_owned();
        async move {
            presentations::redeem(transaction, "r-sign-in", login, &presented, &at)
                .await
                .unwrap()
                .map(|standing| standing.request_id)
        }
    };
    assert_eq!(
        redeemed("login-1", &code, now).await,
        None,
        "a code was spent before any answer"
    );
    let outcome =
        json!({ "identity": { "issuer": "did:web:id.example", "digest": "c".repeat(64) } });
    assert!(
        presentations::settle(
            &transaction,
            "r-sign-in",
            "verified",
            &outcome,
            Some(&code),
            &now
        )
        .await
        .unwrap()
    );
    for (login, presented, at) in [
        ("login-2", &code, now),
        ("login-1", &other, now),
        ("login-1", &code, closes),
    ] {
        assert_eq!(
            redeemed(login, presented, at).await,
            None,
            "spent by {login} at {at}"
        );
    }
    let spent = presentations::redeem(&transaction, "r-sign-in", "login-1", &code, &now)
        .await
        .unwrap()
        .expect("the code, spent");
    assert_eq!(spent.status, "verified");
    assert_eq!(spent.outcome, Some(outcome));
    assert_eq!(spent.redeemed_at, Some(now));
    assert_eq!(
        redeemed("login-1", &code, now).await,
        None,
        "a code was spent twice"
    );
    let standing = presentations::standing_for_login(&transaction, "r-sign-in", "login-1")
        .await
        .unwrap()
        .expect("the request");
    assert_eq!(standing.redeemed_at, Some(now));
}

/// What a login asks for is bound by the schema: a proof or a link names the
/// person, a sign-in names nobody, and a sign-in alone keeps a code, written
/// as a digest.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_a_login_asks_for_is_bound_by_the_schema() {
    let fixture = Fixture::with_user_and_client().await;
    let context = TenantContext::new("acme", "main");
    let now = DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time");
    let closes = now + Duration::seconds(300);
    let query = json!({ "credentials": [{ "id": "identity" }] });
    let asked = |purpose: &'static str, user_id: Option<&'static str>| {
        let mut request = kept("r-bound", "k-bound", &query, closes);
        request.for_login = Some(presentations::ForLogin {
            purpose,
            login_session: "login-1",
            user_id,
        });
        request
    };
    // Each in its own unit of work, since a refused write ends the one it ran in.
    for (purpose, user_id, why) in [
        ("factor", None, "a proof naming nobody"),
        ("link", None, "a link naming nobody"),
        ("sign-in", Some("u-1"), "a sign-in naming somebody"),
    ] {
        let transaction = fixture.scoped(&context).await;
        assert!(
            presentations::keep(&transaction, &asked(purpose, user_id))
                .await
                .is_err(),
            "{why} was kept"
        );
    }
    for (purpose, user_id, code, why) in [
        ("factor", Some("u-1"), "a".repeat(64), "a proof kept a code"),
        (
            "sign-in",
            None,
            "not-a-digest".to_owned(),
            "a code was kept in the clear",
        ),
    ] {
        let transaction = fixture.scoped(&context).await;
        presentations::keep(&transaction, &asked(purpose, user_id))
            .await
            .unwrap();
        assert!(
            presentations::settle(
                &transaction,
                "r-bound",
                "verified",
                &json!({}),
                Some(&code),
                &now
            )
            .await
            .is_err(),
            "{why}"
        );
    }
}
