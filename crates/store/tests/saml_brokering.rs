mod support;

use chrono::{DateTime, Duration, Utc};
use models::entities::brokering::{SamlBrokerSession, SamlLoginRequest, SamlLogoutRequest};
use models::sessions::records::{UserSessionModel, UserSessionState};
use store::providers::{saml_brokering, sessions};
use store::tenancy::TenantContext;
use support::Fixture;

/// Now to the second, which is as fine as the column keeps it.
fn now_in_seconds() -> DateTime<Utc> {
    DateTime::from_timestamp(Utc::now().timestamp(), 0).expect("a time")
}

fn session(id: &str) -> UserSessionModel {
    UserSessionModel {
        browser_state: None,
        tenant: "acme".into(),
        realm_id: "main".into(),
        session_id: id.into(),
        user_id: "ada".into(),
        login_username: "ada".into(),
        broker_session_id: None,
        broker_user_id: None,
        auth_method: Some("saml".into()),
        ip_address: None,
        user_agent: None,
        started_at: 1_000,
        auth_time: Some(1_000),
        loa: Some(1),
        expiration: Some(4_600),
        state: UserSessionState::LoggedIn,
        remember_me: Some(false),
        last_session_refresh: None,
        is_offline: Some(false),
        notes: None,
    }
}

/// An authentication request is spent once, by the provider it was sent to and
/// before it runs out; one at its expiry or past it is not, and the sweep takes
/// exactly those.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_request_is_spent_once_by_its_provider_before_it_runs_out() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    let now = now_in_seconds();
    let open = SamlLoginRequest {
        request_id: "_open".into(),
        provider_alias: "corp".into(),
        auth_session: "auth-7".into(),
        expires_at: now + Duration::minutes(5),
    };
    let at_expiry = SamlLoginRequest {
        request_id: "_at-expiry".into(),
        expires_at: now,
        ..open.clone()
    };
    let stale = SamlLoginRequest {
        request_id: "_stale".into(),
        expires_at: now - Duration::seconds(1),
        ..open.clone()
    };
    for request in [&open, &at_expiry, &stale] {
        saml_brokering::open_login_request(&transaction, request)
            .await
            .unwrap();
    }

    assert_eq!(
        saml_brokering::consume_login_request(&transaction, "_open", "other", now)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        saml_brokering::consume_login_request(&transaction, "_open", "corp", now)
            .await
            .unwrap(),
        Some(open.clone())
    );
    for id in ["_open", "_at-expiry", "_stale"] {
        assert_eq!(
            saml_brokering::consume_login_request(&transaction, id, "corp", now)
                .await
                .unwrap(),
            None,
            "{id}"
        );
    }
    assert_eq!(
        saml_brokering::drop_expired_login_requests(&transaction, now)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        saml_brokering::drop_expired_login_requests(&transaction, now)
            .await
            .unwrap(),
        0
    );
    transaction.commit().await.unwrap();
}

/// A logout request is spent the same way, and keeps where the browser goes
/// after, or that it goes nowhere in particular.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_logout_request_is_spent_once_and_keeps_where_the_browser_goes() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    let now = now_in_seconds();
    let placed = SamlLogoutRequest {
        request_id: "_logout-3".into(),
        provider_alias: "corp".into(),
        resume_to: Some("https://app.example/signed-out".into()),
        expires_at: now + Duration::minutes(5),
    };
    let unplaced = SamlLogoutRequest {
        request_id: "_logout-4".into(),
        resume_to: None,
        ..placed.clone()
    };
    let stale = SamlLogoutRequest {
        request_id: "_logout-5".into(),
        expires_at: now,
        ..placed.clone()
    };
    for request in [&placed, &unplaced, &stale] {
        saml_brokering::open_logout_request(&transaction, request)
            .await
            .unwrap();
    }

    assert_eq!(
        saml_brokering::consume_logout_request(&transaction, "_logout-3", "other", now)
            .await
            .unwrap(),
        None
    );
    for request in [&placed, &unplaced] {
        assert_eq!(
            saml_brokering::consume_logout_request(&transaction, &request.request_id, "corp", now)
                .await
                .unwrap(),
            Some(request.clone())
        );
        assert_eq!(
            saml_brokering::consume_logout_request(&transaction, &request.request_id, "corp", now)
                .await
                .unwrap(),
            None
        );
    }
    assert_eq!(
        saml_brokering::consume_logout_request(&transaction, "_logout-5", "corp", now)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        saml_brokering::drop_expired_logout_requests(&transaction, now)
            .await
            .unwrap(),
        1
    );
    transaction.commit().await.unwrap();
}

/// What a provider named a login by is read back whole, found by the name a
/// logout gives among the sessions it lists, a login without a session index
/// included, is not found once its login has ended, and goes when the login goes;
/// one for a login that does not exist is refused.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_broker_session_is_found_by_the_name_a_logout_gives_and_goes_with_its_login() {
    let fixture = Fixture::with_user().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    for id in ["s-1", "s-2", "s-3", "s-4"] {
        sessions::open(&transaction, &session(id)).await.unwrap();
    }
    let first = SamlBrokerSession {
        session_id: "s-1".into(),
        provider_alias: "corp".into(),
        name_id: "AAdzZWNyZXQx".into(),
        name_id_format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into()),
        name_qualifier: Some("https://idp.test/metadata".into()),
        sp_name_qualifier: Some("https://sp.test/realms/main".into()),
        session_index: Some("_session-1".into()),
    };
    let second = SamlBrokerSession {
        session_id: "s-2".into(),
        name_qualifier: None,
        session_index: Some("_session-2".into()),
        ..first.clone()
    };
    let unindexed = SamlBrokerSession {
        session_id: "s-3".into(),
        session_index: None,
        ..first.clone()
    };
    let elsewhere = SamlBrokerSession {
        session_id: "s-4".into(),
        provider_alias: "partner".into(),
        ..first.clone()
    };
    for recorded in [&first, &second, &unindexed, &elsewhere] {
        saml_brokering::record_broker_session(&transaction, recorded)
            .await
            .unwrap();
    }

    assert_eq!(
        saml_brokering::read_broker_session(&transaction, "s-1")
            .await
            .unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        saml_brokering::read_broker_session(&transaction, "s-none")
            .await
            .unwrap(),
        None
    );
    for (alias, name, indexes, found) in [
        ("corp", "AAdzZWNyZXQx", vec![], vec!["s-1", "s-2", "s-3"]),
        (
            "corp",
            "AAdzZWNyZXQx",
            vec!["_session-2".to_owned()],
            vec!["s-2", "s-3"],
        ),
        ("corp", "AAdzZWNyZXQy", vec![], vec![]),
        ("partner", "AAdzZWNyZXQx", vec![], vec!["s-4"]),
        ("other", "AAdzZWNyZXQx", vec![], vec![]),
    ] {
        assert_eq!(
            saml_brokering::find_named_sessions(&transaction, alias, name, &indexes)
                .await
                .unwrap(),
            found,
            "{alias} {name} {indexes:?}"
        );
    }
    sessions::set_state(&transaction, "s-2", UserSessionState::LoggedOut)
        .await
        .unwrap();
    assert_eq!(
        saml_brokering::find_named_sessions(&transaction, "corp", "AAdzZWNyZXQx", &[])
            .await
            .unwrap(),
        vec!["s-1", "s-3"]
    );

    transaction
        .execute("DELETE FROM user_sessions WHERE session_id = 's-1'", &[])
        .await
        .unwrap();
    assert_eq!(
        saml_brokering::read_broker_session(&transaction, "s-1")
            .await
            .unwrap(),
        None
    );
    assert!(
        saml_brokering::record_broker_session(
            &transaction,
            &SamlBrokerSession {
                session_id: "s-missing".into(),
                ..first
            }
        )
        .await
        .is_err()
    );
}
