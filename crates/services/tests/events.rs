mod support;

use chrono::Utc;
use store::providers::{login_events, realms};
use store::tenancy::TenantContext;
use support::Fixture;

/// The sign-in log obeys the realm's switch: off records nothing, on
/// records the failure the lockout counter saw, newest first, and the
/// sweeper's cutoff ages the window.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_sign_in_log_obeys_the_switch_and_ages_out() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;
    let now = Utc::now();

    let mut realm = realms::load(&transaction, "main")
        .await
        .unwrap()
        .expect("the realm");

    // Switched off, the failure hook records nothing.
    auth::login::lockout::count(&transaction, &realm, "ada", Some("203.0.113.9"), now)
        .await
        .unwrap();
    let (held, _) = login_events::list(&transaction, 0, 10, false)
        .await
        .unwrap();
    assert!(held.is_empty(), "a record slipped past the off switch");

    realm.events_enabled = Some(true);
    realms::update(&transaction, &realm).await.unwrap();

    auth::login::lockout::count(&transaction, &realm, "ada", Some("203.0.113.9"), now)
        .await
        .unwrap();
    login_events::record(
        &transaction,
        now.timestamp() + 5,
        &login_events::LoginEventWrite {
            kind: "signed_in",
            user_id: Some("ada"),
            client_id: Some("app"),
            session_id: Some("s-1"),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let (held, total) = login_events::list(&transaction, 0, 10, true).await.unwrap();
    assert_eq!(total, Some(2));
    assert_eq!(held[0].kind, "signed_in", "not newest first");
    assert_eq!(held[1].kind, "sign_in_failed");
    assert_eq!(held[1].ip.as_deref(), Some("203.0.113.9"));

    // The cutoff ages the window: everything strictly older goes.
    let swept = login_events::drop_older_than(&transaction, now.timestamp() + 1)
        .await
        .unwrap();
    assert_eq!(swept, 1, "the older record survived the cutoff");
    let (held, _) = login_events::list(&transaction, 0, 10, false)
        .await
        .unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].kind, "signed_in");
}
