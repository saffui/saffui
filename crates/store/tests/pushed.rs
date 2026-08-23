//! Authorization requests pushed before the browser, against a database.

mod support;

use store::providers::pushed::{self, Pushed};
use store::tenancy::TenantContext;
use support::Fixture;

fn in_secs(seconds: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(seconds)
}

fn parameters() -> serde_json::Value {
    serde_json::json!({ "response_type": "code", "scope": "openid" })
}

/// A reference is spent by the first presentation and by nothing after it, and
/// what it stands for comes back exactly once.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_reference_is_spent_once() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    pushed::keep(&transaction, "digest-1", "app", &parameters(), in_secs(60))
        .await
        .unwrap();

    let spent = pushed::spend(&transaction, "digest-1").await.unwrap();
    let Pushed::Fresh {
        client_id,
        parameters: held,
    } = spent
    else {
        panic!("a reference just kept was not fresh: {spent:?}");
    };
    assert_eq!(client_id, "app");
    assert_eq!(held, parameters());

    assert!(matches!(
        pushed::spend(&transaction, "digest-1").await.unwrap(),
        Pushed::Unusable
    ));
    assert!(matches!(
        pushed::spend(&transaction, "never-issued").await.unwrap(),
        Pushed::Unusable
    ));
}

/// An expired reference is unusable while it is still there, and the sweeper is
/// what takes it away. The two are separate: a reference that outlived its
/// request must not be spendable in the window before anything sweeps.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_expired_reference_is_unusable_before_it_is_swept() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    pushed::keep(&transaction, "alive", "app", &parameters(), in_secs(60))
        .await
        .unwrap();
    // Written straight in, because the schema refuses a request that expires
    // before it arrives.
    transaction
        .execute(
            "INSERT INTO pushed_requests \
                 (tenant, realm_id, handle_hash, client_id, parameters, pushed_at, expires_at) \
             VALUES ('acme', 'main', 'stale', 'app', '{}'::jsonb, \
                     now() - interval '10 minutes', now() - interval '1 minute')",
            &[],
        )
        .await
        .unwrap();

    assert!(matches!(
        pushed::spend(&transaction, "stale").await.unwrap(),
        Pushed::Unusable
    ));
    assert_eq!(
        pushed::drop_expired_requests(&transaction).await.unwrap(),
        1
    );
    assert!(matches!(
        pushed::spend(&transaction, "alive").await.unwrap(),
        Pushed::Fresh { .. }
    ));
}
