mod support;

use chrono::{Duration, Utc};
use store::providers::{login_events, metrics};
use store::tenancy::TenantContext;
use support::Fixture;

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn metrics_are_aggregated_inside_the_current_realm() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    transaction
        .execute(
            "INSERT INTO authz_decisions
                 (tenant, realm_id, decision_id, subject_type, subject_id, resource_kind,
                  action, reported, computed, detail, duration_us)
             VALUES
                 ('acme', 'main', 'permit-1', 'user', 'ada', 'resource', 'read',
                  'permit', 'permit', '{}'::jsonb, 100),
                 ('acme', 'main', 'denial-1', 'user', 'ada', 'resource', 'read',
                  'deny', 'indeterminate', '{}'::jsonb, 300)",
            &[],
        )
        .await
        .unwrap();

    for kind in ["signed_in", "sign_in_failed", "signed_out", "sms_throttled"] {
        login_events::record(
            &transaction,
            Utc::now().timestamp(),
            &login_events::LoginEventWrite {
                kind,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    let decisions = metrics::decisions(&transaction, Utc::now() - Duration::hours(1))
        .await
        .unwrap();
    assert_eq!(decisions.total, 2);
    assert_eq!(decisions.permits, 1);
    assert_eq!(decisions.denials, 1);
    assert_eq!(decisions.indeterminate, 1);
    assert_eq!(decisions.disagreements, 1);
    assert_eq!(decisions.average_duration_us, Some(200.0));
    assert_eq!(decisions.p95_duration_us, Some(290.0));

    let logins = metrics::logins(&transaction, (Utc::now() - Duration::hours(1)).timestamp())
        .await
        .unwrap();
    assert_eq!(logins.total, 4);
    assert_eq!(logins.signed_in, 1);
    assert_eq!(logins.sign_in_failed, 1);
    assert_eq!(logins.signed_out, 1);
    assert_eq!(logins.sms_throttled, 1);
}
