mod support;

use store::tenancy::TenantContext;
use support::Fixture;

/// A change reaching many people waits for every person being weighed, and a
/// person waits for it. One realm hold, shared by the first and taken whole by
/// the second, so neither weighs a world the other is still changing, while
/// two people are still weighed side by side.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realm_hold_and_a_person_hold_wait_for_each_other() {
    let fixture = Fixture::with_user().await;
    let within = TenantContext::new("acme", "main");

    let weighing = fixture.scoped(&within).await;
    store::providers::governance::sod::hold_person(&weighing, "ada")
        .await
        .expect("the person is held");

    {
        let beside = fixture.scoped(&within).await;
        beside
            .batch_execute("SET LOCAL lock_timeout = '300ms'")
            .await
            .unwrap();
        store::providers::governance::sod::hold_person(&beside, "grace")
            .await
            .expect("a second person waited for the first");
    }
    {
        let reaching = fixture.scoped(&within).await;
        reaching
            .batch_execute("SET LOCAL lock_timeout = '300ms'")
            .await
            .unwrap();
        assert!(
            store::providers::governance::sod::hold_realm(&reaching)
                .await
                .is_err(),
            "a change reaching many people went ahead while a person was being weighed"
        );
    }
    weighing.rollback().await.unwrap();

    let reaching = fixture.scoped(&within).await;
    store::providers::governance::sod::hold_realm(&reaching)
        .await
        .expect("the realm is held");
    let weighing = fixture.scoped(&within).await;
    weighing
        .batch_execute("SET LOCAL lock_timeout = '300ms'")
        .await
        .unwrap();
    assert!(
        store::providers::governance::sod::hold_person(&weighing, "ada")
            .await
            .is_err(),
        "a person was weighed while a change reaching many people was"
    );
}
