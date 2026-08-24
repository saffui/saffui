mod support;

use store::providers::{realms, sessions};
use store::tenancy::{TenantContext, resolve};
use support::Fixture;

fn seconds_ago(seconds: i64) -> i64 {
    chrono::Utc::now().timestamp() - seconds
}

/// The listing answers for the whole deployment, which is the point: a sweep
/// cannot scope a statement to a realm it was never told about. Disabled realms
/// answer too, because their rows expire like anybody's.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn every_realm_is_listed_including_the_disabled_ones() {
    let fixture = Fixture::with_user_and_client().await;
    {
        let mut connection = fixture.connection().await;
        let transaction = fixture
            .scoped(&mut connection, &TenantContext::tenant_wide("acme"))
            .await;
        let mut second = models::entities::realm::RealmCreateModel {
            name: "shut".into(),
            display_name: "Shut".into(),
            enabled: false,
        }
        .into_model(
            "shut".into(),
            models::auditable::AuditableModel::from_creator("acme".into(), "root".into()),
        );
        second.enabled = false;
        realms::create(&transaction, &second).await.unwrap();
        transaction.commit().await.unwrap();
    }

    let connection = fixture.connection().await;
    let listed = resolve::every_realm(&connection).await.unwrap();
    let named: Vec<&str> = listed.iter().map(|realm| realm.realm_id.as_str()).collect();
    assert!(named.contains(&"main"), "{named:?}");
    assert!(
        named.contains(&"shut"),
        "a disabled realm was left out of the sweep: {named:?}"
    );
    assert!(
        listed.iter().all(|realm| realm.tenant == "acme"),
        "{listed:?}"
    );
}

/// A login past its expiry goes, one still running stays, and one opened with
/// no expiry stays: absent means it was opened without one.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn only_the_logins_that_ran_out_are_swept() {
    let fixture = Fixture::with_user_and_client().await;
    let mut connection = fixture.connection().await;
    let transaction = fixture
        .scoped(&mut connection, &TenantContext::new("acme", "main"))
        .await;

    for (id, expiration) in [
        ("gone", Some(seconds_ago(60))),
        ("running", Some(seconds_ago(-3600))),
        ("endless", None),
    ] {
        transaction
            .execute(
                "INSERT INTO user_sessions \
                     (tenant, realm_id, session_id, user_id, login_username, state, \
                      started_at, expiration) \
                 VALUES ('acme', 'main', $1, 'ada', 'ada', 'logged-in', $2, $3)",
                &[&id, &seconds_ago(7200), &expiration],
            )
            .await
            .unwrap();
    }
    // A client session on the one that goes, to show the cascade takes it.
    transaction
        .execute(
            "INSERT INTO client_sessions \
                 (tenant, realm_id, session_id, user_session_id, user_id, client_id, started_at) \
             VALUES ('acme', 'main', 'gone-app', 'gone', 'ada', 'app', $1)",
            &[&seconds_ago(7200)],
        )
        .await
        .unwrap();

    let swept = sessions::drop_expired_sessions(&transaction, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(swept, 1, "the wrong number of logins went");

    for (id, still_there) in [("gone", false), ("running", true), ("endless", true)] {
        assert_eq!(
            sessions::load(&transaction, id).await.unwrap().is_some(),
            still_there,
            "{id}"
        );
    }
    let clients: i64 = transaction
        .query_one("SELECT count(*) FROM client_sessions", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(clients, 0, "a client session outlived the login it was for");
}
