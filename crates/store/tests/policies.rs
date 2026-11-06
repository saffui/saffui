//! The definitions of a realm are checked and written under a lock of the
//! realm: two writers of them take turns, a writer of another realm does
//! not wait.

use std::time::Duration;

use pgcore::pool::PoolSettings;
use saffui_core::testkit::fixtures::create_realm;

mod support;

#[tokio::test]
async fn two_writers_of_the_definitions_of_one_realm_take_turns() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "definitions-lock").await;
    let other = create_realm(&app, "definitions-lock-other").await;

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    first.lock_definitions().await.expect("the lock");
    let waiting = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut second = app.storage.begin(scope).await.expect("a unit of work");
            second.lock_definitions().await.expect("the lock, in turn");
            second.commit().await.expect("a commit");
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !waiting.is_finished(),
        "the second writer waits for the first"
    );

    let mut elsewhere = app.storage.begin(other).await.expect("a unit of work");
    tokio::time::timeout(Duration::from_secs(2), elsewhere.lock_definitions())
        .await
        .expect("a writer of another realm does not wait")
        .expect("the lock");
    elsewhere.commit().await.expect("a commit");

    first.commit().await.expect("a commit");
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("the second writer goes on once the first ends")
        .expect("the task");
}
