//! What a test watches of the locks of its database: the sessions that wait
//! on one, and two writers played against each other.

use std::future::Future;
use std::time::{Duration, Instant};

use pgcore::APP_ROLE;
use pgcore::testkit::TestDatabase;
use tokio::task::JoinHandle;
use tokio_postgres::Client;

use super::connect;

/// What a session waits on for a row another holds, and for a table.
pub const ON_A_ROW: &[&str] = &["transactionid", "tuple"];
pub const ON_A_TABLE: &[&str] = &["relation"];

/// Waits until a session of the database waits on a lock of one of `kinds`,
/// until `task` is done, or three seconds at most: short of what a unit of
/// work waits for a lock, so that a writer left waiting is not timed out.
/// The observer is of the serving role: it sees what its sessions wait on.
pub async fn wait_for_waiter<T>(observer: &Client, kinds: &[&str], task: &JoinHandle<T>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !task.is_finished() && Instant::now() < deadline {
        let waiting: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'
                   AND wait_event = ANY($1)",
                &[&kinds],
            )
            .await
            .expect("a count")
            .get(0);
        if waiting > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// Plays two writers against each other. The first stops on the table an
/// operator holds by `held`, after it has taken its row; the second starts
/// then. Returns whether the second waited on a row, and what each answered.
pub async fn race_two_writers<A, B>(
    database: &TestDatabase,
    held: &str,
    first: impl Future<Output = A> + Send + 'static,
    second: impl Future<Output = B> + Send + 'static,
) -> (bool, A, B)
where
    A: Send + 'static,
    B: Send + 'static,
{
    let observer = connect(database, APP_ROLE).await;
    let operator = connect(database, "saffui_owner").await;
    operator
        .batch_execute(&format!("BEGIN; {held}"))
        .await
        .expect("the table held");
    let first = tokio::spawn(first);
    assert!(
        wait_for_waiter(&observer, ON_A_TABLE, &first).await,
        "the first writer reaches the table"
    );
    let second = tokio::spawn(second);
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    operator
        .batch_execute("ROLLBACK")
        .await
        .expect("the table let go");
    let first = first.await.expect("the first writer");
    let second = second.await.expect("the second writer");
    (waited, first, second)
}
