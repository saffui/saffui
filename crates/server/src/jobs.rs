//! Work this node does on a clock rather than on a request.
//!
//! A job is the second thing that opens a transaction, and it carries the same
//! rule: opened here, handed to the services it calls.

use std::time::Duration;

use chrono::Utc;
use deadpool_postgres::Pool;
use services::housekeeping::{self, Swept};
use store::tenancy::{Tenancy, resolve};
use tokio::task::JoinHandle;

/// Which job the advisory lock is for. The other half says which realm.
const SWEEP: i32 = 0x5746_4545_u32 as i32;

/// Sweep expired rows out of every realm, for as long as this node runs.
///
/// Runs on every node. Each realm is taken under a transaction scoped advisory
/// lock, so two nodes ticking together split the realms rather than deleting
/// the same rows twice. Transaction scoped rather than session scoped: a
/// session lock behind a transaction mode pooler is held on a backend the
/// pooler then hands to somebody else, which is two holders of one lock.
///
/// A failed pass is logged and dropped. What it would have removed is still
/// expired, and still read as absent, until a later pass takes it.
///
/// No interval means never, and says so: a deployment that keeps everything
/// should be readable in its log rather than inferred from silence.
pub fn sweep_expired_rows(
    pool: Pool,
    tenancy: Tenancy,
    every: Option<Duration>,
) -> Option<JoinHandle<()>> {
    let Some(every) = every else {
        tracing::info!("expired rows are never swept");
        return None;
    };
    tracing::info!(seconds = every.as_secs(), "sweeping expired rows");
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        // `interval` fires the first tick at once, and nothing has expired in
        // the second since boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match sweep_every_realm(&pool, &tenancy).await {
                Some(swept) if swept.total() > 0 => tracing::info!(
                    codes = swept.codes,
                    revocations = swept.revocations,
                    assertions = swept.assertions,
                    logins_in_progress = swept.logins_in_progress,
                    one_time_tokens = swept.one_time_tokens,
                    pushed_requests = swept.pushed_requests,
                    sessions = swept.sessions,
                    "swept expired rows"
                ),
                Some(_) => {}
                None => tracing::warn!("the sweep could not list this deployment's realms"),
            }
        }
    }))
}

/// One visit to every realm, or nothing when they could not be listed.
pub async fn sweep_every_realm(pool: &Pool, tenancy: &Tenancy) -> Option<Swept> {
    let connection = pool.get().await.ok()?;
    let realms = resolve::every_realm(&connection).await.ok()?;
    drop(connection);

    let mut total = Swept::default();
    for realm in realms {
        let Ok(mut connection) = pool.get().await else {
            continue;
        };
        // A realm pinned to another region belongs to the nodes there, and is
        // refused here exactly as a request for it would be.
        let Ok(transaction) = tenancy.transaction(&mut connection, &realm).await else {
            continue;
        };
        let held = transaction
            .query_one(
                "SELECT pg_try_advisory_xact_lock($1, hashtext($2))",
                &[&SWEEP, &format!("{}:{}", realm.tenant, realm.realm_id)],
            )
            .await
            .map(|row| row.get::<_, bool>(0));
        if !matches!(held, Ok(true)) {
            continue;
        }

        match housekeeping::drop_expired_rows(&transaction, Utc::now()).await {
            Ok(swept) if transaction.commit().await.is_ok() => total.add(swept),
            Ok(_) | Err(_) => tracing::warn!(
                tenant = realm.tenant,
                realm = realm.realm_id,
                "a sweep did not land"
            ),
        }
    }
    Some(total)
}
