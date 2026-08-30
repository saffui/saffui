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
                    delivery_receipts = swept.delivery_receipts,
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

/// Which job the federation advisory lock is for.
const FEDERATE: i32 = 0x4C44_4150_u32 as i32;

/// Walk every realm's federated shadows against their directory, for as
/// long as this node runs. Off by default: a sync dials out, and a
/// deployment says so before this server does.
pub fn sync_federated_shadows(
    pool: Pool,
    tenancy: Tenancy,
    sealing: std::sync::Arc<crate::api::config::Sealing>,
    every: Option<Duration>,
) -> Option<JoinHandle<()>> {
    let Some(every) = every else {
        tracing::info!("federated shadows are never synced");
        return None;
    };
    tracing::info!(seconds = every.as_secs(), "syncing federated shadows");
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match sync_every_realm(&pool, &tenancy, &sealing).await {
                Some(synced) if synced.total() > 0 => tracing::info!(
                    refreshed = synced.refreshed,
                    suspended = synced.suspended,
                    restored = synced.restored,
                    "synced federated shadows"
                ),
                Some(_) => {}
                None => tracing::warn!("the sync could not list this deployment's realms"),
            }
        }
    }))
}

/// One visit to every federating realm, or nothing when they could not be
/// listed. A realm whose directory is unreachable is left exactly as it
/// stands: an outage is not a departure.
pub async fn sync_every_realm(
    pool: &Pool,
    tenancy: &Tenancy,
    sealing: &crate::api::config::Sealing,
) -> Option<crate::federation::Synced> {
    let connection = pool.get().await.ok()?;
    let realms = resolve::every_realm(&connection).await.ok()?;
    drop(connection);

    let mut total = crate::federation::Synced::default();
    for realm in realms {
        let Ok(mut connection) = pool.get().await else {
            continue;
        };
        let Ok(transaction) = tenancy.transaction(&mut connection, &realm).await else {
            continue;
        };
        let held = transaction
            .query_one(
                "SELECT pg_try_advisory_xact_lock($1, hashtext($2))",
                &[&FEDERATE, &format!("{}:{}", realm.tenant, realm.realm_id)],
            )
            .await
            .map(|row| row.get::<_, bool>(0));
        if !matches!(held, Ok(true)) {
            continue;
        }

        let Ok(Some(federation)) = store::providers::brokering::federation(&transaction).await
        else {
            continue;
        };
        if federation.enabled == Some(false) {
            continue;
        }
        let Ok(settings) = services::federation::LdapSettings::parse(&federation) else {
            tracing::warn!(
                tenant = realm.tenant,
                realm = realm.realm_id,
                "the realm's directory row no longer reads; its shadows were not walked"
            );
            continue;
        };
        let directory =
            crate::federation::directory_for(&transaction, sealing, &realm, &federation, settings)
                .await;
        match crate::federation::sync_shadows(&transaction, &directory).await {
            Ok(synced) if transaction.commit().await.is_ok() => total.add(synced),
            Ok(_) => tracing::warn!(
                tenant = realm.tenant,
                realm = realm.realm_id,
                "a sync pass did not land"
            ),
            // Unreachable, mid-realm: nothing committed, nobody suspended.
            Err(()) => tracing::warn!(
                tenant = realm.tenant,
                realm = realm.realm_id,
                "the directory could not be asked; its shadows were left as they stand"
            ),
        }
    }
    Some(total)
}
