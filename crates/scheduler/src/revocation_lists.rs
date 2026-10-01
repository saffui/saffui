//! The revocation lists the chains of a realm's credentials name, read again
//! as they fall due: claimed on a transaction of their own, read with none
//! open, so no pooled connection waits on an authority, and kept on a third.

use chrono::Utc;
use services::verifier::revocation::{
    REVOCATION_OLDER, claim_due_revocation_lists, keep_revocation_list,
    note_unread_revocation_list, read_due_revocation_list,
};
use store::tenancy::{Tenancy, TenantContext};

use outbound::Sealing;
use outbound::egress::fetch_revocation_list;

use crate::status_lists::Refreshed;

/// Read the lists due in every realm that runs the verifier, or nothing when
/// the realms could not be listed.
pub async fn refresh_every_realm(tenancy: &Tenancy, sealing: &Sealing) -> Option<Refreshed> {
    let realms = tenancy.every_realm().await.ok()?;
    let mut refreshed = Refreshed::default();
    for realm in &realms {
        let landed = refresh_realm(tenancy, sealing, realm).await;
        refreshed.kept += landed.kept;
        refreshed.unread += landed.unread;
    }
    Some(refreshed)
}

async fn refresh_realm(tenancy: &Tenancy, sealing: &Sealing, realm: &TenantContext) -> Refreshed {
    let mut refreshed = Refreshed::default();
    let claimed = async {
        let transaction = tenancy.begin(realm).await.ok()?;
        let due = claim_due_revocation_lists(&transaction, Utc::now())
            .await
            .ok()?;
        transaction.commit().await.ok()?;
        Some(due)
    }
    .await;
    let Some(due) = claimed else {
        tracing::warn!(
            tenant = realm.tenant,
            realm = realm.realm_id,
            "the revocation lists due could not be claimed"
        );
        return refreshed;
    };
    for list in &due {
        let served = fetch_revocation_list(list.uri.clone(), sealing.egress).await;
        let now = Utc::now();
        let read = read_due_revocation_list(list, served.as_deref(), now);
        let Ok(transaction) = tenancy.begin(realm).await else {
            continue;
        };
        let failure = match &read {
            Ok(reading) => {
                match keep_revocation_list(
                    &transaction,
                    sealing.provider.as_ref(),
                    list,
                    reading,
                    now,
                )
                .await
                {
                    Ok(true) => None,
                    Ok(false) => Some(REVOCATION_OLDER),
                    Err(()) => continue,
                }
            }
            Err(why) => Some(*why),
        };
        if let Some(why) = failure
            && note_unread_revocation_list(&transaction, list, why)
                .await
                .is_err()
        {
            continue;
        }
        if transaction.commit().await.is_err() {
            continue;
        }
        match failure {
            None => refreshed.kept += 1,
            Some(why) => {
                refreshed.unread += 1;
                tracing::warn!(
                    tenant = realm.tenant,
                    realm = realm.realm_id,
                    list = list.uri,
                    reason = why,
                    "a revocation list was not kept"
                );
            }
        }
    }
    refreshed
}
