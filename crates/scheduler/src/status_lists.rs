//! The status lists the credentials a realm verifies cite, read again as they
//! fall due: claimed on a transaction of their own, read with none open, so no
//! pooled connection waits on an issuer, and kept on a third.

use chrono::Utc;
use services::verifier::status::{
    ListFormat, claim_due_lists, keep_list, note_unread_list, read_due_list,
};
use store::tenancy::{Tenancy, TenantContext};

use outbound::Sealing;
use outbound::egress::fetch_status_list;

/// What a pass came to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Refreshed {
    pub kept: u64,
    pub unread: u64,
}

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
        let due = claim_due_lists(&transaction, Utc::now()).await.ok()?;
        transaction.commit().await.ok()?;
        Some(due)
    }
    .await;
    let Some(due) = claimed else {
        tracing::warn!(
            tenant = realm.tenant,
            realm = realm.realm_id,
            "the status lists due could not be claimed"
        );
        return refreshed;
    };
    for list in &due.lists {
        let asked_as = ListFormat::parse(&list.format).and_then(ListFormat::asked_as);
        let served = fetch_status_list(list.uri.clone(), sealing.egress, asked_as).await;
        let now = Utc::now();
        let read = read_due_list(
            sealing.provider.as_ref(),
            &due.contexts,
            list,
            served.as_deref(),
            now,
        );
        let Ok(transaction) = tenancy.begin(realm).await else {
            continue;
        };
        let failure = match &read {
            Ok(reading) => {
                match keep_list(&transaction, sealing.provider.as_ref(), list, reading, now).await {
                    Ok(refused) => refused,
                    Err(()) => continue,
                }
            }
            Err(why) => Some(*why),
        };
        if let Some(why) = failure
            && note_unread_list(&transaction, list, why).await.is_err()
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
                    "a status list was not kept"
                );
            }
        }
    }
    refreshed
}
