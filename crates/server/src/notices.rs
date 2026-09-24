use services::messaging::notices::{
    Attempted, claim_due_notices, compose_due_notices, settle_attempts,
};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::mail::deliver;

/// How many notices one pass takes on in one realm.
const NOTICE_CEILING: i64 = 50;

/// Send one realm's due security notices, and settle each one its attempt decided.
///
/// Claimed and composed in one transaction, settled in another, with the sending
/// between them: no pooled connection waits on somebody else's mail server. The
/// realm's keys are only opened when a notice is due.
pub async fn send_due_notices(
    tenancy: &Tenancy,
    sealing: &Sealing,
    context: &TenantContext,
    backoff_seconds: i64,
) {
    let Ok(transaction) = tenancy.begin(context).await else {
        return;
    };
    let claimed = match claim_due_notices(&transaction, NOTICE_CEILING, backoff_seconds).await {
        Ok(claimed) if !claimed.is_empty() => claimed,
        Ok(_) => return,
        Err(_) => {
            tracing::warn!(
                tenant = context.tenant,
                realm = context.realm_id,
                "the security notices could not be claimed"
            );
            return;
        }
    };
    let Ok(Some(realm)) = services::realm::named(&transaction, &context.realm_id).await else {
        return;
    };
    let settings = services::messaging::delivery::read_mail_settings(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await;
    let composed = compose_due_notices(
        &transaction,
        &realm,
        settings.as_ref().filter(|_| sealing.sender.is_some()),
        claimed,
    )
    .await;
    let Ok(due) = composed else {
        tracing::warn!(
            tenant = context.tenant,
            realm = context.realm_id,
            "the security notices could not be composed"
        );
        return;
    };
    if transaction.commit().await.is_err() {
        return;
    }

    let mut attempted = Vec::with_capacity(due.len());
    for notice in due {
        let went_out = deliver(sealing, tenancy, context, notice.outgoing).await;
        attempted.push(Attempted {
            event_id: notice.event_id,
            attempts: notice.attempts,
            went_out,
        });
    }
    if attempted.is_empty() {
        return;
    }
    let Ok(transaction) = tenancy.begin(context).await else {
        return;
    };
    if settle_attempts(&transaction, &attempted).await.is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!(
            tenant = context.tenant,
            realm = context.realm_id,
            "the security notices attempted could not be settled"
        );
    }
}
