use config::serving::{Egress, PublicOrigin};
use outbound::Sealing;
use outbound::pushes::push_logout_token;
use services::oidc::logout::{
    AttemptedLogoutNotice, claim_due_logout_notices, compose_owed_logout_notices,
    settle_logout_attempts,
};
use store::tenancy::{Tenancy, TenantContext};

/// How many notices one pass takes on in one realm.
const NOTICE_CEILING: i64 = 50;

/// Send the logout notices one realm's ended logins owe, and settle each one its
/// attempt decided.
///
/// Claimed and minted in one transaction, settled in another, with the sending
/// between them, as the security notices go: no pooled connection waits on a
/// relying party. Every notice of the pass is posted at once, so a slow client
/// holds back none of the others.
pub async fn send_due_logout_notices(
    tenancy: &Tenancy,
    sealing: &Sealing,
    origin: &PublicOrigin,
    context: &TenantContext,
    backoff_seconds: i64,
    egress: Egress,
) {
    let Ok(transaction) = tenancy.begin(context).await else {
        return;
    };
    let claimed =
        match claim_due_logout_notices(&transaction, NOTICE_CEILING, backoff_seconds).await {
            Ok(claimed) if !claimed.is_empty() => claimed,
            Ok(_) => return,
            Err(_) => {
                tracing::warn!(
                    tenant = context.tenant,
                    realm = context.realm_id,
                    "the logout notices could not be claimed"
                );
                return;
            }
        };
    let Ok(ring) = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    else {
        // Nothing to sign with. The claim stands, so each notice is tried again
        // once its lease runs out and given up on when its attempts do.
        let _ = transaction.commit().await;
        tracing::warn!(
            tenant = context.tenant,
            realm = context.realm_id,
            "the realm's keys could not be opened to sign logout notices"
        );
        return;
    };
    let signing = services::oidc::grant::Signing {
        provider: sealing.provider.as_ref(),
        ring: &ring,
        envelope: &sealing.envelope,
    };
    let composed = compose_owed_logout_notices(
        &transaction,
        &signing,
        &origin.issuer(&context.realm_id),
        claimed,
        chrono::Utc::now(),
    )
    .await;
    let Ok(due) = composed else {
        tracing::warn!(
            tenant = context.tenant,
            realm = context.realm_id,
            "the logout notices could not be minted"
        );
        return;
    };
    if transaction.commit().await.is_err() {
        return;
    }

    let posting: Vec<_> = due
        .into_iter()
        .map(|owed| {
            tokio::spawn(async move {
                let went_out =
                    push_logout_token(&owed.notice.uri, &owed.notice.logout_token, egress).await;
                if !went_out {
                    tracing::warn!(
                        client_id = %owed.client_id,
                        attempts = owed.attempts,
                        "a logout notice was not taken"
                    );
                }
                AttemptedLogoutNotice {
                    session_id: owed.session_id,
                    client_id: owed.client_id,
                    attempts: owed.attempts,
                    went_out,
                }
            })
        })
        .collect();
    let mut attempted = Vec::with_capacity(posting.len());
    for handle in posting {
        if let Ok(done) = handle.await {
            attempted.push(done);
        }
    }
    if attempted.is_empty() {
        return;
    }
    let Ok(transaction) = tenancy.begin(context).await else {
        return;
    };
    if settle_logout_attempts(&transaction, &attempted)
        .await
        .is_err()
        || transaction.commit().await.is_err()
    {
        tracing::warn!(
            tenant = context.tenant,
            realm = context.realm_id,
            "the logout notices attempted could not be settled"
        );
    }
}
