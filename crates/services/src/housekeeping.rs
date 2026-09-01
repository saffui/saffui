use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use store::providers::{
    backchannel, caep_queue, deliveries, devices, dpop, form_post, login, oidc, one_time_tokens,
    pushed, replay, sessions,
};

/// How long a receipt is kept. One nobody looked at for a month is one nobody
/// is going to, and it names an address.
const RECEIPTS_KEPT_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the sweep could not run")]
pub struct Unswept;

/// What one pass took away.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    pub codes: u64,
    pub revocations: u64,
    pub assertions: u64,
    pub logins_in_progress: u64,
    pub one_time_tokens: u64,
    pub replayed: u64,
    pub delivery_receipts: u64,
    pub pushed_requests: u64,
    pub form_post_landings: u64,
    pub dpop_proofs: u64,
    pub security_events: u64,
    pub backchannel_requests: u64,
    pub device_codes: u64,
    pub sessions: u64,
}

impl Swept {
    pub fn total(&self) -> u64 {
        self.codes
            + self.revocations
            + self.assertions
            + self.logins_in_progress
            + self.one_time_tokens
            + self.replayed
            + self.delivery_receipts
            + self.pushed_requests
            + self.form_post_landings
            + self.dpop_proofs
            + self.security_events
            + self.backchannel_requests
            + self.device_codes
            + self.sessions
    }

    pub fn add(&mut self, other: Swept) {
        self.codes += other.codes;
        self.revocations += other.revocations;
        self.assertions += other.assertions;
        self.logins_in_progress += other.logins_in_progress;
        self.one_time_tokens += other.one_time_tokens;
        self.replayed += other.replayed;
        self.delivery_receipts += other.delivery_receipts;
        self.pushed_requests += other.pushed_requests;
        self.form_post_landings += other.form_post_landings;
        self.dpop_proofs += other.dpop_proofs;
        self.security_events += other.security_events;
        self.backchannel_requests += other.backchannel_requests;
        self.device_codes += other.device_codes;
        self.sessions += other.sessions;
    }
}

/// Take away every row of this realm that has run out.
///
/// The caller opens the transaction scoped, which is what keeps a sweep inside
/// the realm it was asked for even if a predicate here were wrong.
pub async fn drop_expired_rows(
    transaction: &Transaction<'_>,
    now: DateTime<Utc>,
) -> Result<Swept, Unswept> {
    let failed = |_| Unswept;
    Ok(Swept {
        codes: oidc::drop_expired_codes(transaction)
            .await
            .map_err(failed)?,
        revocations: oidc::drop_expired_revocations(transaction)
            .await
            .map_err(failed)?,
        assertions: oidc::drop_expired_assertions(transaction)
            .await
            .map_err(failed)?,
        logins_in_progress: login::drop_expired(transaction).await.map_err(failed)?,
        replayed: replay::drop_expired(transaction, now)
            .await
            .map_err(|_| Unswept)?,
        one_time_tokens: one_time_tokens::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        // A receipt is a record of a send, and one nobody looked at for a
        // month is one nobody is going to.
        delivery_receipts: deliveries::drop_older_than(
            transaction,
            now - chrono::Duration::days(RECEIPTS_KEPT_DAYS),
        )
        .await
        .map_err(failed)?,
        dpop_proofs: dpop::drop_expired_proofs(transaction)
            .await
            .map_err(failed)?,
        form_post_landings: form_post::drop_expired_landings(transaction)
            .await
            .map_err(failed)?,
        pushed_requests: pushed::drop_expired_requests(transaction)
            .await
            .map_err(failed)?,
        security_events: caep_queue::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        backchannel_requests: backchannel::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        device_codes: devices::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        // Last, because it cascades: a login taken away here takes its client
        // sessions with it.
        sessions: sessions::drop_expired_sessions(transaction, now)
            .await
            .map_err(failed)?,
    })
}
