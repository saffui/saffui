use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use store::providers::{login, oidc, one_time_tokens, pushed, sessions};

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
    pub pushed_requests: u64,
    pub sessions: u64,
}

impl Swept {
    pub fn total(&self) -> u64 {
        self.codes
            + self.revocations
            + self.assertions
            + self.logins_in_progress
            + self.one_time_tokens
            + self.pushed_requests
            + self.sessions
    }

    pub fn add(&mut self, other: Swept) {
        self.codes += other.codes;
        self.revocations += other.revocations;
        self.assertions += other.assertions;
        self.logins_in_progress += other.logins_in_progress;
        self.one_time_tokens += other.one_time_tokens;
        self.pushed_requests += other.pushed_requests;
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
        one_time_tokens: one_time_tokens::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        pushed_requests: pushed::drop_expired_requests(transaction)
            .await
            .map_err(failed)?,
        // Last, because it cascades: a login taken away here takes its client
        // sessions with it.
        sessions: sessions::drop_expired_sessions(transaction, now)
            .await
            .map_err(failed)?,
    })
}
