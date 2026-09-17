use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use store::providers::{
    backchannel, brokering, caep_queue, deliveries, devices, dpop, form_post, login, notices, oidc,
    one_time_tokens, outbox, page_previews, pushed, replay, saml_brokering, sessions, sms, ussd,
};

/// How long the sign-in log looks back. A window, not an archive: long
/// enough to answer "who signed in this month", short enough that enabling
/// the log is not enabling a dossier.
pub const LOGIN_EVENTS_KEPT_DAYS: i64 = 30;

/// How long a receipt is kept. One nobody looked at for a month is one nobody
/// is going to, and it names an address.
pub const RECEIPTS_KEPT_DAYS: i64 = 30;

/// How far back a redelivery can reach: a delivered event leaves the outbox after
/// this, while a dead one waits for an operator and a pending one is still owed.
pub const DELIVERED_EVENTS_KEPT_DAYS: i32 = 30;

/// How long a settled security notice is kept. It names what changed on whose
/// account, and a month is long enough to answer whether someone was told.
pub const NOTICES_KEPT_DAYS: i64 = 30;

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
    pub sms_counters: u64,
    pub ussd_anchors: u64,
    pub replayed: u64,
    pub delivery_receipts: u64,
    pub pushed_requests: u64,
    pub form_post_landings: u64,
    /// Drafts of a realm's page wording nobody came back to look at.
    pub page_previews: u64,
    pub dpop_proofs: u64,
    pub security_events: u64,
    /// Delivered outbox events past the replay window.
    pub delivered_events: u64,
    /// Sign-in log rows past the retention window.
    pub login_events: u64,
    pub backchannel_requests: u64,
    pub device_codes: u64,
    /// Brokered logins that ran out before the upstream sent anyone back.
    pub broker_login_states: u64,
    /// SAML authentication requests no response answered in time.
    pub saml_login_requests: u64,
    /// SAML logout requests no provider answered in time.
    pub saml_logout_requests: u64,
    pub sessions: u64,
    /// Client grants that ran out under logins still standing.
    pub client_sessions: u64,
    /// Security notices settled past their window.
    pub security_notices: u64,
}

impl Swept {
    pub fn total(&self) -> u64 {
        self.codes
            + self.revocations
            + self.assertions
            + self.logins_in_progress
            + self.one_time_tokens
            + self.sms_counters
            + self.ussd_anchors
            + self.replayed
            + self.delivery_receipts
            + self.pushed_requests
            + self.form_post_landings
            + self.page_previews
            + self.dpop_proofs
            + self.security_events
            + self.delivered_events
            + self.login_events
            + self.backchannel_requests
            + self.device_codes
            + self.broker_login_states
            + self.saml_login_requests
            + self.saml_logout_requests
            + self.sessions
            + self.client_sessions
            + self.security_notices
    }

    pub fn add(&mut self, other: Swept) {
        self.codes += other.codes;
        self.revocations += other.revocations;
        self.assertions += other.assertions;
        self.logins_in_progress += other.logins_in_progress;
        self.one_time_tokens += other.one_time_tokens;
        self.sms_counters += other.sms_counters;
        self.ussd_anchors += other.ussd_anchors;
        self.replayed += other.replayed;
        self.delivery_receipts += other.delivery_receipts;
        self.pushed_requests += other.pushed_requests;
        self.form_post_landings += other.form_post_landings;
        self.page_previews += other.page_previews;
        self.dpop_proofs += other.dpop_proofs;
        self.security_events += other.security_events;
        self.delivered_events += other.delivered_events;
        self.login_events += other.login_events;
        self.backchannel_requests += other.backchannel_requests;
        self.device_codes += other.device_codes;
        self.broker_login_states += other.broker_login_states;
        self.saml_login_requests += other.saml_login_requests;
        self.saml_logout_requests += other.saml_logout_requests;
        self.sessions += other.sessions;
        self.client_sessions += other.client_sessions;
        self.security_notices += other.security_notices;
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
        sms_counters: sms::drop_stale_counters(transaction, now.timestamp())
            .await
            .map_err(failed)?,
        ussd_anchors: ussd::drop_expired_anchors(transaction, now)
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
        page_previews: page_previews::sweep(transaction).await.map_err(failed)?,
        pushed_requests: pushed::drop_expired_requests(transaction)
            .await
            .map_err(failed)?,
        security_events: caep_queue::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        delivered_events: outbox::drop_delivered_older_than(
            transaction,
            DELIVERED_EVENTS_KEPT_DAYS,
        )
        .await
        .map_err(failed)?,
        security_notices: notices::drop_settled_before(
            transaction,
            now - chrono::Duration::days(NOTICES_KEPT_DAYS),
        )
        .await
        .map_err(failed)?,
        login_events: store::providers::login_events::drop_older_than(
            transaction,
            (now - chrono::Duration::days(LOGIN_EVENTS_KEPT_DAYS)).timestamp(),
        )
        .await
        .map_err(failed)?,
        backchannel_requests: backchannel::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        device_codes: devices::drop_expired(transaction, now)
            .await
            .map_err(failed)?,
        broker_login_states: brokering::drop_expired_login_states(transaction, now)
            .await
            .map_err(failed)?,
        saml_login_requests: saml_brokering::drop_expired_login_requests(transaction, now)
            .await
            .map_err(failed)?,
        saml_logout_requests: saml_brokering::drop_expired_logout_requests(transaction, now)
            .await
            .map_err(failed)?,
        // Before the logins, so this pass counts only what ended early: what
        // the login's own removal cascades away is not a second count.
        client_sessions: sessions::drop_expired_client_sessions(transaction, now)
            .await
            .map_err(failed)?,
        // Last, because it cascades: a login taken away here takes its client
        // sessions with it.
        sessions: sessions::drop_expired_sessions(transaction, now)
            .await
            .map_err(failed)?,
    })
}
