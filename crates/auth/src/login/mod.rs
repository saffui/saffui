pub mod authenticator;
pub mod browser;
pub mod directory;
pub mod enrolment;
pub mod step;

use chrono::{DateTime, Utc};
use config::serving::PublicOrigin;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::auth::ExecutionStep;
use models::entities::realm::RealmModel;
use models::entities::user::UserModel;
use store::providers::auth_flows;
use store::providers::login as login_store;

use crate::login::authenticator::{Answer, Authenticator, Posting};
use crate::login::step::{Decided, Outcome, Step};
use crate::messaging::Outgoing;

/// Where a login stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Everything the flow required is established, by these authenticators.
    /// Named rather than counted, because the level a login reached is the
    /// realm's reading of what actually ran.
    Admitted { by: Vec<Authenticator> },
    /// It cannot be, and no further answer changes that.
    Refused,
    /// Too many failures were counted against this person, so nothing is even
    /// tried until the lockout passes. Separate from `Refused` because the
    /// answer was never looked at.
    LockedOut { until: i64 },
    /// A step is waiting on the caller, named so it can be asked, and carrying
    /// both halves of anything it issued: what to show, and what verifying the
    /// answer will need. The second is the caller's to persist — a challenge
    /// handed out and not remembered is one nothing can verify against.
    Waiting {
        execution_id: String,
        asks: Option<serde_json::Value>,
        remember: serde_json::Map<String, serde_json::Value>,
    },
}

/// Why a login could not be run at all.
///
/// Distinct from a refusal: a flow that could not be read has not decided that
/// nobody may in, and answering no would be answering a question nobody asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unrunnable {
    #[error("the realm has no such flow")]
    NoSuchFlow,
    /// A step names an authenticator this build does not have. Refused rather
    /// than skipped: a step that does nothing, in a flow of alternatives, is a
    /// way in nobody wrote.
    #[error("{0}")]
    Unknown(#[from] authenticator::Unknown),
    /// A step runs another flow. Not built, and named rather than skipped for
    /// the same reason.
    #[error("a step runs another flow, which is not built")]
    NestedFlow,
    #[error("the store could not be read")]
    Unreadable,
}

/// Run one pass of a flow.
///
/// Every enabled step is run, not merely the ones before the first refusal: a
/// flow of alternatives has to try them all before it can say none of them let
/// this caller in, and the fold cannot see what was never run.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one pass of one flow"
)]
pub async fn run_flow(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    origin: &PublicOrigin,
    flow_id: &str,
    subject: Option<&UserModel>,
    answers: &[Answer],
    // What the previous round issued, under each authenticator's own name.
    remembered_before: &serde_json::Value,
    // What a mailed step needs. Absent where no step in this flow is one.
    posting: Option<Posting<'_>>,
    // The directory this realm federates from. Absent where it holds none.
    federation: Option<&dyn directory::Directory>,
    // Where this pass came from, recorded against a failure, and when it is.
    from: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(Progress, Option<Box<Outgoing>>), Unrunnable> {
    let executions = auth_flows::executions_of(transaction, flow_id)
        .await
        .map_err(|_| Unrunnable::Unreadable)?;
    if executions.is_empty() {
        return Err(Unrunnable::NoSuchFlow);
    }

    // Before anything is verified, and without counting: an answer that is
    // never looked at cannot be wrong, and extending the lock on every attempt
    // would let anybody hold somebody else's account shut indefinitely.
    if let Some(until) = locked_until(transaction, realm, subject, now).await? {
        return Ok((Progress::LockedOut { until }, None));
    }

    let mut steps = Vec::with_capacity(executions.len());
    let mut sending = None;
    let mut waiting = None;
    let mut asked = None;
    let mut remembered = serde_json::Map::new();
    let mut passed = Vec::new();

    for execution in &executions {
        if !execution.is_enabled() {
            steps.push(Step {
                requirement: execution.requirement,
                outcome: Outcome::Skipped,
            });
            continue;
        }

        let ExecutionStep::Authenticator { authenticator, .. } = &execution.step else {
            return Err(Unrunnable::NestedFlow);
        };
        let named: Authenticator = authenticator.parse()?;

        let answered = authenticator::verify_answer(
            transaction,
            provider,
            realm,
            origin,
            subject,
            named,
            answers,
            remembered_before.get(named.as_str()),
            posting,
            federation,
        )
        .await;
        let outcome = answered.outcome;
        if let Some(message) = answered.sending {
            sending = Some(Box::new(message));
        }

        if let Some(challenge) = answered.asks {
            // Under the authenticator's own name, so two steps issuing
            // challenges cannot overwrite each other's state.
            remembered.insert(named.as_str().to_owned(), challenge.remembered);
            if asked.is_none() {
                asked = Some(challenge.shown);
            }
        }
        if outcome == Outcome::Pending && waiting.is_none() {
            waiting = Some(execution.execution_id.clone());
        }
        if outcome == Outcome::Passed {
            passed.push(named);
        }
        steps.push(Step {
            requirement: execution.requirement,
            outcome,
        });
    }

    let decided = step::decide(&steps);
    if realm.brute_force.protected
        && let Some(subject) = subject
    {
        match decided {
            // Counted once per pass, not once per step: a flow of three
            // alternatives is one wrong answer, not three.
            Decided::Refused => {
                count_failure(transaction, realm, &subject.user_id, from, now).await?;
            }
            // A login that succeeded says the person is the person, so what was
            // counted against them was noise.
            Decided::Admitted => {
                login_store::clear_failures(transaction, &subject.user_id)
                    .await
                    .map_err(|_| Unrunnable::Unreadable)?;
            }
            Decided::Waiting => {}
        }
    }

    let progress = match decided {
        Decided::Admitted => Progress::Admitted { by: passed },
        Decided::Refused => Progress::Refused,
        // The fold said a step waits; which one is the first that did, so a
        // caller is asked the earliest question rather than an arbitrary one.
        Decided::Waiting => match waiting {
            Some(execution_id) => Progress::Waiting {
                execution_id,
                asks: asked,
                remember: remembered,
            },
            None => Progress::Refused,
        },
    };
    Ok((progress, sending))
}

/// When this person's lockout ends, or nothing when they are not locked.
async fn locked_until(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    subject: Option<&UserModel>,
    now: DateTime<Utc>,
) -> Result<Option<i64>, Unrunnable> {
    if !realm.brute_force.protected {
        return Ok(None);
    }
    let Some(subject) = subject else {
        return Ok(None);
    };
    let held = login_store::failures(transaction, &subject.user_id)
        .await
        .map_err(|_| Unrunnable::Unreadable)?;
    Ok(held
        .filter(|record| record.is_locked_at(now.timestamp()))
        .map(|record| record.failed_login_not_before))
}

/// Count one failure, and lock when the count says to.
async fn count_failure(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    user_id: &str,
    from: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), Unrunnable> {
    let policy = realm.brute_force;
    // The window is worked out from the count this failure will make, which is
    // what the row already holds plus one.
    let standing = login_store::failures(transaction, user_id)
        .await
        .map_err(|_| Unrunnable::Unreadable)?
        .map_or(0, |record| record.num_failures);
    login_store::record_failure(
        transaction,
        user_id,
        now.timestamp(),
        from,
        i64::from(policy.max_failures),
        policy.lockout_for(standing + 1),
        i64::from(policy.reset_seconds),
    )
    .await
    .map_err(|_| Unrunnable::Unreadable)?;
    Ok(())
}
