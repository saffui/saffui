//! Letting somebody in, one step at a time.
//!
//! A flow is walked, each enabled step is run against what the realm holds, and
//! what the flow makes of the answers decides. The walk takes the caller's
//! transaction like everything else here, so a login and the session it opens
//! are one snapshot.

pub mod authenticator;
pub mod step;

use chrono::{DateTime, Utc};
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::auth::ExecutionStep;
use models::entities::realm::RealmModel;
use models::entities::user::UserModel;
use store::providers::auth_flows;

use crate::login::authenticator::{Answer, Authenticator};
use crate::login::step::{Decided, Outcome, Step};

/// Where a login stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Everything the flow required is established.
    Admitted,
    /// It cannot be, and no further answer changes that.
    Refused,
    /// A step is waiting on the caller, named so it can be asked.
    Waiting { execution_id: String },
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
pub async fn advance(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    realm: &RealmModel,
    flow_id: &str,
    subject: Option<&UserModel>,
    answer: Option<&Answer>,
    _now: DateTime<Utc>,
) -> Result<Progress, Unrunnable> {
    let executions = auth_flows::executions_of(transaction, flow_id)
        .await
        .map_err(|_| Unrunnable::Unreadable)?;
    if executions.is_empty() {
        return Err(Unrunnable::NoSuchFlow);
    }

    let mut steps = Vec::with_capacity(executions.len());
    let mut waiting = None;

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

        let outcome =
            authenticator::run(transaction, provider, realm, subject, named, answer).await;

        if outcome == Outcome::Pending && waiting.is_none() {
            waiting = Some(execution.execution_id.clone());
        }
        steps.push(Step {
            requirement: execution.requirement,
            outcome,
        });
    }

    Ok(match step::decide(&steps) {
        Decided::Admitted => Progress::Admitted,
        Decided::Refused => Progress::Refused,
        // The fold said a step waits; which one is the first that did, so a
        // caller is asked the earliest question rather than an arbitrary one.
        Decided::Waiting => match waiting {
            Some(execution_id) => Progress::Waiting { execution_id },
            None => Progress::Refused,
        },
    })
}
