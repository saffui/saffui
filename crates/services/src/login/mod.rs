//! Letting somebody in, one step at a time.
//!
//! A flow is walked, each enabled step is run against what the realm holds, and
//! what the flow makes of the answers decides. The walk takes the caller's
//! transaction like everything else here, so a login and the session it opens
//! are one snapshot.

pub mod authenticator;
pub mod browser;
pub mod step;

use chrono::{DateTime, Utc};
use config::serving::PublicOrigin;
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
    /// Everything the flow required is established, by these authenticators.
    /// Named rather than counted, because the level a login reached is the
    /// realm's reading of what actually ran.
    Admitted { by: Vec<Authenticator> },
    /// It cannot be, and no further answer changes that.
    Refused,
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
        )
        .await;
        let outcome = answered.outcome;

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

    Ok(match step::decide(&steps) {
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
    })
}
