//! What the hosted sign-in page reads before anybody is named: the login a
//! browser holds, and what the realm's flow asks of it.

use models::entities::auth::ExecutionStep;
use store::providers::protocol::login::{self, AuthSession};
use store::providers::realms::auth_flows;
use store::tenancy::UnitOfWork;

/// The login a browser holds, while it is still open.
pub async fn read_open_login(
    transaction: &UnitOfWork,
    auth_session_id: &str,
) -> Result<Option<AuthSession>, crate::realm::Unreadable> {
    login::resume(transaction, auth_session_id)
        .await
        .map_err(|_| crate::realm::Unreadable)
}

/// Whether this realm's browser flow has a step that takes a printed code.
///
/// The realm's flow and not the client's: the page is built before any client
/// is named, so a client that overrides the binding to a flow of its own is not
/// read here. Offering the field where no step takes it costs a person one
/// wrong guess; hiding it where one does would cost them the way back.
///
/// One level deep. A sub-flow is walked, because the built browser flow keeps
/// its second factors in one, and a step buried two flows down is a shape
/// nothing this build provisions.
pub async fn offers_recovery_codes(transaction: &UnitOfWork, bound: Option<&str>) -> bool {
    let Ok(Some(flow)) = auth_flows::flow_by_alias(transaction, bound.unwrap_or("browser")).await
    else {
        return false;
    };
    let Ok(steps) = auth_flows::executions_of(transaction, &flow.flow_id).await else {
        return false;
    };
    for step in &steps {
        if !step.is_enabled() {
            continue;
        }
        match &step.step {
            ExecutionStep::Authenticator { authenticator, .. } => {
                if authenticator == "recovery-code" {
                    return true;
                }
            }
            ExecutionStep::SubFlow { flow_id } => {
                let Ok(inner) = auth_flows::executions_of(transaction, flow_id).await else {
                    continue;
                };
                if inner.iter().any(|held| {
                    held.is_enabled()
                        && matches!(
                            &held.step,
                            ExecutionStep::Authenticator { authenticator, .. }
                                if authenticator == "recovery-code"
                        )
                }) {
                    return true;
                }
            }
        }
    }
    false
}

/// Why a code went nowhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Held {
    /// The carrier said the SIM behind the number changed within the realm's
    /// window.
    SimSwapped,
    /// The carrier gave no answer, and the realm holds on silence.
    Unanswered,
}

impl Held {
    fn event(self) -> &'static str {
        match self {
            Self::SimSwapped => "sim_swapped",
            Self::Unanswered => "sim_swap_unanswered",
        }
    }
}

/// Hold a code that was about to go out: void it, mark the step that drew it
/// so the round played again finds that step failed, and record why where a
/// failed sign-in is recorded.
pub async fn hold_code(
    transaction: &UnitOfWork,
    auth_session_id: &str,
    user_id: &str,
    step: &str,
    recipient: &str,
    why: Held,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), crate::realm::Unreadable> {
    store::providers::directory::one_time_tokens::void(transaction, user_id, step)
        .await
        .map_err(|_| crate::realm::Unreadable)?;
    login::hold_step(transaction, auth_session_id, step)
        .await
        .map_err(|_| crate::realm::Unreadable)?;
    store::providers::events::login_events::record(
        transaction,
        now.timestamp(),
        &store::providers::events::login_events::LoginEventWrite {
            kind: why.event(),
            user_id: Some(user_id),
            detail: Some(serde_json::json!({ "to": recipient, "step": step })),
            ..Default::default()
        },
    )
    .await
    .map_err(|_| crate::realm::Unreadable)
}
