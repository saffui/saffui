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
