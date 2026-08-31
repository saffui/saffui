use chrono::{DateTime, Utc};

use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "backchannel_state")]
    /// Where a decoupled sign-in stands.
    pub enum BackchannelState {
        Pending => "pending",
        Approved => "approved",
        Denied => "denied",
    }
}

#[derive(Debug, Clone)]
pub struct BackchannelRequestModel {
    pub tenant: String,
    pub realm_id: String,
    pub client_id: String,
    /// Absent for a ghost: an unknown hint answered normally, approvable by
    /// nobody.
    pub user_id: Option<String>,
    pub scope: String,
    pub binding_message: Option<String>,
    pub state: BackchannelState,
    /// poll or ping; how the client learns the person decided.
    pub delivery: String,
    /// Ping only: the bearer the client handed in, spoken back at the ping.
    pub notification_token: Option<String>,
    /// Ping only: the request id under the realm's seal, since the ping must
    /// say it in the clear and only its digest lives here otherwise.
    pub sealed_request: Option<Vec<u8>>,
    pub interval_secs: i32,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: Option<DateTime<Utc>>,
}
