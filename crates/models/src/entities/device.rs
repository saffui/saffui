use chrono::{DateTime, Utc};

use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "device_code_state")]
    /// Where a device sign-in stands.
    pub enum DeviceCodeState {
        Pending => "pending",
        Approved => "approved",
        Denied => "denied",
    }
}

/// RFC 8628: a sign-in waiting on a person with a better keyboard. The device
/// holds the long secret and polls with it; the short code is what the person
/// types, and both live exactly as long as this row.
#[derive(Debug, Clone)]
pub struct DeviceCodeModel {
    pub tenant: String,
    pub realm_id: String,
    /// Normalized: uppercase, no separators.
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub state: DeviceCodeState,
    /// Written at approval, by the login that approved it. The token the poll
    /// redeems speaks these, so they are frozen here the way a code's are.
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub auth_time: Option<i64>,
    pub acr: Option<String>,
    pub org_id: Option<String>,
    pub org_name: Option<String>,
    pub interval_secs: i32,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub approved_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: Option<DateTime<Utc>>,
}
