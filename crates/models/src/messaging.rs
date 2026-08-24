use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One attempt to send a message, and how it went.
///
/// Never the body. A receipt holding the link is a table anybody with read
/// access can sign in from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub delivery_id: String,
    pub user_id: String,
    /// What it was for, spelled as the token purpose is.
    pub purpose: String,
    pub recipient: String,
    pub attempted_at: DateTime<Utc>,
    pub delivered: bool,
    /// What the far end said, when it said something.
    pub detail: Option<String>,
}
