use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::str_enum::str_enum;

str_enum! {
    /// Which way an attempt to send went.
    pub enum Channel {
        Mail => "mail",
        Sms => "sms",
        WhatsApp => "whatsapp",
    }
}

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
    /// Absent on the attempts made before there was a choice.
    pub channel: Option<Channel>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    #[test]
    fn the_channels_agree_with_their_own_spelling() {
        assert_eq!(Channel::ALL.len(), 3);
        assert_round_trips(Channel::ALL);
    }
}
