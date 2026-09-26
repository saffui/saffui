use secrecy::SecretBox;

use crate::str_enum::str_enum;

str_enum! {
    /// What a code does when the carrier gives no answer.
    pub enum WhenUnanswered {
        /// Sent, and the silence recorded: a carrier's outage does not stop
        /// every sign-in by code.
        Send => "send",
        /// Held, the way a code to a SIM that changed is.
        Hold => "hold",
    }
}

/// How a realm asks its carrier whether the SIM behind a number changed
/// lately, the key it proves itself with included.
///
/// Not serialisable, for the reason `SmsSettings` is not: the private key is
/// in it.
pub struct SimSwapSettings {
    pub client_id: String,
    /// The carrier's backchannel authentication endpoint, in full.
    pub authorize_url: String,
    pub token_url: String,
    /// The SIM Swap API's check operation, in full.
    pub check_url: String,
    /// How far back a change counts, in hours.
    pub max_age_hours: i32,
    pub when_unanswered: WhenUnanswered,
    pub key: SimSwapKey,
}

/// The pair a realm signs its client assertions with, P-256.
pub struct SimSwapKey {
    pub kid: String,
    pub private_pem: SecretBox<Vec<u8>>,
    /// What the carrier is given to check those assertions.
    pub public_jwk: serde_json::Value,
}

/// The same settings without the private key.
#[derive(Debug, Clone, PartialEq)]
pub struct SimSwapSettingsView {
    pub client_id: String,
    pub authorize_url: String,
    pub token_url: String,
    pub check_url: String,
    pub max_age_hours: i32,
    pub when_unanswered: WhenUnanswered,
    pub kid: String,
    pub public_jwk: serde_json::Value,
}

impl SimSwapSettings {
    /// A copy, key included. Written by hand because a secret is deliberately
    /// not `Clone`: every copy of one is a place it can be left.
    pub fn duplicate(&self) -> Self {
        SimSwapSettings {
            client_id: self.client_id.clone(),
            authorize_url: self.authorize_url.clone(),
            token_url: self.token_url.clone(),
            check_url: self.check_url.clone(),
            max_age_hours: self.max_age_hours,
            when_unanswered: self.when_unanswered,
            key: SimSwapKey {
                kid: self.key.kid.clone(),
                private_pem: SecretBox::new(Box::new(
                    secrecy::ExposeSecret::expose_secret(&self.key.private_pem).clone(),
                )),
                public_jwk: self.key.public_jwk.clone(),
            },
        }
    }

    pub fn as_view(&self) -> SimSwapSettingsView {
        SimSwapSettingsView {
            client_id: self.client_id.clone(),
            authorize_url: self.authorize_url.clone(),
            token_url: self.token_url.clone(),
            check_url: self.check_url.clone(),
            max_age_hours: self.max_age_hours,
            when_unanswered: self.when_unanswered,
            kid: self.key.kid.clone(),
            public_jwk: self.key.public_jwk.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    #[test]
    fn the_ways_to_meet_silence_agree_with_their_own_spelling() {
        assert_eq!(WhenUnanswered::ALL.len(), 2);
        assert_round_trips(WhenUnanswered::ALL);
    }
}
