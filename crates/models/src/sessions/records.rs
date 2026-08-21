//! The rows a session leaves behind.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::entities::user::RequiredAction;
use crate::str_enum::str_enum;

str_enum! {
    #[postgres(name = "user_session_state")]
    /// Where a user session stands.
    pub enum UserSessionState {
        LoggedIn => "logged-in",
        /// Logout has finished everywhere it was propagated.
        LoggedOut => "logged-out",
        /// Logout is propagating to the clients that asked to be told.
        LoggingOut => "logging-out",
        /// Logout was started and at least one client never confirmed. The
        /// session is not usable and not provably ended, which is a state an
        /// operator has to be able to see.
        LoggingOutUnconfirmed => "logging-out-unconfirmed",
    }
}

/// A user's session with the realm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionModel {
    pub tenant: String,
    pub session_id: String,
    pub realm_id: String,
    pub user_id: String,
    pub login_username: String,
    pub broker_session_id: Option<String>,
    pub broker_user_id: Option<String>,
    pub auth_method: Option<String>,
    pub ip_address: Option<String>,
    pub started_at: i64,
    /// When the user last actually authenticated, which is not when the session
    /// began. None where it was never tracked, never zero, which reads as the epoch.
    pub auth_time: Option<i64>,
    /// The level of assurance reached. None is unknown and not zero: without it a
    /// step up cannot be recognised and the second factor runs again.
    pub loa: Option<i32>,
    pub expiration: Option<i64>,
    pub state: UserSessionState,
    pub remember_me: Option<bool>,
    pub last_session_refresh: Option<i64>,
    pub is_offline: Option<bool>,
    pub notes: Option<HashMap<String, String>>,
}

/// A client's slice of a user session: what one client got out of one login.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSessionModel {
    pub tenant: String,
    pub session_id: String,
    pub realm_id: String,
    pub user_id: String,
    /// The user session this hangs off.
    pub user_session_id: String,
    pub client_id: String,
    pub auth_method: Option<String>,
    pub redirect_uri: Option<String>,
    pub started_at: i64,
    pub expiration: Option<i64>,
    pub notes: Option<HashMap<String, String>>,
    /// Never serialised. A refresh token is a bearer credential, and a client
    /// session rendered into a response must not carry one.
    #[serde(skip_serializing)]
    pub current_refresh_token: Option<String>,
    /// How many times the current refresh token has been presented. Detecting
    /// replay is what this is for, so it counts rather than flagging.
    pub current_refresh_token_use_count: Option<i32>,
    pub offline: Option<bool>,
    /// What the client asked for by name, OIDC Core §5.5. Read by the userinfo
    /// endpoint and by every renewal, which is why it outlives the code.
    #[serde(default)]
    pub requested_claims: Option<serde_json::Value>,
}

str_enum! {
    /// What a login attempt is waiting on.
    ///
    /// This decides which screen the flow shows, so two actions sharing a
    /// spelling would send a user to the wrong one.
    pub enum AuthenticationAction {
        /// Collecting credentials.
        Authenticate => "authenticate",
        /// Showing the consent screen.
        OauthGrant => "oauth-grant",
        /// Working through the actions the user still owes.
        RequiredActions => "required-actions",
        /// Waiting on a code entered on another device.
        UserCodeVerification => "user-code-verification",
        LoggingOut => "logging-out",
        LoggedOut => "logged-out",
    }
}

str_enum! {
    /// How one step of a flow ended.
    pub enum AuthExecutionStatus {
        Success => "success",
        Failed => "failed",
        /// The step ran and asked the user for something.
        Challenged => "challenged",
        /// The step ran and did not conclude.
        Attempted => "attempted",
        /// The step did not apply.
        Skipped => "skipped",
        /// The user must configure something before the step can run.
        SetupRequired => "setup-required",
        /// The user has no credential of the kind the step needs.
        CredentialSetupRequired => "credential-setup-required",
        /// A condition, and what it decided.
        EvaluatedTrue => "evaluated-true",
        EvaluatedFalse => "evaluated-false",
    }
}

/// The root of a login attempt: one per browser, shared by its tabs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootAuthenticationSessionModel {
    pub tenant: String,
    pub session_id: String,
    pub realm_id: String,
    pub timestamp: i64,
}

/// One tab's login attempt, under a root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationSessionModel {
    pub tenant: String,
    pub tab_id: String,
    pub realm_id: String,
    pub root_session_id: String,
    /// The user, once a step has identified one.
    pub auth_user_id: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_scopes: Option<HashSet<String>>,
    pub timestamp: i64,
    pub action: Option<AuthenticationAction>,
    pub protocol: Option<String>,
    /// How each step of the flow ended, by execution id.
    pub execution_status: Option<HashMap<String, AuthExecutionStatus>>,
    pub client_notes: Option<HashMap<String, String>>,
    pub auth_notes: Option<HashMap<String, String>>,
    pub required_actions: Option<HashSet<RequiredAction>>,
    pub user_session_notes: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;

    #[test]
    fn the_catalogues_agree_with_their_own_spelling() {
        assert_eq!(UserSessionState::ALL.len(), 4);
        assert_eq!(AuthenticationAction::ALL.len(), 6);
        assert_eq!(AuthExecutionStatus::ALL.len(), 9);
        assert_round_trips(UserSessionState::ALL);
        assert_round_trips(AuthenticationAction::ALL);
        assert_round_trips(AuthExecutionStatus::ALL);
    }

    /// No two actions share a spelling. The action decides which screen the flow
    /// shows, so a collision sends a user collecting credentials to the consent
    /// screen instead, and a stored value cannot be read back as what wrote it.
    #[test]
    fn no_two_actions_share_a_spelling() {
        let mut spellings: Vec<&str> = AuthenticationAction::ALL
            .iter()
            .map(|a| a.as_str())
            .collect();
        let count = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), count, "two actions share a spelling");

        assert_eq!(AuthenticationAction::Authenticate.as_str(), "authenticate");
        assert_eq!(AuthenticationAction::OauthGrant.as_str(), "oauth-grant");
        assert_ne!(
            AuthenticationAction::Authenticate.as_str(),
            AuthenticationAction::OauthGrant.as_str()
        );
    }

    /// The same holds for the statuses, which is what a flow reads to decide
    /// whether a step has already run.
    #[test]
    fn no_two_statuses_share_a_spelling() {
        let mut spellings: Vec<&str> = AuthExecutionStatus::ALL
            .iter()
            .map(|s| s.as_str())
            .collect();
        let count = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), count);
        assert_ne!(
            AuthExecutionStatus::EvaluatedTrue.as_str(),
            AuthExecutionStatus::EvaluatedFalse.as_str()
        );
    }

    fn client_session() -> ClientSessionModel {
        ClientSessionModel {
            tenant: "acme".into(),
            session_id: "cs-1".into(),
            realm_id: "realm-1".into(),
            user_id: "ada".into(),
            user_session_id: "us-1".into(),
            client_id: "app".into(),
            auth_method: Some("openid-connect".into()),
            redirect_uri: Some("https://app.example/cb".into()),
            started_at: 1_000,
            expiration: Some(2_000),
            notes: None,
            current_refresh_token: Some("rt-s3cr3t".into()),
            current_refresh_token_use_count: Some(1),
            offline: Some(false),
            requested_claims: None,
        }
    }

    /// A refresh token is a bearer credential and never reaches a rendered
    /// session.
    #[test]
    fn a_rendered_client_session_carries_no_refresh_token() {
        let json = serde_json::to_string(&client_session()).unwrap();
        assert!(!json.contains("rt-s3cr3t"), "{json}");
        assert!(json.contains("cs-1"), "the rest still renders");
    }

    /// A session always has a state. An absent one would have to be read as
    /// something, and every reading of "no state" is a guess about whether the
    /// user is still logged in.
    #[test]
    fn a_session_state_survives_the_wire() {
        for state in UserSessionState::ALL {
            let encoded = serde_json::to_string(state).unwrap();
            assert_eq!(
                serde_json::from_str::<UserSessionState>(&encoded).unwrap(),
                *state
            );
        }
        assert_eq!(
            UserSessionState::LoggingOutUnconfirmed.as_str(),
            "logging-out-unconfirmed"
        );
    }
}
