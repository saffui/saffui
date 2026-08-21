//! OIDC protocol records: the authorization code minted by `/authorize` and
//! redeemed once at `/token`, and the backchannel request a client polls on.

use serde::{Deserialize, Serialize};

use crate::str_enum::str_enum;

/// A minted authorization code, identified by the SHA-256 hash of the code
/// value — the raw code is returned to the client and never stored, so a
/// database leak yields no usable codes.
///
/// The record binds everything `/token` must re-check at redemption: the client,
/// the exact `redirect_uri` the code was issued against, the PKCE challenge, the
/// `nonce` to echo into the id token, and the session and user the code speaks
/// for. Its lifetime lives in the row's `expires_at`, set from a TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// SHA-256 of the raw code, hex-encoded. Primary key.
    pub code_hash: String,
    pub tenant: String,
    pub realm_id: String,
    pub client_id: String,
    pub user_id: String,
    /// The SSO session the code was minted from; becomes the token `sid` claim.
    pub session_id: String,
    /// The redirect_uri this code was issued against. `/token` compares against this
    /// value rather than merely revalidating against the registered set.
    pub redirect_uri: String,
    /// Space-separated granted scopes.
    pub scope: String,
    /// Echoed into the id token when the authorize request carried one.
    pub nonce: Option<String>,
    /// PKCE challenge; required (with method `S256`) for public clients.
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// When the user authenticated (`auth_time`), Unix epoch seconds.
    pub auth_time: i64,
    /// The realm's context value for the level this login reached, frozen here: by
    /// `/token` the request is gone and a fresh answer would attest to another.
    pub acr: Option<String>,
    /// The organization the login was scoped to, carried into the token as the
    /// `org_id` / `org_name` claims. `None` for a realm-level login.
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub org_name: Option<String>,
    /// The `claims` request parameter, OIDC Core §5.5, as the client sent it.
    #[serde(default)]
    pub claims: Option<serde_json::Value>,
}

str_enum! {
    /// The status of a backchannel authentication request.
    pub enum BackchannelStatus {
        /// Awaiting the user's decision on the authentication device.
        Pending => "pending",
        /// The user approved; the polling client may collect its tokens.
        Approved => "approved",
        /// The user declined.
        Denied => "denied",
    }
}

/// A CIBA (Client-Initiated Backchannel Authentication) request.
///
/// The relying party opens one at `/bc-authorize` with a `login_hint`; the
/// server resolves the user and drives an authentication device to get their
/// decision; the relying party then polls `/token` with the `auth_req_id` until
/// it is approved (tokens issued once, then the row is consumed) or denied. Its
/// lifetime lives in the row's `expires_at`.
#[derive(Debug, Clone)]
pub struct BackchannelAuthRequest {
    /// The opaque, unguessable id returned to the relying party and polled on.
    pub auth_req_id: String,
    pub tenant: String,
    pub realm_id: String,
    /// The client that initiated the request, and the tokens' audience.
    pub client_id: String,
    /// The resolved end user.
    pub user_id: String,
    /// Space-separated requested scopes.
    pub scope: String,
    pub status: BackchannelStatus,
    /// Load-time only: whether the row was already past `expires_at` when read,
    /// which the grant maps to the `expired_token` poll error. Not persisted.
    pub expired: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::str_enum::assert_round_trips;
    use std::str::FromStr;

    #[test]
    fn the_statuses_agree_with_their_own_spelling() {
        assert_eq!(BackchannelStatus::ALL.len(), 3);
        assert_round_trips(BackchannelStatus::ALL);
    }

    /// A status nobody named is an error rather than `Pending`. Reading an
    /// unrecognised value as pending tells a polling client to keep waiting for
    /// a decision that may already have been refused.
    #[test]
    fn an_unknown_status_does_not_read_as_pending() {
        assert!(BackchannelStatus::from_str("approve").is_err());
        assert!(BackchannelStatus::from_str("").is_err());
        assert!(BackchannelStatus::from_str("PENDING").is_err());
    }

    /// The code is identified by a hash, so what is stored is never what is
    /// handed out.
    #[test]
    fn an_authorization_code_survives_the_wire_with_its_optional_claims() {
        let code = AuthorizationCode {
            code_hash: "ab".repeat(32),
            tenant: "acme".into(),
            realm_id: "realm-1".into(),
            client_id: "app".into(),
            user_id: "ada".into(),
            session_id: "sess-1".into(),
            redirect_uri: "https://app.example/cb".into(),
            scope: "openid profile".into(),
            nonce: None,
            code_challenge: Some("challenge".into()),
            code_challenge_method: Some("S256".into()),
            auth_time: 1_700_000_000,
            acr: None,
            org_id: None,
            org_name: None,
            claims: None,
        };

        let encoded = serde_json::to_string(&code).unwrap();
        let decoded: AuthorizationCode = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.code_hash, code.code_hash);
        assert_eq!(decoded.redirect_uri, code.redirect_uri);
        assert_eq!(decoded.code_challenge_method.as_deref(), Some("S256"));
        assert_eq!(decoded.acr, None);
    }

    /// The organization claims are absent from an older stored record rather
    /// than a decoding failure.
    #[test]
    fn a_record_without_the_organization_claims_still_decodes() {
        let without = r#"{
            "code_hash":"ab","tenant":"acme","realm_id":"r","client_id":"c",
            "user_id":"u","session_id":"s","redirect_uri":"https://a/cb",
            "scope":"openid","nonce":null,"code_challenge":null,
            "code_challenge_method":null,"auth_time":1,"acr":null
        }"#;
        let decoded: AuthorizationCode = serde_json::from_str(without).unwrap();
        assert_eq!(decoded.org_id, None);
        assert_eq!(decoded.org_name, None);
    }
}
