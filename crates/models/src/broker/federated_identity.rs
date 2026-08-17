//! The link between a local user and the account they hold upstream.
//!
//! Keyed on the upstream subject and nothing else. An email address or a
//! username is mutable at the provider, so keying on either means a user who
//! changes theirs arrives as a different person, or worse as someone else's.

use serde::{Deserialize, Serialize};

use crate::broker::BrokerSecret;

/// A stored link. One row per realm, provider and upstream account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentity {
    pub tenant: String,
    pub realm_id: String,
    pub user_id: String,
    /// The provider's public alias, which is what a broker URL carries, rather
    /// than its internal identifier.
    pub provider_alias: String,
    /// The upstream subject.
    pub external_user_id: String,
    /// Display only, for an account console. Never used to resolve identity.
    pub external_username: Option<String>,
    /// Upstream credentials, kept for refresh and back channel logout.
    ///
    /// Never serialised. These authenticate this deployment to a third party, so
    /// a link rendered into any response must not carry them.
    #[serde(skip_serializing)]
    pub token: Option<BrokerSecret>,
    #[serde(skip_serializing)]
    pub refresh_token: Option<BrokerSecret>,
    /// Unix epoch seconds.
    pub token_expires_at: Option<i64>,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

/// Who a link joins: the local user on one side, the upstream account on the
/// other.
#[derive(Debug, Clone)]
pub struct FederatedAccount {
    pub tenant: String,
    pub realm_id: String,
    pub user_id: String,
    pub provider_alias: String,
    pub external_user_id: String,
    pub external_username: Option<String>,
}

impl FederatedIdentity {
    /// A new link with no upstream tokens retained.
    ///
    /// The default for a provider whose refresh and back channel logout are not
    /// wired. Storing bearer credentials nothing will use is a liability with no
    /// benefit, so keeping them takes an explicit call.
    pub fn new(account: FederatedAccount, now: i64) -> Self {
        FederatedIdentity {
            tenant: account.tenant,
            realm_id: account.realm_id,
            user_id: account.user_id,
            provider_alias: account.provider_alias,
            external_user_id: account.external_user_id,
            external_username: account.external_username,
            token: None,
            refresh_token: None,
            token_expires_at: None,
            created_at: now,
            last_login_at: Some(now),
        }
    }

    /// Retain the upstream tokens on this link.
    pub fn with_tokens(
        mut self,
        token: Option<BrokerSecret>,
        refresh_token: Option<BrokerSecret>,
        token_expires_at: Option<i64>,
    ) -> Self {
        self.token = token;
        self.refresh_token = refresh_token;
        self.token_expires_at = token_expires_at;
        self
    }
}

/// The credential free projection for an admin or account console read.
///
/// A console listing which providers a user has linked needs none of the
/// upstream credentials, and returning them would hand whoever reaches that
/// endpoint a working credential at a third party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedIdentityView {
    pub user_id: String,
    pub provider_alias: String,
    pub external_user_id: String,
    pub external_username: Option<String>,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

impl From<&FederatedIdentity> for FederatedIdentityView {
    fn from(link: &FederatedIdentity) -> Self {
        FederatedIdentityView {
            user_id: link.user_id.clone(),
            provider_alias: link.provider_alias.clone(),
            external_user_id: link.external_user_id.clone(),
            external_username: link.external_username.clone(),
            created_at: link.created_at,
            last_login_at: link.last_login_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account() -> FederatedAccount {
        FederatedAccount {
            tenant: "acme".into(),
            realm_id: "acme".into(),
            user_id: "local-ada".into(),
            provider_alias: "google".into(),
            external_user_id: "upstream-sub-1".into(),
            external_username: Some("ada".into()),
        }
    }

    fn linked() -> FederatedIdentity {
        FederatedIdentity::new(account(), 1_000)
    }

    fn with_credentials() -> FederatedIdentity {
        linked().with_tokens(
            Some(BrokerSecret::new("ya29.upstream-access-token".into())),
            Some(BrokerSecret::new("1//upstream-refresh-token".into())),
            Some(2_000),
        )
    }

    /// Tokens are opt in. A provider whose refresh and logout are not wired
    /// should not leave third party bearer credentials in the database for
    /// nothing.
    #[test]
    fn a_new_link_retains_no_upstream_credentials() {
        let link = linked();
        assert!(link.token.is_none());
        assert!(link.refresh_token.is_none());
        assert!(link.token_expires_at.is_none());
        assert_eq!(link.created_at, 1_000);
        assert_eq!(link.last_login_at, Some(1_000));

        let kept = with_credentials();
        assert_eq!(
            kept.token.as_ref().map(BrokerSecret::expose),
            Some("ya29.upstream-access-token")
        );
        assert_eq!(kept.token_expires_at, Some(2_000));
    }

    /// The link is keyed on the upstream subject, and the username is display
    /// only. Resolving on a mutable value would let a rename arrive as another
    /// person.
    #[test]
    fn the_link_is_keyed_on_the_subject_and_not_the_username() {
        let renamed = FederatedIdentity::new(
            FederatedAccount {
                external_username: Some("ada.lovelace".into()),
                ..account()
            },
            2_000,
        );
        assert_eq!(renamed.external_user_id, linked().external_user_id);
        assert_ne!(renamed.external_username, linked().external_username);
    }

    /// A rendered link carries no upstream credential, whichever way it is
    /// rendered. Both paths reach the same struct.
    #[test]
    fn a_rendered_link_carries_no_upstream_credential() {
        let link = with_credentials();

        let json = serde_json::to_string(&link).unwrap();
        assert!(
            !json.contains("ya29"),
            "an access token was rendered: {json}"
        );
        assert!(
            !json.contains("1//"),
            "a refresh token was rendered: {json}"
        );
        assert!(json.contains("upstream-sub-1"), "the rest still renders");

        let rendered = format!("{link:?}");
        assert!(!rendered.contains("ya29"), "{rendered}");
        assert!(!rendered.contains("1//"), "{rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    /// The view is the deliberate read path, and it is asserted field by field:
    /// mirroring a new field into it without thinking is how a token reaches a
    /// response body, and that mistake compiles.
    #[test]
    fn the_view_carries_only_what_a_console_needs() {
        let link = with_credentials();
        let view = FederatedIdentityView::from(&link);
        let json = serde_json::to_string(&view).unwrap();

        assert!(!json.contains("ya29"), "{json}");
        assert!(!json.contains("1//"), "{json}");
        assert!(
            !json.contains("token"),
            "the view has a token shaped field: {json}"
        );

        assert_eq!(view.user_id, "local-ada");
        assert_eq!(view.provider_alias, "google");
        assert_eq!(view.external_user_id, "upstream-sub-1");
        assert_eq!(view.external_username.as_deref(), Some("ada"));
        assert_eq!(view.created_at, 1_000);
        assert_eq!(view.last_login_at, Some(1_000));
    }
}
