//! What a person allowed a client: the scopes it may be given in their name
//! without asking them again. A client that asks for more asks again, and a
//! person who withdraws their consent ends what the client holds for them.

pub mod answer;
pub mod manage;
pub mod store;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::clients::Client;

/// How many consents of one person a list shows: a person allows few clients.
pub const MOST_LISTED_CONSENTS: u32 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consent {
    pub person: Uuid,
    pub client_id: String,
    /// Every scope allowed so far: what was allowed once stays allowed
    /// until the person withdraws it.
    pub scopes: Vec<String>,
    /// When the person last allowed the client something.
    pub granted_at: OffsetDateTime,
}

/// A consent as a list shows it, with the name of its client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedConsent {
    pub consent: Consent,
    /// Written by whoever registered the client.
    pub client_name: String,
}

/// Whether the person must be asked before the client gets a code: always
/// when it asked so with `prompt=consent`, and for a client that requires
/// consent, whenever it asks a scope the person did not allow it.
#[must_use]
pub fn is_consent_owed(
    client: &Client,
    prompted: bool,
    held: Option<&Consent>,
    asked: &[String],
) -> bool {
    let allowed = held.is_some_and(|consent| {
        asked
            .iter()
            .all(|scope| consent.scopes.iter().any(|kept| kept == scope))
    });
    prompted || (client.requires_consent && !allowed)
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{Consent, is_consent_owed};
    use crate::clients::Client;

    fn make_client(requires_consent: bool) -> Client {
        Client {
            id: Uuid::from_u128(1),
            client_id: "partner".to_owned(),
            name: "Partner".to_owned(),
            secret_digest: None,
            allows_client_credentials: false,
            allows_authorization_code: true,
            redirect_uris: vec!["https://app.example.org/callback".to_owned()],
            post_logout_redirect_uris: Vec::new(),
            requires_consent,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            capabilities: Vec::new(),
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn allow(scopes: &[&str]) -> Consent {
        Consent {
            person: Uuid::from_u128(2),
            client_id: "partner".to_owned(),
            scopes: scopes.iter().map(|&scope| scope.to_owned()).collect(),
            granted_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn a_client_that_requires_consent_asks_until_every_scope_it_asks_was_allowed() {
        let partner = make_client(true);
        let openid = ["openid".to_owned()];
        let both = ["openid".to_owned(), "email".to_owned()];

        assert!(is_consent_owed(&partner, false, None, &openid));
        assert!(is_consent_owed(&partner, false, None, &[]), "nothing yet");
        assert!(!is_consent_owed(
            &partner,
            false,
            Some(&allow(&["openid"])),
            &openid
        ));
        assert!(
            is_consent_owed(&partner, false, Some(&allow(&["openid"])), &both),
            "a scope not allowed before"
        );
        assert!(!is_consent_owed(
            &partner,
            false,
            Some(&allow(&["email", "openid"])),
            &openid
        ));
    }

    #[test]
    fn prompt_consent_asks_any_client_and_a_client_that_requires_none_asks_nothing_else() {
        let webapp = make_client(false);
        let openid = ["openid".to_owned()];

        assert!(!is_consent_owed(&webapp, false, None, &openid));
        assert!(is_consent_owed(&webapp, true, None, &openid));
        assert!(
            is_consent_owed(&make_client(true), true, Some(&allow(&["openid"])), &openid),
            "even what was allowed"
        );
    }
}
