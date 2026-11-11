//! What a person allowed a client: the scopes it may be given in their name
//! without asking them again. A client that asks for more asks again, and a
//! person who withdraws their consent ends what the client holds for them.

pub mod answer;
pub mod manage;
pub mod store;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::clients::Client;
use crate::oidc::authorize::leave_out_offline_access;

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

/// What decides whether a person owes a client their consent, as one
/// statement reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentTerms {
    pub requires_consent: bool,
    /// What the person allowed the client so far. `None` when they allowed
    /// it nothing.
    pub allowed: Option<Vec<String>>,
}

/// How an exchange holds what the person allowed, until it commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentHold {
    /// Against a withdrawal alone: other exchanges hold it beside.
    Shared,
    /// Against other exchanges too, which wait their turn: one that opens an
    /// offline grant counts those the person holds with the client.
    Exclusive,
}

/// What a client may be granted of the scopes a person allowed: all of them
/// to a client that requires consent; to another, all but `offline_access`,
/// which would outlive any consent the person could withdraw. It is left out
/// in silence, as OpenID Connect Core 1.0, section 11, allows.
pub(crate) fn grant_to_client(client: &Client, allowed: &[String]) -> Vec<String> {
    if client.requires_consent {
        allowed.to_vec()
    } else {
        leave_out_offline_access(allowed)
    }
}

/// Whether the person must be asked before the client gets a code: always
/// when it asked so with `prompt=consent`, and for a client that requires
/// consent, whenever it asks a scope the person did not allow it.
#[must_use]
pub fn is_consent_owed(terms: &ConsentTerms, prompted: bool, asked: &[String]) -> bool {
    let allowed = terms.allowed.as_ref().is_some_and(|kept| {
        asked
            .iter()
            .all(|scope| kept.iter().any(|allowed| allowed == scope))
    });
    prompted || (terms.requires_consent && !allowed)
}

#[cfg(test)]
mod tests {
    use super::{ConsentTerms, is_consent_owed};

    fn ask(requires_consent: bool, allowed: Option<&[&str]>) -> ConsentTerms {
        ConsentTerms {
            requires_consent,
            allowed: allowed.map(|scopes| scopes.iter().map(|&scope| scope.to_owned()).collect()),
        }
    }

    #[test]
    fn a_client_that_requires_consent_asks_until_every_scope_it_asks_was_allowed() {
        let openid = ["openid".to_owned()];
        let both = ["openid".to_owned(), "email".to_owned()];

        assert!(is_consent_owed(&ask(true, None), false, &openid));
        assert!(is_consent_owed(&ask(true, None), false, &[]), "nothing yet");
        assert!(!is_consent_owed(
            &ask(true, Some(&["openid"])),
            false,
            &openid
        ));
        assert!(
            is_consent_owed(&ask(true, Some(&["openid"])), false, &both),
            "a scope not allowed before"
        );
        assert!(!is_consent_owed(
            &ask(true, Some(&["email", "openid"])),
            false,
            &openid
        ));
    }

    #[test]
    fn prompt_consent_asks_any_client_and_a_client_that_requires_none_asks_nothing_else() {
        let openid = ["openid".to_owned()];

        assert!(!is_consent_owed(&ask(false, None), false, &openid));
        assert!(is_consent_owed(&ask(false, None), true, &openid));
        assert!(
            is_consent_owed(&ask(true, Some(&["openid"])), true, &openid),
            "even what was allowed"
        );
    }
}
