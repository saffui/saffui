//! What a person allowed a client: the scopes it may be given in their name
//! without asking them again. A client that asks for more asks again, and a
//! person who withdraws their consent ends what the client holds for them.

pub mod answer;
pub mod manage;
pub mod store;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::clients::Client;
use crate::error::Failure;
use crate::oidc::authorize::leave_out_offline_access;
use crate::ports::storage::UnitOfWork;

/// How many consents of one person a list shows: a person allows few clients.
pub const MOST_LISTED_CONSENTS: u32 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Consent {
    pub person: Uuid,
    pub client_id: String,
    /// Every scope allowed so far: what was allowed once stays allowed
    /// until the person withdraws it.
    pub scopes: Vec<String>,
    /// Every claim allowed by name so far, beyond what the scopes say.
    pub claims: Vec<String>,
    /// When the person last allowed the client something.
    pub granted_at: OffsetDateTime,
}

/// What a person allowed a client so far: scopes, and claims named one by one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowance {
    pub scopes: Vec<String>,
    pub claims: Vec<String>,
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
    pub allowed: Option<Allowance>,
    /// The scopes the client may be given: what a claim named is bounded by.
    pub client_scopes: Vec<String>,
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

/// What a person allowed a client that asks them, as it stands now: `None`
/// for a client that asks nobody, nothing for one they allowed nothing.
pub(crate) async fn read_allowance(
    work: &mut dyn UnitOfWork,
    client: &Client,
    person: Uuid,
) -> Result<Option<Allowance>, Failure> {
    if !client.requires_consent {
        return Ok(None);
    }
    let held = work.read_consent(person, &client.client_id).await?;
    Ok(Some(
        held.map(|held| Allowance {
            scopes: held.scopes,
            claims: held.claims,
        })
        .unwrap_or_default(),
    ))
}

/// The scopes that say a claim without the person allowing it by name: those
/// a request asks, which the person allows on its page, and those they
/// allowed before.
pub(crate) fn list_covering_scopes(asked: &[String], allowed: Option<&Allowance>) -> Vec<String> {
    let mut covering = asked.to_vec();
    for scope in allowed.into_iter().flat_map(|allowed| &allowed.scopes) {
        if !covering.contains(scope) {
            covering.push(scope.clone());
        }
    }
    covering
}

/// Whether the person must be asked before the client gets a code: always
/// when it asked so with `prompt=consent`, and for a client that requires
/// consent, whenever it asks a scope the person did not allow it, or names a
/// claim they must allow by name and did not.
#[must_use]
pub fn is_consent_owed(
    terms: &ConsentTerms,
    prompted: bool,
    scopes: &[String],
    claims: &[String],
) -> bool {
    let allowed = terms.allowed.as_ref().is_some_and(|kept| {
        scopes.iter().all(|scope| kept.scopes.contains(scope))
            && claims.iter().all(|claim| kept.claims.contains(claim))
    });
    prompted || (terms.requires_consent && !allowed)
}

#[cfg(test)]
mod tests {
    use super::{Allowance, ConsentTerms, is_consent_owed};

    fn ask(requires_consent: bool, allowed: Option<&[&str]>) -> ConsentTerms {
        ConsentTerms {
            requires_consent,
            allowed: allowed.map(|scopes| Allowance {
                scopes: scopes.iter().map(|&scope| scope.to_owned()).collect(),
                claims: Vec::new(),
            }),
            client_scopes: Vec::new(),
        }
    }

    #[test]
    fn a_client_that_requires_consent_asks_until_every_scope_it_asks_was_allowed() {
        let openid = ["openid".to_owned()];
        let both = ["openid".to_owned(), "email".to_owned()];

        assert!(is_consent_owed(&ask(true, None), false, &openid, &[]));
        assert!(
            is_consent_owed(&ask(true, None), false, &[], &[]),
            "nothing yet"
        );
        assert!(!is_consent_owed(
            &ask(true, Some(&["openid"])),
            false,
            &openid,
            &[]
        ));
        assert!(
            is_consent_owed(&ask(true, Some(&["openid"])), false, &both, &[]),
            "a scope not allowed before"
        );
        assert!(!is_consent_owed(
            &ask(true, Some(&["email", "openid"])),
            false,
            &openid,
            &[]
        ));
    }

    #[test]
    fn prompt_consent_asks_any_client_and_a_client_that_requires_none_asks_nothing_else() {
        let openid = ["openid".to_owned()];

        assert!(!is_consent_owed(&ask(false, None), false, &openid, &[]));
        assert!(is_consent_owed(&ask(false, None), true, &openid, &[]));
        assert!(
            is_consent_owed(&ask(true, Some(&["openid"])), true, &openid, &[]),
            "even what was allowed"
        );
    }

    #[test]
    fn a_claim_named_beyond_the_scopes_asks_until_it_was_allowed_by_name() {
        let openid = ["openid".to_owned()];
        let email = ["email".to_owned()];
        let mut terms = ask(true, Some(&["openid"]));

        assert!(is_consent_owed(&terms, false, &openid, &email));
        terms.allowed = Some(Allowance {
            scopes: openid.to_vec(),
            claims: email.to_vec(),
        });
        assert!(!is_consent_owed(&terms, false, &openid, &email));
        assert!(
            !is_consent_owed(&ask(false, None), false, &openid, &email),
            "a client that requires no consent asks nothing"
        );
    }
}
