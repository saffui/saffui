//! What an access token's scope allows a client to learn about its holder.
//!
//! The scope gate is the whole point: a token granted only `openid` must not
//! yield an address. What is released is decided here rather than by whoever
//! renders it, so a second renderer cannot release more.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::attributes;
use models::entities::keys::RealmSigningKeyView;
use models::entities::user::{UserModel, address, profile};
use serde_json::{Map, Value, json};
use store::providers::{client_scopes, clients, sessions, users};

use crate::claims_request::{self, ClaimsRequest};
use crate::token;
use crate::token::issuance::Kind;

/// Why nothing was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Untold {
    /// Not a token this realm accepts, or not one that speaks for a person.
    /// RFC 6750 §3.1 spells this `invalid_token`, and it is one answer for
    /// every way of being wrong so nothing here reports which.
    #[error("the token presented is not one this realm accepts")]
    InvalidToken,
    #[error("the store could not be read")]
    Unreadable,
}

/// The claims this token allows.
///
/// Two ways a claim gets in, and they add up: the scopes the token carries
/// name sets of claims (§5.4), and the `claims` the request named one by one
/// (§5.5) are read off the client session the login opened for this client.
pub async fn claims_for(
    transaction: &Transaction<'_>,
    keys: &[RealmSigningKeyView],
    bearer: &str,
    now: DateTime<Utc>,
) -> Result<Map<String, Value>, Untold> {
    let verified = token::verify_presented(transaction, keys, bearer, now)
        .await
        .map_err(|_| Untold::InvalidToken)?;

    // An id token is a record of a login, not a credential, and it names the
    // client as its audience. Accepting one here would let anything that saw a
    // login read the person behind it.
    if verified.claims.get("typ").and_then(Value::as_str) != Some(Kind::Access.claimed()) {
        return Err(Untold::InvalidToken);
    }

    // §8: the identifier in the token is what this client is told, and it is
    // the account's own only where the client asked for nothing else.
    let party = match verified.claims.get("azp").and_then(Value::as_str) {
        Some(client_id) => clients::load(transaction, client_id)
            .await
            .map_err(|_| Untold::Unreadable)?,
        None => None,
    };
    let account = crate::pairwise::account_for(transaction, party.as_ref(), &verified.subject)
        .await
        .map_err(|_| Untold::InvalidToken)?;
    let subject = users::load(transaction, &account)
        .await
        .map_err(|_| Untold::Unreadable)?
        .filter(|user| user.enabled)
        .ok_or(Untold::InvalidToken)?;
    let held = held_claims(&subject);

    // OIDC Core §5.3.2. A response whose `sub` differs from the token's is one a
    // client must reject, so it is the token's or there is no response.
    let mut claims = claims_of_scope(&verified.scope, &held);
    claims.insert("sub".into(), json!(verified.subject));

    let asked = match (
        verified.claims.get("sid").and_then(Value::as_str),
        verified.claims.get("azp").and_then(Value::as_str),
    ) {
        (Some(sid), Some(client_id)) => sessions::requested_claims_of(transaction, sid, client_id)
            .await
            .map_err(|_| Untold::Unreadable)?,
        _ => None,
    };
    if let Some(asked) = asked {
        let entitled = entitled_scopes(
            transaction,
            verified
                .claims
                .get("azp")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .await
        .map_err(|_| Untold::Unreadable)?;
        claims.extend(within_entitlement(
            claims_request::release(&ClaimsRequest::from_value(&asked).userinfo, &held),
            &entitled,
        ));
    }

    Ok(claims)
}

/// Of what the realm holds of a person, what these scopes name: §5.4.
pub fn claims_of_scope(scope: &str, held: &Map<String, Value>) -> Map<String, Value> {
    let mut claims = Map::new();
    for (named, behind) in SCOPE_CLAIMS {
        if !granted(scope, named) {
            continue;
        }
        for claim in behind {
            if let Some(value) = held.get(*claim) {
                claims.insert((*claim).to_owned(), value.clone());
            }
        }
    }
    claims
}

/// What the request named for the identity token, §5.5, of what the realm
/// holds of this person and of what the client is entitled to be told.
pub async fn asked_id_token_claims(
    transaction: &Transaction<'_>,
    asked: Option<&Value>,
    client_id: &str,
    user_id: &str,
) -> Result<Map<String, Value>, ()> {
    let Some(asked) = asked.map(ClaimsRequest::from_value) else {
        return Ok(Map::new());
    };
    if asked.id_token.is_empty() {
        return Ok(Map::new());
    }
    let Some(person) = users::load(transaction, user_id).await.map_err(|_| ())? else {
        return Ok(Map::new());
    };
    let entitled = entitled_scopes(transaction, client_id).await?;
    Ok(within_entitlement(
        claims_request::release(&asked.id_token, &held_claims(&person)),
        &entitled,
    ))
}

/// The standard scopes this client may have at all, attached as default or
/// as optional. What a client may be told by name is bounded by the same
/// registration that bounds what it may be told by scope: §5.5.1 makes a
/// scope shorthand for a set of claims, and naming one of the set is not a
/// way around the registration that never granted the set.
pub async fn entitled_scopes(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> Result<Vec<String>, ()> {
    let attached = client_scopes::scopes_of_client(transaction, client_id)
        .await
        .map_err(|_| ())?;
    Ok(attached.into_iter().map(|(scope, _)| scope.name).collect())
}

/// Of claims released by name, those whose scope the client may have. A
/// claim no standard scope names is nobody's to give this way.
pub fn within_entitlement(released: Map<String, Value>, entitled: &[String]) -> Map<String, Value> {
    released
        .into_iter()
        .filter(|(claim, _)| {
            claim == "sub"
                || SCOPE_CLAIMS.iter().any(|(scope, named)| {
                    named.contains(&claim.as_str()) && entitled.iter().any(|held| held == scope)
                })
        })
        .collect()
}

/// What OIDC Core §5.4 puts behind each scope, by name.
const SCOPE_CLAIMS: [(&str, &[&str]); 4] = [
    (
        "profile",
        &[
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
    ),
    ("email", &["email", "email_verified"]),
    ("phone", &["phone_number", "phone_number_verified"]),
    ("address", &["address"]),
];

/// Every standard claim this realm holds of a person, regardless of who may
/// have it. Resolved once, and selected from by scope and by name.
///
/// Only what is there. A claim released empty is one a relying party reads as
/// a value, and `name` composed from nothing would be a blank the client shows.
pub fn held_claims(subject: &UserModel) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(subject.user_id));
    claims.insert("preferred_username".into(), json!(subject.user_name));

    let attributes = subject.attributes.as_ref();
    let held = |named: &str| {
        attributes
            .and_then(|held| attributes::string_at(held, named))
            .filter(|value| !value.is_empty())
    };
    for (claim, attribute) in [
        ("given_name", profile::FIRST_NAME),
        ("family_name", profile::LAST_NAME),
        ("middle_name", profile::MIDDLE_NAME),
        ("nickname", profile::NICK_NAME),
        ("profile", profile::PROFILE_PAGE),
        ("picture", profile::PICTURE),
        ("website", profile::WEBSITE),
        ("gender", profile::GENDER),
        ("birthdate", profile::BIRTH_DATE),
        ("zoneinfo", profile::ZONEINFO),
        ("locale", profile::LOCALE),
    ] {
        if let Some(value) = held(attribute) {
            claims.insert(claim.into(), json!(value));
        }
    }
    // §5.4 lists `name` as the full name in displayable form. Composed from the
    // two halves, because the realm stores those and not the whole, and left out
    // when neither is there rather than released as a space.
    let full: Vec<&str> = [profile::FIRST_NAME, profile::LAST_NAME]
        .into_iter()
        .filter_map(held)
        .collect();
    if !full.is_empty() {
        claims.insert("name".into(), json!(full.join(" ")));
    }
    // §5.1: when the profile was last changed, as seconds. The record's own
    // stamp, because nothing else knows; a record never changed since it was
    // made was last changed when it was made.
    if let Some(updated) = subject.metadata.updated_at.or(subject.metadata.created_at) {
        claims.insert("updated_at".into(), json!(updated.timestamp()));
    }

    // An address the realm holds but never checked is still an address, so it
    // is released with the flag that says which it is rather than withheld.
    if !subject.email.is_empty() {
        claims.insert("email".into(), json!(subject.email));
        claims.insert(
            "email_verified".into(),
            json!(subject.email_verified.unwrap_or(false)),
        );
    }
    if let Some(number) = subject
        .phone_number
        .as_deref()
        .filter(|held| !held.is_empty())
    {
        claims.insert("phone_number".into(), json!(number));
        claims.insert(
            "phone_number_verified".into(),
            json!(subject.phone_number_verified.unwrap_or(false)),
        );
    }
    // §5.1.1: one object, of whichever components the realm holds. A realm
    // that holds a country and nothing finer releases a country, which the
    // spec allows by name; an address with no component at all is no address.
    let postal: Map<String, Value> = address::COMPONENTS
        .into_iter()
        .filter_map(|(member, attribute)| {
            held(attribute).map(|value| (member.to_owned(), json!(value)))
        })
        .collect();
    if !postal.is_empty() {
        claims.insert("address".into(), Value::Object(postal));
    }
    claims
}

/// Whole scopes, never prefixes. `profile_extended` is not `profile`, and a
/// substring test would read it as one.
fn granted(scope: &str, named: &str) -> bool {
    scope.split_whitespace().any(|held| held == named)
}

#[cfg(test)]
mod tests {
    use super::granted;

    #[test]
    fn a_scope_is_matched_whole() {
        assert!(granted("openid profile email", "profile"));
        assert!(granted("profile", "profile"));
        assert!(!granted("openid email", "profile"));
        assert!(!granted("", "profile"));
        assert!(
            !granted("profile_extended", "profile"),
            "a longer name that starts the same is not the same scope"
        );
    }
}
