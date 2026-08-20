//! What an access token's scope allows a client to learn about its holder.
//!
//! The scope gate is the whole point: a token granted only `openid` must not
//! yield an address. What is released is decided here rather than by whoever
//! renders it, so a second renderer cannot release more.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::keys::RealmSigningKeyView;
use serde_json::{Map, Value, json};
use store::providers::users;

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

    let subject = users::load(transaction, &verified.subject)
        .await
        .map_err(|_| Untold::Unreadable)?
        .filter(|user| user.enabled)
        .ok_or(Untold::InvalidToken)?;

    // OIDC Core §5.3.2. A response whose `sub` differs from the token's is one a
    // client must reject, so it is the token's or there is no response.
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(verified.subject));

    if granted(&verified.scope, "profile") {
        claims.insert("preferred_username".into(), json!(subject.user_name));
    }
    // An address the realm holds but never checked is still an address, so it is
    // released with the flag that says which it is rather than being withheld.
    if granted(&verified.scope, "email") && !subject.email.is_empty() {
        claims.insert("email".into(), json!(subject.email));
        claims.insert(
            "email_verified".into(),
            json!(subject.email_verified.unwrap_or(false)),
        );
    }
    if let Some(number) = subject
        .phone_number
        .filter(|held| !held.is_empty())
        .filter(|_| granted(&verified.scope, "phone"))
    {
        claims.insert("phone_number".into(), json!(number));
        claims.insert(
            "phone_number_verified".into(),
            json!(subject.phone_number_verified.unwrap_or(false)),
        );
    }

    Ok(claims)
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
