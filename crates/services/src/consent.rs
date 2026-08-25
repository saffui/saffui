use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use store::providers::consents;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the store could not be read")]
pub struct Unreadable;

/// Whether this person has to be asked before this client is served.
///
/// Asked when the client says so, when the request says so, or when what is
/// asked for now is wider than what was agreed to. Narrower is not: a client
/// that had `openid profile` and now asks for `openid` has asked for nothing
/// new, and asking again would train people to click through.
pub async fn must_ask(
    transaction: &Transaction<'_>,
    client: &ClientModel,
    user_id: &str,
    scope: &str,
    asked_again: bool,
) -> Result<bool, Unreadable> {
    if asked_again {
        return Ok(true);
    }
    if client.consent_required != Some(true) {
        return Ok(false);
    }
    let held = consents::held(transaction, user_id, &client.client_id)
        .await
        .map_err(|_| Unreadable)?;
    let Some(held) = held else {
        return Ok(true);
    };
    Ok(!covered(&held.scopes, scope))
}

/// Whether everything now asked for was already agreed to.
fn covered(agreed: &[String], asked: &str) -> bool {
    asked
        .split_whitespace()
        .all(|wanted| agreed.iter().any(|held| held == wanted))
}

/// Record what was agreed to.
pub async fn keep(
    transaction: &Transaction<'_>,
    user_id: &str,
    client_id: &str,
    scope: &str,
    now: DateTime<Utc>,
) -> Result<(), Unreadable> {
    let scopes: Vec<String> = scope.split_whitespace().map(str::to_owned).collect();
    consents::keep(transaction, user_id, client_id, &scopes, now)
        .await
        .map_err(|_| Unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agreed(named: &str) -> Vec<String> {
        named.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn what_was_agreed_to_covers_the_same_and_less() {
        let held = agreed("openid profile email");
        assert!(covered(&held, "openid"));
        assert!(covered(&held, "openid profile"));
        assert!(covered(&held, "email openid profile"));
        assert!(covered(&held, ""));
    }

    #[test]
    fn anything_new_is_not_covered() {
        let held = agreed("openid profile");
        assert!(!covered(&held, "openid profile email"));
        assert!(!covered(&held, "offline_access"));
        // Whole values, never prefixes: `profile_extended` is not `profile`.
        assert!(!covered(&held, "profile_extended"));
    }

    #[test]
    fn agreeing_to_nothing_covers_nothing_but_nothing() {
        assert!(covered(&[], ""));
        assert!(!covered(&[], "openid"));
    }
}
