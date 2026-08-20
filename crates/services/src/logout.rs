//! Ending a login the browser holds.
//!
//! Permissive about what it ends and strict about where it sends you after. A
//! user clicking logout twice has still achieved their goal, so no cookie, an
//! unknown session and an already-ended one all succeed: reporting "no such
//! session" would answer a question about somebody else's login to whoever asks.

use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::keys::RealmSigningKeyView;
use models::sessions::records::UserSessionState;
use serde_json::Value;
use store::providers::{clients, sessions};

use crate::token;

/// What the request carried.
#[derive(Debug, Default)]
pub struct Requested<'a> {
    pub id_token_hint: Option<&'a str>,
    pub post_logout_redirect_uri: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub state: Option<&'a str>,
}

/// What the browser does next.
#[derive(Debug, PartialEq, Eq)]
pub enum EndedAt {
    /// Nowhere to send it that this realm will vouch for.
    Nowhere,
    /// A registered landing place, with the state the client asked to have
    /// echoed.
    Redirect(String),
}

/// End the login, and say where the browser goes.
///
/// The store failing is not reported either. A logout that could not be written
/// has not ended the session, but telling the caller so tells them a session
/// existed, and the cookie is cleared regardless so the browser stops offering
/// it.
pub async fn end_session(
    transaction: &Transaction<'_>,
    keys: &[RealmSigningKeyView],
    requested: &Requested<'_>,
    signed_in: Option<&str>,
    now: DateTime<Utc>,
) -> EndedAt {
    // The hint is read for what it says, not for whether it is still current. An
    // identity token presented at logout is a record of a login that already
    // happened, and refusing an expired one would refuse every logout that
    // arrives late.
    let hint = requested
        .id_token_hint
        .and_then(|token| token::verify_signature(keys, token).ok());

    let ending = signed_in
        .filter(|named| !named.is_empty())
        .map(str::to_owned)
        .or_else(|| claim(hint.as_ref(), "sid"));

    if let Some(session_id) = ending {
        // Transitioned, not deleted. The row is the record of a login, and a
        // session that ended is not a session that never happened.
        let _ = sessions::set_state(transaction, &session_id, UserSessionState::LoggedOut).await;
    }

    match requested.post_logout_redirect_uri {
        None => EndedAt::Nowhere,
        Some(asked) => landing(transaction, requested, hint.as_ref(), asked, now).await,
    }
}

/// Where the browser lands, when this realm will vouch for it.
///
/// The client is taken from the hint first, because that one is signed. A bare
/// `client_id` is a claim anybody can write, and it is accepted only because the
/// URI still has to match what that client registered: the worst a wrong name
/// buys is a redirect to somewhere its owner already wrote down.
async fn landing(
    transaction: &Transaction<'_>,
    requested: &Requested<'_>,
    hint: Option<&crypto::jose::jwt::JwtPayload>,
    asked: &str,
    _now: DateTime<Utc>,
) -> EndedAt {
    let Some(client_id) = claim(hint, "azp").or_else(|| requested.client_id.map(str::to_owned))
    else {
        return EndedAt::Nowhere;
    };
    let Ok(Some(client)) = clients::load(transaction, &client_id).await else {
        return EndedAt::Nowhere;
    };

    // Exact, and against the logout list rather than the login one. A logout
    // landing page is usually not a callback, and treating them as one set makes
    // every logout destination a valid place to deliver a code.
    if !client
        .post_logout_redirect_uris
        .as_ref()
        .is_some_and(|registered| registered.iter().any(|uri| uri == asked))
    {
        return EndedAt::Nowhere;
    }

    let mut landing = asked.to_owned();
    if let Some(state) = requested.state {
        let separator = if landing.contains('?') { '&' } else { '?' };
        landing.push_str(&format!("{separator}state={}", escaped(state)));
    }
    EndedAt::Redirect(landing)
}

fn claim(payload: Option<&crypto::jose::jwt::JwtPayload>, named: &str) -> Option<String> {
    payload?
        .claim(named)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// RFC 3986 §2.3's unreserved set kept, everything else escaped.
fn escaped(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}
