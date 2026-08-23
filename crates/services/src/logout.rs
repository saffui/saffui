//! Ending a login the browser holds.
//!
//! Strict about who may end it and where it sends you after. RP-Initiated
//! Logout §2: the person is asked before their login ends unless a hint signed
//! by this realm names the very session the browser holds. And a user clicking
//! logout twice has still achieved their goal, so no cookie and an already-ended
//! login both succeed: reporting "no such session" would answer a question
//! about somebody else's login to whoever asks.

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
    /// The person said yes on the page that asked. Only a same-site form can
    /// say it: the cookie it ends is withheld from a cross-site post.
    pub confirmed: bool,
}

/// What the browser does next.
#[derive(Debug, PartialEq, Eq)]
pub enum EndedAt {
    /// Ended, and nowhere was asked for.
    Nowhere,
    /// Ended, and a registered landing place with the state echoed.
    Redirect(String),
    /// Ended, but the landing asked for is not one this realm vouches for,
    /// so the browser stays and is told.
    Refused,
    /// Not ended. Nothing signed by this realm named the login the browser
    /// holds, so the person is asked first.
    Confirm,
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

    let held = signed_in.filter(|named| !named.is_empty());
    if let Some(session_id) = held {
        // The hint vouches only when it names this very session: one for
        // another login is somebody else's record, however well signed.
        let vouched = claim(hint.as_ref(), "sid").is_some_and(|named| named == session_id);
        if !vouched && !requested.confirmed {
            return EndedAt::Confirm;
        }
        // Transitioned, not deleted. The row is the record of a login, and a
        // session that ended is not a session that never happened.
        let _ = sessions::set_state(transaction, session_id, UserSessionState::LoggedOut).await;
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
        return EndedAt::Refused;
    };
    let Ok(Some(client)) = clients::load(transaction, &client_id).await else {
        return EndedAt::Refused;
    };

    // Exact, and against the logout list rather than the login one. A logout
    // landing page is usually not a callback, and treating them as one set makes
    // every logout destination a valid place to deliver a code.
    if !client
        .post_logout_redirect_uris
        .as_ref()
        .is_some_and(|registered| registered.iter().any(|uri| uri == asked))
    {
        return EndedAt::Refused;
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

/// One client to be told a login ended, and the token that tells it.
/// OpenID Connect Back-Channel Logout 1.0 §2.4.
#[derive(Debug, Clone)]
pub struct Notice {
    pub client_id: String,
    pub uri: String,
    pub logout_token: String,
}

/// One client to be loaded in the browser, Front-Channel Logout 1.0 §2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub client_id: String,
    pub uri: String,
}

/// The frames for every client that took part and registered where to be
/// loaded. `iss` and `sid` are added when the client asked to be told which
/// session (§2.1); nothing else goes in the query.
pub async fn frames_for(
    transaction: &Transaction<'_>,
    issuer: &str,
    session_id: &str,
) -> Vec<Frame> {
    let Ok(party_ids) = sessions::clients_of(transaction, session_id).await else {
        return Vec::new();
    };
    let mut frames = Vec::new();
    for client_id in party_ids {
        let Ok(Some(client)) = clients::load(transaction, &client_id).await else {
            tracing::warn!(%client_id, "a client of the login could not be read");
            continue;
        };
        let Some(uri) = client
            .frontchannel_logout_uri
            .clone()
            .filter(|uri| !uri.is_empty())
        else {
            continue;
        };
        let uri = if client.frontchannel_logout_session_required {
            let separator = if uri.contains('?') { '&' } else { '?' };
            format!(
                "{uri}{separator}iss={}&sid={}",
                escaped(issuer),
                escaped(session_id)
            )
        } else {
            uri
        };
        frames.push(Frame { client_id, uri });
    }
    frames
}

/// How long a logout token stays acceptable. Short: it is delivered now, and
/// a client is told to refuse one it has seen (§2.6).
const NOTICE_LIFESPAN: i64 = 120;

/// The notices for every client that took part in this login and registered
/// where to be told. Minted here, delivered by whoever can reach out.
pub async fn notices_for(
    transaction: &Transaction<'_>,
    signing: &crate::grant::Signing<'_>,
    issuer: &str,
    session_id: &str,
    now: DateTime<Utc>,
) -> Vec<Notice> {
    let Ok(Some(session)) = sessions::load(transaction, session_id).await else {
        tracing::warn!(session = %session_id, "no login to tell anybody about");
        return Vec::new();
    };
    let Ok(party_ids) = sessions::clients_of(transaction, session_id).await else {
        tracing::warn!(session = %session_id, "the clients of a login could not be read");
        return Vec::new();
    };
    tracing::debug!(session = %session_id, clients = party_ids.len(), "clients of the login");
    let mut notices = Vec::new();
    for client_id in party_ids {
        let Ok(Some(client)) = clients::load(transaction, &client_id).await else {
            // A client that took part and cannot be read now: on the record,
            // since it is one nobody will tell.
            tracing::warn!(%client_id, "a client of the login could not be read");
            continue;
        };
        let Some(uri) = client
            .backchannel_logout_uri
            .clone()
            .filter(|uri| !uri.is_empty())
        else {
            continue;
        };
        // Signed as the client reads identity tokens, since that is the key it
        // verifies logout tokens with (§2.4).
        let Ok(key) = crate::grant::identity_key_for(transaction, signing, &client).await else {
            // Registered to be told and cannot be: on the record, since the
            // client will go on believing the login is live.
            tracing::warn!(%client_id, "no key to sign a logout token with");
            continue;
        };
        let mut extra = serde_json::Map::new();
        extra.insert(
            "events".into(),
            serde_json::json!({ "http://schemas.openid.net/event/backchannel-logout": {} }),
        );
        let minted = token::issuance::mint_token(
            signing.provider,
            &key,
            token::issuance::Minting {
                kind: token::issuance::Kind::Logout,
                issuer,
                subject: &session.user_id,
                audiences: vec![client_id.clone()],
                party: &client_id,
                session_id,
                scope: "",
                lifespan: chrono::Duration::seconds(NOTICE_LIFESPAN),
                now,
                extra,
            },
        );
        match minted {
            Ok(minted) => notices.push(Notice {
                client_id,
                uri,
                logout_token: minted.token,
            }),
            Err(why) => tracing::warn!(%client_id, why = ?why, "no logout token to tell with"),
        }
    }
    notices
}
