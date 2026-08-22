//! Establishing that a bearer is one this realm accepts, right now.
//!
//! Three questions, and they are separate because two of them have exceptions
//! and one does not. A signature says the realm minted the token and can never
//! be taken back. A window says when it stops on its own and is checked against
//! an instant the caller states, so a decision and its later replay read the
//! same clock. A revocation says somebody withdrew it early, which is the only
//! one of the three an administrator can act on.
//!
//! Keeping them apart matters because one caller legitimately wants a token
//! whose window has passed: an identity token presented as a hint is a record
//! of a login that already happened, and refusing it for being over would
//! refuse every logout that arrives late. Nothing else may reach for that door,
//! which is why it is named rather than being a flag on one function.

pub mod issuance;

use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use crypto::jose::jwk::Jwk;
use crypto::jose::jws::{ES256, ES384, ES512, EdDSA, PS256, PS384, PS512, RS256, RS384, RS512};
use crypto::jose::jwt::{self, JwtPayload};
use crypto::provider::SignAlg;
use deadpool_postgres::Transaction;
use models::entities::keys::RealmSigningKeyView;
use models::sessions::records::UserSessionState;
use serde_json::Value;
use store::providers::{oidc, sessions};

/// What a token established, once it was accepted.
///
/// Every claim is kept and not only the ones the admin plane happens to read.
/// A policy names the claim it compares, so a verifier that forwarded three
/// fields would decide which rules can ever be written, and would do it from a
/// layer that has no idea what anybody wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub subject: String,
    pub audiences: Vec<String>,
    /// Space separated, as the token carries it.
    pub scope: String,
    /// What a revocation names, where the token carries one.
    pub token_id: Option<String>,
    /// Every claim the payload carried, the named ones included.
    pub claims: serde_json::Map<String, serde_json::Value>,
}

/// Why a token was not accepted.
///
/// Distinct on the way out because the log needs them distinct. What a caller
/// is told is not decided here: this says what happened, and the layer that
/// answers decides how much of it to repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// Not a token, or one whose header names no key.
    #[error("the token could not be read")]
    Unreadable,
    /// It names a key this realm has not published.
    #[error("the token names a key the realm has not published")]
    UnknownKey,
    #[error("the signature does not check out")]
    BadSignature,
    /// It states no expiry, so nothing would ever stop it.
    #[error("the token states no expiry")]
    NoExpiry,
    #[error("the token is expired or not yet valid")]
    OutsideWindow,
    /// Withdrawn before its expiry.
    #[error("the token has been withdrawn")]
    Revoked,
    /// The login it was minted for is over. A token outlives nothing.
    #[error("the login the token belongs to has ended")]
    Ended,
    /// The store could not be asked whether it was withdrawn. Refused, because
    /// not having found a withdrawal is not the same as there not being one.
    #[error("whether the token was withdrawn could not be established")]
    Unestablished,
}

/// Verify the signature, and nothing about the clock.
///
/// Split out for the one caller that must accept a token whose window has
/// passed. Nothing else should reach for it: a token that is merely well signed
/// is not a token that is currently good, and treating one as the other is how
/// an expired credential becomes a live one.
pub fn verify_signature(keys: &[RealmSigningKeyView], token: &str) -> Result<JwtPayload, Refused> {
    let header = jwt::decode_header(token).map_err(|_| Refused::Unreadable)?;
    let kid = header
        .claim("kid")
        .and_then(|kid| kid.as_str())
        .ok_or(Refused::Unreadable)?;

    // The header names one key and only that one is tried. Trying each
    // published key in turn would let a token be verified by whichever happens
    // to accept it, which is how a retired key keeps signing.
    let key = keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or(Refused::UnknownKey)?;

    let jwk = key
        .public_jwk
        .as_object()
        .cloned()
        .and_then(|map| Jwk::from_map(map).ok())
        .ok_or(Refused::UnknownKey)?;

    // The algorithm comes from the key, never from the token's header, which is
    // what stops a token choosing a weaker one than the key was published for.
    let verifier = verifier_for(key.algorithm, &jwk).ok_or(Refused::UnknownKey)?;

    Ok(jwt::decode_with_verifier(token, &*verifier)
        .map_err(|_| Refused::BadSignature)?
        .0)
}

/// Verify the signature, and that the token is inside the window it states.
///
/// The instant is an argument. Reading a clock in here would make the answer
/// depend on when the question was asked rather than on what was asked, so a
/// decision and the replay of that decision would disagree for a reason nothing
/// records.
pub fn verify_signature_and_window(
    keys: &[RealmSigningKeyView],
    token: &str,
    now: DateTime<Utc>,
) -> Result<Verified, Refused> {
    let payload = verify_signature(keys, token)?;

    // Refused here rather than left to the validator, which reads a time claim
    // only when the token carries one: a token stating no expiry would
    // otherwise satisfy every bound it never stated.
    payload.expires_at().ok_or(Refused::NoExpiry)?;

    let mut window = jwt::JwtPayloadValidator::new();
    window.set_base_time(instant(now));
    window
        .validate(&payload)
        .map_err(|_| Refused::OutsideWindow)?;

    Ok(established(payload))
}

/// The whole gate: signature, window, and whether it was withdrawn.
///
/// What every caller presenting a bearer should ask for.
pub async fn verify_presented(
    transaction: &Transaction<'_>,
    keys: &[RealmSigningKeyView],
    token: &str,
    now: DateTime<Utc>,
) -> Result<Verified, Refused> {
    let verified = verify_signature_and_window(keys, token, now)?;

    // A token carrying no identifier names nothing a withdrawal could have been
    // written against, and is left to its window.
    if let Some(token_id) = verified.token_id.as_deref() {
        let withdrawn = oidc::is_revoked(transaction, token_id)
            .await
            .map_err(|_| Refused::Unestablished)?;
        if withdrawn {
            return Err(Refused::Revoked);
        }
    }
    // Bound to a login, and refused with it: a logout that left the tokens it
    // minted working would be a logout in name.
    if let Some(session_id) = verified.claims.get("sid").and_then(Value::as_str) {
        let live = sessions::load(transaction, session_id)
            .await
            .map_err(|_| Refused::Unestablished)?
            .is_some_and(|session| session.state == UserSessionState::LoggedIn);
        if !live {
            return Err(Refused::Ended);
        }
    }

    Ok(verified)
}

fn established(payload: JwtPayload) -> Verified {
    Verified {
        subject: payload.subject().unwrap_or_default().to_owned(),
        audiences: payload
            .audience()
            .map(|audiences| audiences.iter().map(|a| (*a).to_owned()).collect())
            .unwrap_or_default(),
        scope: payload
            .claim("scope")
            .and_then(|scope| scope.as_str())
            .unwrap_or_default()
            .to_owned(),
        token_id: payload.jwt_id().map(str::to_owned),
        claims: payload.claims_set().clone(),
    }
}

/// An instant the validator can read. Before the epoch it is the epoch, which
/// refuses every window rather than wrapping into a far future one.
fn instant(now: DateTime<Utc>) -> SystemTime {
    let seconds = now.timestamp().max(0) as u64;
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

/// The verifier the published algorithm names.
///
/// Exhaustive over the catalogue rather than a lookup with a fallback: an
/// algorithm this build does not implement must fail to compile here, not fail
/// to verify at runtime and read as a bad token.
fn verifier_for(algorithm: SignAlg, jwk: &Jwk) -> Option<Box<dyn crypto::jose::jws::JwsVerifier>> {
    let verifier =
        match algorithm {
            SignAlg::Rs256 => Box::new(RS256.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Rs384 => Box::new(RS384.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Rs512 => Box::new(RS512.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Ps256 => Box::new(PS256.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Ps384 => Box::new(PS384.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Ps512 => Box::new(PS512.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Es256 => Box::new(ES256.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Es384 => Box::new(ES384.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::Es512 => Box::new(ES512.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
            SignAlg::EdDsa => Box::new(EdDSA.verifier_from_jwk(jwk).ok()?)
                as Box<dyn crypto::jose::jws::JwsVerifier>,
        };
    Some(verifier)
}
