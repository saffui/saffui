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
use store::providers::{oidc, realms, sessions};

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
    /// It names a key, and the caller did not prove holding that key. A token
    /// stolen off the wire is refused here and nowhere else.
    #[error("the token is bound to a key this caller did not prove")]
    Unbound,
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
/// What the caller can say about the key a token is bound to.
///
/// Named at every call rather than passed as an option, because the two cases
/// are decisions and not the presence of a value: one enforces the binding,
/// the other reports it. An option would let a caller mean the second by
/// forgetting the first.
#[derive(Debug, Clone, Copy)]
pub enum Binding<'a> {
    /// This caller is the one presenting the token, and proved what `Proofs`
    /// says. A bound token presented without what it names is refused.
    Presented(Proofs<'a>),
    /// This caller is asking about a token somebody else holds. Introspection
    /// reports the binding for the resource server to check; enforcing it here
    /// would call a live token dead.
    Reported,
}

/// What a caller proved about the keys a token may be bound to.
///
/// Both are read, and each answers for its own confirmation method: a token
/// naming two is a token that has to satisfy two. Neither is a fallback for
/// the other.
#[derive(Debug, Clone, Copy, Default)]
pub struct Proofs<'a> {
    /// A proof over a key the caller signed with, RFC 9449.
    pub key: Option<&'a crate::dpop::Proven>,
    /// The certificate a trusted proxy said this caller presented, RFC 8705,
    /// as its thumbprint.
    pub certificate: Option<&'a str>,
}

impl<'a> Proofs<'a> {
    /// Neither proved, which is every caller that sends no proof and reaches
    /// this server without a client certificate.
    pub fn none() -> Self {
        Proofs::default()
    }
}

pub async fn verify_presented(
    transaction: &Transaction<'_>,
    keys: &[RealmSigningKeyView],
    token: &str,
    binding: Binding<'_>,
    now: DateTime<Utc>,
) -> Result<Verified, Refused> {
    let verified = verify_signature_and_window(keys, token, now)?;

    // RFC 9449 §7.1: a token that names a key is worth nothing without it. The
    // check sits here, beside the signature and the window, because a binding
    // verified somewhere else is a binding somebody forgets to verify.
    if let Binding::Presented(proofs) = binding {
        let confirmation = verified.claims.get("cnf");
        let named = |method: &str| {
            confirmation
                .and_then(|held| held.get(method))
                .and_then(Value::as_str)
        };
        // Each method answers for itself, and a token naming two satisfies
        // two: taking one as enough would let a caller holding half of what a
        // token names present it as though it held all of it.
        for (bound_to, held) in [
            (
                named("jkt"),
                proofs.key.map(|proven| proven.thumbprint.as_str()),
            ),
            (named("x5t#S256"), proofs.certificate),
        ] {
            if let Some(bound_to) = bound_to
                && held != Some(bound_to)
            {
                return Err(Refused::Unbound);
            }
        }
    }

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
    // The realm's own cut, which is a withdrawal written once against every
    // token at once. It answers with the same refusal as a single one, and
    // deliberately: whether a token died alone or with everybody else's is not
    // something the holder of a dead token gets to learn.
    //
    // Judged against what the token says of itself and never against the clock,
    // so a token minted before the cut stays refused however long it is
    // presented after. A realm that cannot be read refuses rather than admits:
    // the alternative is a database hiccup quietly lifting a cut somebody set
    // because they were under attack.
    let realm = realms::of_context(transaction)
        .await
        .map_err(|_| Refused::Unestablished)?
        .ok_or(Refused::Unestablished)?;
    if let Some(cut) = realm.not_before {
        let minted_at = verified
            .claims
            .get("iat")
            .and_then(|held| {
                held.as_i64()
                    .or_else(|| held.as_f64().map(|seconds| seconds.trunc() as i64))
            })
            .ok_or(Refused::Revoked)?;
        if minted_at < i64::from(cut) {
            return Err(Refused::Revoked);
        }
    }

    // Bound to a login, and refused with it: a logout that left the tokens it
    // minted working would be a logout in name.
    //
    // Except the one grant that exists to outlive a login. OIDC Core §11 asks
    // for an access token that reaches the UserInfo endpoint with the user
    // away, so a token carrying `offline_access` needs its login to be there
    // and not to be open.
    if let Some(session_id) = verified.claims.get("sid").and_then(Value::as_str) {
        let offline = verified
            .scope
            .split_whitespace()
            .any(|held| held == crate::authorize::OFFLINE_ACCESS);
        let live = sessions::load(transaction, session_id)
            .await
            .map_err(|_| Refused::Unestablished)?
            .is_some_and(|session| offline || session.state == UserSessionState::LoggedIn);
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
pub(crate) fn verifier_for(
    algorithm: SignAlg,
    jwk: &Jwk,
) -> Option<Box<dyn crypto::jose::jws::JwsVerifier>> {
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
