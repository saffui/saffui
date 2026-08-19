//! Minting a token this realm will accept back.
//!
//! The mirror of the verifiers next door, and written against the same rules
//! rather than against a specification read twice. Every claim the accept path
//! requires is minted here unconditionally: a token that omits one is not a
//! lenient token, it is a token that some gate will wave through because it has
//! nothing to check.

use chrono::{DateTime, Duration, Utc};
use crypto::jose::jws::{
    ES256, ES384, ES512, EdDSA, JwsHeader, JwsSigner, PS256, PS384, PS512, RS256, RS384, RS512,
};
use crypto::jose::jwt::{self, JwtPayload};
use crypto::provider::{CryptoProvider, SignAlg};
use models::entities::keys::RealmSigningKey;
use serde_json::{Map, Value};

/// What a token is for.
///
/// Three kinds because three things are handed out and none of them may stand
/// in for another. An identity token is a record of a login and not a
/// credential; a refresh token buys a new access token and is not one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Access,
    Identity,
    Refresh,
}

impl Kind {
    /// What the protected header states this is.
    ///
    /// `at+jwt` is RFC 9068 §2.1. Naming the kind in the header rather than only
    /// in the payload is what lets a gate refuse a token before trusting a byte
    /// of the body: reading a payload claim to decide whether to accept the
    /// payload is a decision made from the thing being decided about.
    pub fn media_type(self) -> &'static str {
        match self {
            Kind::Access => "at+jwt",
            Kind::Identity | Kind::Refresh => "JWT",
        }
    }

    /// What the payload calls it, spelled the way Keycloak spells it so a client
    /// migrating from one reads the same word.
    pub fn claimed(self) -> &'static str {
        match self {
            Kind::Access => "Bearer",
            Kind::Identity => "ID",
            Kind::Refresh => "Refresh",
        }
    }
}

/// What a token is being minted from.
#[derive(Debug)]
pub struct Minting<'a> {
    pub kind: Kind,
    /// Names the realm. The accept path resolves a realm from it before any
    /// signature is checked, so it is a lookup key and not a decoration.
    pub issuer: &'a str,
    pub subject: &'a str,
    /// Who the token is for. Empty is refused: a token nobody is the audience
    /// of is one every audience check has to decide what to do about.
    pub audiences: Vec<String>,
    /// The client that obtained it, `azp`.
    pub party: &'a str,
    /// The login it was minted for, `sid`. What a logout closes.
    pub session_id: &'a str,
    /// Space separated, as the token carries it.
    pub scope: &'a str,
    pub lifespan: Duration,
    pub now: DateTime<Utc>,
    /// Everything the flow adds: `nonce`, `auth_time`, `acr`, `org_id`. Written
    /// under the named claims, so none of them can be quietly displaced.
    pub extra: Map<String, Value>,
}

/// A token, and the two things about it that have to be recorded.
#[derive(Debug, Clone)]
pub struct Minted {
    pub token: String,
    /// What a withdrawal is written against.
    pub token_id: String,
    pub expires_at: DateTime<Utc>,
}

/// Why nothing was minted.
///
/// Every one of these fails issuance rather than producing a token with a hole
/// in it. A minted token is accepted by this realm for as long as its window
/// lasts, so the moment to refuse is before there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unmintable {
    /// The key cannot sign, or does not hold what its algorithm needs.
    #[error("the realm's key cannot sign")]
    UnusableKey,
    /// No audience was named.
    #[error("a token was asked for with no audience")]
    NoAudience,
    /// The identifier could not be drawn.
    #[error("a token identifier could not be drawn")]
    NoIdentifier,
    #[error("the token could not be signed")]
    Unsignable,
}

/// Mint one.
///
/// The algorithm comes from the key and never from a registration. A header
/// naming one algorithm over a key published for another produces a token this
/// realm's own verifier refuses, because that side reads the algorithm off the
/// stored key too.
pub fn mint_token(
    provider: &dyn CryptoProvider,
    key: &RealmSigningKey,
    minting: Minting<'_>,
) -> Result<Minted, Unmintable> {
    if minting.audiences.is_empty() {
        return Err(Unmintable::NoAudience);
    }

    let token_id = draw_token_id(provider)?;
    let expires_at = minting.now + minting.lifespan;

    let mut header = JwsHeader::new();
    header.set_algorithm(jws_algorithm_name(key.algorithm));
    header.set_token_type(minting.kind.media_type());
    header.set_key_id(&key.kid);

    let mut payload = JwtPayload::new();
    payload.set_issuer(minting.issuer);
    payload.set_subject(minting.subject);
    payload.set_audience(minting.audiences.clone());
    payload.set_jwt_id(&token_id);

    // Written as whole seconds rather than through the setters, which render a
    // fraction. A reader that expects an integer gets nothing from a fraction
    // and falls back to whatever it decided absence means, which is how a cut
    // stops cutting.
    for (claim, seconds) in [
        ("iat", minting.now.timestamp()),
        ("nbf", minting.now.timestamp()),
        ("exp", expires_at.timestamp()),
    ] {
        payload
            .set_claim(claim, Some(Value::from(seconds)))
            .map_err(|_| Unmintable::Unsignable)?;
    }

    for (claim, value) in [
        ("typ", minting.kind.claimed()),
        ("azp", minting.party),
        ("sid", minting.session_id),
        ("scope", minting.scope),
    ] {
        payload
            .set_claim(claim, Some(Value::from(value)))
            .map_err(|_| Unmintable::Unsignable)?;
    }

    // Last, and only where the payload has nothing of that name. A mapper that
    // could overwrite `sub` or `exp` would be a way to mint any token at all
    // from a client registration.
    for (claim, value) in minting.extra {
        if payload.claim(&claim).is_none() {
            payload
                .set_claim(&claim, Some(value))
                .map_err(|_| Unmintable::Unsignable)?;
        }
    }

    let signer = signer_for(key).ok_or(Unmintable::UnusableKey)?;
    let token =
        jwt::encode_with_signer(&payload, &header, &*signer).map_err(|_| Unmintable::Unsignable)?;

    Ok(Minted {
        token,
        token_id,
        expires_at,
    })
}

/// A fresh token identifier.
///
/// Always minted, never optional. A token carrying none names nothing a
/// withdrawal could be written against, so it would outlive every revocation,
/// every logout and every reuse detection, and verification would keep
/// returning success the whole time.
fn draw_token_id(provider: &dyn CryptoProvider) -> Result<String, Unmintable> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Unmintable::NoIdentifier)?;
    Ok(bytes
        .iter()
        .fold(String::with_capacity(32), |mut id, byte| {
            use std::fmt::Write as _;
            let _ = write!(id, "{byte:02x}");
            id
        }))
}

/// How the JWS header spells the algorithm the key was published for.
fn jws_algorithm_name(algorithm: SignAlg) -> &'static str {
    match algorithm {
        SignAlg::Rs256 => "RS256",
        SignAlg::Rs384 => "RS384",
        SignAlg::Rs512 => "RS512",
        SignAlg::Ps256 => "PS256",
        SignAlg::Ps384 => "PS384",
        SignAlg::Ps512 => "PS512",
        SignAlg::Es256 => "ES256",
        SignAlg::Es384 => "ES384",
        SignAlg::Es512 => "ES512",
        SignAlg::EdDsa => "EdDSA",
    }
}

/// The signer the stored key names.
///
/// Exhaustive over the catalogue, like the verifier it mirrors: an algorithm
/// this build does not implement must fail to compile here rather than fail to
/// sign at runtime and read as a broken key.
fn signer_for(key: &RealmSigningKey) -> Option<Box<dyn JwsSigner>> {
    let pem = &key.private_pem;
    let signer = match key.algorithm {
        SignAlg::Rs256 => Box::new(RS256.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Rs384 => Box::new(RS384.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Rs512 => Box::new(RS512.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Ps256 => Box::new(PS256.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Ps384 => Box::new(PS384.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Ps512 => Box::new(PS512.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Es256 => Box::new(ES256.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Es384 => Box::new(ES384.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::Es512 => Box::new(ES512.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
        SignAlg::EdDsa => Box::new(EdDSA.signer_from_pem(pem).ok()?) as Box<dyn JwsSigner>,
    };
    Some(signer)
}
