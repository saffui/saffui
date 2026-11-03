use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::jws::sign_compact;
use super::store::RefreshToken;
use super::{
    ACCESS_TOKEN_LIFETIME_SECONDS, ACCESS_TOKEN_TYPE, IDENTITY_TOKEN_TYPE, IssuedAccessToken,
};
use crate::app::App;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::keys::jwks::open_signing_key;
use crate::login::session::Session;
use crate::ports::crypto::SignatureAlgorithm;
use crate::ports::storage::UnitOfWork;

/// How long an identity token is good for: long enough to be read once.
const IDENTITY_TOKEN_LIFETIME_SECONDS: u64 = 300;

pub struct AccessTokenSubject<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    /// The session behind the token, when a person is.
    pub session: Option<Uuid>,
}

pub struct IdentityTokenSubject<'a> {
    pub issuer: &'a str,
    pub person: &'a Person,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub nonce: Option<&'a str>,
    pub session: Uuid,
    pub authenticated_at: OffsetDateTime,
}

async fn sign_claims(
    app: &App,
    work: &mut dyn UnitOfWork,
    token_type: &str,
    claims: &Value,
) -> Result<String, Failure> {
    let (key, private_key) = open_signing_key(app, work, SignatureAlgorithm::Es256).await?;
    sign_compact(app.signer.as_ref(), &key, &private_key, token_type, claims)
        .map_err(|_| Failure::with_detail(ErrorCode::CryptoUnavailable, "a token cannot be signed"))
}

/// Mints an access token signed by the key of the realm.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the realm cannot sign, or
/// the storage failure.
pub async fn mint_access_token(
    app: &App,
    work: &mut dyn UnitOfWork,
    subject: AccessTokenSubject<'_>,
) -> Result<IssuedAccessToken, Failure> {
    let issued_at = app.now().unix_timestamp();
    let scope = subject.scopes.join(" ");
    let mut claims = json!({
        "iss": subject.issuer,
        "sub": subject.subject,
        // Until a resource is named, a token is for the realm that issued it.
        "aud": subject.issuer,
        "client_id": subject.client_id,
        "scope": scope,
        "iat": issued_at,
        "exp": issued_at.saturating_add_unsigned(ACCESS_TOKEN_LIFETIME_SECONDS),
        "jti": mint_id(app)?.to_string(),
    });
    if let Some(session) = subject.session {
        claims["sid"] = Value::String(session.to_string());
    }
    Ok(IssuedAccessToken {
        token: sign_claims(app, work, ACCESS_TOKEN_TYPE, &claims).await?,
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
        scope,
    })
}

/// Mints the identity token of a person for one client. What it says of the
/// person is what the granted scopes allow, and nothing more.
///
/// # Errors
///
/// As [`mint_access_token`].
pub async fn mint_identity_token(
    app: &App,
    work: &mut dyn UnitOfWork,
    subject: IdentityTokenSubject<'_>,
) -> Result<String, Failure> {
    let issued_at = app.now().unix_timestamp();
    let person = subject.person;
    let mut claims = json!({
        "iss": subject.issuer,
        "sub": person.id.to_string(),
        "aud": subject.client_id,
        "iat": issued_at,
        "exp": issued_at.saturating_add_unsigned(IDENTITY_TOKEN_LIFETIME_SECONDS),
        // When the person proved who they are, not when this token was made.
        "auth_time": subject.authenticated_at.unix_timestamp(),
        "sid": subject.session.to_string(),
    });
    if let Some(nonce) = subject.nonce {
        claims["nonce"] = Value::String(nonce.to_owned());
    }
    write_person_claims(&mut claims, person, subject.scopes);
    sign_claims(app, work, IDENTITY_TOKEN_TYPE, &claims).await
}

/// Writes what the granted scopes allow to be said of a person, and nothing more.
fn write_person_claims(claims: &mut Value, person: &Person, scopes: &[String]) {
    let granted = |scope: &str| scopes.iter().any(|known| known == scope);
    if granted("profile") {
        claims["preferred_username"] = Value::String(person.username.clone());
        if let Some(name) = &person.display_name {
            claims["name"] = Value::String(name.clone());
        }
    }
    if let (true, Some(email)) = (granted("email"), &person.email) {
        claims["email"] = Value::String(email.clone());
        claims["email_verified"] = Value::Bool(person.email_verified);
    }
}

/// The longest a refresh token lives. It never outlives its session.
pub const REFRESH_TOKEN_LIFETIME: Duration = Duration::days(30);

pub struct RefreshGrant<'a> {
    /// The family the new token continues. `None` starts one.
    pub family: Option<Uuid>,
    pub client_id: &'a str,
    pub session: &'a Session,
    pub scopes: &'a [String],
}

/// Mints a refresh token, keeps its digest, and returns the token itself:
/// the one time it exists outside the client, with its family.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`] or the storage failure.
pub async fn issue_refresh_token(
    app: &App,
    work: &mut dyn UnitOfWork,
    grant: RefreshGrant<'_>,
) -> Result<(String, Uuid), Failure> {
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let token = URL_SAFE_NO_PAD.encode(random);
    let now = app.now();
    let family = match grant.family {
        Some(family) => family,
        None => mint_id(app)?,
    };
    work.insert_refresh_token(&RefreshToken {
        token_digest: app.digester.sha256(token.as_bytes()).to_vec(),
        family,
        client_id: grant.client_id.to_owned(),
        person: grant.session.person,
        session: grant.session.id,
        scopes: grant.scopes.to_vec(),
        issued_at: now,
        expires_at: (now + REFRESH_TOKEN_LIFETIME).min(grant.session.expires_at),
    })
    .await?;
    Ok((token, family))
}
