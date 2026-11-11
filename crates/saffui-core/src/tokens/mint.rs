use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

use super::jws::sign_compact;
use super::store::RefreshToken;
use super::{
    ACCESS_TOKEN_LIFETIME_SECONDS, ACCESS_TOKEN_TYPE, IDENTITY_TOKEN_TYPE, IssuedAccessToken,
};
use crate::app::App;
use crate::authz::grants::RoleClaims;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::keys::SigningKey;
use crate::keys::jwks::open_signing_key;
use crate::login::assurance::Assurance;
use crate::login::session::{AuthenticationMethod, Session};
use crate::ports::crypto::SignatureAlgorithm;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;

/// How long an identity token is good for: long enough to be read once.
const IDENTITY_TOKEN_LIFETIME_SECONDS: u64 = 300;

#[derive(Clone, Copy)]
pub struct AccessTokenSubject<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    /// The session behind the token, when a person is.
    pub session: Option<&'a Session>,
    /// What the token says of the roles of the person, when it was asked.
    pub roles: Option<&'a RoleClaims>,
}

#[derive(Clone, Copy)]
pub struct IdentityTokenSubject<'a> {
    pub issuer: &'a str,
    pub person: &'a Person,
    pub client_id: &'a str,
    pub scopes: &'a [String],
    pub nonce: Option<&'a str>,
    /// The session behind the token: when the person proved who they are,
    /// and with what.
    pub session: &'a Session,
}

/// The key of the realm, opened once for every token of one answer.
pub struct MintingKey {
    key: SigningKey,
    private_key: Secret,
}

/// Opens the key the tokens of the realm are signed with.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the realm cannot sign, or
/// the storage failure.
pub async fn open_minting_key(app: &App, work: &mut dyn UnitOfWork) -> Result<MintingKey, Failure> {
    let (key, private_key) = open_signing_key(app, work, SignatureAlgorithm::Es256).await?;
    Ok(MintingKey { key, private_key })
}

fn sign_claims(
    app: &App,
    key: &MintingKey,
    token_type: &str,
    claims: &Value,
) -> Result<String, Failure> {
    sign_compact(
        app.signer.as_ref(),
        &key.key,
        &key.private_key,
        token_type,
        claims,
    )
    .map_err(|_| Failure::with_detail(ErrorCode::CryptoUnavailable, "a token cannot be signed"))
}

/// Mints an access token signed by the key of the realm.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the key does not sign, or
/// [`ErrorCode::RandomUnavailable`].
pub fn mint_access_token(
    app: &App,
    key: &MintingKey,
    subject: AccessTokenSubject<'_>,
) -> Result<IssuedAccessToken, Failure> {
    let issued_at = app.now().unix_timestamp();
    let lifetime_ends = issued_at.saturating_add_unsigned(ACCESS_TOKEN_LIFETIME_SECONDS);
    // A token that says a role lives no longer than the role.
    let expires_at = subject
        .roles
        .and_then(|roles| roles.until)
        .map_or(lifetime_ends, |until| {
            until.unix_timestamp().min(lifetime_ends)
        });
    let scope = subject.scopes.join(" ");
    let mut claims = json!({
        "iss": subject.issuer,
        "sub": subject.subject,
        // Until a resource is named, a token is for the realm that issued it.
        "aud": subject.issuer,
        "client_id": subject.client_id,
        "scope": scope,
        "iat": issued_at,
        "exp": expires_at,
        "jti": mint_id(app)?.to_string(),
    });
    if let Some(session) = subject.session {
        claims["sid"] = Value::String(session.id.to_string());
        // What a resource server weighs before an action that asks for more
        // (RFC 9068, section 2.2.1).
        claims["auth_time"] = json!(session.authenticated_at.unix_timestamp());
        claims["acr"] = json!(Assurance::reached_by(session).name());
    }
    if let Some(roles) = subject.roles {
        claims["realm_access"] = roles.write_realm_access();
        claims["resource_access"] = roles.write_resource_access(subject.client_id);
    }
    Ok(IssuedAccessToken {
        token: sign_claims(app, key, ACCESS_TOKEN_TYPE, &claims)?,
        expires_in: u64::try_from(expires_at - issued_at).unwrap_or(0),
        scope,
    })
}

/// Mints the identity token of a person for one client. What it says of the
/// person is what the granted scopes allow, and nothing more.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the key does not sign.
pub fn mint_identity_token(
    app: &App,
    key: &MintingKey,
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
        "auth_time": subject.session.authenticated_at.unix_timestamp(),
        "sid": subject.session.id.to_string(),
    });
    if let Some(nonce) = subject.nonce {
        claims["nonce"] = Value::String(nonce.to_owned());
    }
    claims["amr"] = write_methods(&subject.session.methods);
    claims["acr"] = json!(Assurance::reached_by(subject.session).name());
    write_person_claims(&mut claims, person, subject.scopes);
    sign_claims(app, key, IDENTITY_TOKEN_TYPE, &claims)
}

/// Names what proved the person (RFC 8176), and says so when it took more
/// than one factor.
fn write_methods(methods: &[AuthenticationMethod]) -> Value {
    let mut names: Vec<&str> = methods.iter().map(|method| method.name()).collect();
    if names.len() > 1 {
        names.push("mfa");
    }
    json!(names)
}

/// Writes what the granted scopes allow to be said of a person, and nothing more.
pub(crate) fn write_person_claims(claims: &mut Value, person: &Person, scopes: &[String]) {
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
    /// The family the new token belongs to: every token of one grant.
    pub family: Uuid,
    pub client_id: &'a str,
    pub session: &'a Session,
    pub scopes: &'a [String],
}

/// Mints a refresh token, keeps its digest, and returns the token itself:
/// the one time it exists outside the client.
///
/// # Errors
///
/// Returns [`ErrorCode::RandomUnavailable`] or the storage failure.
pub async fn issue_refresh_token(
    app: &App,
    work: &mut dyn UnitOfWork,
    grant: RefreshGrant<'_>,
) -> Result<String, Failure> {
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let token = URL_SAFE_NO_PAD.encode(random);
    let now = app.now();
    work.insert_refresh_token(&RefreshToken {
        token_digest: app.digester.sha256(token.as_bytes()).to_vec(),
        family: grant.family,
        client_id: grant.client_id.to_owned(),
        person: grant.session.person,
        session: grant.session.id,
        scopes: grant.scopes.to_vec(),
        issued_at: now,
        expires_at: (now + REFRESH_TOKEN_LIFETIME).min(grant.session.expires_at),
    })
    .await?;
    Ok(token)
}
