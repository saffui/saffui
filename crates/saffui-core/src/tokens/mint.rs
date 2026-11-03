use serde_json::json;

use super::jws::sign_compact;
use super::{ACCESS_TOKEN_LIFETIME_SECONDS, ACCESS_TOKEN_TYPE, IssuedAccessToken};
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::keys::jwks::open_signing_key;
use crate::ports::crypto::SignatureAlgorithm;
use crate::ports::storage::UnitOfWork;

pub struct AccessTokenSubject<'a> {
    pub issuer: &'a str,
    pub subject: &'a str,
    pub client_id: &'a str,
    pub scopes: &'a [String],
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
    let (key, private_key) = open_signing_key(app, work, SignatureAlgorithm::Es256).await?;
    let issued_at = app.now().unix_timestamp();
    let scope = subject.scopes.join(" ");
    let claims = json!({
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
    let token = sign_compact(
        app.signer.as_ref(),
        &key,
        &private_key,
        ACCESS_TOKEN_TYPE,
        &claims,
    )
    .map_err(|_| Failure::with_detail(ErrorCode::CryptoUnavailable, "a token cannot be signed"))?;
    Ok(IssuedAccessToken {
        token,
        expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
        scope,
    })
}
