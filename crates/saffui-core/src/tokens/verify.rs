use uuid::Uuid;

use super::ACCESS_TOKEN_TYPE;
use super::jws::verify_compact;
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ports::storage::UnitOfWork;

/// How far ahead of this node the clock of the node that signed may be.
const CLOCK_SKEW_SECONDS: i64 = 30;

/// What a verified access token says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessTokenClaims {
    pub subject: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub token_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    /// The session behind the token, when a person is.
    pub session: Option<Uuid>,
}

/// Verifies an access token of the realm of `work`.
///
/// # Errors
///
/// Returns [`ErrorCode::TokenInvalid`] for a token that was not signed by a
/// key of this realm, that is not an access token, that names another issuer,
/// that expired, or that claims to come from the future. Returns the storage
/// failure when the keys cannot be read.
pub async fn verify_access_token(
    app: &App,
    work: &mut dyn UnitOfWork,
    issuer: &str,
    token: &str,
) -> Result<AccessTokenClaims, Failure> {
    let keys = work.list_signing_keys().await?;
    let invalid = || Failure::new(ErrorCode::TokenInvalid);
    let verified = verify_compact(app.signer.as_ref(), token, &keys).ok_or_else(invalid)?;
    if verified.token_type.as_deref() != Some(ACCESS_TOKEN_TYPE) {
        return Err(invalid());
    }
    let claims = &verified.claims;
    let now = app.now().unix_timestamp();
    let expires_at = claims["exp"].as_i64().ok_or_else(invalid)?;
    let issued_at = claims["iat"].as_i64().ok_or_else(invalid)?;
    if claims["iss"].as_str() != Some(issuer)
        || expires_at <= now
        || issued_at > now + CLOCK_SKEW_SECONDS
    {
        return Err(invalid());
    }
    let read_text = |name: &str| claims[name].as_str().map(str::to_owned).ok_or_else(invalid);
    Ok(AccessTokenClaims {
        subject: read_text("sub")?,
        client_id: read_text("client_id")?,
        scopes: read_text("scope")?
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
        token_id: read_text("jti")?,
        issued_at,
        expires_at,
        session: match claims.get("sid") {
            None => None,
            Some(session) => Some(
                session
                    .as_str()
                    .and_then(|text| Uuid::parse_str(text).ok())
                    .ok_or_else(invalid)?,
            ),
        },
    })
}
