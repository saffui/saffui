use serde_json::Value;
use uuid::Uuid;

use super::jws::verify_compact;
use super::{ACCESS_TOKEN_TYPE, IDENTITY_TOKEN_TYPE};
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
    /// What the token is for: the realm that issued it first, then the
    /// resources its mappers named.
    pub audiences: Vec<String>,
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
/// key of this realm, that is not an access token, that names another issuer
/// or no audience, that expired, or that claims to come from the future.
/// Returns the storage failure when the keys cannot be read.
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
    let audiences = match &claims["aud"] {
        Value::String(one) => vec![one.clone()],
        Value::Array(all) if !all.is_empty() => all
            .iter()
            .map(|audience| audience.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
            .ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    Ok(AccessTokenClaims {
        subject: read_text("sub")?,
        client_id: read_text("client_id")?,
        scopes: read_text("scope")?
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
        audiences,
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

/// What an identity token says when a client presents it back as a hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityHint {
    pub client_id: String,
    pub session: Uuid,
    /// The person the token was issued for.
    pub subject: String,
}

/// Reads an identity token that a client presents back as a hint. Its expiry
/// is not checked: a hint is presented long after the token was read. A token
/// this realm did not sign, of another kind or of another issuer is no hint.
///
/// # Errors
///
/// Returns the storage failure when the keys cannot be read.
pub async fn read_identity_hint(
    app: &App,
    work: &mut dyn UnitOfWork,
    issuer: &str,
    token: &str,
) -> Result<Option<IdentityHint>, Failure> {
    let keys = work.list_signing_keys().await?;
    let Some(verified) = verify_compact(app.signer.as_ref(), token, &keys) else {
        return Ok(None);
    };
    let claims = &verified.claims;
    if verified.token_type.as_deref() != Some(IDENTITY_TOKEN_TYPE)
        || claims["iss"].as_str() != Some(issuer)
    {
        return Ok(None);
    }
    let session = claims["sid"]
        .as_str()
        .and_then(|text| Uuid::parse_str(text).ok());
    let (Some(client_id), Some(session), Some(subject)) =
        (claims["aud"].as_str(), session, claims["sub"].as_str())
    else {
        return Ok(None);
    };
    Ok(Some(IdentityHint {
        client_id: client_id.to_owned(),
        session,
        subject: subject.to_owned(),
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::verify_access_token;
    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::keys::jwks::open_signing_key;
    use crate::ports::crypto::SignatureAlgorithm;
    use crate::ports::storage::UnitOfWork;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_realm;
    use crate::testkit::memory::MemoryStorage;
    use crate::tokens::ACCESS_TOKEN_TYPE;
    use crate::tokens::jws::sign_compact;

    const ISSUER: &str = "https://id.example.test/realms/acme";

    /// Signs an access token of the realm that names `audience`, and reads
    /// back the audiences the verifier finds in it.
    fn verify_audience(
        app: &App,
        work: &mut dyn UnitOfWork,
        audience: &Value,
    ) -> Result<Vec<String>, ErrorCode> {
        let (key, private_key) = complete(open_signing_key(app, work, SignatureAlgorithm::Es256))
            .expect("the key of the realm");
        let now = app.now().unix_timestamp();
        let claims = json!({
            "iss": ISSUER,
            "sub": "billing",
            "aud": audience,
            "client_id": "billing",
            "scope": "invoices:read",
            "iat": now,
            "exp": now + 300,
            "jti": "a-token",
        });
        let token = sign_compact(
            app.signer.as_ref(),
            &key,
            &private_key,
            ACCESS_TOKEN_TYPE,
            &claims,
        )
        .expect("a token");
        complete(verify_access_token(app, work, ISSUER, &token))
            .map(|verified| verified.audiences)
            .map_err(|failure| failure.code)
    }

    #[test]
    fn a_token_names_one_audience_or_a_list_of_them_and_nothing_else() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");

        assert_eq!(
            verify_audience(&app, work.as_mut(), &json!(ISSUER)),
            Ok(vec![ISSUER.to_owned()])
        );
        assert_eq!(
            verify_audience(
                &app,
                work.as_mut(),
                &json!([ISSUER, "https://api.example.org"])
            ),
            Ok(vec![
                ISSUER.to_owned(),
                "https://api.example.org".to_owned()
            ])
        );
        for wrong in [json!([]), json!([ISSUER, 5]), json!(5), Value::Null] {
            assert_eq!(
                verify_audience(&app, work.as_mut(), &wrong),
                Err(ErrorCode::TokenInvalid),
                "{wrong}"
            );
        }
    }
}
