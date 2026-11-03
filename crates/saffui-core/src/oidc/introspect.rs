//! Token introspection (RFC 7662): a client asks whether a token still
//! stands, and what it says.

use serde::Serialize;

use super::discovery::name_issuer;
use super::errors::OAuthFailure;
use crate::app::App;
use crate::clients::authenticate::authenticate_client;
use crate::error::{ErrorCode, Failure};
use crate::login::session::read_live_subject;
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::verify::verify_access_token;

/// What is said of a token. Of a token that does not stand, only that.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Introspection {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<&'static str>,
}

/// Tells a client whether a token stands. An access token stands while it
/// verifies and, when a person is behind it, while their session lasts. A
/// refresh token is told only to the client it was issued to.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientAuthenticationFailed`] for a caller that is
/// not a client with its secret, [`ErrorCode::RequestInvalid`] when no token
/// is presented, or the storage failure. A token that does not stand is not
/// an error: it is an answer.
pub async fn introspect_token(
    app: &App,
    realm: &str,
    client_id: Option<&str>,
    client_secret: Option<Secret>,
    token: Option<&str>,
) -> Result<Introspection, OAuthFailure> {
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let (Some(client_id), Some(client_secret)) = (client_id, client_secret) else {
        return Err(ErrorCode::ClientAuthenticationFailed.into());
    };
    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let client = authenticate_client(app, work.as_mut(), client_id, &client_secret).await?;
    let token = token.ok_or(ErrorCode::RequestInvalid)?;
    let issuer = name_issuer(&app.settings, &realm_name);
    let now = app.now();

    match verify_access_token(app, work.as_mut(), &issuer, token).await {
        Ok(claims) => {
            let stands = match claims.session {
                None => true,
                Some(session) => read_live_subject(app, work.as_mut(), session)
                    .await?
                    .is_some(),
            };
            return Ok(if stands {
                Introspection {
                    active: true,
                    scope: Some(claims.scopes.join(" ")),
                    client_id: Some(claims.client_id),
                    sub: Some(claims.subject),
                    iss: Some(issuer),
                    exp: Some(claims.expires_at),
                    iat: Some(claims.issued_at),
                    jti: Some(claims.token_id),
                    sid: claims.session.map(|session| session.to_string()),
                    token_type: Some("Bearer"),
                }
            } else {
                Introspection::default()
            });
        }
        Err(failure) if failure.code == ErrorCode::TokenInvalid => {}
        Err(failure) => return Err(failure.into()),
    }

    let digest = app.digester.sha256(token.as_bytes());
    let stored = work
        .read_refresh_token(&digest)
        .await
        .map_err(Failure::from)?
        .filter(|stored| stored.is_live(now) && stored.token.client_id == client.client_id);
    let Some(stored) = stored else {
        return Ok(Introspection::default());
    };
    if read_live_subject(app, work.as_mut(), stored.token.session)
        .await?
        .is_none()
    {
        return Ok(Introspection::default());
    }
    Ok(Introspection {
        active: true,
        scope: Some(stored.token.scopes.join(" ")),
        client_id: Some(stored.token.client_id),
        sub: Some(stored.token.person.to_string()),
        iss: Some(issuer),
        exp: Some(stored.token.expires_at.unix_timestamp()),
        iat: Some(stored.token.issued_at.unix_timestamp()),
        jti: None,
        sid: Some(stored.token.session.to_string()),
        token_type: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{Introspection, introspect_token};
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{CodeFlow, create_application, run_code_flow};

    fn ask(scenario: &Scenario, token: &str) -> Introspection {
        complete(introspect_token(
            &scenario.app,
            "acme",
            Some("billing"),
            Some(scenario.copy_service_secret()),
            Some(token),
        ))
        .expect("an answer")
    }

    #[test]
    fn a_client_is_told_what_an_access_token_says_while_its_session_lasts() {
        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid email");

        let told = ask(&scenario, &signed_in.tokens.access_token);

        assert!(told.active);
        assert_eq!(told.scope.as_deref(), Some("openid email"));
        assert_eq!(told.client_id.as_deref(), Some("webapp"));
        assert_eq!(told.token_type, Some("Bearer"));
        assert_eq!(
            told.iss.as_deref(),
            Some("https://id.example.test/realms/acme")
        );
        assert_eq!(
            told.exp.zip(told.iat).map(|(exp, iat)| exp - iat),
            Some(300)
        );
        assert!(told.sub.is_some() && told.sid.is_some() && told.jti.is_some());

        scenario.end_session(&signed_in.ticket);
        assert_eq!(
            ask(&scenario, &signed_in.tokens.access_token),
            Introspection::default(),
            "a token whose session ended does not stand, and nothing is said of it"
        );
    }

    #[test]
    fn a_refresh_token_is_told_only_to_its_client_and_only_while_it_can_be_spent() {
        let scenario = Scenario::start();
        let secret = complete(create_application(
            &scenario.app,
            scenario.scope,
            "backend",
            "https://backend.example.org/callback",
            false,
        ))
        .expect("a secret");
        let flow = CodeFlow {
            realm: "acme",
            client_id: "backend",
            client_secret: Some(&secret),
            redirect_uri: "https://backend.example.org/callback",
            scope: "openid",
            username: "ada",
            password: crate::oidc::scenario::PASSWORD,
        };
        let refresh = complete(run_code_flow(&scenario.app, flow))
            .tokens
            .refresh_token
            .expect("a refresh token");
        let ask_as_owner = || {
            complete(introspect_token(
                &scenario.app,
                "acme",
                Some("backend"),
                Some(crate::secret::Secret::new(secret.expose().to_vec())),
                Some(&refresh),
            ))
            .expect("an answer")
        };

        let told = ask_as_owner();
        assert!(told.active);
        assert_eq!(told.client_id.as_deref(), Some("backend"));
        assert_eq!(told.scope.as_deref(), Some("openid"));
        assert_eq!(told.token_type, None);
        assert_eq!(
            ask(&scenario, &refresh),
            Introspection::default(),
            "another client learns nothing of a refresh token"
        );
        assert_eq!(ask(&scenario, "not-a-token"), Introspection::default());

        scenario.storage.end_every_session();
        assert_eq!(ask_as_owner(), Introspection::default());
    }

    #[test]
    fn only_a_client_with_its_secret_may_ask() {
        let scenario = Scenario::start();
        let token = scenario.sign_in("openid").tokens.access_token;
        let ask_as = |client_id: Option<&str>, secret: Option<&str>| {
            complete(introspect_token(
                &scenario.app,
                "acme",
                client_id,
                secret.map(|secret| crate::secret::Secret::new(secret.as_bytes().to_vec())),
                Some(&token),
            ))
            .map_err(|failure| failure.error)
        };

        assert_eq!(ask_as(None, None), Err(OAuthError::InvalidClient));
        assert_eq!(ask_as(Some("webapp"), None), Err(OAuthError::InvalidClient));
        assert_eq!(
            ask_as(Some("billing"), Some("not-the-secret")),
            Err(OAuthError::InvalidClient)
        );
        let without_token = complete(introspect_token(
            &scenario.app,
            "acme",
            Some("billing"),
            Some(scenario.copy_service_secret()),
            None,
        ));
        assert_eq!(
            without_token.map_err(|failure| failure.error),
            Err(OAuthError::InvalidRequest)
        );
    }
}
