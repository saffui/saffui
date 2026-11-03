//! The token endpoint.

use serde::Serialize;
use serde_json::json;

use super::discovery::name_issuer;
use super::errors::OAuthFailure;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::authenticate::authenticate_client;
use crate::clients::check_scope_token;
use crate::error::ErrorCode;
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::mint::{AccessTokenSubject, mint_access_token};

/// What a client sent to the token endpoint, already read from the request.
pub struct TokenRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub client_secret: Option<Secret>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
}

/// Grants a token, or says why not in the words of RFC 6749.
///
/// # Errors
///
/// Returns the refusal, with the refusal of the catalog behind it.
pub async fn grant_token(
    app: &App,
    realm: &str,
    request: TokenRequest<'_>,
) -> Result<TokenResponse, OAuthFailure> {
    // Judged before the realm is looked for: a grant that is not served is
    // refused alike in a realm that exists and in one that does not.
    match request.grant_type {
        Some("client_credentials") => {}
        Some(_) => return Err(ErrorCode::GrantTypeUnsupported.into()),
        None => return Err(ErrorCode::RequestInvalid.into()),
    }
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let (Some(client_id), Some(client_secret)) = (request.client_id, request.client_secret) else {
        return Err(ErrorCode::ClientAuthenticationFailed.into());
    };

    let mut work = app
        .storage
        .begin(scope)
        .await
        .map_err(crate::error::Failure::from)?;
    let client = authenticate_client(app, work.as_mut(), client_id, &client_secret).await?;
    if !client.allows_client_credentials {
        return Err(ErrorCode::GrantNotAllowed.into());
    }

    // Asked for nothing, a client gets what it is allowed. It never gets more.
    let granted: Vec<String> = match request.scope {
        None => client.scopes.clone(),
        Some(asked) => {
            let mut granted = Vec::new();
            for token in asked.split(' ').filter(|token| !token.is_empty()) {
                check_scope_token(token)?;
                if !client.scopes.iter().any(|allowed| allowed == token) {
                    return Err(ErrorCode::ScopeNotAllowed.into());
                }
                if !granted.iter().any(|known| known == token) {
                    granted.push(token.to_owned());
                }
            }
            granted
        }
    };

    let issuer = name_issuer(&app.settings, &realm_name);
    let minted = mint_access_token(
        app,
        work.as_mut(),
        AccessTokenSubject {
            issuer: &issuer,
            subject: &client.client_id,
            client_id: &client.client_id,
            scopes: &granted,
        },
    )
    .await?;
    let told = json!({ "client_id": client.client_id, "grant": "client_credentials", "scope": minted.scope });
    record_event(app, work.as_mut(), EventKind::TokenIssued, told).await?;
    work.commit().await.map_err(crate::error::Failure::from)?;

    Ok(TokenResponse {
        access_token: minted.token,
        token_type: "Bearer",
        expires_in: minted.expires_in,
        scope: minted.scope,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{TokenRequest, grant_token};
    use crate::app::App;
    use crate::error::ErrorCode;
    use crate::oidc::errors::OAuthError;
    use crate::secret::Secret;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{create_realm, create_service_client};
    use crate::testkit::memory::MemoryStorage;
    use crate::tokens::verify::verify_access_token;

    const ISSUER: &str = "https://id.example.test/realms/acme";

    fn copy_secret(secret: &Secret) -> Secret {
        Secret::new(secret.expose().to_vec())
    }

    fn ask<'a>(client_id: &'a str, secret: &Secret, scope: Option<&'a str>) -> TokenRequest<'a> {
        TokenRequest {
            grant_type: Some("client_credentials"),
            scope,
            client_id: Some(client_id),
            client_secret: Some(copy_secret(secret)),
        }
    }

    /// A realm `acme` with a service client `billing` allowed two scopes.
    fn start() -> (App, std::sync::Arc<MemoryStorage>, Secret) {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let secret = complete(create_service_client(
            &app,
            scope,
            "billing",
            &["invoices:read", "invoices:write"],
        ));
        (app, storage, secret)
    }

    fn refuse(app: &App, realm: &str, request: TokenRequest<'_>) -> (OAuthError, ErrorCode) {
        let refused = complete(grant_token(app, realm, request)).expect_err("a refusal");
        (refused.error, refused.cause.code)
    }

    #[test]
    fn a_service_gets_a_token_that_verifies_under_the_keys_of_its_realm() {
        let (app, _storage, secret) = start();

        let response =
            complete(grant_token(&app, "acme", ask("billing", &secret, None))).expect("a token");

        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 300);
        assert_eq!(response.scope, "invoices:read invoices:write");
        let scope = complete(create_realm_scope(&app));
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        let claims = complete(verify_access_token(
            &app,
            work.as_mut(),
            ISSUER,
            &response.access_token,
        ))
        .expect("a token that verifies");
        assert_eq!(claims.subject, "billing");
        assert_eq!(claims.client_id, "billing");
        assert_eq!(claims.scopes, ["invoices:read", "invoices:write"]);
    }

    async fn create_realm_scope(app: &App) -> crate::tenancy::RealmScope {
        crate::tenancy::resolve::resolve_realm(app, "acme")
            .await
            .expect("the realm")
            .1
    }

    #[test]
    fn a_client_gets_the_scopes_it_asked_for_once_each_and_never_one_it_is_not_allowed() {
        let (app, _storage, secret) = start();

        let narrowed = complete(grant_token(
            &app,
            "acme",
            ask("billing", &secret, Some("invoices:read  invoices:read")),
        ))
        .expect("a token");
        assert_eq!(narrowed.scope, "invoices:read");

        assert_eq!(
            refuse(
                &app,
                "acme",
                ask("billing", &secret, Some("invoices:read admin"))
            ),
            (OAuthError::InvalidScope, ErrorCode::ScopeNotAllowed)
        );
        assert_eq!(
            refuse(&app, "acme", ask("billing", &secret, Some("bad\"scope"))),
            (OAuthError::InvalidScope, ErrorCode::ScopeInvalid)
        );
    }

    #[test]
    fn an_unknown_client_a_wrong_secret_a_disabled_client_and_an_unknown_realm_answer_alike() {
        let (app, storage, secret) = start();
        let wrong = Secret::new(b"not-the-secret".to_vec());

        assert_eq!(
            refuse(&app, "acme", ask("nobody", &secret, None)).0,
            OAuthError::InvalidClient
        );
        assert_eq!(
            refuse(&app, "acme", ask("billing", &wrong, None)).0,
            OAuthError::InvalidClient
        );
        assert_eq!(
            refuse(&app, "nowhere", ask("billing", &secret, None)).0,
            OAuthError::InvalidClient
        );
        let missing = TokenRequest {
            grant_type: Some("client_credentials"),
            scope: None,
            client_id: Some("billing"),
            client_secret: None,
        };
        assert_eq!(refuse(&app, "acme", missing).0, OAuthError::InvalidClient);

        storage.disable_client("billing");
        assert_eq!(
            refuse(&app, "acme", ask("billing", &secret, None)).0,
            OAuthError::InvalidClient
        );
    }

    #[test]
    fn a_grant_type_that_is_missing_or_unknown_is_refused_before_the_client_is_looked_at() {
        let (app, storage, secret) = start();
        let before = storage.count_units_of_work();
        let with_grant = |grant_type| TokenRequest {
            grant_type,
            ..ask("billing", &secret, None)
        };

        assert_eq!(
            refuse(&app, "acme", with_grant(None)).0,
            OAuthError::InvalidRequest
        );
        assert_eq!(
            refuse(&app, "acme", with_grant(Some("password"))).0,
            OAuthError::UnsupportedGrantType
        );
        assert_eq!(storage.count_units_of_work(), before, "nothing was read");
        assert_eq!(
            refuse(&app, "nowhere", with_grant(Some("password"))).0,
            OAuthError::UnsupportedGrantType,
            "an unknown realm answers the same"
        );
    }

    #[test]
    fn an_issued_token_is_recorded_in_the_chain_of_the_realm_and_a_refusal_is_not() {
        let (app, storage, secret) = start();
        let scope = complete(create_realm_scope(&app));
        let count_issued = || {
            storage
                .read_audit_envelopes(scope.realm())
                .iter()
                .filter(|event| event["kind"] == "token.issued")
                .count()
        };

        complete(grant_token(&app, "acme", ask("billing", &secret, None))).expect("a token");
        assert_eq!(count_issued(), 1);

        let wrong = Secret::new(b"not-the-secret".to_vec());
        let _ = complete(grant_token(&app, "acme", ask("billing", &wrong, None)));
        assert_eq!(count_issued(), 1);
    }

    #[test]
    fn a_token_is_refused_once_expired_by_another_realm_and_when_a_byte_of_it_changed() {
        let (app, _storage, clock) = MemoryStorage::wire_with_clock();
        let acme = complete(create_realm(&app, "acme"));
        let globex = complete(create_realm(&app, "globex"));
        let secret = complete(create_service_client(
            &app,
            acme,
            "billing",
            &["invoices:read"],
        ));
        let token = complete(grant_token(&app, "acme", ask("billing", &secret, None)))
            .expect("a token")
            .access_token;
        let verify = |scope, issuer: &'static str, token: String| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(verify_access_token(&app, work.as_mut(), issuer, &token))
                .map_err(|failure| failure.code)
        };

        assert!(verify(acme, ISSUER, token.clone()).is_ok());
        assert_eq!(
            verify(
                globex,
                "https://id.example.test/realms/globex",
                token.clone()
            ),
            Err(ErrorCode::TokenInvalid),
            "another realm has other keys"
        );
        assert_eq!(
            verify(acme, "https://id.example.test/realms/globex", token.clone()),
            Err(ErrorCode::TokenInvalid),
            "the issuer is compared, not only the signature"
        );
        let mut altered = token.clone().into_bytes();
        let middle = altered.len() / 2;
        altered[middle] = if altered[middle] == b'A' { b'B' } else { b'A' };
        assert_eq!(
            verify(acme, ISSUER, String::from_utf8(altered).expect("text")),
            Err(ErrorCode::TokenInvalid)
        );

        clock.advance(Duration::from_mins(5));
        assert_eq!(
            verify(acme, ISSUER, token),
            Err(ErrorCode::TokenInvalid),
            "expired"
        );
    }
}
