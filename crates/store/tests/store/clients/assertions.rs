//! Client assertions on Postgres: one is spent in a unit of work of its own,
//! and a request it proves never holds two units at once.

use pgcore::pool::PoolSettings;
use saffui_core::app::App;
use saffui_core::clients::ClientAuthMethod;
use saffui_core::clients::assertion::ASSERTION_TYPE;
use saffui_core::clients::register::NewClient;
use saffui_core::oidc::errors::OAuthError;
use saffui_core::oidc::token::{TokenRequest, grant_token};
use saffui_core::secret::Secret;
use saffui_core::testkit::fixtures::{
    check_and_register_client, create_realm, sign_client_assertion,
};

use crate::support;

/// Registers `signer`, which signs its assertions with its secret, in the
/// realm `acme`, and returns the secret.
async fn register_signer(app: &App) -> Secret {
    let scope = create_realm(app, "acme").await;
    let scopes = ["reports:read".to_owned()];
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let (_client, secret) = check_and_register_client(
        app,
        work.as_mut(),
        NewClient {
            client_id: "signer",
            name: "A service that signs",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &[],
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: None,
            response_types: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: Some(ClientAuthMethod::ClientSecretJwt),
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            require_pkce: true,
            created_by: None,
        },
    )
    .await
    .expect("a client");
    work.commit().await.expect("a commit");
    secret.expect("a secret, shown once")
}

fn sign_assertion(app: &App, secret: &Secret, jti: &str) -> String {
    sign_client_assertion(
        app,
        "signer",
        secret,
        "https://id.example.test/realms/acme",
        jti,
    )
}

async fn present(app: &App, assertion: &str, scope: Option<&str>) -> Result<String, OAuthError> {
    let request = TokenRequest {
        grant_type: Some("client_credentials"),
        scope,
        client_assertion_type: Some(ASSERTION_TYPE),
        client_assertion: Some(assertion),
        ..TokenRequest::default()
    };
    grant_token(app, "acme", request)
        .await
        .map(|tokens| tokens.scope)
        .map_err(|failure| failure.error)
}

#[tokio::test]
async fn an_assertion_proves_its_client_through_a_pool_of_one_connection() {
    let one = PoolSettings {
        max_size: 1,
        ..PoolSettings::default()
    };
    let (app, _database) = support::wire_on_postgres(one).await;
    let secret = register_signer(&app).await;

    let granted = present(&app, &sign_assertion(&app, &secret, "p-1"), None).await;

    assert_eq!(granted, Ok("reports:read".to_owned()));
}

#[tokio::test]
async fn an_assertion_is_spent_even_when_the_request_it_proved_is_refused() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let secret = register_signer(&app).await;
    let assertion = sign_assertion(&app, &secret, "s-1");

    let refused = present(&app, &assertion, Some("admin")).await;
    let again = present(&app, &assertion, None).await;

    assert_eq!(refused, Err(OAuthError::InvalidScope));
    assert_eq!(
        again,
        Err(OAuthError::InvalidClient),
        "spent by the refusal"
    );
}
