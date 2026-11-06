//! The token endpoint.

use std::fmt;

use serde::Serialize;
use serde_json::json;

use super::discovery::name_issuer;
use super::errors::OAuthFailure;
use super::pkce::matches_challenge;
use super::refresh::{describe_family_end, rotate_refresh_token};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::authenticate::{authenticate_client, identify_client};
use crate::clients::check_scope_token;
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::login::session::{Session, read_live_subject};
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::resolve::resolve_realm;
use crate::tenancy::{RealmName, RealmScope};
use crate::tokens::mint::{
    AccessTokenSubject, IdentityTokenSubject, RefreshGrant, issue_refresh_token, mint_access_token,
    mint_identity_token, open_minting_key,
};

/// What a client sent to the token endpoint, already read from the request.
#[derive(Default)]
pub struct TokenRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub client_secret: Option<Secret>,
    pub code: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

// Written by hand: a derived `Debug` would print the tokens.
impl fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("access_token", &"..")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("id_token", &self.id_token.as_ref().map(|_| ".."))
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| ".."))
            .finish()
    }
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
    let grant = match request.grant_type {
        Some(served @ ("client_credentials" | "authorization_code" | "refresh_token")) => served,
        Some(_) => return Err(ErrorCode::GrantTypeUnsupported.into()),
        None => return Err(ErrorCode::RequestInvalid.into()),
    };
    // The form too: a request the realm could not serve is refused alike
    // whether the realm exists or not.
    if grant != "client_credentials" {
        request
            .client_id
            .ok_or(ErrorCode::ClientAuthenticationFailed)?;
        let complete = if grant == "authorization_code" {
            request.code.is_some()
                && request.redirect_uri.is_some()
                && request.code_verifier.is_some()
        } else {
            request.refresh_token.is_some()
        };
        if !complete {
            return Err(ErrorCode::RequestInvalid.into());
        }
    }
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    match grant {
        "client_credentials" => grant_to_service(app, &realm_name, scope, request).await,
        "authorization_code" => exchange_code(app, &realm_name, scope, request).await,
        _ => rotate_refresh_token(app, &realm_name, scope, request).await,
    }
}

/// Narrows what may be given to what was asked for. Asked for nothing, the
/// whole is given. Nothing outside it ever is.
pub(super) fn narrow_scopes(
    asked: Option<&str>,
    allowed: &[String],
) -> Result<Vec<String>, Failure> {
    let Some(asked) = asked else {
        return Ok(allowed.to_vec());
    };
    let mut granted = Vec::new();
    for token in asked.split(' ').filter(|token| !token.is_empty()) {
        check_scope_token(token)?;
        if !allowed.iter().any(|known| known == token) {
            return Err(Failure::new(ErrorCode::ScopeNotAllowed));
        }
        if !granted.iter().any(|known| known == token) {
            granted.push(token.to_owned());
        }
    }
    Ok(granted)
}

async fn grant_to_service(
    app: &App,
    realm_name: &RealmName,
    scope: RealmScope,
    request: TokenRequest<'_>,
) -> Result<TokenResponse, OAuthFailure> {
    let (Some(client_id), Some(client_secret)) = (request.client_id, request.client_secret) else {
        return Err(ErrorCode::ClientAuthenticationFailed.into());
    };

    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let client = authenticate_client(app, work.as_mut(), client_id, &client_secret).await?;
    if !client.allows_client_credentials {
        return Err(ErrorCode::GrantNotAllowed.into());
    }

    // Asked for nothing, a client gets what it is allowed. It never gets more.
    let granted = narrow_scopes(request.scope, &client.scopes)?;

    let issuer = name_issuer(&app.settings, realm_name);
    let key = open_minting_key(app, work.as_mut()).await?;
    let minted = mint_access_token(
        app,
        &key,
        AccessTokenSubject {
            issuer: &issuer,
            subject: &client.client_id,
            client_id: &client.client_id,
            scopes: &granted,
            session: None,
        },
    )?;
    let told = json!({ "client_id": client.client_id, "grant": "client_credentials", "scope": minted.scope });
    record_event(app, work.as_mut(), EventKind::TokenIssued, told).await?;
    work.commit().await.map_err(Failure::from)?;

    Ok(TokenResponse {
        access_token: minted.token,
        token_type: "Bearer",
        expires_in: minted.expires_in,
        scope: minted.scope,
        id_token: None,
        refresh_token: None,
    })
}

async fn exchange_code(
    app: &App,
    realm_name: &RealmName,
    scope: RealmScope,
    request: TokenRequest<'_>,
) -> Result<TokenResponse, OAuthFailure> {
    let client_id = request
        .client_id
        .ok_or(ErrorCode::ClientAuthenticationFailed)?;
    let (Some(code), Some(redirect_uri), Some(verifier)) =
        (request.code, request.redirect_uri, request.code_verifier)
    else {
        return Err(ErrorCode::RequestInvalid.into());
    };
    let invalid = || OAuthFailure::from(ErrorCode::GrantInvalid);

    // The code is spent first, in a unit of work of its own that commits
    // whatever follows: a code presented once is spent, even when the rest
    // of the exchange is refused.
    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let client = identify_client(app, work.as_mut(), client_id, request.client_secret).await?;
    if !client.allows_authorization_code {
        return Err(ErrorCode::GrantNotAllowed.into());
    }
    let digest = app.digester.sha256(code.as_bytes());
    let now = app.now();
    let spent = work
        .spend_authorization_code(&digest, now)
        .await
        .map_err(Failure::from)?;
    let Some(code) = spent else {
        take_back_what_a_code_obtained(app, work.as_mut(), &digest, &client.client_id, now).await?;
        work.commit().await.map_err(Failure::from)?;
        return Err(invalid());
    };
    work.commit().await.map_err(Failure::from)?;

    // Compared to what was bound to the code, not to what the client has registered.
    if code.client_id != client.client_id
        || code.redirect_uri != redirect_uri
        || !matches_challenge(app.digester.as_ref(), verifier, &code.code_challenge)
    {
        return Err(invalid());
    }

    let mut work = app.storage.begin(scope).await.map_err(Failure::from)?;
    let (session, person) = read_live_subject(app, work.as_mut(), code.session)
        .await?
        .filter(|(_, person)| person.id == code.person)
        .ok_or_else(invalid)?;

    // Presented again meanwhile, the code obtains nothing. Bound before
    // anything is written: the event comes last, as the head of the chain
    // stays locked from the event to the commit.
    let family = mint_id(app)?;
    let bound = work
        .bind_code_family(&digest, family)
        .await
        .map_err(Failure::from)?;
    if !bound {
        return Err(invalid());
    }
    let issuer = name_issuer(&app.settings, realm_name);
    let granted = Granted {
        issuer: &issuer,
        client_id: &client.client_id,
        session: &session,
        person: &person,
        scopes: &code.scopes,
        nonce: code.nonce.as_deref(),
        family: RefreshGrant {
            family,
            client_id: &client.client_id,
            session: &session,
            scopes: &code.scopes,
        },
    };
    let response = answer_for_person(app, work.as_mut(), granted).await?;
    let told = json!({
        "client_id": client.client_id,
        "family": family.to_string(),
        "grant": "authorization_code",
        "person_id": person.id.to_string(),
        "scope": response.scope,
        "session_id": session.id.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::TokenIssued, told).await?;
    work.commit().await.map_err(Failure::from)?;
    Ok(response)
}

/// A code presented after it was spent was copied by someone: the refresh
/// tokens its first exchange started are taken back (RFC 6749, section
/// 4.1.2). Which of the two holders is the thief cannot be told. The access
/// token already given lives out its few minutes.
async fn take_back_what_a_code_obtained(
    app: &App,
    work: &mut dyn UnitOfWork,
    digest: &[u8],
    client_id: &str,
    now: time::OffsetDateTime,
) -> Result<(), Failure> {
    let Some(replayed) = work.mark_code_replayed(digest, client_id, now).await? else {
        return Ok(());
    };
    let Some(family) = replayed.family else {
        return Ok(());
    };
    if let Some(ended) = work.revoke_refresh_family(family, now).await? {
        let told = describe_family_end(
            client_id,
            family,
            replayed.person,
            replayed.session,
            "code_replayed",
            &ended,
        );
        record_event(app, work, EventKind::TokenRevoked, told).await?;
    }
    Ok(())
}

pub(super) struct Granted<'a> {
    pub(super) issuer: &'a str,
    pub(super) client_id: &'a str,
    pub(super) session: &'a Session,
    pub(super) person: &'a Person,
    /// What this answer carries. The refresh token keeps its own.
    pub(super) scopes: &'a [String],
    pub(super) nonce: Option<&'a str>,
    pub(super) family: RefreshGrant<'a>,
}

/// Mints everything a client gets for a person: an access token, an identity
/// token when `openid` was granted, and the next refresh token of the family.
/// It records nothing: what is said of it in the chain is the caller's.
pub(super) async fn answer_for_person(
    app: &App,
    work: &mut dyn UnitOfWork,
    granted: Granted<'_>,
) -> Result<TokenResponse, Failure> {
    let subject = granted.person.id.to_string();
    let key = open_minting_key(app, work).await?;
    let minted = mint_access_token(
        app,
        &key,
        AccessTokenSubject {
            issuer: granted.issuer,
            subject: &subject,
            client_id: granted.client_id,
            scopes: granted.scopes,
            session: Some(granted.session.id),
        },
    )?;
    let id_token = if granted.scopes.iter().any(|scope| scope == "openid") {
        let identity = IdentityTokenSubject {
            issuer: granted.issuer,
            person: granted.person,
            client_id: granted.client_id,
            scopes: granted.scopes,
            nonce: granted.nonce,
            session: granted.session.id,
            authenticated_at: granted.session.authenticated_at,
            methods: &granted.session.methods,
        };
        Some(mint_identity_token(app, &key, identity)?)
    } else {
        None
    };
    let refresh_token = issue_refresh_token(app, work, granted.family).await?;
    Ok(TokenResponse {
        access_token: minted.token,
        token_type: "Bearer",
        expires_in: minted.expires_in,
        scope: minted.scope,
        id_token,
        refresh_token: Some(refresh_token),
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
            ..TokenRequest::default()
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
            ..TokenRequest::default()
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

    #[test]
    fn an_exchange_missing_a_part_is_refused_alike_in_a_realm_that_exists_and_in_one_that_does_not()
    {
        let (app, _storage, _secret) = start();
        let missing_code = || TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("portal"),
            redirect_uri: Some("https://app.example.org/callback"),
            code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            ..TokenRequest::default()
        };

        assert_eq!(
            refuse(&app, "acme", missing_code()).0,
            refuse(&app, "nowhere", missing_code()).0
        );
        assert_eq!(
            refuse(&app, "nowhere", missing_code()).0,
            OAuthError::InvalidRequest
        );
    }

    #[test]
    fn a_token_answer_does_not_print_its_tokens() {
        let answer = super::TokenResponse {
            access_token: "eyJ.access.token".to_owned(),
            token_type: "Bearer",
            expires_in: 300,
            scope: "openid".to_owned(),
            id_token: Some("eyJ.identity.token".to_owned()),
            refresh_token: Some("opaque-refresh".to_owned()),
        };

        let printed = format!("{answer:?}");

        assert!(!printed.contains("eyJ"), "{printed}");
        assert!(!printed.contains("opaque"), "{printed}");
        assert!(printed.contains("Bearer"), "{printed}");
    }
}
