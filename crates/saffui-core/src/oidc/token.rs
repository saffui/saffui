//! The token endpoint.

use std::fmt;

use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use super::discovery::name_issuer;
use super::errors::OAuthFailure;
use super::pkce::matches_challenge;
use super::refresh::{end_grant, rotate_refresh_token};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::claims::gather::gather_claim_inputs;
use crate::claims::rules::{ClaimGrant, NamedClaims, WrittenClaims, write_claims};
use crate::claims::{ClaimInputs, ClaimTarget};
use crate::clients::authenticate::{
    PresentedProof, PresentedSecret, identify_client, read_client_proof,
};
use crate::clients::{Client, check_scope_token};
use crate::consent::{Allowance, ConsentHold, ConsentTerms, grant_to_client, is_consent_owed};
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::login::assurance::RequiredLevel;
use crate::login::session::{Session, open_offline_session, read_live_subject};
use crate::ports::crypto::SignatureAlgorithm;
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;
use crate::tenancy::resolve::resolve_realm;
use crate::tokens::mint::{
    AccessTokenSubject, IdentityTokenSubject, RefreshGrant, issue_refresh_token, mint_access_token,
    mint_identity_token, open_minting_key, open_minting_keys,
};
use crate::tokens::{DEFAULT_ALGORITHM, IssuedAccessToken};

/// The scope by which a client asks to act while the person is away.
pub const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// How many grants a person keeps offline with one client: one for each
/// device they use it on, and room to spare. Past it, the oldest gives way.
pub const MOST_OFFLINE_GRANTS_PER_CLIENT: u32 = 10;

/// What a client sent to the token endpoint, already read from the request.
#[derive(Default)]
pub struct TokenRequest<'a> {
    pub grant_type: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub client_id: Option<&'a str>,
    pub client_secret: Option<PresentedSecret>,
    /// The type of a client assertion, and the assertion (RFC 7523).
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
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
    mut request: TokenRequest<'_>,
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
        // A client names itself, or its assertion names it.
        if request.client_id.is_none() && request.client_assertion.is_none() {
            return Err(ErrorCode::ClientAuthenticationFailed.into());
        }
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
    let proof = read_client_proof(PresentedProof {
        secret: request.client_secret.take(),
        assertion_type: request.client_assertion_type,
        assertion: request.client_assertion,
    })?;
    let (realm_name, scope) = resolve_realm(app, realm).await?;
    let issuer = name_issuer(&app.settings, &realm_name);
    // Once, before any grant: an assertion is spent here, whatever follows.
    let (client, work) = identify_client(app, scope, request.client_id, proof, &issuer).await?;
    match grant {
        "client_credentials" => grant_to_service(app, &issuer, work, &client, &request).await,
        "authorization_code" => exchange_code(app, &issuer, scope, work, &client, &request).await,
        _ => rotate_refresh_token(app, &issuer, work, &client, &request).await,
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
    issuer: &str,
    mut work: Box<dyn UnitOfWork>,
    client: &Client,
    request: &TokenRequest<'_>,
) -> Result<TokenResponse, OAuthFailure> {
    // A public client proves nothing: it never acts as itself.
    if client.is_public() {
        return Err(ErrorCode::ClientAuthenticationFailed.into());
    }
    if !client.allows_client_credentials {
        return Err(ErrorCode::GrantNotAllowed.into());
    }

    // Asked for nothing, a client gets what it is allowed. It never gets more.
    let granted = narrow_scopes(request.scope, &client.scopes)?;

    let grant = ClaimGrant {
        person: None,
        client_id: &client.client_id,
        scopes: &granted,
        named: None,
    };
    let targets = [ClaimTarget::AccessToken];
    let inputs = gather_claim_inputs(work.as_mut(), &grant, &targets, app.now()).await?;
    let written = write_claims(ClaimTarget::AccessToken, &grant, &inputs)?;
    let key = open_minting_key(app, work.as_mut(), DEFAULT_ALGORITHM).await?;
    let minted = mint_access_token(
        app,
        &key,
        AccessTokenSubject {
            issuer,
            subject: &client.client_id,
            client_id: &client.client_id,
            scopes: &granted,
            session: None,
            family: None,
            claims: Some(&written),
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
    issuer: &str,
    scope: RealmScope,
    mut work: Box<dyn UnitOfWork>,
    client: &Client,
    request: &TokenRequest<'_>,
) -> Result<TokenResponse, OAuthFailure> {
    let (Some(code), Some(redirect_uri), Some(verifier)) =
        (request.code, request.redirect_uri, request.code_verifier)
    else {
        return Err(ErrorCode::RequestInvalid.into());
    };
    let invalid = || OAuthFailure::from(ErrorCode::GrantInvalid);
    if !client.allows_authorization_code {
        return Err(ErrorCode::GrantNotAllowed.into());
    }

    // The code is spent first, in the unit identify_client returned, which
    // commits whatever follows: a code presented once is spent, even when
    // the rest of the exchange is refused.
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
    // Whatever the code carries, a client that requires no consent is
    // granted nothing offline.
    let scopes = grant_to_client(client, &code.scopes);
    let allowed = match hold_consent_for(work.as_mut(), client, person.id, &scopes).await? {
        HeldConsent::NotRequired => None,
        HeldConsent::Allowed(allowance) => Some(allowance),
        HeldConsent::Short => return Err(invalid()),
    };

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
    let (offline, given_way) =
        open_offline_grant(app, work.as_mut(), &client.client_id, &scopes, &session).await?;
    let held_in = offline.as_ref().unwrap_or(&session);
    let granted = Granted {
        issuer,
        client_id: &client.client_id,
        session: held_in,
        person: &person,
        scopes: &scopes,
        nonce: code.nonce.as_deref(),
        id_token_algorithm: client
            .id_token_signed_response_alg
            .unwrap_or(DEFAULT_ALGORITHM),
        named: code.claims.as_ref().map(|request| NamedClaims {
            request,
            entitled: &client.scopes,
            allowed: allowed.as_ref(),
        }),
        family: RefreshGrant {
            family,
            client_id: &client.client_id,
            session: held_in,
            scopes: &scopes,
            claims: code.claims.as_ref(),
        },
    };
    let response = answer_for_person(app, work.as_mut(), granted).await?;
    // One event, the chain locked once: an offline session opened here is
    // said here, with the session it came from and those it took the place of.
    let given_way: Vec<String> = given_way.iter().map(Uuid::to_string).collect();
    let told = json!({
        "client_id": client.client_id,
        "family": family.to_string(),
        "from_session_id": offline.as_ref().map(|_| session.id.to_string()),
        "grant": "authorization_code",
        "offline_sessions_ended": given_way,
        "person_id": person.id.to_string(),
        "scope": response.scope,
        "session_id": held_in.id.to_string(),
        "session_kind": held_in.kind.name(),
    });
    record_event(app, work.as_mut(), EventKind::TokenIssued, told).await?;
    work.commit().await.map_err(Failure::from)?;
    Ok(response)
}

/// What a consent held for a grant answers.
pub(super) enum HeldConsent {
    /// The client asks nobody.
    NotRequired,
    /// What the person allowed, every scope of the grant among it.
    Allowed(Allowance),
    /// The person did not allow every scope of the grant.
    Short,
}

/// Holds what the person allowed a client that requires consent, until the
/// commit and before anything is locked: a withdrawal that comes meanwhile
/// waits, then revokes the family this opens; one that came first left
/// nothing to hold. An exchange that opens an offline grant holds it alone:
/// two of them for one person take turns, and the second counts the grant of
/// the first against the bound.
pub(super) async fn hold_consent_for(
    work: &mut dyn UnitOfWork,
    client: &Client,
    person: Uuid,
    scopes: &[String],
) -> Result<HeldConsent, Failure> {
    if !client.requires_consent {
        return Ok(HeldConsent::NotRequired);
    }
    let hold = if scopes.iter().any(|scope| scope == OFFLINE_ACCESS_SCOPE) {
        ConsentHold::Exclusive
    } else {
        ConsentHold::Shared
    };
    let terms = ConsentTerms {
        requires_consent: true,
        allowed: work.hold_consent(person, &client.client_id, hold).await?,
        client_scopes: client.scopes.clone(),
    };
    // The claims named one by one are weighed where each token is written.
    if is_consent_owed(&terms, false, scopes, &[]) {
        return Ok(HeldConsent::Short);
    }
    Ok(HeldConsent::Allowed(terms.allowed.unwrap_or_default()))
}

/// Opens the offline session a grant of `client_id` lives in, when it is
/// granted `offline_access`: only when the person allowed it on the page of
/// its request, to a client that requires consent. Opened from the session
/// they signed in with, it holds the grant from its first token, and the end
/// of that session leaves it standing. The oldest of theirs with this client
/// past the bound gives way first, with its tokens: the sessions before the
/// tokens, as everywhere. Returns it, and those that gave way.
async fn open_offline_grant(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_id: &str,
    scopes: &[String],
    from: &Session,
) -> Result<(Option<Session>, Vec<Uuid>), Failure> {
    if !scopes.iter().any(|scope| scope == OFFLINE_ACCESS_SCOPE) {
        return Ok((None, Vec::new()));
    }
    let given_way = work
        .end_oldest_offline_sessions(
            from.person,
            client_id,
            MOST_OFFLINE_GRANTS_PER_CLIENT - 1,
            app.now(),
        )
        .await?;
    if !given_way.is_empty() {
        work.revoke_refresh_tokens_of_sessions(&given_way, app.now())
            .await?;
    }
    let opened = open_offline_session(app, work, from).await?;
    Ok((Some(opened), given_way))
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
    end_grant(
        app,
        work,
        client_id,
        family,
        replayed.person,
        replayed.session,
        "code_replayed",
    )
    .await
}

pub(super) struct Granted<'a> {
    pub(super) issuer: &'a str,
    pub(super) client_id: &'a str,
    pub(super) session: &'a Session,
    pub(super) person: &'a Person,
    /// What this answer carries. The refresh token keeps its own.
    pub(super) scopes: &'a [String],
    pub(super) nonce: Option<&'a str>,
    /// The algorithm the client registered for its identity tokens.
    pub(super) id_token_algorithm: SignatureAlgorithm,
    /// The claims the request of the grant named, and what bounds them.
    pub(super) named: Option<NamedClaims<'a>>,
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
    let says_identity = granted.scopes.iter().any(|scope| scope == "openid");
    let signed = sign_for_person(
        app,
        work,
        PersonTokens {
            issuer: granted.issuer,
            client_id: granted.client_id,
            session: granted.session,
            person: granted.person,
            scopes: granted.scopes,
            nonce: granted.nonce,
            id_token_algorithm: granted.id_token_algorithm,
            signed: if says_identity {
                Signed::AccessAndIdentity
            } else {
                Signed::Access
            },
            code: None,
            named: granted.named,
            // Only a grant that named claims for userinfo has its access
            // tokens name its family: any other is said as it was.
            family: granted
                .named
                .filter(|named| !named.request.userinfo.is_empty())
                .map(|_| granted.family.family),
        },
    )
    .await?;
    let minted = signed.access.ok_or(Failure::new(ErrorCode::Internal))?;
    let refresh_token = issue_refresh_token(app, work, granted.family).await?;
    Ok(TokenResponse {
        access_token: minted.token,
        token_type: "Bearer",
        expires_in: minted.expires_in,
        scope: minted.scope,
        id_token: signed.identity,
        refresh_token: Some(refresh_token),
    })
}

/// Which tokens one answer signs for a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Signed {
    Access,
    /// An identity token alone, from the authorization endpoint: it says
    /// what the scopes name, as nothing else will (OpenID Connect Core, 5.4).
    Identity,
    /// An identity token beside a code, from the authorization endpoint: it
    /// binds the code, and says who signed in and how, nothing more.
    BoundIdentity,
    /// Both, as the token endpoint signs them.
    AccessAndIdentity,
    /// Both, from the authorization endpoint: the identity token binds the
    /// access token, and says who signed in and how, nothing more.
    AccessAndBoundIdentity,
}

/// The tokens of one answer for a person.
pub(super) struct PersonTokens<'a> {
    pub(super) issuer: &'a str,
    pub(super) client_id: &'a str,
    pub(super) session: &'a Session,
    pub(super) person: &'a Person,
    pub(super) scopes: &'a [String],
    pub(super) nonce: Option<&'a str>,
    /// The algorithm the client registered for its identity tokens.
    pub(super) id_token_algorithm: SignatureAlgorithm,
    pub(super) signed: Signed,
    /// The code the identity token is bound to, when one came back beside it.
    pub(super) code: Option<&'a str>,
    /// The claims the request named, and what bounds them.
    pub(super) named: Option<NamedClaims<'a>>,
    /// The family of refresh tokens the access token names, for userinfo to
    /// find what was named. None at the authorization endpoint, which opens
    /// no family: what it signs is told what its scopes say.
    pub(super) family: Option<Uuid>,
}

/// What [`sign_for_person`] signed.
pub(super) struct SignedForPerson {
    pub(super) access: Option<IssuedAccessToken>,
    pub(super) identity: Option<String>,
}

/// What an identity token beside a code or an access token says beyond who
/// signed in and how: the claims named for it, and nothing its scopes say.
fn write_bound_claims(
    grant: &ClaimGrant<'_>,
    inputs: &ClaimInputs,
) -> Result<WrittenClaims, Failure> {
    if grant.named.is_none() {
        return Ok(WrittenClaims::default());
    }
    let named_only = ClaimGrant {
        scopes: &[],
        ..*grant
    };
    write_claims(ClaimTarget::IdToken, &named_only, inputs)
}

/// Signs the tokens of one answer for a person, wherever it is given: the
/// same claims, mappers, audiences, lifetimes and session at the token
/// endpoint and at the authorization endpoint. The access token is signed
/// first: the identity token may say its hash.
pub(super) async fn sign_for_person(
    app: &App,
    work: &mut dyn UnitOfWork,
    asked: PersonTokens<'_>,
) -> Result<SignedForPerson, Failure> {
    let subject = asked.person.id.to_string();
    // Read each time a token is made, a refresh included: a role taken away
    // or an attribute changed is gone from the next token.
    let grant = ClaimGrant {
        person: Some(asked.person),
        client_id: asked.client_id,
        scopes: asked.scopes,
        named: asked.named,
    };
    // What each token says beyond who signed in and how. An identity token
    // that comes back beside a code or an access token says nothing more:
    // the client asks the rest with them (OpenID Connect Core 1.0, 5.4). It
    // says what the request named for it all the same (section 5.5).
    let names_identity = asked
        .named
        .is_some_and(|named| !named.request.id_token.is_empty());
    let targets: &[ClaimTarget] = match (asked.signed, names_identity) {
        (Signed::Access | Signed::AccessAndBoundIdentity, false) | (Signed::Access, true) => {
            &[ClaimTarget::AccessToken]
        }
        (Signed::Identity, _) | (Signed::BoundIdentity, true) => &[ClaimTarget::IdToken],
        (Signed::BoundIdentity, false) => &[],
        (Signed::AccessAndIdentity, _) | (Signed::AccessAndBoundIdentity, true) => {
            &[ClaimTarget::AccessToken, ClaimTarget::IdToken]
        }
    };
    let required_level = RequiredLevel::read(asked.named.map(|named| named.request));
    let inputs = if targets.is_empty() {
        ClaimInputs::default()
    } else {
        gather_claim_inputs(work, &grant, targets, app.now()).await?
    };
    // Signed in the algorithm the client registered, and in no other. An
    // access token is always signed in the default one.
    let (access_algorithm, identity_algorithm) = match asked.signed {
        Signed::Access => (DEFAULT_ALGORITHM, DEFAULT_ALGORITHM),
        Signed::Identity | Signed::BoundIdentity => {
            (asked.id_token_algorithm, asked.id_token_algorithm)
        }
        Signed::AccessAndIdentity | Signed::AccessAndBoundIdentity => {
            (DEFAULT_ALGORITHM, asked.id_token_algorithm)
        }
    };
    let (key, identity_key) =
        open_minting_keys(app, work, access_algorithm, identity_algorithm).await?;
    let access = if targets.contains(&ClaimTarget::AccessToken) {
        let for_access = write_claims(ClaimTarget::AccessToken, &grant, &inputs)?;
        Some(mint_access_token(
            app,
            &key,
            AccessTokenSubject {
                issuer: asked.issuer,
                subject: &subject,
                client_id: asked.client_id,
                scopes: asked.scopes,
                session: Some(asked.session),
                family: asked.family,
                claims: Some(&for_access),
            },
        )?)
    } else {
        None
    };
    // What the identity token says beyond who signed in and how, and the
    // access token it binds by its hash.
    let identity = match asked.signed {
        Signed::Access => None,
        Signed::Identity | Signed::AccessAndIdentity => {
            Some((write_claims(ClaimTarget::IdToken, &grant, &inputs)?, None))
        }
        Signed::BoundIdentity => Some((write_bound_claims(&grant, &inputs)?, None)),
        Signed::AccessAndBoundIdentity => Some((
            write_bound_claims(&grant, &inputs)?,
            access.as_ref().map(|minted| minted.token.as_str()),
        )),
    };
    let identity = match identity {
        Some((for_identity, bound)) => Some(mint_identity_token(
            app,
            identity_key.as_ref().unwrap_or(&key),
            IdentityTokenSubject {
                issuer: asked.issuer,
                person: asked.person,
                client_id: asked.client_id,
                claims: &for_identity,
                nonce: asked.nonce,
                session: asked.session,
                required_level: &required_level,
                access_token: bound,
                code: asked.code,
            },
        )?),
        None => None,
    };
    Ok(SignedForPerson { access, identity })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{TokenRequest, grant_token};
    use crate::app::App;
    use crate::clients::authenticate::PresentedSecret;
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
            client_secret: Some(PresentedSecret::Basic(copy_secret(secret))),
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
    fn a_code_presented_again_ends_the_offline_session_its_exchange_opened() {
        use crate::oidc::scenario::{CALLBACK, Scenario};

        let scenario = Scenario::start();
        scenario.register_partner();
        let granted = scenario.sign_in_and_consent("partner", "openid offline_access");
        assert!(scenario.is_token_active(&granted.tokens.access_token));
        let again = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some("partner"),
            code: Some(&granted.code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            ..TokenRequest::default()
        };

        let replayed = complete(grant_token(&scenario.app, "acme", again)).map(|_| ());

        assert_eq!(
            replayed.map_err(|failure| failure.error),
            Err(OAuthError::InvalidGrant)
        );
        assert!(
            !scenario.is_token_active(&granted.tokens.access_token),
            "the offline session ended with what the code obtained"
        );
    }

    #[test]
    fn a_code_that_carries_offline_access_for_a_client_that_requires_no_consent_opens_nothing_offline()
     {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use crate::oidc::code::AuthorizationCode;
        use crate::oidc::scenario::{CALLBACK, Scenario, VERIFIER};

        let scenario = Scenario::start();
        let signed_in = scenario.sign_in("openid");
        let ada = scenario.find_ada();
        let now = scenario.app.now();
        let code = "a-code-no-page-gave";
        // Written as no flow writes it: the page leaves the scope out first.
        let mut work =
            complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
        complete(work.insert_authorization_code(&AuthorizationCode {
            code_digest: scenario.app.digester.sha256(code.as_bytes()).to_vec(),
            client_id: "webapp".to_owned(),
            person: ada,
            session: signed_in.ticket.session,
            redirect_uri: CALLBACK.to_owned(),
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
            nonce: None,
            code_challenge:
                URL_SAFE_NO_PAD.encode(scenario.app.digester.sha256(VERIFIER.as_bytes())),
            authenticated_at: now,
            expires_at: now + time::Duration::minutes(1),
            claims: None,
        }))
        .expect("a code");
        complete(work.commit()).expect("a commit");

        let tokens = scenario.exchange_as("webapp", code);

        assert_eq!(
            tokens.scope, "openid",
            "the scope is left out at the exchange too"
        );
        let issued = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rev()
            .find(|event| event["kind"] == "token.issued")
            .expect("the exchange");
        assert_eq!(issued["payload"]["session_kind"], "browser", "{issued}");
        assert_eq!(
            issued["payload"]["session_id"],
            signed_in.ticket.session.to_string(),
            "{issued}"
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
