//! Turning an authenticated client into tokens.
//!
//! The client is established before anything here runs, so nothing here asks
//! who is calling.

use chrono::{DateTime, Duration, Utc};
use crypto::constant_time;
use crypto::envelope::Envelope;
use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use models::entities::keys::{KeyUse, RealmSigningKey};
use models::entities::oidc::AuthorizationCode;
use models::entities::realm::RealmModel;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use serde_json::Value;
use store::keyring::RealmKeyring;
use store::providers::{oidc, realm_keys, sessions, users};
use store::tenancy::TenantContext;

use crate::token::issuance::{Kind, Minted, Minting, mint_token};

/// Short, because an unconfigured realm is not a reason to hand out a
/// long-lived credential.
const DEFAULT_ACCESS_LIFESPAN: i64 = 300;

/// Renewed on every use, so an active client never reaches this. What it bounds
/// is how long an abandoned one stays spendable.
const DEFAULT_REFRESH_LIFESPAN: i64 = 1_800;

/// What it takes to sign. All three or none, so a new grant cannot forget one.
pub struct Signing<'a> {
    pub provider: &'a dyn CryptoProvider,
    pub ring: &'a RealmKeyring,
    pub envelope: &'a Envelope,
}

/// Where the grant is happening.
pub struct Within<'a> {
    pub tenant: &'a TenantContext,
    pub realm: &'a RealmModel,
    /// Built from the deployment's origin, so a grant cannot invent one.
    pub issuer: &'a str,
}

/// What a grant produced.
#[derive(Debug)]
pub struct Granted {
    pub access_token: String,
    pub expires_in: i64,
    pub scope: String,
    /// Present when the scope asked for `openid`. A record of a login and never
    /// a credential.
    pub id_token: Option<String>,
    /// Present when the grant is one that may be renewed without the user.
    pub refresh_token: Option<String>,
}

/// Why nothing was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Ungranted {
    /// The client may authenticate and may not have this grant.
    #[error("this client may not use this grant")]
    Unauthorized,
    /// Never minted, already spent, another client's, another redirect's, or a
    /// proof that does not check out. One variant, or a client could learn
    /// whether a code it does not hold exists.
    #[error("the grant presented was not honoured")]
    InvalidGrant,
    /// It may, and the realm has nothing to sign with.
    #[error("the realm has no key to sign with")]
    NoKey,
    #[error("the token could not be minted")]
    Unmintable,
    #[error("the store could not be read")]
    Unreadable,
}

/// A client acting for itself, RFC 6749 §4.4.
///
/// The account it acts as is a real user. A machine token carrying no subject
/// would be a second kind of caller for every gate to learn, and the ones that
/// had not learned it would be the holes.
pub async fn client_credentials(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    within: &Within<'_>,
    client: &ClientModel,
    now: DateTime<Utc>,
) -> Result<Granted, Ungranted> {
    // §4.4: authentication by credential alone, and a public client has none it
    // can keep.
    if client.public_client == Some(true) || client.service_account_enabled != Some(true) {
        return Err(Ungranted::Unauthorized);
    }

    let account = users::load_service_account(transaction, &client.client_id)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::Unauthorized)?;

    // The lever an operator reaches for first, and it outranks the
    // registration.
    if !account.enabled {
        return Err(Ungranted::Unauthorized);
    }

    let lifespan = Duration::seconds(
        within
            .realm
            .access_token_lifespan
            .map_or(DEFAULT_ACCESS_LIFESPAN, i64::from),
    );

    let session_id = draw_session_id(signing.provider)?;
    open_login(
        transaction,
        within.tenant,
        &account.user_id,
        &account.user_name,
        &session_id,
        client,
        now,
        lifespan,
    )
    .await?;

    let key = realm_keys::active(transaction, signing.ring, signing.envelope, KeyUse::Sig)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::NoKey)?;

    // Its own audience, so no downstream check has to decide what an absent one
    // means.
    let scope = String::new();
    let minted: Minted = mint_token(
        signing.provider,
        &key,
        Minting {
            kind: Kind::Access,
            issuer: within.issuer,
            subject: &account.user_id,
            audiences: vec![client.client_id.clone()],
            party: &client.client_id,
            session_id: &session_id,
            scope: &scope,
            lifespan,
            now,
            extra: serde_json::Map::new(),
        },
    )
    .map_err(|_| Ungranted::Unmintable)?;

    Ok(Granted {
        access_token: minted.token,
        expires_in: lifespan.num_seconds(),
        scope,
        id_token: None,
        refresh_token: None,
    })
}

/// What a client presents to spend a code.
#[derive(Debug)]
pub struct Redeeming<'a> {
    pub code: &'a str,
    pub redirect_uri: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
}

/// Spending an authorization code, RFC 6749 §4.1.3 and OIDC Core §3.1.3.
///
/// Spent by the attempt, not by the attempt succeeding: every refusal below
/// happens after the row is gone.
pub async fn authorization_code(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    within: &Within<'_>,
    client: &ClientModel,
    redeeming: &Redeeming<'_>,
    now: DateTime<Utc>,
) -> Result<Granted, Ungranted> {
    let digest = code_digest(signing.provider, redeeming.code.as_bytes())?;
    let code = oidc::redeem_code(transaction, &digest)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::InvalidGrant)?;

    if code.client_id != client.client_id {
        return Err(Ungranted::InvalidGrant);
    }
    // Against the value the code was minted with, not the registered set: two
    // registered redirects would otherwise be interchangeable.
    if redeeming.redirect_uri != Some(code.redirect_uri.as_str()) {
        return Err(Ungranted::InvalidGrant);
    }
    verify_code_challenge(signing.provider, client, &code, redeeming.code_verifier)?;

    // A code outlives nothing. Logging out between authorizing and redeeming
    // would leave these tokens naming a session no gate can find.
    let login = sessions::load(transaction, &code.session_id)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .filter(|login| login.state == UserSessionState::LoggedIn)
        .ok_or(Ungranted::InvalidGrant)?;

    let lifespan = Duration::seconds(
        within
            .realm
            .access_token_lifespan
            .map_or(DEFAULT_ACCESS_LIFESPAN, i64::from),
    );
    let renewal = Duration::seconds(DEFAULT_REFRESH_LIFESPAN);

    let minting_for = |kind: Kind, life: Duration, audiences: Vec<String>| Minting {
        kind,
        issuer: within.issuer,
        subject: &code.user_id,
        audiences,
        party: &client.client_id,
        session_id: &code.session_id,
        scope: &code.scope,
        lifespan: life,
        now,
        extra: serde_json::Map::new(),
    };

    // Once. Three reads are three chances for a rotation to land between them.
    let key = active_signing_key(transaction, signing).await?;
    let access = mint_token(
        signing.provider,
        &key,
        minting_for(Kind::Access, lifespan, vec![client.client_id.clone()]),
    )
    .map_err(|_| Ungranted::Unmintable)?;

    let refresh = mint_token(
        signing.provider,
        &key,
        minting_for(Kind::Refresh, renewal, vec![client.client_id.clone()]),
    )
    .map_err(|_| Ungranted::Unmintable)?;

    let id_token = code
        .scope
        .split_whitespace()
        .any(|scope| scope == "openid")
        .then(|| {
            let mut minting = minting_for(Kind::Identity, lifespan, vec![client.client_id.clone()]);
            // `auth_time` is the login's instant, not this one: the question is
            // how recently the user authenticated.
            minting
                .extra
                .insert("auth_time".into(), Value::from(code.auth_time));
            if let Some(nonce) = &code.nonce {
                minting
                    .extra
                    .insert("nonce".into(), Value::from(nonce.as_str()));
            }
            if let Some(acr) = &code.acr {
                minting
                    .extra
                    .insert("acr".into(), Value::from(acr.as_str()));
            }
            if let Some(org) = &code.org_id {
                minting
                    .extra
                    .insert("org_id".into(), Value::from(org.as_str()));
            }
            mint_token(signing.provider, &key, minting)
        })
        .transpose()
        .map_err(|_| Ungranted::Unmintable)?;

    // Anchored by the refresh token's own identifier, so a later presentation
    // is compared against what was handed out.
    sessions::open_client_session(
        transaction,
        &ClientSessionModel {
            tenant: within.tenant.tenant.clone(),
            session_id: refresh.token_id.clone(),
            realm_id: within.tenant.realm_id.clone(),
            user_session_id: login.session_id.clone(),
            user_id: code.user_id.clone(),
            client_id: client.client_id.clone(),
            auth_method: Some("authorization_code".to_owned()),
            redirect_uri: Some(code.redirect_uri.clone()),
            started_at: now.timestamp(),
            expiration: Some((now + renewal).timestamp()),
            notes: None,
            current_refresh_token: Some(refresh.token_id.clone()),
            current_refresh_token_use_count: Some(0),
            offline: Some(false),
        },
    )
    .await
    .map_err(|_| Ungranted::Unreadable)?;

    Ok(Granted {
        access_token: access.token,
        expires_in: lifespan.num_seconds(),
        scope: code.scope.clone(),
        id_token: id_token.map(|minted| minted.token),
        refresh_token: Some(refresh.token),
    })
}

/// Whether the caller holds what the code was minted against.
///
/// A public client authenticates with nothing, so this is the whole of its
/// proof. A code from one carrying no challenge is one anybody who intercepted
/// the redirect can spend.
fn verify_code_challenge(
    provider: &dyn CryptoProvider,
    client: &ClientModel,
    code: &AuthorizationCode,
    verifier: Option<&str>,
) -> Result<(), Ungranted> {
    let Some(challenge) = code.code_challenge.as_deref() else {
        return match client.public_client {
            Some(true) => Err(Ungranted::InvalidGrant),
            _ => Ok(()),
        };
    };
    let verifier = verifier.ok_or(Ungranted::InvalidGrant)?;

    let offered = match code.code_challenge_method.as_deref() {
        Some("S256") => BASE64URL_NOPAD.encode(&sha256(provider, verifier.as_bytes())?),
        // RFC 7636 §4.2. Named rather than defaulted: an unknown method must
        // not fall back to comparing the verifier against the challenge.
        Some("plain") | None => verifier.to_owned(),
        Some(_) => return Err(Ungranted::InvalidGrant),
    };

    constant_time::eq(offered.as_bytes(), challenge.as_bytes())
        .then_some(())
        .ok_or(Ungranted::InvalidGrant)
}

async fn active_signing_key(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
) -> Result<RealmSigningKey, Ungranted> {
    realm_keys::active(transaction, signing.ring, signing.envelope, KeyUse::Sig)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::NoKey)
}

fn sha256(provider: &dyn CryptoProvider, data: &[u8]) -> Result<Vec<u8>, Ungranted> {
    provider
        .digest()
        .hash(HashAlg::Sha256, data)
        .map_err(|_| Ungranted::Unmintable)
}

/// Hex, as the model states, so minting and presenting land on one key.
fn code_digest(provider: &dyn CryptoProvider, data: &[u8]) -> Result<String, Ungranted> {
    Ok(HEXLOWER.encode(&sha256(provider, data)?))
}

/// Write the login the token is bound to. Both rows: the gate refuses a token
/// whose login is missing, and a logout walks the client session.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one login"
)]
async fn open_login(
    transaction: &Transaction<'_>,
    tenant: &TenantContext,
    user_id: &str,
    user_name: &str,
    session_id: &str,
    client: &ClientModel,
    now: DateTime<Utc>,
    lifespan: Duration,
) -> Result<(), Ungranted> {
    let expiry = (now + lifespan).timestamp();

    // Tenant and realm off the transaction's context, never off the request:
    // these inserts bind them from the model and RLS refuses silently.
    sessions::open(
        transaction,
        &UserSessionModel {
            tenant: tenant.tenant.clone(),
            session_id: session_id.to_owned(),
            realm_id: tenant.realm_id.clone(),
            user_id: user_id.to_owned(),
            login_username: user_name.to_owned(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: Some("client_credentials".to_owned()),
            ip_address: None,
            started_at: now.timestamp(),
            auth_time: Some(now.timestamp()),
            // A secret authenticates no person, so a level here would be a
            // claim nobody made.
            loa: None,
            expiration: Some(expiry),
            state: UserSessionState::LoggedIn,
            remember_me: Some(false),
            last_session_refresh: None,
            is_offline: Some(false),
            notes: None,
        },
    )
    .await
    .map_err(|_| Ungranted::Unreadable)?;

    sessions::open_client_session(
        transaction,
        &ClientSessionModel {
            tenant: tenant.tenant.clone(),
            session_id: session_id.to_owned(),
            realm_id: tenant.realm_id.clone(),
            user_session_id: session_id.to_owned(),
            user_id: user_id.to_owned(),
            client_id: client.client_id.clone(),
            auth_method: Some("client_credentials".to_owned()),
            redirect_uri: None,
            started_at: now.timestamp(),
            expiration: Some(expiry),
            notes: None,
            // §4.4.3. The client can ask again with what it already holds, so
            // this would be a second credential for one authority.
            current_refresh_token: None,
            current_refresh_token_use_count: Some(0),
            offline: Some(false),
        },
    )
    .await
    .map_err(|_| Ungranted::Unreadable)
}

fn draw_session_id(provider: &dyn CryptoProvider) -> Result<String, Ungranted> {
    let mut bytes = [0_u8; 16];
    provider
        .rand()
        .fill(&mut bytes)
        .map_err(|_| Ungranted::Unmintable)?;
    Ok(bytes
        .iter()
        .fold(String::with_capacity(32), |mut id, byte| {
            use std::fmt::Write as _;
            let _ = write!(id, "{byte:02x}");
            id
        }))
}
