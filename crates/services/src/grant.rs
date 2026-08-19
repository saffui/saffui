//! Turning an authenticated client into tokens.
//!
//! The client is established before anything here runs, so nothing in this
//! module asks who is calling. What it decides is whether that client may have
//! what it asked for, and what the realm says the answer looks like.

use chrono::{DateTime, Duration, Utc};
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use models::entities::keys::KeyUse;
use models::entities::realm::RealmModel;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use store::keyring::RealmKeyring;
use store::providers::{realm_keys, sessions, users};
use store::tenancy::TenantContext;

use crate::token::issuance::{Kind, Minted, Minting, mint_token};

/// What five minutes means when the realm says nothing.
///
/// Short, because the realm not having been configured is not a reason to hand
/// out a long-lived credential. An operator who wants longer says so.
const DEFAULT_ACCESS_LIFESPAN: i64 = 300;

/// What it takes to sign, gathered once.
///
/// Every grant needs all three and none of them alone, so they travel together
/// rather than as arguments a new grant has to remember to thread.
pub struct Signing<'a> {
    pub provider: &'a dyn CryptoProvider,
    pub ring: &'a RealmKeyring,
    pub envelope: &'a Envelope,
}

/// Where the grant is happening.
pub struct Within<'a> {
    pub tenant: &'a TenantContext,
    pub realm: &'a RealmModel,
    /// What the minted token states. Built from the deployment's origin, so a
    /// grant cannot invent one.
    pub issuer: &'a str,
}

/// What a grant produced.
#[derive(Debug)]
pub struct Granted {
    pub access_token: String,
    pub expires_in: i64,
    pub scope: String,
}

/// Why nothing was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Ungranted {
    /// The client may authenticate and may not have this grant.
    #[error("this client may not use this grant")]
    Unauthorized,
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
/// The account it acts as is a real user, and that is the point: everything
/// downstream reads a subject, a login and the roles held by one. A machine
/// token that carried no subject would be a second kind of caller for every
/// gate to learn, and the gates that had not learned it yet would be the holes.
pub async fn client_credentials(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    within: &Within<'_>,
    client: &ClientModel,
    now: DateTime<Utc>,
) -> Result<Granted, Ungranted> {
    // §4.4 confines this grant to confidential clients: it is authentication by
    // credential alone, and a public client has none it can keep.
    if client.public_client == Some(true) || client.service_account_enabled != Some(true) {
        return Err(Ungranted::Unauthorized);
    }

    let account = users::load_service_account(transaction, &client.client_id)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::Unauthorized)?;

    // The realm can switch off an account that a client registration still
    // enables, and that is the lever an operator reaches for first.
    if !account.enabled {
        return Err(Ungranted::Unauthorized);
    }

    let lifespan = Duration::seconds(
        within
            .realm
            .access_token_lifespan
            .map_or(DEFAULT_ACCESS_LIFESPAN, i64::from),
    );

    let session_id = draw_id(signing.provider)?;
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

    // The client is its own audience. A machine token names who it is for like
    // every other token, and leaving it out would make an audience check
    // somewhere downstream decide what an absent one means.
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
    })
}

/// Write the login the token is bound to.
///
/// Both rows, because a token naming a login that is not there is refused by
/// the gate that reads it, and a client session is what a later revocation and
/// a later logout both walk.
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

    // Tenant and realm come off the transaction's context and not off the
    // request: these two inserts bind them from the model, and a model naming
    // another is refused by the rules with nothing saying why.
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
            // No level of assurance. A client presenting a secret has not
            // authenticated a person, and a number here would be a claim about
            // one nobody made.
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
            // §4.4.3: no refresh token. The client holds the credential that
            // produced this one and can ask again, so a refresh token would be
            // a second credential for the same authority with a longer life.
            current_refresh_token: None,
            current_refresh_token_use_count: Some(0),
            offline: Some(false),
        },
    )
    .await
    .map_err(|_| Ungranted::Unreadable)
}

fn draw_id(provider: &dyn CryptoProvider) -> Result<String, Ungranted> {
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
