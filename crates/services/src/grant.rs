use chrono::{DateTime, Duration, Utc};
use crypto::constant_time;
use crypto::envelope::Envelope;
use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use deadpool_postgres::Transaction;
use models::entities::client::ClientModel;
use models::entities::keys::{KeyUse, RealmSigningKey, RealmSigningKeyView};
use models::entities::oidc::AuthorizationCode;
use models::entities::realm::RealmModel;
use models::sessions::records::{ClientSessionModel, UserSessionModel, UserSessionState};
use serde_json::{Map, Value};
use store::keyring::RealmKeyring;
use store::providers::oidc::Redemption;
use store::providers::sessions::Refreshed;
use store::providers::{oidc, realm_keys, sessions, users};
use store::tenancy::TenantContext;

use crate::claims_request::{self, ClaimsRequest};
use crate::token::issuance::{Kind, Minted, Minting, mint_token};
use crate::userinfo;

/// Short, because an unconfigured realm is not a reason to hand out a
/// long-lived credential.
const DEFAULT_ACCESS_LIFESPAN: i64 = 300;

/// Renewed on every use, so an active client never reaches this. What it bounds
/// is how long an abandoned one stays spendable.
const DEFAULT_REFRESH_LIFESPAN: i64 = 1_800;

/// How long the token a rotation replaced is still accepted.
///
/// Short, and it exists for one thing: a client that fired two refreshes at once
/// or retried after a response that never arrived is otherwise indistinguishable
/// from an attacker replaying a stolen token, and reuse detection would destroy
/// its session for a double submit. A stolen token presented later than this
/// still trips it.
const ROTATION_GRACE: i64 = 30;

/// Thirty days. A grant that outlives its login is renewed by something with no
/// user in front of it, so the bound is the grant's own and not a login's.
const DEFAULT_OFFLINE_LIFESPAN: i64 = 2_592_000;

fn offline_or_refresh_lifespan(realm: &models::entities::realm::RealmModel, offline: bool) -> i64 {
    if offline {
        realm
            .offline_session_lifespan
            .map_or(DEFAULT_OFFLINE_LIFESPAN, i64::from)
    } else {
        DEFAULT_REFRESH_LIFESPAN
    }
}

/// Oldest first: nobody is standing in front of the one that has not been
/// renewed in months, and the newest is the one just asked for.
async fn make_room_for_offline(
    transaction: &Transaction<'_>,
    realm: &models::entities::realm::RealmModel,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<(), Ungranted> {
    let cap = usize::try_from(realm.max_offline_grants).unwrap_or(0);
    if cap == 0 {
        return Ok(());
    }
    let held = sessions::offline_grants_of(transaction, user_id, now.timestamp())
        .await
        .map_err(|_| Ungranted::Unreadable)?;
    for over in held.iter().take(held.len().saturating_sub(cap)) {
        sessions::close_client_session(transaction, &over.session_id)
            .await
            .map_err(|_| Ungranted::Unreadable)?;
    }
    Ok(())
}

fn offline_ends_at(realm: &models::entities::realm::RealmModel, started_at: i64) -> Option<i64> {
    (realm.offline_session_max_lifespan > 0)
        .then(|| started_at + i64::from(realm.offline_session_max_lifespan))
}

/// The token's own expiry is this same instant. A client told it holds
/// something with no end, then refused, has nothing to explain it.
fn bounded_end(
    realm: &models::entities::realm::RealmModel,
    offline: bool,
    started_at: i64,
    sliding: i64,
) -> i64 {
    match offline
        .then(|| offline_ends_at(realm, started_at))
        .flatten()
    {
        Some(absolute) => sliding.min(absolute),
        None => sliding,
    }
}

fn holds_offline_access(scope: &str) -> bool {
    scope
        .split_whitespace()
        .any(|held| held == crate::authorize::OFFLINE_ACCESS)
}

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
    /// The key the caller proved holding, RFC 9449. What is minted here may
    /// then only be presented with it. Absent is a bearer token, which is what
    /// every caller that sends no proof still gets.
    pub bound_to: Option<&'a str>,
    /// The certificate a named proxy said this caller presented, RFC 8705 §3,
    /// as its thumbprint. Independent of the line above: a caller may prove
    /// both, and what it is handed then names both.
    pub certified_by: Option<&'a str>,
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
    /// A rotated refresh token presented again. Its own variant because the
    /// answer is not only a refusal: the session is gone.
    #[error("a rotated refresh token was presented again")]
    Replayed,
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
    seen: &crate::provenance::Provenance,
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
        seen,
        now,
        lifespan,
    )
    .await?;

    let key = preferred_key(transaction, signing, SignAlg::Es256).await?;

    // Its own audience, so no downstream check has to decide what an absent one
    // means.
    let scope = String::new();
    let minted: Minted = mint_token(
        signing.provider,
        &key,
        Minting {
            bound_to: within.bound_to.map(str::to_owned),
            certified_by: within.certified_by.map(str::to_owned),
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

/// What a request named for the identity token, of what the realm holds of
/// the person. Nothing asked is nothing resolved, and no reading of the person
/// either.
async fn claims_asked_of(
    transaction: &Transaction<'_>,
    asked: Option<&Value>,
    client_id: &str,
    user_id: &str,
) -> Result<Map<String, Value>, Ungranted> {
    userinfo::asked_id_token_claims(transaction, asked, client_id, user_id)
        .await
        .map_err(|()| Ungranted::Unreadable)
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
    let code = match oidc::redeem_code(transaction, &digest)
        .await
        .map_err(|_| Ungranted::Unreadable)?
    {
        Redemption::Fresh(code) => *code,
        Redemption::Unknown => return Err(Ungranted::InvalidGrant),
        // RFC 6749 §4.1.2: refused, and what the first presentation bought is
        // taken back. Whoever holds those tokens got them from a code that was
        // then presented again, and one of the two presenters was not the
        // client.
        Redemption::Reused { issued_token_ids } => {
            let until = now + Duration::seconds(DEFAULT_REFRESH_LIFESPAN);
            for token_id in &issued_token_ids {
                oidc::revoke(transaction, token_id, until, "authorization code reused")
                    .await
                    .map_err(|_| Ungranted::Unreadable)?;
                // The client session is anchored by the refresh token's own
                // identifier, so closing it ends every renewal descended from
                // it, not only the token in hand.
                sessions::close_client_session(transaction, token_id)
                    .await
                    .map_err(|_| Ungranted::Unreadable)?;
            }
            return Err(Ungranted::InvalidGrant);
        }
    };

    // Checked again here, not only where the code was minted. An operator who
    // switches the flow off expects the codes already in flight to stop working,
    // and a check that only guards the mint leaves them spendable.
    if client.standard_flow_enabled != Some(true) {
        return Err(Ungranted::Unauthorized);
    }
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
    let offline = holds_offline_access(&code.scope);
    let renewal = Duration::seconds(offline_or_refresh_lifespan(within.realm, offline));

    // What the request named for the identity token, §5.5, of what the realm
    // holds of this person. Resolved now and not carried on the refresh token:
    // a claim about a person is the person's current value, not the value at
    // the login, and the request itself is what the client session keeps.
    let asked_of_person = claims_asked_of(
        transaction,
        code.claims.as_ref(),
        &client.client_id,
        &code.user_id,
    )
    .await?;

    // §8: what this client calls the account, which is its own identifier
    // unless the client asked to be told a different one from every sector.
    let told = crate::pairwise::subject_for(transaction, signing.provider, client, &code.user_id)
        .await
        .map_err(|_| Ungranted::Unreadable)?;
    let minting_for = |kind: Kind, life: Duration, audiences: Vec<String>| Minting {
        bound_to: within.bound_to.map(str::to_owned),
        certified_by: within.certified_by.map(str::to_owned),
        kind,
        issuer: within.issuer,
        subject: &told,
        audiences,
        party: &client.client_id,
        session_id: &code.session_id,
        scope: &code.scope,
        lifespan: life,
        now,
        extra: serde_json::Map::new(),
    };

    // Once each. Three reads are three chances for a rotation to land between
    // them. The identity token is signed as the client registered, RS256
    // unless it said; the others with the realm's own preference.
    let key = preferred_key(transaction, signing, SignAlg::Es256).await?;
    let identity_key = identity_key_for(transaction, signing, client).await?;
    let access = mint_token(
        signing.provider,
        &key,
        minting_for(Kind::Access, lifespan, vec![client.client_id.clone()]),
    )
    .map_err(|_| Ungranted::Unmintable)?;

    // The claims a renewal reissues from. Carried on the refresh token because a
    // renewal must not resolve them again: a step up in another tab would raise
    // `acr` on a chain whose holder never performed it.
    let mut renewing = minting_for(Kind::Refresh, renewal, vec![client.client_id.clone()]);
    renewing
        .extra
        .insert("auth_time".into(), Value::from(code.auth_time));
    for (named, value) in [("acr", &code.acr), ("org_id", &code.org_id)] {
        if let Some(value) = value {
            renewing
                .extra
                .insert(named.into(), Value::from(value.as_str()));
        }
    }
    let refresh =
        mint_token(signing.provider, &key, renewing).map_err(|_| Ungranted::Unmintable)?;

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
            minting.extra.extend(asked_of_person.clone());
            mint_token(signing.provider, &identity_key, minting)
        })
        .transpose()
        .map_err(|_| Ungranted::Unmintable)?;

    // Remembered against the code, so a second presentation of it can take
    // these back.
    oidc::record_issued(
        transaction,
        &digest,
        &[access.token_id.clone(), refresh.token_id.clone()],
    )
    .await
    .map_err(|_| Ungranted::Unreadable)?;

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
            offline: Some(offline),
            requested_claims: code.claims.clone(),
        },
    )
    .await
    .map_err(|_| Ungranted::Unreadable)?;

    if offline {
        make_room_for_offline(transaction, within.realm, &code.user_id, now).await?;
    }

    Ok(Granted {
        access_token: access.token,
        expires_in: lifespan.num_seconds(),
        scope: code.scope.clone(),
        id_token: id_token
            .map(|minted| crate::encryption::identity_for(client, minted.token))
            .transpose()
            .map_err(|_| Ungranted::Unmintable)?,
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

    // S256 or nothing. `plain` compares the verifier against the challenge, and
    // the challenge travelled in the authorize request, so whoever saw that
    // request holds the answer. `/authorize` mints no code without S256, so a
    // code carrying anything else was not minted here.
    let Some("S256") = code.code_challenge_method.as_deref() else {
        return Err(Ungranted::InvalidGrant);
    };
    let offered = BASE64URL_NOPAD.encode(&sha256(provider, verifier.as_bytes())?);

    constant_time::eq(offered.as_bytes(), challenge.as_bytes())
        .then_some(())
        .ok_or(Ungranted::InvalidGrant)
}

/// The active key of this algorithm, or of any when the realm has none of it.
async fn preferred_key(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    algorithm: SignAlg,
) -> Result<RealmSigningKey, Ungranted> {
    for wanted in [Some(algorithm), None] {
        let found = realm_keys::active(
            transaction,
            signing.ring,
            signing.envelope,
            KeyUse::Sig,
            wanted,
        )
        .await
        .map_err(|_| Ungranted::Unreadable)?;
        if let Some(key) = found {
            return Ok(key);
        }
    }
    Err(Ungranted::NoKey)
}

/// The key an identity token for this client is signed with: what it
/// registered, and nothing else when it did; OIDC Core §2's RS256 when it did
/// not, falling back to what the realm has.
pub async fn identity_key_for(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    client: &ClientModel,
) -> Result<RealmSigningKey, Ungranted> {
    match client.id_token_signed_response_alg {
        Some(registered) => realm_keys::active(
            transaction,
            signing.ring,
            signing.envelope,
            KeyUse::Sig,
            Some(registered),
        )
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::NoKey),
        None => preferred_key(transaction, signing, SignAlg::Rs256).await,
    }
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
    seen: &crate::provenance::Provenance,
    now: DateTime<Utc>,
    lifespan: Duration,
) -> Result<(), Ungranted> {
    let expiry = (now + lifespan).timestamp();

    // Tenant and realm off the transaction's context, never off the request:
    // these inserts bind them from the model and RLS refuses silently.
    sessions::open(
        transaction,
        &UserSessionModel {
            // No browser took part, so nothing in one is watching this login.
            browser_state: None,
            tenant: tenant.tenant.clone(),
            session_id: session_id.to_owned(),
            realm_id: tenant.realm_id.clone(),
            user_id: user_id.to_owned(),
            login_username: user_name.to_owned(),
            broker_session_id: None,
            broker_user_id: None,
            auth_method: Some("client_credentials".to_owned()),
            ip_address: seen.address.clone(),
            user_agent: seen.agent.clone(),
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
            requested_claims: None,
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

/// What a client presents to renew.
#[derive(Debug)]
pub struct Renewing<'a> {
    pub refresh_token: &'a str,
    /// The realm's published keys. The token is one this realm signed, so it is
    /// verified the way any presented token is.
    pub keys: &'a [RealmSigningKeyView],
}

/// Renewing without the user, RFC 6749 §6.
///
/// Everything the reissue needs rides on the presented token rather than being
/// resolved afresh. A refresh does not re-authenticate, so reading the session
/// again would re-stamp a strength this chain never established: a step up in
/// another tab would raise `acr` on a token whose holder never performed it.
pub async fn refresh_token(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    within: &Within<'_>,
    client: &ClientModel,
    renewing: &Renewing<'_>,
    now: DateTime<Utc>,
) -> Result<Granted, Ungranted> {
    let verified = crate::token::verify_presented(
        transaction,
        renewing.keys,
        renewing.refresh_token,
        crate::token::Binding::Presented(crate::token::Proofs::none()),
        now,
    )
    .await
    .map_err(|_| Ungranted::InvalidGrant)?;

    // An access token must not renew anything. Without this the longest-lived
    // credential a client holds is whichever of its tokens lives longest.
    if claim(&verified, "typ") != Some(Kind::Refresh.claimed()) {
        return Err(Ungranted::InvalidGrant);
    }
    // Issued to the client that is presenting it. A token is a bearer thing, so
    // the only thing tying it to a client is what it says about one.
    if claim(&verified, "azp") != Some(client.client_id.as_str()) {
        return Err(Ungranted::InvalidGrant);
    }
    let (Some(session_id), Some(presented_id)) =
        (claim(&verified, "sid"), verified.token_id.as_deref())
    else {
        return Err(Ungranted::InvalidGrant);
    };

    let login = sessions::load(transaction, session_id)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .ok_or(Ungranted::InvalidGrant)?;

    // By client, which is unambiguous: one login holds one row per client, and
    // a token further back than the row remembers has to reach the rotation to
    // be recognised as the replay it is.
    let client_session = sessions::client_sessions_of(transaction, &login.session_id)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .into_iter()
        .find(|session| session.client_id == client.client_id)
        .ok_or(Ungranted::InvalidGrant)?;

    // Every grant has its own end, and it is the one this row holds. Reading
    // only the login's would keep renewing a grant that ran out under a login
    // that has not.
    let offline = client_session.offline == Some(true);
    let ended = client_session
        .expiration
        .is_some_and(|ends| ends <= now.timestamp())
        // And the login's, except for the one grant that outlives a login,
        // §11. Without this a logout ends nothing.
        || (!offline
            && (login.state != UserSessionState::LoggedIn
                || login.expiration.is_some_and(|ends| ends <= now.timestamp())));
    if ended {
        return Err(Ungranted::InvalidGrant);
    }

    // The account can be switched off between two renewals, and that is how an
    // administrator shuts down a compromised one. Honouring it at login only
    // leaves it live for as long as its refresh token lasts.
    let account = crate::pairwise::account_for(transaction, Some(client), &verified.subject)
        .await
        .map_err(|_| Ungranted::InvalidGrant)?;
    let subject = users::load(transaction, &account)
        .await
        .map_err(|_| Ungranted::Unreadable)?
        .filter(|user| user.enabled)
        .ok_or(Ungranted::InvalidGrant)?;

    // What the request named for the identity token, §5.5, resolved again
    // from the person: their current values, off the request the client
    // session kept.
    let asked_of_person = match client_session.requested_claims.as_ref() {
        Some(asked) => {
            let entitled = userinfo::entitled_scopes(transaction, &client.client_id)
                .await
                .map_err(|_| Ungranted::Unreadable)?;
            userinfo::within_entitlement(
                claims_request::release(
                    &ClaimsRequest::from_value(asked).id_token,
                    &userinfo::held_claims(&subject),
                ),
                &entitled,
            )
        }
        None => Map::new(),
    };

    // The same cut the gate applies. Without it this endpoint keeps minting for
    // a subject whose tokens were all invalidated, and every one of them is
    // refused at the first resource it is presented to.
    let minted_at = verified.claims.get("iat").and_then(Value::as_i64);
    if subject
        .not_before
        .is_some_and(|cut| minted_at.is_none_or(|issued| issued < cut))
    {
        return Err(Ungranted::InvalidGrant);
    }

    let lifespan = Duration::seconds(
        within
            .realm
            .access_token_lifespan
            .map_or(DEFAULT_ACCESS_LIFESPAN, i64::from),
    );
    // Held back by the absolute bound where the realm set one, so the token
    // states the instant the grant actually ends rather than one past it.
    let renewal = Duration::seconds(
        bounded_end(
            within.realm,
            offline,
            client_session.started_at,
            (now + Duration::seconds(offline_or_refresh_lifespan(within.realm, offline)))
                .timestamp(),
        ) - now.timestamp(),
    );
    // A grant already past its ceiling renews nothing. Refused as a grant that
    // is over, not as one nobody recognises.
    if renewal <= Duration::zero() {
        return Err(Ungranted::InvalidGrant);
    }
    let scope = verified.scope.clone();
    let key = preferred_key(transaction, signing, SignAlg::Es256).await?;
    let identity_key = identity_key_for(transaction, signing, client).await?;

    let told =
        crate::pairwise::subject_for(transaction, signing.provider, client, &subject.user_id)
            .await
            .map_err(|_| Ungranted::Unreadable)?;
    let minting_for = |kind: Kind, life: Duration| Minting {
        bound_to: within.bound_to.map(str::to_owned),
        certified_by: within.certified_by.map(str::to_owned),
        kind,
        issuer: within.issuer,
        subject: &told,
        audiences: vec![client.client_id.clone()],
        party: &client.client_id,
        session_id,
        scope: &scope,
        lifespan: life,
        now,
        extra: serde_json::Map::new(),
    };

    // Rotation unless the realm has said otherwise. A realm that has said
    // nothing gets the recommendation rather than the older behaviour: a token
    // that never changes is one an interception keeps forever.
    let rotates = within.realm.revoke_refresh_token != Some(false);
    let successor = rotates
        .then(|| mint_token(signing.provider, &key, minting_for(Kind::Refresh, renewal)))
        .transpose()
        .map_err(|_| Ungranted::Unmintable)?;

    // The comparison is the write. Two renewals racing both name the same token
    // and the second re-reads a row that no longer holds it, so there is no
    // window between deciding and rotating for one to land in.
    match sessions::advance_refresh_token(
        transaction,
        &client_session.session_id,
        presented_id,
        successor.as_ref().map(|minted| minted.token_id.as_str()),
        now,
        now - Duration::seconds(ROTATION_GRACE),
    )
    .await
    .map_err(|_| Ungranted::Unreadable)?
    {
        Refreshed::Rotated { .. } => {}
        // A realm that does not rotate bounds how often one token may be
        // presented instead. Absent means unbounded, which is what not rotating
        // asks for.
        // The count includes this presentation, and the budget is for reuses,
        // so the first one has to spend nothing: comparing the count itself
        // refuses every token on a realm that allows no reuse, which is the
        // default and would mean nothing may refresh at all.
        Refreshed::Reused { presentations, .. } => {
            if within
                .realm
                .refresh_token_max_reuse
                .is_some_and(|allowed| presentations.saturating_sub(1) > allowed)
            {
                return Err(Ungranted::InvalidGrant);
            }
        }
        // Verified, names this session, and is not the token the session holds.
        // That is a rotated token being replayed, so the session ends rather
        // than this one request being refused.
        Refreshed::Replayed => {
            // The family, not the login. RFC 9700 4.14.2 revokes the tokens of
            // the client and user the replayed token belongs to; ending the SSO
            // session would sign the user out of every other client, which makes
            // one stale token a way to do that on demand.
            //
            // Closing the row strands the whole chain: the successor is anchored
            // nowhere, and the access tokens already handed out name a client
            // session the gate can no longer find. The failures are returned
            // rather than swallowed, or a store fault would answer exactly like
            // an ordinary refusal with nothing written.
            sessions::close_client_session(transaction, &client_session.session_id)
                .await
                .map_err(|_| Ungranted::Unreadable)?;
            oidc::revoke(
                transaction,
                presented_id,
                now + renewal,
                "refresh token reuse",
            )
            .await
            .map_err(|_| Ungranted::Unreadable)?;
            return Err(Ungranted::Replayed);
        }
        Refreshed::Unknown => return Err(Ungranted::InvalidGrant),
    }

    // The bound slides, so what has to stay inside the window is the gap
    // between two renewals and not the age of the grant. Which is what an
    // offline grant needs, since it is held by something that may be away for
    // weeks, and what an online one needed too: its end was written once and
    // never moved, so checking it would have ended every grant at the first
    // renewal past the first window.
    //
    // A realm may put a ceiling over the sliding window, and then the grant
    // ends at the earlier of the two.
    sessions::extend_client_session(
        transaction,
        &client_session.session_id,
        (now + renewal).timestamp(),
    )
    .await
    .map_err(|_| Ungranted::Unreadable)?;

    let access = mint_token(signing.provider, &key, minting_for(Kind::Access, lifespan))
        .map_err(|_| Ungranted::Unmintable)?;

    let id_token = wants_openid(&scope)
        .then(|| {
            let mut minting = minting_for(Kind::Identity, lifespan);
            // Carried, not resolved again. A nonce belongs to the authentication
            // that asked for it and means nothing on a renewal, so it is the one
            // claim deliberately dropped.
            for named in ["auth_time", "acr", "org_id"] {
                if let Some(value) = verified.claims.get(named) {
                    minting.extra.insert(named.to_owned(), value.clone());
                }
            }
            minting.extra.extend(asked_of_person.clone());
            mint_token(signing.provider, &identity_key, minting)
        })
        .transpose()
        .map_err(|_| Ungranted::Unmintable)?;

    Ok(Granted {
        access_token: access.token,
        expires_in: lifespan.num_seconds(),
        scope,
        id_token: id_token
            .map(|minted| crate::encryption::identity_for(client, minted.token))
            .transpose()
            .map_err(|_| Ungranted::Unmintable)?,
        // Absent when the realm does not rotate, which RFC 6749 5.1 reads as
        // "keep the one you have".
        refresh_token: successor.map(|minted| minted.token),
    })
}

fn claim<'a>(verified: &'a crate::token::Verified, named: &str) -> Option<&'a str> {
    verified.claims.get(named).and_then(Value::as_str)
}

fn wants_openid(scope: &str) -> bool {
    scope.split_whitespace().any(|asked| asked == "openid")
}
