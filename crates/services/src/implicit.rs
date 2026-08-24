//! What the authorization endpoint hands back itself, OIDC Core §3.2 and §3.3.
//!
//! A code is redeemed in a request nobody else sees. What is minted here
//! crosses a browser instead, so it is short lived and it carries a hash of
//! whatever came back beside it.

use chrono::{DateTime, Duration, Utc};
use models::entities::client::ClientModel;
use models::entities::realm::RealmModel;
use models::sessions::records::ClientSessionModel;
use serde_json::{Map, Value};
use store::providers::{sessions, users};
use store::tenancy::TenantContext;

use crate::detached::half_hash;
use crate::grant::{Signing, identity_key_for};
use crate::response_type::ResponseType;
use crate::token::issuance::{Kind, Minting, mint_token};

/// Short: nothing here proves the client was the one asking.
const DEFAULT_LIFESPAN: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("nothing could be minted here")]
pub struct Unmintable;

/// What the flow established.
pub struct Established<'a> {
    pub client: &'a ClientModel,
    pub realm: &'a RealmModel,
    pub issuer: &'a str,
    pub user_id: &'a str,
    pub session_id: &'a str,
    pub scope: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: i64,
    pub acr: Option<&'a str>,
    /// The code, when one is coming back too.
    pub code: Option<&'a str>,
    /// The `claims` the request named, §5.5, as the store keeps them.
    pub claims: Option<&'a Value>,
}

/// Mint what the response type asks this endpoint for.
///
/// The access token first: the identity token carries its hash, and the other
/// order hashes something that does not exist yet.
pub async fn issue(
    transaction: &deadpool_postgres::Transaction<'_>,
    signing: &Signing<'_>,
    tenant: &TenantContext,
    asked: ResponseType,
    established: &Established<'_>,
    now: DateTime<Utc>,
) -> Result<Vec<(&'static str, String)>, Unmintable> {
    if !asked.mints_here() {
        return Ok(Vec::new());
    }

    let lifespan = Duration::seconds(
        established
            .realm
            .access_token_lifespan
            .map_or(DEFAULT_LIFESPAN, i64::from),
    );
    let key = identity_key_for(transaction, signing, established.client)
        .await
        .map_err(|_| Unmintable)?;

    let told = crate::pairwise::subject_for(
        transaction,
        signing.provider,
        established.client,
        established.user_id,
    )
    .await
    .map_err(|_| Unmintable)?;
    let minting = |kind: Kind, extra: Map<String, Value>| Minting {
        kind,
        issuer: established.issuer,
        subject: &told,
        audiences: vec![established.client.client_id.clone()],
        party: &established.client.client_id,
        session_id: established.session_id,
        scope: established.scope,
        lifespan,
        now,
        extra,
    };

    let mut handed = Vec::new();
    let access = asked
        .token
        .then(|| mint_token(signing.provider, &key, minting(Kind::Access, Map::new())))
        .transpose()
        .map_err(|_| Unmintable)?;
    let mut anchor = access.as_ref().map(|minted| minted.token_id.clone());

    if asked.id_token {
        let mut extra = identity_claims(transaction, asked, established).await?;
        extra.insert("auth_time".into(), Value::from(established.auth_time));
        for (named, value) in [("nonce", established.nonce), ("acr", established.acr)] {
            if let Some(value) = value {
                extra.insert(named.into(), Value::from(value));
            }
        }
        // A client holding two values with no way to pair them is one an
        // attacker hands one of its own.
        if asked.needs_at_hash()
            && let Some(access) = &access
        {
            let hashed =
                half_hash(signing.provider, key.algorithm, &access.token).ok_or(Unmintable)?;
            extra.insert("at_hash".into(), Value::from(hashed));
        }
        if asked.needs_c_hash()
            && let Some(code) = established.code
        {
            let hashed = half_hash(signing.provider, key.algorithm, code).ok_or(Unmintable)?;
            extra.insert("c_hash".into(), Value::from(hashed));
        }
        let minted = mint_token(signing.provider, &key, minting(Kind::Identity, extra))
            .map_err(|_| Unmintable)?;
        anchor.get_or_insert(minted.token_id);
        handed.push(("id_token", minted.token));
    }

    if let Some(anchor) = anchor {
        record_grant(transaction, tenant, established, &anchor, now).await?;
    }
    if let Some(access) = access {
        handed.push(("access_token", access.token));
        handed.push(("token_type", "Bearer".to_owned()));
        handed.push(("expires_in", lifespan.num_seconds().to_string()));
    }
    Ok(handed)
}

/// What the identity token says of the person.
///
/// §5.4 sends what a scope names to the userinfo endpoint, except where the
/// response type is `id_token`: nothing is minted there to reach it with, so
/// the token carries them itself.
async fn identity_claims(
    transaction: &deadpool_postgres::Transaction<'_>,
    asked: ResponseType,
    established: &Established<'_>,
) -> Result<Map<String, Value>, Unmintable> {
    let client_id = &established.client.client_id;
    let mut claims = crate::userinfo::asked_id_token_claims(
        transaction,
        established.claims,
        client_id,
        established.user_id,
    )
    .await
    .map_err(|()| Unmintable)?;
    if asked.code || asked.token {
        return Ok(claims);
    }
    let person = users::load(transaction, established.user_id)
        .await
        .map_err(|_| Unmintable)?
        .ok_or(Unmintable)?;
    let held = crate::userinfo::held_claims(&person);
    claims.extend(crate::userinfo::claims_of_scope(established.scope, &held));
    Ok(claims)
}

/// What this client got out of this login, so a logout finds it and an
/// administrator sees it. No refresh token anchors it: this flow mints none,
/// and a client with no row is one nothing can reach.
///
/// It outlives the access token deliberately. Expired with it, the row would
/// be swept minutes into a login that is still open.
async fn record_grant(
    transaction: &deadpool_postgres::Transaction<'_>,
    tenant: &TenantContext,
    established: &Established<'_>,
    anchor: &str,
    now: DateTime<Utc>,
) -> Result<(), Unmintable> {
    let login = sessions::load(transaction, established.session_id)
        .await
        .map_err(|_| Unmintable)?
        .ok_or(Unmintable)?;
    sessions::open_client_session(
        transaction,
        &ClientSessionModel {
            tenant: tenant.tenant.clone(),
            realm_id: tenant.realm_id.clone(),
            session_id: anchor.to_owned(),
            user_session_id: established.session_id.to_owned(),
            user_id: established.user_id.to_owned(),
            client_id: established.client.client_id.clone(),
            auth_method: Some("implicit".to_owned()),
            redirect_uri: None,
            started_at: now.timestamp(),
            expiration: login.expiration,
            notes: None,
            current_refresh_token: None,
            current_refresh_token_use_count: Some(0),
            offline: Some(false),
            // The userinfo endpoint resolves §5.5 off the row, so a token
            // minted here reaches the same claims a redeemed code would.
            requested_claims: established.claims.cloned(),
        },
    )
    .await
    .map_err(|_| Unmintable)
}
