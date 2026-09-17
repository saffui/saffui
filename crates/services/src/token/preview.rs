use std::collections::BTreeMap;

use chrono::{Duration, Utc};
use crypto::provider::SignAlg;
use deadpool_postgres::Transaction;
use models::entities::realm::RealmModel;
use serde_json::{Map, Value};
use store::keyring::Signing;

use crate::grant::{DEFAULT_ACCESS_LIFESPAN, identity_key_for, preferred_key};
use crate::token::issuance::{Kind, Minting, token_body, token_header};

/// One token as it would look: the header the key would write, and the body
/// the assembly would produce. There is no third part, because nothing signed.
pub struct Shown {
    pub header: Map<String, Value>,
    pub body: Map<String, Value>,
}

/// What a grant would carry, without the grant happening.
pub struct Foreseen {
    pub access: Shown,
    /// Absent unless the scope asks for openid, exactly as issuance decides.
    pub identity: Option<Shown>,
    /// The mapper that wrote each claim, by claim name. Nothing names the
    /// claims the assembly writes itself, which is how a reader tells a
    /// registered rule from what every token carries.
    pub authors: BTreeMap<String, String>,
}

/// The claims whose value cannot exist before there is a login and a minting.
///
/// Named so nobody reads the placeholder as the value they will be handed. The
/// times beside them are real: a preview is asked now, and now is when the
/// window it shows would open.
pub const DRAWN_AT_ISSUANCE: [&str; 2] = ["jti", "sid"];

/// Why nothing could be foreseen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unforeseeable {
    #[error("no such client in this realm")]
    NoSuchClient,
    #[error("the realm holds no key to name")]
    NoKey,
    #[error("the realm could not be read")]
    Unreadable,
}

/// What this client would be handed for this person, assembled and unsigned.
///
/// The bodies come off the same function issuance calls, so what is shown here
/// is what would be written rather than a second rendering kept alike by hand.
/// Nothing is signed and nothing is recorded: a preview that produced a token
/// would be a way for whoever may read a client to become anybody in it.
pub async fn foresee(
    transaction: &Transaction<'_>,
    signing: &Signing<'_>,
    realm: &RealmModel,
    issuer: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
) -> Result<Foreseen, Unforeseeable> {
    let client = store::providers::clients::load(transaction, client_id)
        .await
        .map_err(|_| Unforeseeable::Unreadable)?
        .ok_or(Unforeseeable::NoSuchClient)?;

    // §8: what this client calls the account, which is its own identifier
    // unless it asked to be told a different one from every sector. A preview
    // that showed the raw identifier would show a subject this client never
    // sees.
    let told = crate::pairwise::subject_for(transaction, signing.provider, &client, user_id)
        .await
        .map_err(|_| Unforeseeable::Unreadable)?;

    let overlay = crate::mappers::overlay_for(transaction, client_id, user_id, scope)
        .await
        .map_err(|()| Unforeseeable::Unreadable)?;
    let authors = crate::mappers::preview(transaction, client_id, user_id, scope)
        .await
        .map_err(|()| Unforeseeable::Unreadable)?
        .into_iter()
        .map(|row| (row.claim, row.origin))
        .collect();

    let now = Utc::now();
    let lifespan = Duration::seconds(
        realm
            .access_token_lifespan
            .map_or(DEFAULT_ACCESS_LIFESPAN, i64::from),
    );
    let expires_at = now + lifespan;

    let minting_for = |kind: Kind, audiences: Vec<String>, extra: Map<String, Value>| Minting {
        kind,
        issuer,
        subject: &told,
        audiences,
        party: &client.client_id,
        // No login stands behind a preview, and none is opened to answer one.
        session_id: "",
        scope,
        lifespan,
        now,
        extra,
        // Presented by nobody, so bound to nothing. A preview cannot know the
        // key or the certificate a caller would prove, and inventing one would
        // say this token is bound when the minted one may not be.
        bound_to: None,
        certified_by: None,
    };

    let key = preferred_key(transaction, signing, SignAlg::Es256)
        .await
        .map_err(|_| Unforeseeable::NoKey)?;
    let mut access_audiences = vec![client.client_id.clone()];
    crate::mappers::widen(&mut access_audiences, &overlay.access_audiences);
    let access_body = token_body(
        minting_for(Kind::Access, access_audiences, overlay.access.clone()),
        "",
        expires_at,
    )
    .map_err(|_| Unforeseeable::NoKey)?;
    let access = Shown {
        header: token_header(Kind::Access, &key).claims_set().clone(),
        body: access_body.claims_set().clone(),
    };

    // Exactly as issuance decides it: no openid in the scope, no identity
    // token, and a preview that showed one anyway would promise a token this
    // grant would never produce.
    let identity = if scope.split_whitespace().any(|named| named == "openid") {
        let identity_key = identity_key_for(transaction, signing, &client)
            .await
            .map_err(|_| Unforeseeable::NoKey)?;
        let mut audiences = vec![client.client_id.clone()];
        crate::mappers::widen(&mut audiences, &overlay.identity_audiences);
        let body = token_body(
            minting_for(Kind::Identity, audiences, overlay.identity.clone()),
            "",
            expires_at,
        )
        .map_err(|_| Unforeseeable::NoKey)?;
        Some(Shown {
            header: token_header(Kind::Identity, &identity_key)
                .claims_set()
                .clone(),
            body: body.claims_set().clone(),
        })
    } else {
        None
    };

    Ok(Foreseen {
        access,
        identity,
        authors,
    })
}
