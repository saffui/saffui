//! The public keys of a realm, and the private key that signs for it.

use serde::Serialize;
use serde_json::Value;

use super::{SIGNING_KEY_PURPOSE, SigningKey};
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ports::crypto::{SealPlace, SignatureAlgorithm};
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::RealmScope;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeySet {
    pub keys: Vec<Value>,
}

/// The key set a realm publishes: the public half of each of its keys.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn publish_key_set(app: &App, scope: RealmScope) -> Result<KeySet, Failure> {
    let mut work = app.storage.begin(scope).await?;
    let keys = work.list_signing_keys().await?;
    Ok(KeySet {
        keys: keys.into_iter().map(|key| key.public_jwk).collect(),
    })
}

/// The key that signs for the realm in `algorithm`, the newest of them, with
/// its private half opened.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the realm has no key of that
/// algorithm, or when its private half does not open where it is stored.
pub async fn open_signing_key(
    app: &App,
    work: &mut dyn UnitOfWork,
    algorithm: SignatureAlgorithm,
) -> Result<(SigningKey, Secret), Failure> {
    let scope = work.scope();
    let unavailable = |detail: &str| Failure::with_detail(ErrorCode::CryptoUnavailable, detail);

    let key = work
        .list_signing_keys()
        .await?
        .into_iter()
        .rfind(|key| key.algorithm == algorithm)
        .ok_or_else(|| unavailable("the realm has no signing key of this algorithm"))?;
    let data_key = work
        .read_data_key()
        .await?
        .ok_or_else(|| unavailable("the realm has no data key"))?;
    let place = SealPlace {
        tenant: scope.tenant().as_uuid(),
        realm: scope.realm().as_uuid(),
        purpose: SIGNING_KEY_PURPOSE,
        row: key.id,
    };
    let private_key = app
        .sealer
        .open(&data_key, &place, &key.sealed_private_key)
        .map_err(|_| unavailable("a signing key does not open where it is stored"))?;
    Ok((key, private_key))
}
