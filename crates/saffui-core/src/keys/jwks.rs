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

/// The key set a realm publishes: the public half of each of its keys, the
/// retired ones included, in the algorithms this build signs in.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn publish_key_set(app: &App, scope: RealmScope) -> Result<KeySet, Failure> {
    let mut work = app.storage.begin(scope).await?;
    let keys = work.list_signing_keys().await?;
    Ok(KeySet {
        keys: keys
            .into_iter()
            .filter(|key| app.signer.signs_in(key.algorithm))
            .map(|key| key.public_jwk)
            .collect(),
    })
}

/// The keys that sign for the realm in each of `algorithms`, in that
/// order, with their private halves opened: one read of the keys, and one of
/// the data key. Only the active key of an algorithm signs: a token is never
/// signed in another algorithm than the one asked.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when the realm has no active key
/// of one of them, when this build does not sign in one, or when a private
/// half does not open where it is stored.
pub async fn open_signing_keys(
    app: &App,
    work: &mut dyn UnitOfWork,
    algorithms: &[SignatureAlgorithm],
) -> Result<Vec<(SigningKey, Secret)>, Failure> {
    let scope = work.scope();
    let unavailable = |detail: &str| Failure::with_detail(ErrorCode::CryptoUnavailable, detail);
    if !algorithms
        .iter()
        .all(|algorithm| app.signer.signs_in(*algorithm))
    {
        return Err(unavailable("this build does not sign in this algorithm"));
    }

    let mut active = work.read_active_keys(algorithms).await?;
    let data_key = work
        .read_data_key()
        .await?
        .ok_or_else(|| unavailable("the realm has no data key"))?;
    let mut opened = Vec::with_capacity(algorithms.len());
    for algorithm in algorithms {
        let at = active
            .iter()
            .position(|sealed| sealed.key.algorithm == *algorithm)
            .ok_or_else(|| unavailable("the realm has no active signing key of this algorithm"))?;
        let sealed = active.swap_remove(at);
        let place = SealPlace {
            tenant: scope.tenant().as_uuid(),
            realm: scope.realm().as_uuid(),
            purpose: SIGNING_KEY_PURPOSE,
            row: sealed.key.id,
        };
        let private_key = app
            .sealer
            .open(&data_key, &place, &sealed.sealed_private_key)
            .map_err(|_| unavailable("a signing key does not open where it is stored"))?;
        opened.push((sealed.key, private_key));
    }
    Ok(opened)
}

/// The key that signs for the realm in `algorithm`, with its private half
/// opened.
///
/// # Errors
///
/// As [`open_signing_keys`].
pub async fn open_signing_key(
    app: &App,
    work: &mut dyn UnitOfWork,
    algorithm: SignatureAlgorithm,
) -> Result<(SigningKey, Secret), Failure> {
    open_signing_keys(app, work, &[algorithm])
        .await?
        .pop()
        .ok_or_else(|| Failure::new(ErrorCode::Internal))
}
