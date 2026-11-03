use serde_json::json;

use super::{SIGNING_KEY_PURPOSE, SigningKey};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::crypto::{SealPlace, SignatureAlgorithm};
use crate::ports::storage::UnitOfWork;

/// Gives a new realm its data key and its first signing key, in the unit of
/// work that creates the realm: a realm never exists without them.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when a key cannot be made or
/// sealed, or the storage failure.
pub async fn create_first_keys(
    app: &App,
    work: &mut dyn UnitOfWork,
) -> Result<SigningKey, Failure> {
    let scope = work.scope();
    let (tenant, realm) = (scope.tenant().as_uuid(), scope.realm().as_uuid());
    let unavailable = |_| Failure::new(ErrorCode::CryptoUnavailable);

    let data_key = app
        .sealer
        .make_data_key(tenant, realm, 1)
        .map_err(unavailable)?;
    work.insert_data_key(&data_key).await?;

    let generated = app
        .signer
        .generate_key(SignatureAlgorithm::Es256)
        .map_err(unavailable)?;
    let id = mint_id(app)?;
    let place = SealPlace {
        tenant,
        realm,
        purpose: SIGNING_KEY_PURPOSE,
        row: id,
    };
    let key = SigningKey {
        id,
        key_id: generated.key_id,
        algorithm: generated.algorithm,
        public_jwk: generated.public_jwk,
        sealed_private_key: app
            .sealer
            .seal(&data_key, &place, &generated.private_key)
            .map_err(unavailable)?,
        created_at: app.now(),
    };
    work.insert_signing_key(&key).await?;
    let created = json!({ "kid": key.key_id, "alg": key.algorithm.name() });
    record_event(app, work, EventKind::SigningKeyCreated, created).await?;
    Ok(key)
}
