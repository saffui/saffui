use crypto::envelope::Envelope;
use crypto::provider::SignAlg;
use deadpool_postgres::Transaction;
use models::entities::keys::{
    JweAlgorithm, KeyStatus, KeyUse, RealmEncryptionKey, RealmEncryptionKeyView, RealmSigningKey,
    RealmSigningKeyView,
};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::keyring::RealmKeyring;

/// What the sealed private half is scoped to. A key sealed for one row does not
/// open as another's, and one sealed as a client secret does not open here.
const PURPOSE: &str = "realm-signing-key";

const COLUMNS: &str = "tenant, realm_id, kid, algorithm, key_use, status, priority, \
                       private_pem, public_jwk, created_at";

/// Record a key, sealing its private half.
pub async fn create(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    key: &RealmSigningKey,
) -> StoreResult<()> {
    let sealed = ring
        .seal(envelope, PURPOSE, &key.kid, &key.private_pem)
        .await?;
    let algorithm = serde_json::to_value(key.algorithm)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(StoreError::Backend)?;

    transaction
        .execute(
            "INSERT INTO realm_signing_keys \
                 (tenant, realm_id, kid, algorithm, key_use, status, priority, \
                  private_pem, public_jwk, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8",
            &[
                &key.kid,
                &algorithm,
                &key.key_use,
                &key.status,
                &key.priority,
                &sealed,
                &key.public_jwk,
                &key.created_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The key a realm signs with, private half opened: the active one of the
/// algorithm asked for, or of any when none is, highest priority first.
pub async fn active(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    key_use: KeyUse,
    algorithm: Option<SignAlg>,
) -> StoreResult<Option<RealmSigningKey>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM realm_signing_keys \
         WHERE key_use = $1 AND status = 'active' AND ($2::text IS NULL OR algorithm = $2) \
         ORDER BY priority DESC, kid ASC LIMIT 1"
    );
    let named = algorithm.map(|algorithm| algorithm.name().to_owned());
    let Some(row) = transaction
        .query_opt(statement.as_str(), &[&key_use, &named])
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    Ok(Some(read(row, ring, envelope).await?))
}

/// One key by the identifier a token carries.
pub async fn by_kid(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    kid: &str,
) -> StoreResult<Option<RealmSigningKey>> {
    let statement = format!("SELECT {COLUMNS} FROM realm_signing_keys WHERE kid = $1");
    let Some(row) = transaction
        .query_opt(statement.as_str(), &[&kid])
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    Ok(Some(read(row, ring, envelope).await?))
}

/// What the realm publishes: every key that still verifies something.
///
/// A disabled key is not published, and a passive one is: tokens signed before
/// the last rotation are still in flight, and dropping their key from the set
/// makes every one of them fail to verify at once.
///
/// Nothing here is unsealed. Publication needs the public half only, and
/// opening a private key to answer a public endpoint is work done to throw
/// away.
pub async fn published(
    transaction: &Transaction<'_>,
    key_use: KeyUse,
) -> StoreResult<Vec<RealmSigningKeyView>> {
    let rows = transaction
        .query(
            "SELECT kid, realm_id, algorithm, key_use, status, priority, public_jwk, created_at \
             FROM realm_signing_keys \
             WHERE key_use = $1 AND status <> 'disabled' \
             ORDER BY priority DESC, kid ASC",
            &[&key_use],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    rows.into_iter().map(view).collect()
}

/// Every key of this use the realm holds, disabled ones included.
///
/// The plane's view, not the public one: publication hides a disabled key on
/// purpose, and an administrator auditing what was disabled needs to see it.
pub async fn held(
    transaction: &Transaction<'_>,
    key_use: KeyUse,
) -> StoreResult<Vec<RealmSigningKeyView>> {
    let rows = transaction
        .query(
            "SELECT kid, realm_id, algorithm, key_use, status, priority, public_jwk, created_at \
             FROM realm_signing_keys \
             WHERE key_use = $1 \
             ORDER BY priority DESC, kid ASC",
            &[&key_use],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    rows.into_iter().map(view).collect()
}

/// Retire the key that signs and put another in its place.
///
/// The old key goes passive rather than away, because tokens it signed are
/// still being presented. Nothing re-signs.
///
/// Only the same algorithm's key steps down. A realm keeps one signer per
/// algorithm, and a client that registered one is answered from that
/// algorithm's active key alone: a successor of another algorithm would not
/// succeed it, it would silence it.
pub async fn rotate(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    next: &RealmSigningKey,
) -> StoreResult<()> {
    let algorithm = serde_json::to_value(next.algorithm)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(StoreError::Backend)?;
    transaction
        .execute(
            "UPDATE realm_signing_keys SET status = 'passive' \
             WHERE key_use = $1 AND algorithm = $2 AND status = 'active'",
            &[&next.key_use, &algorithm],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    create(transaction, ring, envelope, next).await
}

/// Stop publishing a key, and stop verifying with it.
pub async fn disable(transaction: &Transaction<'_>, kid: &str) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE realm_signing_keys SET status = 'disabled' WHERE kid = $1",
            &[&kid],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

async fn read(row: Row, ring: &RealmKeyring, envelope: &Envelope) -> StoreResult<RealmSigningKey> {
    let kid: String = row.get("kid");
    let sealed: Vec<u8> = row.get("private_pem");
    let private_pem = ring.open(envelope, PURPOSE, &kid, &sealed).await?;

    Ok(RealmSigningKey {
        tenant: row.get("tenant"),
        realm_id: row.get("realm_id"),
        algorithm: algorithm(&row)?,
        kid,
        key_use: row.get::<_, KeyUse>("key_use"),
        status: row.get::<_, KeyStatus>("status"),
        priority: row.get("priority"),
        private_pem: crypto::secrecy::ExposeSecret::expose_secret(&private_pem).clone(),
        public_jwk: row.get("public_jwk"),
        created_at: row.get("created_at"),
    })
}

fn view(row: Row) -> StoreResult<RealmSigningKeyView> {
    let algorithm = algorithm(&row)?;
    Ok(RealmSigningKeyView {
        kid: row.get("kid"),
        realm_id: row.get("realm_id"),
        algorithm,
        key_type: algorithm.key_type().to_owned(),
        key_use: row.get::<_, KeyUse>("key_use"),
        status: row.get::<_, KeyStatus>("status"),
        priority: row.get("priority"),
        public_jwk: row.get("public_jwk"),
        created_at: row.get("created_at"),
    })
}

/// Read back through the same catalogue that wrote it. A value the build does
/// not know is refused here rather than carried as a string nothing can sign
/// with.
fn algorithm(row: &Row) -> StoreResult<crypto::provider::SignAlg> {
    serde_json::from_value(serde_json::Value::String(row.get("algorithm")))
        .map_err(|_| StoreError::Backend)
}

/// Write a key this realm publishes to be encrypted to.
pub async fn create_encryption(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    key: &RealmEncryptionKey,
) -> StoreResult<()> {
    let sealed = ring
        .seal(envelope, PURPOSE, &key.kid, &key.private_pem)
        .await?;
    transaction
        .execute(
            "INSERT INTO realm_signing_keys \
                 (tenant, realm_id, kid, algorithm, key_use, status, priority, \
                  private_pem, public_jwk, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, 'enc', 'active', 0, $3, $4, $5",
            &[
                &key.kid,
                &key.algorithm.as_str(),
                &sealed,
                &key.public_jwk,
                &chrono::Utc::now().timestamp(),
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The key a client encrypted to, private half opened.
///
/// By algorithm, because the header names one and a key of another cannot open
/// what that one closed.
pub async fn active_encryption(
    transaction: &Transaction<'_>,
    ring: &RealmKeyring,
    envelope: &Envelope,
    algorithm: JweAlgorithm,
) -> StoreResult<Option<RealmEncryptionKey>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT kid, algorithm, private_pem, public_jwk FROM realm_signing_keys \
             WHERE key_use = 'enc' AND status = 'active' AND algorithm = $1 \
             ORDER BY priority DESC, kid ASC LIMIT 1",
            &[&algorithm.as_str()],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };

    let kid: String = row.get("kid");
    let sealed: Vec<u8> = row.get("private_pem");
    let private_pem = ring.open(envelope, PURPOSE, &kid, &sealed).await?;
    Ok(Some(RealmEncryptionKey {
        algorithm: read_encryption_algorithm(&row)?,
        kid,
        private_pem: crypto::secrecy::ExposeSecret::expose_secret(&private_pem).clone(),
        public_jwk: row.get("public_jwk"),
    }))
}

/// The keys this realm publishes to be encrypted to.
pub async fn published_encryption(
    transaction: &Transaction<'_>,
) -> StoreResult<Vec<RealmEncryptionKeyView>> {
    let rows = transaction
        .query(
            "SELECT kid, algorithm, status, public_jwk FROM realm_signing_keys \
             WHERE key_use = 'enc' AND status <> 'disabled' \
             ORDER BY priority DESC, kid ASC",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    rows.into_iter()
        .map(|row| {
            Ok(RealmEncryptionKeyView {
                kid: row.get("kid"),
                algorithm: read_encryption_algorithm(&row)?,
                status: row.get::<_, KeyStatus>("status"),
                public_jwk: row.get("public_jwk"),
            })
        })
        .collect()
}

/// Every encryption key the realm holds, disabled ones included, for the
/// same audit [`held`] serves on the signing side.
pub async fn held_encryption(
    transaction: &Transaction<'_>,
) -> StoreResult<Vec<RealmEncryptionKeyView>> {
    let rows = transaction
        .query(
            "SELECT kid, algorithm, status, public_jwk FROM realm_signing_keys \
             WHERE key_use = 'enc' \
             ORDER BY priority DESC, kid ASC",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    rows.into_iter()
        .map(|row| {
            Ok(RealmEncryptionKeyView {
                kid: row.get("kid"),
                algorithm: read_encryption_algorithm(&row)?,
                status: row.get::<_, KeyStatus>("status"),
                public_jwk: row.get("public_jwk"),
            })
        })
        .collect()
}

/// Read back through the catalogue that wrote it, like the signing side: a
/// value this build does not know is refused here rather than carried as a
/// string nothing can decrypt with.
fn read_encryption_algorithm(row: &Row) -> StoreResult<JweAlgorithm> {
    row.get::<_, String>("algorithm")
        .parse()
        .map_err(|_| StoreError::Backend)
}
