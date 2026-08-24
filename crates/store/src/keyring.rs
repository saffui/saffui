use std::collections::HashMap;

use crypto::envelope::{Envelope, RealmDek, SecretScope};
use crypto::secrecy::SecretBox;
use deadpool_postgres::Transaction;

use crate::error::{StoreError, StoreResult};

/// One realm's generations, opened.
pub struct RealmKeyring {
    tenant: String,
    realm_id: String,
    active: u32,
    generations: HashMap<u32, RealmDek>,
}

impl RealmKeyring {
    /// The version new writes are sealed under.
    pub fn active_version(&self) -> u32 {
        self.active
    }

    /// Seal a value for one column of one row.
    ///
    /// The scope is authenticated rather than merely used: a blob sealed for
    /// one purpose and row cannot be opened as another, so lifting a client
    /// secret into a signing key column yields a value nothing can read rather
    /// than a working key in the wrong place.
    pub async fn seal(
        &self,
        envelope: &Envelope,
        purpose: &str,
        id: &str,
        plaintext: &[u8],
    ) -> StoreResult<Vec<u8>> {
        let dek = self
            .generations
            .get(&self.active)
            .ok_or(StoreError::Backend)?;

        envelope
            .seal(dek, &self.scope(purpose, id), plaintext)
            .map_err(|_| StoreError::Backend)
    }

    /// Open a value, under the generation it names.
    ///
    /// The version comes out of the blob's own header, which is what lets a
    /// retired generation keep opening what it sealed while writes move on. A
    /// blob naming a generation this ring does not hold is an error and never a
    /// silently empty secret: a credential that reads as absent is one a login
    /// would treat as never configured.
    pub async fn open(
        &self,
        envelope: &Envelope,
        purpose: &str,
        id: &str,
        sealed: &[u8],
    ) -> StoreResult<SecretBox<Vec<u8>>> {
        let version = crypto::envelope::dek_version(sealed).ok_or(StoreError::NotSealed)?;
        let dek = self
            .generations
            .get(&version)
            .ok_or(StoreError::UnknownGeneration { version })?;

        // Handed back still wrapped. Stripping the wrapper here would put the
        // plaintext in a plain Vec that logs and formats like any other.
        envelope
            .open(dek, &self.scope(purpose, id), sealed)
            .map_err(|_| StoreError::Backend)
    }

    fn scope<'a>(&'a self, purpose: &'a str, id: &'a str) -> SecretScope<'a> {
        SecretScope {
            tenant: &self.tenant,
            realm_id: &self.realm_id,
            purpose,
            id,
        }
    }
}

/// Every generation a realm holds, opened once.
///
/// Opened once because a caller reading a thousand rows would otherwise unwrap
/// per row, and because the retired generations are exactly what an export
/// needs to read rows written before the last rotation.
pub async fn load(
    transaction: &Transaction<'_>,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<RealmKeyring> {
    let rows = transaction
        .query(
            "SELECT version, wrapped_dek, status::text FROM realm_deks ORDER BY version",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    if rows.is_empty() {
        return Err(StoreError::NoKeyring);
    }

    let mut generations = HashMap::with_capacity(rows.len());
    let mut active = None;
    for row in &rows {
        let version: i32 = row.get("version");
        let version = u32::try_from(version).map_err(|_| StoreError::Backend)?;
        let wrapped: Vec<u8> = row.get("wrapped_dek");

        let scope = SecretScope {
            tenant,
            realm_id,
            purpose: PURPOSE_DEK,
            id: &version.to_string(),
        };
        let dek = envelope
            .unwrap_dek(&scope, version, &wrapped)
            .map_err(|_| StoreError::Backend)?;

        if row.get::<_, String>("status") == "active" {
            active = Some(version);
        }
        generations.insert(version, dek);
    }

    Ok(RealmKeyring {
        tenant: tenant.to_owned(),
        realm_id: realm_id.to_owned(),
        active: active.ok_or(StoreError::NoActiveGeneration)?,
        generations,
    })
}

/// What a wrapped generation is scoped to. Its row is named by its version.
const PURPOSE_DEK: &str = "realm-dek";

/// Give a realm its first generation, or leave the one it has.
///
/// Two nodes starting together both try, and the partial unique index decides:
/// the loser conflicts and reads what the winner wrote, rather than minting a
/// second key under which half the realm's later writes would be sealed.
pub async fn provision(
    transaction: &Transaction<'_>,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<bool> {
    let dek = envelope.generate_dek(1).map_err(|_| StoreError::Backend)?;
    let scope = SecretScope {
        tenant,
        realm_id,
        purpose: PURPOSE_DEK,
        id: "1",
    };
    let wrapped = envelope
        .wrap_dek(&scope, &dek)
        .map_err(|_| StoreError::Backend)?;
    let kek_id = envelope.kek_id().map_err(|_| StoreError::Backend)?;

    let written = transaction
        .execute(
            "INSERT INTO realm_deks (tenant, realm_id, version, wrapped_dek, kek_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), 1, $1, $2 \
             ON CONFLICT DO NOTHING",
            &[&wrapped, &kek_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(written > 0)
}

/// Retire the generation taking writes and mint the next.
///
/// Nothing is re-encrypted. Existing ciphertext keeps naming the generation it
/// was sealed under, and that generation keeps opening it; what changes is only
/// what new writes use. Resealing the old rows is a separate, resumable pass.
pub async fn rotate(
    transaction: &Transaction<'_>,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<u32> {
    let retired = transaction
        .query_opt(
            "UPDATE realm_deks SET status = 'retired', retired_at = now() \
             WHERE status = 'active' RETURNING version",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .ok_or(StoreError::NoActiveGeneration)?;

    let previous: i32 = retired.get("version");
    let next = u32::try_from(previous).map_err(|_| StoreError::Backend)? + 1;

    let dek = envelope
        .generate_dek(next)
        .map_err(|_| StoreError::Backend)?;
    let scope = SecretScope {
        tenant,
        realm_id,
        purpose: PURPOSE_DEK,
        id: &next.to_string(),
    };
    let wrapped = envelope
        .wrap_dek(&scope, &dek)
        .map_err(|_| StoreError::Backend)?;
    let kek_id = envelope.kek_id().map_err(|_| StoreError::Backend)?;

    transaction
        .execute(
            "INSERT INTO realm_deks (tenant, realm_id, version, wrapped_dek, kek_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3",
            &[
                &i32::try_from(next).map_err(|_| StoreError::Backend)?,
                &wrapped,
                &kek_id,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    Ok(next)
}

/// Rewrap this realm's generations from one wrapping key to another.
///
/// Both keys are needed and that is not an inconvenience: the rows are opened
/// under the key that closed them and closed again under the new one. A single
/// envelope could only ever rewrap rows already wrapped under itself, which is
/// the one case where there is nothing to do.
///
/// Reads no ciphertext and writes none. This is the whole point of storing the
/// key wrapped rather than deriving it: changing the outer key rewrites one row
/// per generation instead of every secret in the realm.
///
/// Rows already under the new key are left alone, so an interrupted sweep
/// resumes by running again.
pub async fn rewrap(
    transaction: &Transaction<'_>,
    from: &Envelope,
    to: &Envelope,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<usize> {
    let previous = from.kek_id().map_err(|_| StoreError::Backend)?;
    let kek_id = to.kek_id().map_err(|_| StoreError::Backend)?;
    let rows = transaction
        .query(
            "SELECT version, wrapped_dek FROM realm_deks WHERE kek_id = $1 ORDER BY version",
            &[&previous],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    let mut rewrapped = 0;
    for row in &rows {
        let version: i32 = row.get("version");
        let version_u32 = u32::try_from(version).map_err(|_| StoreError::Backend)?;
        let wrapped: Vec<u8> = row.get("wrapped_dek");
        let scope = SecretScope {
            tenant,
            realm_id,
            purpose: PURPOSE_DEK,
            id: &version_u32.to_string(),
        };

        let dek = from
            .unwrap_dek(&scope, version_u32, &wrapped)
            .map_err(|_| StoreError::Backend)?;
        let fresh = to.wrap_dek(&scope, &dek).map_err(|_| StoreError::Backend)?;

        transaction
            .execute(
                "UPDATE realm_deks SET wrapped_dek = $2, kek_id = $3 WHERE version = $1",
                &[&version, &fresh, &kek_id],
            )
            .await
            .map_err(|_| StoreError::Backend)?;
        rewrapped += 1;
    }

    Ok(rewrapped)
}
