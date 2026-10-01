use chrono::{DateTime, Utc};
use crypto::envelope::Envelope;
use models::entities::verifier::{
    DrawnVerifierKey, ServingVerifierKey, VerifierCertificate, VerifierKeyView, VerifierSettings,
    VerifierSubject,
};
use secrecy::{ExposeSecret, SecretBox};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::keyring::RealmKeyring;
use crate::tenancy::UnitOfWork;

/// What a verifier key's private half is sealed for. A key sealed for the
/// realm's tokens does not open as one, nor this one as theirs.
const PURPOSE: &str = "verifier-key";

/// Which lock a realm's verifier changes are made under.
const PRESENTING: i32 = 0x5645_5249;

const KEY_COLUMNS: &str = "kid, state, public_jwk, subject, request_pem, chain, leaf_hash, \
                           not_before, not_after, certified_at, created_by, created_at";

/// Wait for whoever else is changing how this realm presents itself.
///
/// Transaction scoped, so it is released at commit. Without it, choosing the
/// certificate as the realm's identity and withdrawing that certificate's key
/// could each read a state the other is about to change.
pub async fn hold_changes(transaction: &UnitOfWork) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_tenant', true) || ':' \
                          || current_setting('saffui.current_realm', true)))",
            &[&PRESENTING],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// How the realm presents itself, when it ever said.
pub async fn load_settings(transaction: &UnitOfWork) -> StoreResult<Option<VerifierSettings>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT identity, registrar_dataset, registration_certificate, updated_by, updated_at \
             FROM realm_verifier_settings",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };
    Ok(Some(VerifierSettings {
        identity: row
            .get::<_, String>("identity")
            .parse()
            .map_err(|_| StoreError::Backend)?,
        registrar_dataset: row.get("registrar_dataset"),
        registration_certificate: row.get("registration_certificate"),
        updated_by: row.get("updated_by"),
        updated_at: row.get("updated_at"),
    }))
}

/// Keep how the realm presents itself, replacing what it said before.
pub async fn keep_settings(
    transaction: &UnitOfWork,
    settings: &VerifierSettings,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO realm_verifier_settings \
                 (tenant, realm_id, identity, registrar_dataset, registration_certificate, \
                  updated_by, updated_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5 \
             ON CONFLICT (tenant, realm_id) DO UPDATE SET \
                 identity = EXCLUDED.identity, \
                 registrar_dataset = EXCLUDED.registrar_dataset, \
                 registration_certificate = EXCLUDED.registration_certificate, \
                 updated_by = EXCLUDED.updated_by, \
                 updated_at = EXCLUDED.updated_at",
            &[
                &settings.identity.as_str(),
                &settings.registrar_dataset,
                &settings.registration_certificate,
                &settings.updated_by,
                &settings.updated_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// Keep a key drawn with its certificate request, to await the certificate.
/// A realm holds one key awaiting at most, and a second is refused by the
/// schema and said to be so.
pub async fn keep_drawn(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
    key: &DrawnVerifierKey,
) -> StoreResult<()> {
    let sealed = ring
        .seal(envelope, PURPOSE, &key.kid, key.private_pem.expose_secret())
        .await?;
    let version = ring.active_version() as i32;
    let subject = serde_json::to_value(&key.subject).map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "INSERT INTO realm_verifier_keys \
                 (tenant, realm_id, kid, sealed_key, sealed_version, public_jwk, subject, \
                  request_pem, created_by, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8",
            &[
                &key.kid,
                &sealed,
                &version,
                &key.public_jwk,
                &subject,
                &key.request_pem,
                &key.created_by,
                &key.created_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// Every key the realm holds, the one serving first, none opened.
pub async fn list_keys(transaction: &UnitOfWork) -> StoreResult<Vec<VerifierKeyView>> {
    let statement = format!(
        "SELECT {KEY_COLUMNS} FROM realm_verifier_keys \
         ORDER BY state = 'serving' DESC, created_at, kid"
    );
    let rows = transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    rows.into_iter().map(read_key).collect()
}

/// Hold the key awaiting its certificate until the transaction ends, so a
/// certificate is taken for it once.
pub async fn hold_awaiting(transaction: &UnitOfWork) -> StoreResult<Option<VerifierKeyView>> {
    let statement = format!(
        "SELECT {KEY_COLUMNS} FROM realm_verifier_keys WHERE state = 'awaiting' FOR UPDATE"
    );
    transaction
        .query_opt(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_key)
        .transpose()
}

/// Put a key in service under the certificate taken for it, in place of the
/// key serving, which is dropped: nothing it signed needs it again. Says
/// whether the key still awaited its certificate.
pub async fn certify(
    transaction: &UnitOfWork,
    kid: &str,
    certificate: &VerifierCertificate,
) -> StoreResult<bool> {
    let awaiting = transaction
        .query_opt(
            "SELECT kid FROM realm_verifier_keys \
             WHERE kid = $1 AND state = 'awaiting' FOR UPDATE",
            &[&kid],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if awaiting.is_none() {
        return Ok(false);
    }
    transaction
        .execute(
            "DELETE FROM realm_verifier_keys WHERE state = 'serving'",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let promoted = transaction
        .execute(
            "UPDATE realm_verifier_keys \
             SET state = 'serving', chain = $2, leaf_hash = $3, not_before = $4, \
                 not_after = $5, certified_at = $6 \
             WHERE kid = $1 AND state = 'awaiting'",
            &[
                &kid,
                &certificate.chain,
                &certificate.leaf_hash,
                &certificate.not_before,
                &certificate.not_after,
                &certificate.certified_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(promoted > 0)
}

/// The key in service, private half opened, when the realm has one.
pub async fn open_serving(
    transaction: &UnitOfWork,
    ring: &RealmKeyring,
    envelope: &Envelope,
) -> StoreResult<Option<ServingVerifierKey>> {
    let Some(row) = transaction
        .query_opt(
            "SELECT kid, sealed_key, chain, leaf_hash, not_before, not_after, certified_at \
             FROM realm_verifier_keys WHERE state = 'serving'",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
    else {
        return Ok(None);
    };
    let kid: String = row.get("kid");
    let sealed: Vec<u8> = row.get("sealed_key");
    let opened = ring.open(envelope, PURPOSE, &kid, &sealed).await?;
    let certificate = read_certificate(&row)?.ok_or(StoreError::Backend)?;
    Ok(Some(ServingVerifierKey {
        kid,
        private_pem: SecretBox::new(Box::new(opened.expose_secret().clone())),
        certificate,
    }))
}

/// Withdraw a key, and say whether there was one to withdraw.
pub async fn withdraw(transaction: &UnitOfWork, kid: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_verifier_keys WHERE kid = $1", &[&kid])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read_key(row: Row) -> StoreResult<VerifierKeyView> {
    let subject: VerifierSubject =
        serde_json::from_value(row.get("subject")).map_err(|_| StoreError::Backend)?;
    Ok(VerifierKeyView {
        state: row
            .get::<_, String>("state")
            .parse()
            .map_err(|_| StoreError::Backend)?,
        certificate: read_certificate(&row)?,
        kid: row.get("kid"),
        public_jwk: row.get("public_jwk"),
        subject,
        request_pem: row.get("request_pem"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
    })
}

/// The certificate a row holds; the schema keeps its parts present together.
fn read_certificate(row: &Row) -> StoreResult<Option<VerifierCertificate>> {
    let chain: Option<Vec<Vec<u8>>> = row.get("chain");
    let Some(chain) = chain else {
        return Ok(None);
    };
    let read = |column: &str| -> StoreResult<DateTime<Utc>> {
        row.get::<_, Option<DateTime<Utc>>>(column)
            .ok_or(StoreError::Backend)
    };
    Ok(Some(VerifierCertificate {
        chain,
        leaf_hash: row
            .get::<_, Option<String>>("leaf_hash")
            .ok_or(StoreError::Backend)?,
        not_before: read("not_before")?,
        not_after: read("not_after")?,
        certified_at: read("certified_at")?,
    }))
}
