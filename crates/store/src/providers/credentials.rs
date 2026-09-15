use crypto::provider::{DigestProvider, HashAlg};
use data_encoding::HEXLOWER;
use deadpool_postgres::Transaction;
use models::entities::credentials::{
    CredentialChange, CredentialModel, CredentialSecret, CredentialType, OtpCredentialData,
};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const COLUMNS: &str = "tenant, realm_id, credential_id, user_id, credential_type, user_label, \
                       secret, otp, priority, created_by, created_at, updated_by, updated_at, \
                       version";

/// Record a credential, and say so.
///
/// A credential arriving is a security signal: a receiver is told, because a
/// second factor appearing on an account is a thing somebody may need to know
/// about within the minute.
pub async fn create(
    transaction: &Transaction<'_>,
    credential: &CredentialModel,
) -> StoreResult<()> {
    write(transaction, credential).await?;
    announce_credential_change(
        transaction,
        &credential.user_id,
        credential.credential_type,
        CredentialChange::Create,
    )
    .await
}

/// Record a credential and say nothing.
///
/// For the rows that are bookkeeping rather than something a person holds. A
/// retired password kept so the next one can be compared against it has not
/// been enrolled by anybody, and announcing it would tell every receiver that a
/// credential of a type nobody carries had changed, once per password change.
pub async fn create_quietly(
    transaction: &Transaction<'_>,
    credential: &CredentialModel,
) -> StoreResult<()> {
    write(transaction, credential).await
}

async fn write(transaction: &Transaction<'_>, credential: &CredentialModel) -> StoreResult<()> {
    let secret = credential.secret.expose();
    let otp = otp_json(credential)?;
    let set = WriteSet::insert(vec![
        col("tenant", &credential.metadata.tenant),
        col("realm_id", &credential.realm_id),
        col("credential_id", &credential.credential_id),
        col("user_id", &credential.user_id),
        col("credential_type", &credential.credential_type),
        col("user_label", &credential.user_label),
        col("secret", &secret),
        col("otp", &otp),
        col("priority", &credential.priority),
        col("created_by", &credential.metadata.created_by),
    ]);

    transaction
        .execute(
            statement::insert("user_credentials", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Everything a user holds, lowest priority first.
///
/// The order is the order they are tried, so it is the statement's rather than
/// whatever the rows happened to come back in. Two credentials at one rank are
/// then ordered by identifier, so the answer does not change between reads.
pub async fn load_for_user(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<CredentialModel>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM user_credentials WHERE user_id = $1 \
         ORDER BY priority ASC, credential_id ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

/// What a user holds of one kind, lowest priority first.
pub async fn load_for_user_of_type(
    transaction: &Transaction<'_>,
    user_id: &str,
    credential_type: CredentialType,
) -> StoreResult<Vec<CredentialModel>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM user_credentials WHERE user_id = $1 AND credential_type = $2 \
         ORDER BY priority ASC, credential_id ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&user_id, &credential_type])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

/// One credential by identifier.
pub async fn load(
    transaction: &Transaction<'_>,
    credential_id: &str,
) -> StoreResult<Option<CredentialModel>> {
    let statement = format!("SELECT {COLUMNS} FROM user_credentials WHERE credential_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&credential_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Replace what verifies a credential, and its parameters with it.
///
/// The two go together. A password rehashed at a new cost and stored beside the
/// old parameters is one nothing can verify, and an OTP secret replaced without
/// its width is one that produces codes of the wrong length.
pub async fn replace_secret(
    transaction: &Transaction<'_>,
    credential_id: &str,
    secret: &CredentialSecret,
    otp: Option<&OtpCredentialData>,
    actor: &str,
) -> StoreResult<bool> {
    let exposed = secret.expose();
    let otp = otp
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;

    let set = WriteSet::update(
        vec![
            col("secret", &exposed),
            col("otp", &otp),
            col("updated_by", &actor),
        ],
        vec![col("credential_id", &credential_id)],
    );

    let statement = statement::update("user_credentials", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );

    let changed = transaction
        .query(
            &format!("{} RETURNING user_id, credential_type", statement.as_str()),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let Some(row) = changed.first() else {
        return Ok(false);
    };
    announce_credential_change(
        transaction,
        &row.get::<_, String>("user_id"),
        row.get("credential_type"),
        CredentialChange::Update,
    )
    .await?;
    Ok(true)
}

/// Spend a one-time code's step, once.
///
/// The comparison is the write. Reading the last step, comparing it and writing
/// the new one as three calls means three snapshots, and two submissions of the
/// same code racing both read the same value and both pass. Here the second one
/// waits on the row lock, re-reads a step that has moved, and matches nothing.
///
/// Strictly greater, not merely different: a step *below* the last consumed one
/// is still inside the acceptance window, so a replay of an older code has to be
/// refused too.
pub async fn consume_otp_step(
    transaction: &Transaction<'_>,
    credential_id: &str,
    step: i64,
) -> StoreResult<bool> {
    let spent = transaction
        .execute(
            "UPDATE user_credentials SET otp_last_step = $2 \
             WHERE credential_id = $1 \
               AND (otp_last_step IS NULL OR otp_last_step < $2)",
            &[&credential_id, &step],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(spent > 0)
}

/// The digest a recovery code is stored and looked up under.
///
/// Normalised first, because the code that comes back is one a human retyped
/// off paper: dashes, spaces and case are the user's business and not the
/// secret's. Sha256 and not a password hash: eighty bits of entropy have no
/// dictionary to be walked, so what is wanted is preimage resistance and not
/// cost, and a login that had to pay ten stretched hashes to refuse one wrong
/// code would be a lever for anyone who wanted the server busy.
fn recovery_digest(digest: &dyn DigestProvider, code: &str) -> StoreResult<String> {
    digest
        .hash(HashAlg::Sha256, crypto::otp::normalise(code).as_bytes())
        .map(|bytes| HEXLOWER.encode(&bytes))
        .map_err(|_| StoreError::Backend)
}

/// Replace a user's whole set of recovery codes.
///
/// The old set goes in the same transaction the new one arrives in. A set drawn
/// twice must not leave both live: the point of drawing again is that the sheet
/// somebody printed last year no longer opens anything. The sheet is announced
/// once, as a create when nothing stood and an update when it replaced one,
/// however many codes it holds.
pub async fn replace_recovery_codes(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    realm_id: &str,
    user_id: &str,
    codes: &[impl AsRef<str>],
    identifiers: &[impl AsRef<str>],
    metadata: &models::auditable::AuditableModel,
) -> StoreResult<()> {
    if codes.len() != identifiers.len() {
        return Err(StoreError::Backend);
    }
    let replaced = transaction
        .execute(
            "DELETE FROM user_credentials WHERE user_id = $1 AND credential_type = $2",
            &[&user_id, &CredentialType::RecoveryCode],
        )
        .await
        .map_err(|_| StoreError::Backend)?;

    for (code, credential_id) in codes.iter().zip(identifiers) {
        let credential = CredentialModel::recovery_code(
            credential_id.as_ref().to_owned(),
            realm_id.to_owned(),
            user_id.to_owned(),
            CredentialSecret::new(recovery_digest(digest, code.as_ref())?),
            metadata.clone(),
        );
        write(transaction, &credential).await?;
    }
    announce_credential_change(
        transaction,
        user_id,
        CredentialType::RecoveryCode,
        if replaced > 0 {
            CredentialChange::Update
        } else {
            CredentialChange::Create
        },
    )
    .await
}

/// Spend one code, saying whether it was one of this user's.
///
/// The row leaves as it is matched, in one statement: a code read and then
/// deleted is a code two logins racing can both read. What the database compares
/// is a digest against an equal digest, so no part of the answer depends on how
/// far down the set the match sat.
pub async fn spend_recovery_code(
    transaction: &Transaction<'_>,
    digest: &dyn DigestProvider,
    user_id: &str,
    presented: &str,
) -> StoreResult<bool> {
    let hash = recovery_digest(digest, presented)?;
    let spent = transaction
        .query(
            "DELETE FROM user_credentials              WHERE user_id = $1 AND credential_type = $2 AND secret = $3              RETURNING credential_id",
            &[&user_id, &CredentialType::RecoveryCode, &hash],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if spent.is_empty() {
        return Ok(false);
    }
    announce_recovery_code_spent(transaction, user_id).await?;
    Ok(true)
}

/// How many codes a user has left.
///
/// A count and not the codes: nothing that reads this is entitled to the set,
/// and an administrator watching it fall towards zero is exactly the use.
pub async fn count_recovery_codes(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<i64> {
    let row = transaction
        .query_one(
            "SELECT count(*)::bigint AS held FROM user_credentials              WHERE user_id = $1 AND credential_type = $2",
            &[&user_id, &CredentialType::RecoveryCode],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get("held"))
}

/// Take a person's whole sheet of codes away, and say how many went. One
/// announcement for the sheet, since the sheet is what the person gave up.
pub async fn delete_recovery_codes(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<u64> {
    let removed = transaction
        .execute(
            "DELETE FROM user_credentials WHERE user_id = $1 AND credential_type = $2",
            &[&user_id, &CredentialType::RecoveryCode],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    if removed > 0 {
        announce_credential_change(
            transaction,
            user_id,
            CredentialType::RecoveryCode,
            CredentialChange::Delete,
        )
        .await?;
    }
    Ok(removed)
}

const FACTORS: i32 = 0x4641_4354;

/// One writer at a time over a person's factors, until the transaction ends.
///
/// Two removals racing would each read the other's factor as still standing,
/// and a rule that keeps the last one would let both go.
pub async fn hold_factors(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_realm', true) || ':' || $2))",
            &[&FACTORS, &user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take a bookkeeping row away and say nothing, for the same reason
/// [`create_quietly`] writes one that way: a retired password falling off the
/// end of the remembered set is not a credential anybody lost.
pub async fn delete_quietly(
    transaction: &Transaction<'_>,
    credential_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM user_credentials WHERE credential_id = $1",
            &[&credential_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Remove a credential at its holder's hand, and say whether there was one.
pub async fn delete(transaction: &Transaction<'_>, credential_id: &str) -> StoreResult<bool> {
    remove(transaction, credential_id, CredentialChange::Delete).await
}

/// Take a credential away at an administrator's hand, and say whether there
/// was one. Only what a receiver is told sets it apart from [`delete`].
pub async fn revoke(transaction: &Transaction<'_>, credential_id: &str) -> StoreResult<bool> {
    remove(transaction, credential_id, CredentialChange::Revoke).await
}

async fn remove(
    transaction: &Transaction<'_>,
    credential_id: &str,
    change: CredentialChange,
) -> StoreResult<bool> {
    let removed = transaction
        .query(
            "DELETE FROM user_credentials WHERE credential_id = $1 \
             RETURNING user_id, credential_type",
            &[&credential_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    let Some(row) = removed.first() else {
        return Ok(false);
    };
    announce_credential_change(
        transaction,
        &row.get::<_, String>("user_id"),
        row.get("credential_type"),
        change,
    )
    .await?;
    Ok(true)
}

/// Put one credential in place of every one of its type the person holds, and
/// say so once: an update when something stood, a create when nothing did.
///
/// For a door that sets a credential outright, as a provisioning client pushing
/// a password does. Announcing the clearing and the writing apart would tell a
/// receiver the password was deleted when it was only replaced.
pub async fn replace_all_of_type(
    transaction: &Transaction<'_>,
    credential: &CredentialModel,
) -> StoreResult<()> {
    let replaced = transaction
        .execute(
            "DELETE FROM user_credentials WHERE user_id = $1 AND credential_type = $2",
            &[&credential.user_id, &credential.credential_type],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    write(transaction, credential).await?;
    announce_credential_change(
        transaction,
        &credential.user_id,
        credential.credential_type,
        if replaced > 0 {
            CredentialChange::Update
        } else {
            CredentialChange::Create
        },
    )
    .await
}

/// Tell whoever listens that one of a person's credentials changed, and how.
async fn announce_credential_change(
    transaction: &Transaction<'_>,
    user_id: &str,
    credential_type: CredentialType,
    change: CredentialChange,
) -> StoreResult<()> {
    super::outbox::emit(
        transaction,
        super::outbox::CREDENTIAL_CHANGED,
        user_id,
        &serde_json::json!({ "credential_type": credential_type, "change_type": change }),
    )
    .await
}

/// Tell whoever listens that a person signed in with one of their recovery codes:
/// a deletion, marked apart from a sheet given up.
async fn announce_recovery_code_spent(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<()> {
    super::outbox::emit(
        transaction,
        super::outbox::CREDENTIAL_CHANGED,
        user_id,
        &serde_json::json!({
            "credential_type": CredentialType::RecoveryCode,
            "change_type": CredentialChange::Delete,
            "spent": true,
        }),
    )
    .await
}

/// Which kinds a user holds, without any of the material.
///
/// The kind is not the material, and a restore that cannot tell "had a password,
/// redacted away" from "never had one" cannot decide what has to be enrolled
/// again. Guessing from an absence of rows is no substitute: a first factor that
/// stores nothing makes every user look credential-less.
pub async fn kinds_held(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<CredentialType>> {
    Ok(transaction
        .query(
            "SELECT DISTINCT credential_type FROM user_credentials WHERE user_id = $1 \
             ORDER BY credential_type",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .iter()
        .map(|row| row.get("credential_type"))
        .collect())
}

fn otp_json(credential: &CredentialModel) -> StoreResult<Option<serde_json::Value>> {
    credential
        .otp
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}

fn read(row: Row) -> CredentialModel {
    CredentialModel {
        credential_id: row.get("credential_id"),
        realm_id: row.get("realm_id"),
        user_id: row.get("user_id"),
        credential_type: row.get("credential_type"),
        user_label: row.get("user_label"),
        secret: CredentialSecret::new(row.get("secret")),
        otp: row
            .get::<_, Option<serde_json::Value>>("otp")
            .and_then(|value| serde_json::from_value(value).ok()),
        priority: row.get("priority"),
        metadata: models::auditable::AuditableModel {
            tenant: row.get("tenant"),
            created_by: row.get("created_by"),
            created_at: row.get("created_at"),
            updated_by: row.get("updated_by"),
            updated_at: row.get("updated_at"),
            version: row.get("version"),
        },
    }
}
