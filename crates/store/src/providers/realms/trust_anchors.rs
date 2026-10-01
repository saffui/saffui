use models::entities::trust_anchors::{TrustAnchor, TrustAnchorRole};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult, refuse_broken_rule};
use crate::tenancy::UnitOfWork;

/// Deposit an authority. One already deposited for the same role is refused
/// by the schema, and said to be so.
pub async fn deposit(transaction: &UnitOfWork, anchor: &TrustAnchor) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO realm_trust_anchors \
                 (tenant, realm_id, anchor_id, role, certificate, fingerprint, subject, \
                  key_identifier, not_after, created_by, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9",
            &[
                &anchor.anchor_id,
                &anchor.role.as_str(),
                &anchor.certificate,
                &anchor.fingerprint,
                &anchor.subject,
                &anchor.key_identifier,
                &anchor.not_after,
                &anchor.created_by,
                &anchor.created_at,
            ],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(())
}

/// Every authority the realm trusts, whatever for, oldest deposit first.
pub async fn list(transaction: &UnitOfWork) -> StoreResult<Vec<TrustAnchor>> {
    let rows = transaction
        .query(
            "SELECT anchor_id, role, certificate, fingerprint, subject, key_identifier, \
                    not_after, created_by, created_at \
             FROM realm_trust_anchors ORDER BY created_at, anchor_id",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    rows.into_iter().map(read).collect()
}

/// Which lock a realm's authorities are counted under.
const ANCHORING: i32 = 0x414E_4348;

/// Wait for whoever else is depositing an authority in this realm.
///
/// Transaction scoped, so it is released at commit and never rides a pooled
/// backend to the next caller. Counting and then depositing without it lets
/// two deposits one below the bound both read a count that passes.
pub async fn hold_deposits(transaction: &UnitOfWork) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_tenant', true) || ':' \
                          || current_setting('saffui.current_realm', true)))",
            &[&ANCHORING],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// How many authorities the realm trusts for one role.
pub async fn count(transaction: &UnitOfWork, role: TrustAnchorRole) -> StoreResult<i64> {
    Ok(transaction
        .query_one(
            "SELECT count(*) FROM realm_trust_anchors WHERE role = $1",
            &[&role.as_str()],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0))
}

/// Withdraw one authority, and say whether there was one to withdraw. One an
/// issuer the realm names is trusted through is refused by the schema, and
/// said to be so.
pub async fn withdraw(transaction: &UnitOfWork, anchor_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM realm_trust_anchors WHERE anchor_id = $1",
            &[&anchor_id],
        )
        .await
        .map_err(refuse_broken_rule)?;
    Ok(removed > 0)
}

fn read(row: Row) -> StoreResult<TrustAnchor> {
    Ok(TrustAnchor {
        anchor_id: row.get("anchor_id"),
        role: row
            .get::<_, String>("role")
            .parse()
            .map_err(|_| StoreError::Backend)?,
        certificate: row.get("certificate"),
        fingerprint: row.get("fingerprint"),
        subject: row.get("subject"),
        key_identifier: row.get("key_identifier"),
        not_after: row.get("not_after"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
    })
}
