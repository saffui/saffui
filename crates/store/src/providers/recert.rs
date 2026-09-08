use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

pub const DRAFT: &str = "draft";
pub const ACTIVE: &str = "active";
pub const CLOSED: &str = "closed";
pub const CANCELLED: &str = "cancelled";

pub const CERTIFY: &str = "certify";
pub const REVOKE: &str = "revoke";
pub const ABSTAIN: &str = "abstain";

#[derive(Debug, Clone)]
pub struct Campaign {
    pub campaign_id: String,
    pub name: String,
    pub scope_kind: String,
    pub scope_ref: Option<String>,
    pub reviewer_id: String,
    pub state: String,
    pub snapshot_at: Option<chrono::DateTime<chrono::Utc>>,
    pub closed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub excluded: i32,
    pub report_digest: Option<Vec<u8>>,
    pub report_seq: Option<i64>,
    pub created_by: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub version: i32,
}

#[derive(Debug, Clone)]
pub struct Item {
    pub item_id: String,
    pub campaign_id: String,
    pub subject_id: String,
    pub edge_kind: String,
    pub edge_ref: String,
    pub frozen: serde_json::Value,
    pub snapshot_hash: Vec<u8>,
    pub state: String,
    pub resolution: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub seq: i64,
    pub item_id: String,
    pub reviewer_id: String,
    pub decision: String,
    pub justification: Option<String>,
    pub decided_at: chrono::DateTime<chrono::Utc>,
}

const CAMPAIGN_COLUMNS: &str = "campaign_id, name, scope_kind, scope_ref, reviewer_id, state, \
                                snapshot_at, closed_at, excluded, report_digest, report_seq, \
                                created_by, created_at, version";
const ITEM_COLUMNS: &str = "item_id, campaign_id, subject_id, edge_kind, edge_ref, frozen, \
                            snapshot_hash, state, resolution";

pub async fn open_campaign(transaction: &Transaction<'_>, campaign: &Campaign) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO recert_campaigns \
                 (tenant, realm_id, campaign_id, name, scope_kind, scope_ref, reviewer_id, \
                  created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6",
            &[
                &campaign.campaign_id,
                &campaign.name,
                &campaign.scope_kind,
                &campaign.scope_ref,
                &campaign.reviewer_id,
                &campaign.created_by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn campaigns(transaction: &Transaction<'_>) -> StoreResult<Vec<Campaign>> {
    let statement =
        format!("SELECT {CAMPAIGN_COLUMNS} FROM recert_campaigns ORDER BY created_at DESC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_campaign)
        .collect())
}

pub async fn campaign(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> StoreResult<Option<Campaign>> {
    let statement =
        format!("SELECT {CAMPAIGN_COLUMNS} FROM recert_campaigns WHERE campaign_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&campaign_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_campaign))
}

/// Move a campaign from one named state to another, and only from that one.
/// Answers whether a row moved: none did means somebody moved it first, and
/// the caller stops rather than snapshotting or closing twice.
pub async fn set_state(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    from: &str,
    to: &str,
) -> StoreResult<bool> {
    let moved = transaction
        .execute(
            "UPDATE recert_campaigns SET state = $3, version = version + 1 \
             WHERE campaign_id = $1 AND state = $2",
            &[&campaign_id, &from, &to],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(moved > 0)
}

pub async fn stamp_snapshot(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    excluded: i32,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE recert_campaigns \
                 SET snapshot_at = now(), excluded = $2, version = version + 1 \
             WHERE campaign_id = $1",
            &[&campaign_id, &excluded],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Seal the campaign with its report, and only if it carries none: a retried
/// close finds the row already sealed and writes no second anchor.
pub async fn seal(
    transaction: &Transaction<'_>,
    campaign_id: &str,
    digest: &[u8],
    envelope: &str,
    seq: i64,
) -> StoreResult<bool> {
    let sealed = transaction
        .execute(
            "UPDATE recert_campaigns \
                 SET closed_at = now(), report_digest = $2, report_envelope = $3, \
                     report_seq = $4, version = version + 1 \
             WHERE campaign_id = $1 AND report_digest IS NULL",
            &[&campaign_id, &digest, &envelope, &seq],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(sealed > 0)
}

pub async fn report_of(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT report_envelope FROM recert_campaigns WHERE campaign_id = $1",
            &[&campaign_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| row.get("report_envelope")))
}

/// Write one frozen edge. Conflicts do nothing, so a snapshot interrupted
/// and run again adds what is missing and disturbs nothing that stands.
pub async fn freeze_item(transaction: &Transaction<'_>, item: &Item) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO recert_items \
                 (tenant, realm_id, item_id, campaign_id, subject_id, edge_kind, edge_ref, \
                  frozen, snapshot_hash) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6, $7 \
             ON CONFLICT (tenant, realm_id, campaign_id, subject_id, edge_kind, edge_ref) \
                 DO NOTHING",
            &[
                &item.item_id,
                &item.campaign_id,
                &item.subject_id,
                &item.edge_kind,
                &item.edge_ref,
                &item.frozen,
                &item.snapshot_hash,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn items(transaction: &Transaction<'_>, campaign_id: &str) -> StoreResult<Vec<Item>> {
    let statement = format!(
        "SELECT {ITEM_COLUMNS} FROM recert_items WHERE campaign_id = $1 \
         ORDER BY subject_id ASC, edge_kind ASC, edge_ref ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&campaign_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_item)
        .collect())
}

pub async fn item(transaction: &Transaction<'_>, item_id: &str) -> StoreResult<Option<Item>> {
    let statement = format!("SELECT {ITEM_COLUMNS} FROM recert_items WHERE item_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&item_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_item))
}

/// Append a decision and carry it onto the item in one write each, in one
/// transaction: the denormalised state can never lag the trail.
pub async fn decide(
    transaction: &Transaction<'_>,
    decision_id: &str,
    campaign_id: &str,
    item_id: &str,
    reviewer_id: &str,
    decision: &str,
    justification: Option<&str>,
) -> StoreResult<i64> {
    let row = transaction
        .query_one(
            "INSERT INTO recert_decisions \
                 (tenant, realm_id, decision_id, campaign_id, item_id, reviewer_id, decision, \
                  justification) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6 \
             RETURNING seq",
            &[
                &decision_id,
                &campaign_id,
                &item_id,
                &reviewer_id,
                &decision,
                &justification,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "UPDATE recert_items SET state = $2 WHERE item_id = $1",
            &[&item_id, &decision],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get("seq"))
}

/// The decision that stands for each item of a campaign: the last one
/// written, by the sequence rather than by a clock.
pub async fn standing_decisions(
    transaction: &Transaction<'_>,
    campaign_id: &str,
) -> StoreResult<Vec<Decision>> {
    Ok(transaction
        .query(
            "SELECT DISTINCT ON (item_id) \
                 seq, item_id, reviewer_id, decision, justification, decided_at \
             FROM recert_decisions WHERE campaign_id = $1 \
             ORDER BY item_id ASC, seq DESC",
            &[&campaign_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_decision)
        .collect())
}

pub async fn decisions_of_item(
    transaction: &Transaction<'_>,
    item_id: &str,
) -> StoreResult<Vec<Decision>> {
    Ok(transaction
        .query(
            "SELECT seq, item_id, reviewer_id, decision, justification, decided_at \
             FROM recert_decisions WHERE item_id = $1 ORDER BY seq ASC",
            &[&item_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_decision)
        .collect())
}

pub async fn resolve_item(
    transaction: &Transaction<'_>,
    item_id: &str,
    state: &str,
    resolution: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "UPDATE recert_items SET state = $2, resolution = $3, resolved_at = now() \
             WHERE item_id = $1",
            &[&item_id, &state, &resolution],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

fn read_campaign(row: Row) -> Campaign {
    Campaign {
        campaign_id: row.get("campaign_id"),
        name: row.get("name"),
        scope_kind: row.get("scope_kind"),
        scope_ref: row.get("scope_ref"),
        reviewer_id: row.get("reviewer_id"),
        state: row.get("state"),
        snapshot_at: row.get("snapshot_at"),
        closed_at: row.get("closed_at"),
        excluded: row.get("excluded"),
        report_digest: row.get("report_digest"),
        report_seq: row.get("report_seq"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        version: row.get("version"),
    }
}

fn read_item(row: Row) -> Item {
    Item {
        item_id: row.get("item_id"),
        campaign_id: row.get("campaign_id"),
        subject_id: row.get("subject_id"),
        edge_kind: row.get("edge_kind"),
        edge_ref: row.get("edge_ref"),
        frozen: row.get("frozen"),
        snapshot_hash: row.get("snapshot_hash"),
        state: row.get("state"),
        resolution: row.get("resolution"),
    }
}

fn read_decision(row: Row) -> Decision {
    Decision {
        seq: row.get("seq"),
        item_id: row.get("item_id"),
        reviewer_id: row.get("reviewer_id"),
        decision: row.get("decision"),
        justification: row.get("justification"),
        decided_at: row.get("decided_at"),
    }
}
