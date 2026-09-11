use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

#[derive(Debug, Clone)]
pub struct SodRule {
    pub rule_id: String,
    pub roles: Vec<String>,
    pub min_conflicting: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct SodException {
    pub rule_id: String,
    pub user_id: String,
    /// The exact combination excused; a different one re-arms the block.
    pub covered_roles: Vec<String>,
    pub justification: String,
    pub granted_by: String,
    pub valid_until: chrono::DateTime<chrono::Utc>,
}

const WEIGHING: i32 = 0x534F_4457;
const WEIGHING_REALM: i32 = 0x534F_4452;

/// One person's grants are weighed by one writer at a time. Transaction
/// scoped, so two halves of a toxic pair cannot each pass a read taken
/// before the other's write.
///
/// The realm is held too, shared: people are weighed side by side, and a change
/// reaching many of them at once waits for every one of those weighings to land.
pub async fn hold_person(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock_shared($1, \
                 hashtext(current_setting('saffui.current_realm', true)))",
            &[&WEIGHING_REALM],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_realm', true) || ':' || $2))",
            &[&WEIGHING, &user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Every person of the realm at once, for a change that reaches many of them:
/// a role given to a group, a role placed under another, a group moved. One lock
/// however many people the change reaches, and no person is weighed alongside
/// it, so its weighing reads a world nobody else is changing.
pub async fn hold_realm(transaction: &Transaction<'_>) -> StoreResult<()> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock($1, \
                 hashtext(current_setting('saffui.current_realm', true)))",
            &[&WEIGHING_REALM],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn rules(transaction: &Transaction<'_>) -> StoreResult<Vec<SodRule>> {
    Ok(transaction
        .query(
            "SELECT rule_id, roles, min_conflicting, enabled FROM sod_rules \
             ORDER BY rule_id ASC",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_rule)
        .collect())
}

pub async fn keep_rule(transaction: &Transaction<'_>, rule: &SodRule, by: &str) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO sod_rules \
                 (tenant, realm_id, rule_id, roles, min_conflicting, enabled, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5 \
             ON CONFLICT (tenant, realm_id, rule_id) DO UPDATE \
                 SET roles = EXCLUDED.roles, \
                     min_conflicting = EXCLUDED.min_conflicting, \
                     enabled = EXCLUDED.enabled, \
                     updated_by = EXCLUDED.created_by, \
                     updated_at = now(), \
                     version = sod_rules.version + 1",
            &[
                &rule.rule_id,
                &rule.roles,
                &rule.min_conflicting,
                &rule.enabled,
                &by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn drop_rule(transaction: &Transaction<'_>, rule_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM sod_rules WHERE rule_id = $1", &[&rule_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

pub async fn exceptions_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<SodException>> {
    Ok(transaction
        .query(
            "SELECT rule_id, user_id, covered_roles, justification, granted_by, valid_until \
             FROM sod_exceptions WHERE user_id = $1 ORDER BY rule_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_exception)
        .collect())
}

pub async fn exceptions(transaction: &Transaction<'_>) -> StoreResult<Vec<SodException>> {
    Ok(transaction
        .query(
            "SELECT rule_id, user_id, covered_roles, justification, granted_by, valid_until \
             FROM sod_exceptions ORDER BY rule_id ASC, user_id ASC",
            &[],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_exception)
        .collect())
}

pub async fn keep_exception(
    transaction: &Transaction<'_>,
    exception: &SodException,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO sod_exceptions \
                 (tenant, realm_id, rule_id, user_id, covered_roles, justification, \
                  granted_by, valid_until) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6 \
             ON CONFLICT (tenant, realm_id, rule_id, user_id) DO UPDATE \
                 SET covered_roles = EXCLUDED.covered_roles, \
                     justification = EXCLUDED.justification, \
                     granted_by = EXCLUDED.granted_by, \
                     valid_until = EXCLUDED.valid_until",
            &[
                &exception.rule_id,
                &exception.user_id,
                &exception.covered_roles,
                &exception.justification,
                &exception.granted_by,
                &exception.valid_until,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn drop_exception(
    transaction: &Transaction<'_>,
    rule_id: &str,
    user_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM sod_exceptions WHERE rule_id = $1 AND user_id = $2",
            &[&rule_id, &user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read_rule(row: Row) -> SodRule {
    SodRule {
        rule_id: row.get("rule_id"),
        roles: row.get("roles"),
        min_conflicting: row.get("min_conflicting"),
        enabled: row.get("enabled"),
    }
}

fn read_exception(row: Row) -> SodException {
    SodException {
        rule_id: row.get("rule_id"),
        user_id: row.get("user_id"),
        covered_roles: row.get("covered_roles"),
        justification: row.get("justification"),
        granted_by: row.get("granted_by"),
        valid_until: row.get("valid_until"),
    }
}
