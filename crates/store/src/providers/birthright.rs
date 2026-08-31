use deadpool_postgres::Transaction;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};

#[derive(Debug, Clone)]
pub struct BirthrightRule {
    pub rule_id: String,
    pub when_attribute: String,
    pub when_value: String,
    pub roles: Vec<String>,
    pub priority: i32,
    pub enabled: bool,
}

const COLUMNS: &str = "rule_id, when_attribute, when_value, roles, priority, enabled";

pub async fn rules(transaction: &Transaction<'_>) -> StoreResult<Vec<BirthrightRule>> {
    let statement =
        format!("SELECT {COLUMNS} FROM birthright_rules ORDER BY priority ASC, rule_id ASC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read)
        .collect())
}

pub async fn keep_rule(
    transaction: &Transaction<'_>,
    rule: &BirthrightRule,
    by: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO birthright_rules \
                 (tenant, realm_id, rule_id, when_attribute, when_value, roles, priority, \
                  enabled, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6, $7 \
             ON CONFLICT (tenant, realm_id, rule_id) DO UPDATE \
                 SET when_attribute = EXCLUDED.when_attribute, \
                     when_value = EXCLUDED.when_value, \
                     roles = EXCLUDED.roles, \
                     priority = EXCLUDED.priority, \
                     enabled = EXCLUDED.enabled, \
                     updated_by = EXCLUDED.created_by, \
                     updated_at = now(), \
                     version = birthright_rules.version + 1",
            &[
                &rule.rule_id,
                &rule.when_attribute,
                &rule.when_value,
                &rule.roles,
                &rule.priority,
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
        .execute(
            "DELETE FROM birthright_rules WHERE rule_id = $1",
            &[&rule_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

pub async fn governed_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<(String, String)>> {
    Ok(transaction
        .query(
            "SELECT role_id, rule_id FROM governed_grants WHERE user_id = $1 \
             ORDER BY role_id ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| (row.get("role_id"), row.get("rule_id")))
        .collect())
}

pub async fn record_grant(
    transaction: &Transaction<'_>,
    user_id: &str,
    role_id: &str,
    rule_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO governed_grants (tenant, realm_id, user_id, role_id, rule_id) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT (tenant, realm_id, user_id, role_id) DO NOTHING",
            &[&user_id, &role_id, &rule_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

pub async fn erase_grant(
    transaction: &Transaction<'_>,
    user_id: &str,
    role_id: &str,
) -> StoreResult<()> {
    transaction
        .execute(
            "DELETE FROM governed_grants WHERE user_id = $1 AND role_id = $2",
            &[&user_id, &role_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

fn read(row: Row) -> BirthrightRule {
    BirthrightRule {
        rule_id: row.get("rule_id"),
        when_attribute: row.get("when_attribute"),
        when_value: row.get("when_value"),
        roles: row.get("roles"),
        priority: row.get("priority"),
        enabled: row.get("enabled"),
    }
}
