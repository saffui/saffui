use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::authz::IdentityProviderModel;
use models::entities::brokering::{BrokerLoginState, FederatedIdentityModel};
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const PROVIDER_COLUMNS: &str = "tenant, realm_id, internal_id, provider_id, name, display_name, \
                                description, enabled, trust_email, configs, created_by, \
                                created_at, updated_by, updated_at, version";

/// Record a provider.
pub async fn create_provider(
    transaction: &Transaction<'_>,
    provider: &IdentityProviderModel,
) -> StoreResult<()> {
    let configs = json(&provider.configs)?;
    let enabled = provider.enabled.unwrap_or(true);
    let trust_email = provider.trust_email.unwrap_or(false);
    let set = WriteSet::insert(vec![
        col("tenant", &provider.metadata.tenant),
        col("realm_id", &provider.realm_id),
        col("internal_id", &provider.internal_id),
        col("provider_id", &provider.provider_id),
        col("name", &provider.name),
        col("display_name", &provider.display_name),
        col("description", &provider.description),
        col("enabled", &enabled),
        col("trust_email", &trust_email),
        col("configs", &configs),
        col("created_by", &provider.metadata.created_by),
    ]);
    transaction
        .execute(
            statement::insert("identity_providers", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One provider by the alias a login URL names.
pub async fn provider_by_alias(
    transaction: &Transaction<'_>,
    alias: &str,
) -> StoreResult<Option<IdentityProviderModel>> {
    let statement =
        format!("SELECT {PROVIDER_COLUMNS} FROM identity_providers WHERE provider_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&alias])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_provider))
}

/// Every provider of this realm.
pub async fn list_providers(
    transaction: &Transaction<'_>,
) -> StoreResult<Vec<IdentityProviderModel>> {
    let statement =
        format!("SELECT {PROVIDER_COLUMNS} FROM identity_providers ORDER BY provider_id ASC");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_provider)
        .collect())
}

/// Rewrite a provider, and say whether it was there to rewrite.
pub async fn update_provider(
    transaction: &Transaction<'_>,
    provider: &IdentityProviderModel,
) -> StoreResult<bool> {
    let configs = json(&provider.configs)?;
    let enabled = provider.enabled.unwrap_or(true);
    let trust_email = provider.trust_email.unwrap_or(false);
    let set = WriteSet::update(
        vec![
            col("provider_id", &provider.provider_id),
            col("name", &provider.name),
            col("display_name", &provider.display_name),
            col("description", &provider.description),
            col("enabled", &enabled),
            col("trust_email", &trust_email),
            col("configs", &configs),
            col("updated_by", &provider.metadata.updated_by),
        ],
        vec![col("internal_id", &provider.internal_id)],
    );
    let statement = statement::update("identity_providers", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );
    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Remove a provider, and say whether it was there to remove.
pub async fn delete_provider(
    transaction: &Transaction<'_>,
    internal_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM identity_providers WHERE internal_id = $1",
            &[&internal_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// Whether any local account is linked through this alias.
pub async fn alias_still_linked(transaction: &Transaction<'_>, alias: &str) -> StoreResult<bool> {
    let row = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM federated_identities WHERE provider_alias = $1) AS held",
            &[&alias],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.get("held"))
}

/// Bind a local user to who they are upstream.
pub async fn link(
    transaction: &Transaction<'_>,
    identity: &FederatedIdentityModel,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO federated_identities \
                 (tenant, realm_id, user_id, provider_alias, external_user_id, \
                  external_username, created_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5",
            &[
                &identity.user_id,
                &identity.provider_alias,
                &identity.external_user_id,
                &identity.external_username,
                &identity.created_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The local user an upstream subject is bound to, if any.
pub async fn linked_user(
    transaction: &Transaction<'_>,
    alias: &str,
    external_user_id: &str,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT user_id FROM federated_identities \
             WHERE provider_alias = $1 AND external_user_id = $2",
            &[&alias, &external_user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| row.get("user_id")))
}

/// The identities a local user holds elsewhere.
pub async fn identities_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<FederatedIdentityModel>> {
    Ok(transaction
        .query(
            "SELECT realm_id, user_id, provider_alias, external_user_id, external_username, \
                    created_at \
             FROM federated_identities WHERE user_id = $1 ORDER BY provider_alias ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_identity)
        .collect())
}

/// Open one brokered login: what left for the upstream, kept hashed.
pub async fn open_state(
    transaction: &Transaction<'_>,
    state: &BrokerLoginState,
) -> StoreResult<()> {
    transaction
        .execute(
            "INSERT INTO broker_login_states \
                 (tenant, realm_id, state_hash, provider_alias, auth_session, \
                  code_verifier, nonce, expires_at) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5, $6",
            &[
                &state.state_hash,
                &state.provider_alias,
                &state.auth_session,
                &state.code_verifier,
                &state.nonce,
                &state.expires_at,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Spend the state that matches what came back, exactly once.
///
/// Keyed on the hash and the provider both: a replay finds nothing, and a
/// state started for one provider cannot be spent on another's endpoint. The
/// expiry is part of the match, so a stale row cannot be spent either.
pub async fn consume_state(
    transaction: &Transaction<'_>,
    state_hash: &str,
    alias: &str,
    now: DateTime<Utc>,
) -> StoreResult<Option<BrokerLoginState>> {
    Ok(transaction
        .query_opt(
            "DELETE FROM broker_login_states \
             WHERE state_hash = $1 AND provider_alias = $2 AND expires_at > $3 \
             RETURNING state_hash, provider_alias, auth_session, code_verifier, nonce, \
                       expires_at",
            &[&state_hash, &alias, &now],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_state))
}

/// Drop what expired without being spent.
pub async fn sweep_states(transaction: &Transaction<'_>, now: DateTime<Utc>) -> StoreResult<u64> {
    transaction
        .execute(
            "DELETE FROM broker_login_states WHERE expires_at <= $1",
            &[&now],
        )
        .await
        .map_err(|_| StoreError::Backend)
}

fn json(
    configs: &Option<models::entities::attributes::AttributesMap>,
) -> StoreResult<Option<serde_json::Value>> {
    configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)
}

fn read_provider(row: Row) -> IdentityProviderModel {
    IdentityProviderModel {
        internal_id: row.get("internal_id"),
        realm_id: row.get("realm_id"),
        provider_id: row.get("provider_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row.get("description"),
        enabled: Some(row.get("enabled")),
        trust_email: Some(row.get("trust_email")),
        configs: row
            .get::<_, Option<serde_json::Value>>("configs")
            .and_then(|value| serde_json::from_value(value).ok()),
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

fn read_identity(row: Row) -> FederatedIdentityModel {
    FederatedIdentityModel {
        realm_id: row.get("realm_id"),
        user_id: row.get("user_id"),
        provider_alias: row.get("provider_alias"),
        external_user_id: row.get("external_user_id"),
        external_username: row.get("external_username"),
        created_at: row.get("created_at"),
    }
}

fn read_state(row: Row) -> BrokerLoginState {
    BrokerLoginState {
        state_hash: row.get("state_hash"),
        provider_alias: row.get("provider_alias"),
        auth_session: row.get("auth_session"),
        code_verifier: row.get("code_verifier"),
        nonce: row.get("nonce"),
        expires_at: row.get("expires_at"),
    }
}
