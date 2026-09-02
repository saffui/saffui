use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::authz::IdentityProviderModel;
use models::entities::brokering::{
    BrokerLoginState, FederatedIdentityModel, IdpMapperModel, RealmSpnegoModel,
    UserClaimSourceModel, UserFederationModel,
};
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

/// The provider aliases a local account is bound to, for reading a person's
/// provenance. Ordered so the answer is stable.
pub async fn links_of(transaction: &Transaction<'_>, user_id: &str) -> StoreResult<Vec<String>> {
    Ok(transaction
        .query(
            "SELECT provider_alias FROM federated_identities \
             WHERE user_id = $1 ORDER BY provider_alias ASC",
            &[&user_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(|row| row.get("provider_alias"))
        .collect())
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

const MAPPER_COLUMNS: &str = "tenant, realm_id, mapper_id, provider_alias, name, mapper_type, \
                              configs, created_by, created_at, updated_by, updated_at, version";

/// Record a rule.
pub async fn create_mapper(
    transaction: &Transaction<'_>,
    mapper: &IdpMapperModel,
) -> StoreResult<()> {
    let configs = mapper
        .configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;
    let set = WriteSet::insert(vec![
        col("tenant", &mapper.metadata.tenant),
        col("realm_id", &mapper.realm_id),
        col("mapper_id", &mapper.mapper_id),
        col("provider_alias", &mapper.provider_alias),
        col("name", &mapper.name),
        col("mapper_type", &mapper.mapper_type),
        col("configs", &configs),
        col("created_by", &mapper.metadata.created_by),
    ]);
    transaction
        .execute(
            statement::insert("idp_mappers", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// The rules of one provider, in the order they were named.
pub async fn mappers_of(
    transaction: &Transaction<'_>,
    provider_alias: &str,
) -> StoreResult<Vec<IdpMapperModel>> {
    let statement = format!(
        "SELECT {MAPPER_COLUMNS} FROM idp_mappers \
         WHERE provider_alias = $1 ORDER BY name ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&provider_alias])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_mapper)
        .collect())
}

/// One rule, wherever it hangs.
pub async fn load_mapper(
    transaction: &Transaction<'_>,
    mapper_id: &str,
) -> StoreResult<Option<IdpMapperModel>> {
    let statement = format!("SELECT {MAPPER_COLUMNS} FROM idp_mappers WHERE mapper_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&mapper_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_mapper))
}

/// Rewrite a rule, and say whether it was there to rewrite.
pub async fn update_mapper(
    transaction: &Transaction<'_>,
    mapper: &IdpMapperModel,
) -> StoreResult<bool> {
    let configs = mapper
        .configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;
    let set = WriteSet::update(
        vec![
            col("name", &mapper.name),
            col("mapper_type", &mapper.mapper_type),
            col("configs", &configs),
            col("updated_by", &mapper.metadata.updated_by),
        ],
        vec![col("mapper_id", &mapper.mapper_id)],
    );
    let statement = statement::update("idp_mappers", &set).replace(
        " WHERE ",
        ", updated_at = now(), version = version + 1 WHERE ",
    );
    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Remove a rule, and say whether it was there to remove.
pub async fn delete_mapper(transaction: &Transaction<'_>, mapper_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM idp_mappers WHERE mapper_id = $1",
            &[&mapper_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read_mapper(row: Row) -> IdpMapperModel {
    IdpMapperModel {
        mapper_id: row.get("mapper_id"),
        realm_id: row.get("realm_id"),
        provider_alias: row.get("provider_alias"),
        name: row.get("name"),
        mapper_type: row.get("mapper_type"),
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

const SPNEGO_COLUMNS: &str = "tenant, realm_id, enabled, configs, created_by, created_at, \
                               updated_by, updated_at, version";
const FEDERATION_COLUMNS: &str = "tenant, realm_id, alias, enabled, priority, configs, \
                                  created_by, created_at, updated_by, updated_at, version";

/// Every directory this realm federates from, first-asked first.
pub async fn federations(transaction: &Transaction<'_>) -> StoreResult<Vec<UserFederationModel>> {
    let statement =
        format!("SELECT {FEDERATION_COLUMNS} FROM user_federations ORDER BY priority, alias");
    Ok(transaction
        .query(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_federation)
        .collect())
}

pub async fn federation(
    transaction: &Transaction<'_>,
    alias: &str,
) -> StoreResult<Option<UserFederationModel>> {
    let statement = format!("SELECT {FEDERATION_COLUMNS} FROM user_federations WHERE alias = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&alias])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_federation))
}

/// Write one directory, whole: an alias is a name, so writing is replacing.
pub async fn keep_federation(
    transaction: &Transaction<'_>,
    federation: &UserFederationModel,
) -> StoreResult<()> {
    let enabled = federation.enabled.unwrap_or(true);
    let configs = federation
        .configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "INSERT INTO user_federations \
                 (tenant, realm_id, alias, enabled, priority, configs, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3, $4, $5 \
             ON CONFLICT (tenant, realm_id, alias) DO UPDATE \
                 SET enabled = EXCLUDED.enabled, \
                     priority = EXCLUDED.priority, \
                     configs = EXCLUDED.configs, \
                     updated_by = EXCLUDED.created_by, \
                     updated_at = now(), \
                     version = user_federations.version + 1",
            &[
                &federation.alias,
                &enabled,
                &federation.priority,
                &configs,
                &federation.metadata.created_by,
            ],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take one directory away, and say whether it was there.
pub async fn drop_federation(transaction: &Transaction<'_>, alias: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM user_federations WHERE alias = $1", &[&alias])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// The one ticket door this realm answers, when it holds one.
pub async fn spnego(transaction: &Transaction<'_>) -> StoreResult<Option<RealmSpnegoModel>> {
    let statement = format!("SELECT {SPNEGO_COLUMNS} FROM realm_spnego");
    Ok(transaction
        .query_opt(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read_spnego))
}

/// Write the realm's ticket door, whole: the row is a singleton, so writing
/// is replacing.
pub async fn keep_spnego(
    transaction: &Transaction<'_>,
    spnego: &RealmSpnegoModel,
) -> StoreResult<()> {
    let enabled = spnego.enabled.unwrap_or(true);
    let configs = spnego
        .configs
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| StoreError::Backend)?;
    transaction
        .execute(
            "INSERT INTO realm_spnego (tenant, realm_id, enabled, configs, created_by) \
             SELECT current_setting('saffui.current_tenant', true), \
                    current_setting('saffui.current_realm', true), $1, $2, $3 \
             ON CONFLICT (tenant, realm_id) DO UPDATE \
                 SET enabled = EXCLUDED.enabled, \
                     configs = EXCLUDED.configs, \
                     updated_by = EXCLUDED.created_by, \
                     updated_at = now(), \
                     version = realm_spnego.version + 1",
            &[&enabled, &configs, &spnego.metadata.created_by],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Take the ticket door away, and say whether there was one.
pub async fn drop_spnego(transaction: &Transaction<'_>) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM realm_spnego", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read_spnego(row: Row) -> RealmSpnegoModel {
    RealmSpnegoModel {
        realm_id: row.get("realm_id"),
        enabled: Some(row.get("enabled")),
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

fn read_federation(row: Row) -> UserFederationModel {
    UserFederationModel {
        realm_id: row.get("realm_id"),
        alias: row.get("alias"),
        enabled: Some(row.get("enabled")),
        priority: row.get("priority"),
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

const SOURCE_COLUMNS: &str = "tenant, realm_id, source_id, user_id, claims, kind, jwt, endpoint, \
                              endpoint_token, created_by, created_at, updated_by, updated_at, \
                              version";

/// Record what another provider answers for about this person.
pub async fn create_claim_source(
    transaction: &Transaction<'_>,
    source: &UserClaimSourceModel,
) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &source.metadata.tenant),
        col("realm_id", &source.realm_id),
        col("source_id", &source.source_id),
        col("user_id", &source.user_id),
        col("claims", &source.claims),
        col("kind", &source.kind),
        col("jwt", &source.jwt),
        col("endpoint", &source.endpoint),
        col("endpoint_token", &source.endpoint_token),
        col("created_by", &source.metadata.created_by),
    ]);
    transaction
        .execute(
            statement::insert("user_claim_sources", &set).as_str(),
            &set.params(),
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// Every source answering for this person, oldest first, so which source a
/// claim points at does not move between reads.
pub async fn claim_sources_of(
    transaction: &Transaction<'_>,
    user_id: &str,
) -> StoreResult<Vec<UserClaimSourceModel>> {
    let statement = format!(
        "SELECT {SOURCE_COLUMNS} FROM user_claim_sources \
         WHERE user_id = $1 ORDER BY created_at ASC, source_id ASC"
    );
    Ok(transaction
        .query(statement.as_str(), &[&user_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .into_iter()
        .map(read_claim_source)
        .collect())
}

/// Remove one source, and say whether it was there and this person's.
pub async fn delete_claim_source(
    transaction: &Transaction<'_>,
    user_id: &str,
    source_id: &str,
) -> StoreResult<bool> {
    let removed = transaction
        .execute(
            "DELETE FROM user_claim_sources WHERE user_id = $1 AND source_id = $2",
            &[&user_id, &source_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

fn read_claim_source(row: Row) -> UserClaimSourceModel {
    UserClaimSourceModel {
        source_id: row.get("source_id"),
        realm_id: row.get("realm_id"),
        user_id: row.get("user_id"),
        claims: row.get("claims"),
        kind: row.get("kind"),
        jwt: row.get("jwt"),
        endpoint: row.get("endpoint"),
        endpoint_token: row.get("endpoint_token"),
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
