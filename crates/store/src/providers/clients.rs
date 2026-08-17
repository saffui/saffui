//! The clients of a realm.

use deadpool_postgres::Transaction;
use models::entities::client::{ClientModel, ClientSecret, Protocol};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

/// What a read asks for.
///
/// The bearer credentials are not among them. A client is loaded on the token
/// path and rendered into admin responses, and neither needs the secret that
/// authenticates it: [`load_secret`] is the one way to it, so every place that
/// wants one is a place somebody wrote that call.
const COLUMNS: &str = "tenant, realm_id, client_id, name, display_name, description, enabled, \
                       public_client, protocol, secret_created_at, secret_expires_at, \
                       created_by, created_at, updated_by, updated_at, version";

/// Record a client.
pub async fn create(transaction: &Transaction<'_>, client: &ClientModel) -> StoreResult<()> {
    let secret = client.secret.as_ref().map(ClientSecret::expose);
    let registration_token = client.registration_token.as_ref().map(ClientSecret::expose);

    let set = WriteSet::insert(vec![
        col("tenant", &client.metadata.tenant),
        col("realm_id", &client.realm_id),
        col("client_id", &client.client_id),
        col("name", &client.name),
        col("display_name", &client.display_name),
        col("description", &client.description),
        col("enabled", &client.enabled),
        col("secret", &secret),
        col("registration_token", &registration_token),
        col("secret_created_at", &client.secret_created_at),
        col("secret_expires_at", &client.secret_expires_at),
        col("public_client", &client.public_client),
        col("protocol", &client.protocol),
        col("created_by", &client.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("clients", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One client of this realm, without what authenticates it.
pub async fn load(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Option<ClientModel>> {
    let statement = format!("SELECT {COLUMNS} FROM clients WHERE client_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&client_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// The secret a client authenticates with.
///
/// Its own call, so reaching one is something somebody wrote rather than
/// something that arrived with every load. Absent both when the client has none
/// and when there is no such client, which are the same answer to whoever is
/// about to compare it.
pub async fn load_secret(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Option<ClientSecret>> {
    Ok(transaction
        .query_opt(
            "SELECT secret FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| row.get::<_, Option<String>>("secret"))
        .map(ClientSecret::new))
}

/// Whether the identifier is taken in this realm.
pub async fn exists(transaction: &Transaction<'_>, client_id: &str) -> StoreResult<bool> {
    let found: i64 = transaction
        .query_one(
            "SELECT count(*) FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok(found > 0)
}

/// Replace a client's secret and stamp when that happened.
///
/// The two go together. A secret written without the instant it was minted is
/// one whose age nothing can read, and an expiry set from a stale stamp expires
/// the wrong credential.
pub async fn rotate_secret(
    transaction: &Transaction<'_>,
    client_id: &str,
    secret: &ClientSecret,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> StoreResult<bool> {
    let exposed = secret.expose();
    let set = WriteSet::update(
        vec![
            col("secret", &exposed),
            col("secret_expires_at", &expires_at),
        ],
        vec![col("client_id", &client_id)],
    );

    let statement = statement::update("clients", &set).replace(
        " WHERE ",
        ", secret_created_at = now(), updated_at = now(), version = version + 1 WHERE ",
    );

    let changed = transaction
        .execute(statement.as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Remove a client, and say whether there was one to remove.
pub async fn delete(transaction: &Transaction<'_>, client_id: &str) -> StoreResult<bool> {
    let removed = transaction
        .execute("DELETE FROM clients WHERE client_id = $1", &[&client_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(removed > 0)
}

/// One page of this realm's clients, with the total when it was asked for.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<ClientModel>> {
    let rows = transaction
        .query(query.select(COLUMNS, "clients").as_str(), &query.params())
        .await
        .map_err(|_| StoreError::Backend)?;

    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("clients").as_str(), &query.params())
                .await
                .map_err(|_| StoreError::Backend)?
                .get::<_, i64>(0),
        )
    } else {
        None
    };

    Ok(Page::new(
        rows.into_iter().map(read).collect(),
        query.window(),
        total,
    ))
}

fn read(row: Row) -> ClientModel {
    ClientModel {
        client_id: row.get("client_id"),
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        description: row
            .get::<_, Option<String>>("description")
            .unwrap_or_default(),
        enabled: row.get("enabled"),
        public_client: row.get("public_client"),
        protocol: row.get::<_, Option<Protocol>>("protocol"),
        secret_created_at: row.get("secret_created_at"),
        secret_expires_at: row.get("secret_expires_at"),
        // Never read here. Reaching a bearer credential is its own call.
        secret: None,
        registration_token: None,
        consent_required: None,
        root_url: None,
        web_origins: None,
        redirect_uris: None,
        post_logout_redirect_uris: None,
        id_token_signed_response_alg: None,
        userinfo_signed_response_alg: None,
        request_object_signing_alg: None,
        id_token_encryption: None,
        userinfo_encryption: None,
        request_object_encryption: None,
        client_authenticator_type: None,
        full_scope_allowed: None,
        authorization_code_flow_enabled: None,
        implicit_flow_enabled: None,
        direct_access_grants_enabled: None,
        standard_flow_enabled: None,
        bearer_only: None,
        front_channel_logout: None,
        is_surrogate_auth_required: None,
        not_before: None,
        configs: None,
        service_account_enabled: None,
        auth_flow_binding_overrides: None,
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
