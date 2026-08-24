use deadpool_postgres::Transaction;
use models::entities::client::{ClientModel, ClientSecret, JweRegistration, Protocol};
use models::entities::keys::{JweAlgorithm, JweEncryption};
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
                       client_authenticator_type, full_scope_allowed, consent_required, \
                       bearer_only, service_account_enabled, is_surrogate_auth_required, \
                       authorization_code_flow_enabled, implicit_flow_enabled, \
                       direct_access_grants_enabled, standard_flow_enabled, \
                       front_channel_logout, \
                       root_url, web_origins, redirect_uris, post_logout_redirect_uris, \
                       backchannel_logout_uri, backchannel_logout_session_required, \
                       frontchannel_logout_uri, frontchannel_logout_session_required, \
                       id_token_signed_response_alg, userinfo_signed_response_alg, \
                       request_object_signing_alg, token_endpoint_auth_signing_alg, \
                       jwks, jwks_uri, \
                       client_uri, logo_uri, policy_uri, tos_uri, contacts, \
                       application_type, response_types, default_max_age, \
                       default_acr_values, initiate_login_uri, request_uris, \
                       subject_type, sector_identifier_uri, \
                       registered_at, \
                       id_token_encryption_alg, id_token_encryption_enc, \
                       userinfo_encryption_alg, userinfo_encryption_enc, \
                       request_object_encryption_alg, request_object_encryption_enc, \
                       not_before, configs, auth_flow_binding_overrides, \
                       created_by, created_at, updated_by, updated_at, version";

/// Record a client.
/// Record a client.
///
/// Writes no bearer credential. `client.secret` is not persisted here: a secret
/// is hashed before it is stored and this call has nothing to hash with, so
/// minting one is [`rotate_secret`], which is the single door that sets one.
pub async fn create(transaction: &Transaction<'_>, client: &ClientModel) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &client.metadata.tenant),
        col("realm_id", &client.realm_id),
        col("client_id", &client.client_id),
        col("name", &client.name),
        col("display_name", &client.display_name),
        col("description", &client.description),
        col("enabled", &client.enabled),
        col("secret_created_at", &client.secret_created_at),
        col("secret_expires_at", &client.secret_expires_at),
        col("public_client", &client.public_client),
        col("protocol", &client.protocol),
        // Written here and never by `update`: registering is one event, and an
        // edit afterwards is not a second registration.
        col("registered_at", &client.registered_at),
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

/// What a presented secret is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredSecret {
    /// An Argon2id PHC string, which is what everything written since V018 is.
    Hashed(String),
    /// A row an older binary wrote. Checked once more, then replaced, the way a
    /// password hash is upgraded on a login.
    Plain(ClientSecret),
    /// Recoverable, because `client_secret_jwt` recomputes an HMAC over it and
    /// a hash cannot give it back. Sealed under the realm's key.
    Sealed(Vec<u8>),
}

/// What a client authenticates with.
///
/// Its own call, so reaching one is something somebody wrote rather than
/// something that arrived with every load. Absent both when the client has none
/// and when there is no such client, which are the same answer to whoever is
/// about to check it.
///
/// The hash wins when both columns are set. A rolling update has the old binary
/// still writing the plaintext one, and preferring it would mean a rotation
/// performed by the new binary could be undone by the old one's leftovers.
pub async fn load_secret(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Option<StoredSecret>> {
    Ok(transaction
        .query_opt(
            "SELECT secret_hash, secret, sealed_secret FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| match row.get::<_, Option<Vec<u8>>>("sealed_secret") {
            Some(sealed) => Some(StoredSecret::Sealed(sealed)),
            None => match row.get::<_, Option<String>>("secret_hash") {
                Some(encoded) => Some(StoredSecret::Hashed(encoded)),
                None => row
                    .get::<_, Option<String>>("secret")
                    .map(|plain| StoredSecret::Plain(ClientSecret::new(plain))),
            },
        }))
}

/// Keep a secret this deployment must be able to read back, sealed.
///
/// The hash and the plaintext column are cleared: one storage form per client,
/// and a leftover in either would keep authenticating what a rotation replaced.
pub async fn seal_secret(
    transaction: &Transaction<'_>,
    client_id: &str,
    sealed: &[u8],
    version: i32,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> StoreResult<bool> {
    let nothing: Option<String> = None;
    let set = WriteSet::update(
        vec![
            col("sealed_secret", &sealed),
            col("sealed_version", &version),
            col("secret_hash", &nothing),
            col("secret", &nothing),
            col("secret_expires_at", &expires_at),
        ],
        vec![col("client_id", &client_id)],
    );
    let changed = transaction
        .execute(statement::update("clients", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Where this client publishes its keys and when they were last read, for a
/// caller deciding whether to read them again.
pub async fn published_keys_at(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Option<(Option<String>, Option<chrono::DateTime<chrono::Utc>>)>> {
    Ok(transaction
        .query_opt(
            "SELECT jwks_uri, jwks_fetched_at FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .map(|row| (row.get("jwks_uri"), row.get("jwks_fetched_at"))))
}

/// Keep the key set just read, and when it was read.
///
/// Behind a savepoint, because this happens inside a transaction opened for
/// something else. A failed statement leaves a Postgres transaction unable to
/// run any other, so a best-effort write that could not be made would take the
/// request it was helping down with it.
pub async fn keep_published_keys(
    transaction: &Transaction<'_>,
    client_id: &str,
    jwks: &serde_json::Value,
    at: chrono::DateTime<chrono::Utc>,
) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![col("jwks", &jwks), col("jwks_fetched_at", &at)],
        vec![col("client_id", &client_id)],
    );
    transaction
        .execute("SAVEPOINT keeping_published_keys", &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    let outcome = transaction
        .execute(statement::update("clients", &set).as_str(), &set.params())
        .await;
    let undo = match outcome {
        Ok(_) => "RELEASE SAVEPOINT keeping_published_keys",
        Err(_) => "ROLLBACK TO SAVEPOINT keeping_published_keys",
    };
    transaction
        .execute(undo, &[])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(outcome.map_err(|_| StoreError::Backend)? > 0)
}

/// What a registration access token is checked against, RFC 7592 §2.
pub async fn load_registration_token(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> StoreResult<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT registration_token FROM clients WHERE client_id = $1",
            &[&client_id],
        )
        .await
        .map_err(|_| StoreError::Backend)?
        .and_then(|row| row.get::<_, Option<String>>("registration_token")))
}

/// Set the hash a registration access token is checked against.
pub async fn rotate_registration_token(
    transaction: &Transaction<'_>,
    client_id: &str,
    encoded: &str,
) -> StoreResult<bool> {
    let set = WriteSet::update(
        vec![col("registration_token", &encoded)],
        vec![col("client_id", &client_id)],
    );
    let changed = transaction
        .execute(statement::update("clients", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

/// Put a hash where a plaintext secret was, without touching anything else.
///
/// What converts a row on the authentication that proved the plaintext. The
/// stamps are left alone deliberately: the credential has not changed, only how
/// it is kept, and moving `secret_created_at` would age a secret that is exactly
/// as old as it was a moment ago.
pub async fn convert_secret(
    transaction: &Transaction<'_>,
    client_id: &str,
    encoded: &str,
) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE clients SET secret_hash = $2, secret = NULL \
             WHERE client_id = $1 AND secret IS NOT NULL",
            &[&client_id, &encoded],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
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
    encoded: &str,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> StoreResult<bool> {
    // The plaintext column is cleared, not left. A rotation that wrote the hash
    // and left the old value behind would leave the credential it replaced
    // readable and, worse, still accepted by a binary that reads that column.
    let nothing: Option<String> = None;
    let nothing_sealed: Option<Vec<u8>> = None;
    let nothing_version: Option<i32> = None;
    let set = WriteSet::update(
        vec![
            col("secret_hash", &encoded),
            col("secret", &nothing),
            col("sealed_secret", &nothing_sealed),
            col("sealed_version", &nothing_version),
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

/// Write a client's registrations back.
///
/// Not [`create`], which names what a client is. Everything a client is trusted
/// for, its redirect URIs, its flows, its signing and encryption registrations,
/// is set afterwards behind its own capability, so registering a client cannot
/// also decide which callbacks it may send a user to.
///
/// The bearer credentials are not written here either. Rotating one is
/// [`rotate_secret`], so a settings edit cannot quietly replace a credential.
pub async fn update(transaction: &Transaction<'_>, client: &ClientModel) -> StoreResult<bool> {
    // Serialised up front because the write set borrows what it binds, so a
    // value built inside the vector would not outlive it.
    let id_token_alg = alg_name(client.id_token_signed_response_alg);
    let userinfo_alg = alg_name(client.userinfo_signed_response_alg);
    let request_object_alg = alg_name(client.request_object_signing_alg);
    let assertion_alg = alg_name(client.token_endpoint_auth_signing_alg);
    let (id_token_enc_alg, id_token_enc) = split_registration(client.id_token_encryption);
    let (userinfo_enc_alg, userinfo_enc) = split_registration(client.userinfo_encryption);
    let (request_object_enc_alg, request_object_enc) =
        split_registration(client.request_object_encryption);
    let configs = as_document(client.configs.as_ref().map(serde_json::to_value))?;
    let overrides = as_document(
        client
            .auth_flow_binding_overrides
            .as_ref()
            .map(serde_json::to_value),
    )?;

    let set = WriteSet::update(
        vec![
            col("name", &client.name),
            col("display_name", &client.display_name),
            col("description", &client.description),
            col("enabled", &client.enabled),
            col("public_client", &client.public_client),
            col("protocol", &client.protocol),
            col(
                "client_authenticator_type",
                &client.client_authenticator_type,
            ),
            col("full_scope_allowed", &client.full_scope_allowed),
            col("consent_required", &client.consent_required),
            col("bearer_only", &client.bearer_only),
            col("service_account_enabled", &client.service_account_enabled),
            col(
                "is_surrogate_auth_required",
                &client.is_surrogate_auth_required,
            ),
            col(
                "authorization_code_flow_enabled",
                &client.authorization_code_flow_enabled,
            ),
            col("implicit_flow_enabled", &client.implicit_flow_enabled),
            col(
                "direct_access_grants_enabled",
                &client.direct_access_grants_enabled,
            ),
            col("standard_flow_enabled", &client.standard_flow_enabled),
            col("front_channel_logout", &client.front_channel_logout),
            col("root_url", &client.root_url),
            col("web_origins", &client.web_origins),
            col("redirect_uris", &client.redirect_uris),
            col(
                "post_logout_redirect_uris",
                &client.post_logout_redirect_uris,
            ),
            col("backchannel_logout_uri", &client.backchannel_logout_uri),
            col(
                "backchannel_logout_session_required",
                &client.backchannel_logout_session_required,
            ),
            col("frontchannel_logout_uri", &client.frontchannel_logout_uri),
            col(
                "frontchannel_logout_session_required",
                &client.frontchannel_logout_session_required,
            ),
            col("id_token_signed_response_alg", &id_token_alg),
            col("userinfo_signed_response_alg", &userinfo_alg),
            col("request_object_signing_alg", &request_object_alg),
            col("token_endpoint_auth_signing_alg", &assertion_alg),
            col("jwks", &client.jwks),
            col("jwks_uri", &client.jwks_uri),
            col("client_uri", &client.client_uri),
            col("logo_uri", &client.logo_uri),
            col("policy_uri", &client.policy_uri),
            col("tos_uri", &client.tos_uri),
            col("contacts", &client.contacts),
            col("application_type", &client.application_type),
            col("response_types", &client.response_types),
            col("default_max_age", &client.default_max_age),
            col("default_acr_values", &client.default_acr_values),
            col("initiate_login_uri", &client.initiate_login_uri),
            col("request_uris", &client.request_uris),
            col("subject_type", &client.subject_type),
            col("sector_identifier_uri", &client.sector_identifier_uri),
            col("id_token_encryption_alg", &id_token_enc_alg),
            col("id_token_encryption_enc", &id_token_enc),
            col("userinfo_encryption_alg", &userinfo_enc_alg),
            col("userinfo_encryption_enc", &userinfo_enc),
            col("request_object_encryption_alg", &request_object_enc_alg),
            col("request_object_encryption_enc", &request_object_enc),
            col("not_before", &client.not_before),
            col("configs", &configs),
            col("auth_flow_binding_overrides", &overrides),
            col("updated_by", &client.metadata.updated_by),
        ],
        vec![col("client_id", &client.client_id)],
    );

    let changed = transaction
        .execute(statement::update("clients", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
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
        consent_required: row.get("consent_required"),
        root_url: row.get("root_url"),
        web_origins: row.get("web_origins"),
        redirect_uris: row.get("redirect_uris"),
        post_logout_redirect_uris: row.get("post_logout_redirect_uris"),
        backchannel_logout_uri: row.get("backchannel_logout_uri"),
        backchannel_logout_session_required: row.get("backchannel_logout_session_required"),
        frontchannel_logout_uri: row.get("frontchannel_logout_uri"),
        frontchannel_logout_session_required: row.get("frontchannel_logout_session_required"),
        id_token_signed_response_alg: read_signing_alg(&row, "id_token_signed_response_alg"),
        userinfo_signed_response_alg: read_signing_alg(&row, "userinfo_signed_response_alg"),
        request_object_signing_alg: read_signing_alg(&row, "request_object_signing_alg"),
        token_endpoint_auth_signing_alg: read_signing_alg(&row, "token_endpoint_auth_signing_alg"),
        jwks: row.get("jwks"),
        jwks_uri: row.get("jwks_uri"),
        client_uri: row.get("client_uri"),
        logo_uri: row.get("logo_uri"),
        policy_uri: row.get("policy_uri"),
        tos_uri: row.get("tos_uri"),
        contacts: row.get("contacts"),
        application_type: row.get("application_type"),
        response_types: row.get("response_types"),
        default_max_age: row.get("default_max_age"),
        default_acr_values: row.get("default_acr_values"),
        initiate_login_uri: row.get("initiate_login_uri"),
        request_uris: row.get("request_uris"),
        subject_type: row.get("subject_type"),
        sector_identifier_uri: row.get("sector_identifier_uri"),
        registered_at: row.get("registered_at"),
        id_token_encryption: read_encryption(&row, "id_token_encryption"),
        userinfo_encryption: read_encryption(&row, "userinfo_encryption"),
        request_object_encryption: read_encryption(&row, "request_object_encryption"),
        client_authenticator_type: row.get("client_authenticator_type"),
        full_scope_allowed: row.get("full_scope_allowed"),
        authorization_code_flow_enabled: row.get("authorization_code_flow_enabled"),
        implicit_flow_enabled: row.get("implicit_flow_enabled"),
        direct_access_grants_enabled: row.get("direct_access_grants_enabled"),
        standard_flow_enabled: row.get("standard_flow_enabled"),
        bearer_only: row.get("bearer_only"),
        front_channel_logout: row.get("front_channel_logout"),
        is_surrogate_auth_required: row.get("is_surrogate_auth_required"),
        not_before: row.get("not_before"),
        configs: row
            .get::<_, Option<serde_json::Value>>("configs")
            .and_then(|value| serde_json::from_value(value).ok()),
        service_account_enabled: row.get("service_account_enabled"),
        auth_flow_binding_overrides: row
            .get::<_, Option<serde_json::Value>>("auth_flow_binding_overrides")
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

/// A registered signing algorithm, read back through the catalogue that wrote
/// it.
///
/// A value this build does not know reads as unregistered rather than as a
/// string nothing can sign with. Held as text in the column because the
/// catalogue lives in the build and not in the database.
fn read_signing_alg(row: &Row, column: &str) -> Option<crypto::provider::SignAlg> {
    let named: Option<String> = row.get(column);
    serde_json::from_value(serde_json::Value::String(named?)).ok()
}

/// A registered encryption pair.
///
/// The pair is the unit: an `enc` with no `alg` is not a registration, and an
/// `alg` alone takes the specified default. Reading them as two independent
/// options would let the half-written state back into the model that was built
/// to make it unrepresentable.
fn read_encryption(row: &Row, registration: &str) -> Option<JweRegistration> {
    let named: Option<String> = row.get(format!("{registration}_alg").as_str());
    let alg: JweAlgorithm = serde_json::from_value(serde_json::Value::String(named?)).ok()?;
    let enc = row
        .get::<_, Option<String>>(format!("{registration}_enc").as_str())
        .and_then(|named| {
            serde_json::from_value::<JweEncryption>(serde_json::Value::String(named)).ok()
        });
    Some(JweRegistration::new(alg, enc))
}

/// How the catalogue spells an algorithm, which is what the column holds.
fn alg_name(algorithm: Option<crypto::provider::SignAlg>) -> Option<String> {
    let named = serde_json::to_value(algorithm?).ok()?;
    named.as_str().map(str::to_owned)
}

/// A registration split into the two columns that hold it, both absent together.
fn split_registration(registration: Option<JweRegistration>) -> (Option<String>, Option<String>) {
    let Some(registration) = registration else {
        return (None, None);
    };
    let spell = |value: serde_json::Value| value.as_str().map(str::to_owned);
    (
        serde_json::to_value(registration.alg).ok().and_then(spell),
        serde_json::to_value(registration.enc).ok().and_then(spell),
    )
}

/// A serialised document on its way into a jsonb column.
fn as_document(
    value: Option<Result<serde_json::Value, serde_json::Error>>,
) -> StoreResult<Option<serde_json::Value>> {
    value.transpose().map_err(|_| StoreError::Backend)
}
