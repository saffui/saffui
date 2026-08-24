use deadpool_postgres::Transaction;
use models::entities::realm::{ClientRegistration, RealmModel, SslEnforcement};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const COLUMNS: &str = "tenant, realm_id, name, display_name, enabled, \
                       registration_allowed, client_registration, registration_secret, \
                       offline_session_max_lifespan, max_offline_grants, \
                       brute_force_protected, max_login_failures, lockout_seconds, \
                       max_lockout_seconds, failure_reset_seconds, \
                       register_email_as_username, verify_email, \
                       login_with_email_allowed, duplicated_email_allowed, \
                       edit_user_name_allowed, reset_password_allowed, remember_me, \
                       ssl_enforcement, password_policy, \
                       revoke_refresh_token, refresh_token_max_reuse, access_token_lifespan, \
                       offline_session_lifespan, \
                       action_tokens_lifespan, access_code_lifespan, \
                       access_code_lifespan_user_action, access_code_lifespan_login, \
                       master_admin_client, events_enabled, admin_events_enabled, not_before, \
                       attributes, acr_loa_map, \
                       created_by, created_at, updated_by, updated_at, version";

/// Record a realm.
///
/// The tenant comes from the transaction, so a model naming another is refused
/// by the rules rather than written under a name nobody would look for it by.
pub async fn create(transaction: &Transaction<'_>, realm: &RealmModel) -> StoreResult<()> {
    let set = WriteSet::insert(vec![
        col("tenant", &realm.metadata.tenant),
        col("realm_id", &realm.realm_id),
        col("name", &realm.name),
        col("display_name", &realm.display_name),
        col("enabled", &realm.enabled),
        col("ssl_enforcement", &realm.ssl_enforcement),
        col("created_by", &realm.metadata.created_by),
    ]);

    transaction
        .execute(statement::insert("realms", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(())
}

/// One realm of this tenant, by its identifier.
pub async fn load(
    transaction: &Transaction<'_>,
    realm_id: &str,
) -> StoreResult<Option<RealmModel>> {
    let statement = format!("SELECT {COLUMNS} FROM realms WHERE realm_id = $1");
    Ok(transaction
        .query_opt(statement.as_str(), &[&realm_id])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Whether a name is taken in this tenant.
///
/// A realm's name is what its issuer is built from, so two realms answering to
/// one name is two issuers nothing can tell apart.
pub async fn name_taken(transaction: &Transaction<'_>, name: &str) -> StoreResult<bool> {
    let found: i64 = transaction
        .query_one("SELECT count(*) FROM realms WHERE name = $1", &[&name])
        .await
        .map_err(|_| StoreError::Backend)?
        .get(0);
    Ok(found > 0)
}

/// One page of this tenant's realms, with the total when it was asked for.
///
/// The count runs the same filters as the page. One that did not would report a
/// total for a set the caller is not reading.
pub async fn list(
    transaction: &Transaction<'_>,
    query: &ListQuery<'_>,
    with_total: bool,
) -> StoreResult<Page<RealmModel>> {
    let rows = transaction
        .query(query.select(COLUMNS, "realms").as_str(), &query.params())
        .await
        .map_err(|_| StoreError::Backend)?;

    let total = if with_total {
        Some(
            transaction
                .query_one(query.count("realms").as_str(), &query.params())
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

/// Write a realm's settings back.
///
/// Every rule a realm has lives here rather than on [`create`], which names what
/// a realm is and nothing about how it behaves. Setting them is a separate act
/// behind its own capability, so creating a realm cannot also decide that it
/// allows registration or that it needs no secured transport.
///
/// The identifier and the name are not written. A realm's name is what its
/// issuer is built from, and moving it under a settings edit would invalidate
/// every token already issued.
pub async fn update(transaction: &Transaction<'_>, realm: &RealmModel) -> StoreResult<bool> {
    // Serialised up front rather than inline: the write set borrows what it
    // binds, so a value built inside the vector would not outlive it.
    let password_policy = as_document(realm.password_policy.as_ref().map(serde_json::to_value))?;
    let attributes = as_document(realm.attributes.as_ref().map(serde_json::to_value))?;
    let acr_loa_map = as_document(realm.acr_loa_map.as_ref().map(serde_json::to_value))?;
    let policy = realm.client_registration.as_str();

    let set = WriteSet::update(
        vec![
            col("display_name", &realm.display_name),
            col("enabled", &realm.enabled),
            col("registration_allowed", &realm.registration_allowed),
            col("client_registration", &policy),
            col(
                "offline_session_max_lifespan",
                &realm.offline_session_max_lifespan,
            ),
            col("max_offline_grants", &realm.max_offline_grants),
            col("brute_force_protected", &realm.brute_force.protected),
            col("max_login_failures", &realm.brute_force.max_failures),
            col("lockout_seconds", &realm.brute_force.lockout_seconds),
            col(
                "max_lockout_seconds",
                &realm.brute_force.max_lockout_seconds,
            ),
            col("failure_reset_seconds", &realm.brute_force.reset_seconds),
            col("registration_secret", &realm.registration_secret),
            col(
                "register_email_as_username",
                &realm.register_email_as_username,
            ),
            col("verify_email", &realm.verify_email),
            col("login_with_email_allowed", &realm.login_with_email_allowed),
            col("duplicated_email_allowed", &realm.duplicated_email_allowed),
            col("edit_user_name_allowed", &realm.edit_user_name_allowed),
            col("reset_password_allowed", &realm.reset_password_allowed),
            col("remember_me", &realm.remember_me),
            col("ssl_enforcement", &realm.ssl_enforcement),
            col("password_policy", &password_policy),
            col("revoke_refresh_token", &realm.revoke_refresh_token),
            col("refresh_token_max_reuse", &realm.refresh_token_max_reuse),
            col("access_token_lifespan", &realm.access_token_lifespan),
            col("offline_session_lifespan", &realm.offline_session_lifespan),
            col("action_tokens_lifespan", &realm.action_tokens_lifespan),
            col("access_code_lifespan", &realm.access_code_lifespan),
            col(
                "access_code_lifespan_user_action",
                &realm.access_code_lifespan_user_action,
            ),
            col(
                "access_code_lifespan_login",
                &realm.access_code_lifespan_login,
            ),
            col("master_admin_client", &realm.master_admin_client),
            col("events_enabled", &realm.events_enabled),
            col("admin_events_enabled", &realm.admin_events_enabled),
            col("not_before", &realm.not_before),
            col("attributes", &attributes),
            col("acr_loa_map", &acr_loa_map),
            col("updated_by", &realm.metadata.updated_by),
        ],
        vec![col("realm_id", &realm.realm_id)],
    );

    let changed = transaction
        .execute(statement::update("realms", &set).as_str(), &set.params())
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}

fn read(row: Row) -> RealmModel {
    RealmModel {
        realm_id: row.get("realm_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        enabled: row.get("enabled"),
        ssl_enforcement: row.get::<_, Option<SslEnforcement>>("ssl_enforcement"),
        registration_allowed: row.get("registration_allowed"),
        client_registration: row
            .get::<_, String>("client_registration")
            .parse()
            .unwrap_or(ClientRegistration::Disabled),
        registration_secret: row.get("registration_secret"),
        offline_session_max_lifespan: row.get("offline_session_max_lifespan"),
        max_offline_grants: row.get("max_offline_grants"),
        brute_force: models::entities::realm::BruteForce {
            protected: row.get("brute_force_protected"),
            max_failures: row.get("max_login_failures"),
            lockout_seconds: row.get("lockout_seconds"),
            max_lockout_seconds: row.get("max_lockout_seconds"),
            reset_seconds: row.get("failure_reset_seconds"),
        },
        register_email_as_username: row.get("register_email_as_username"),
        verify_email: row.get("verify_email"),
        login_with_email_allowed: row.get("login_with_email_allowed"),
        duplicated_email_allowed: row.get("duplicated_email_allowed"),
        edit_user_name_allowed: row.get("edit_user_name_allowed"),
        reset_password_allowed: row.get("reset_password_allowed"),
        remember_me: row.get("remember_me"),
        password_policy: row
            .get::<_, Option<serde_json::Value>>("password_policy")
            .and_then(|value| serde_json::from_value(value).ok()),
        revoke_refresh_token: row.get("revoke_refresh_token"),
        refresh_token_max_reuse: row.get("refresh_token_max_reuse"),
        access_token_lifespan: row.get("access_token_lifespan"),
        offline_session_lifespan: row.get("offline_session_lifespan"),
        action_tokens_lifespan: row.get("action_tokens_lifespan"),
        access_code_lifespan: row.get("access_code_lifespan"),
        access_code_lifespan_user_action: row.get("access_code_lifespan_user_action"),
        access_code_lifespan_login: row.get("access_code_lifespan_login"),
        master_admin_client: row.get("master_admin_client"),
        events_enabled: row.get("events_enabled"),
        admin_events_enabled: row.get("admin_events_enabled"),
        not_before: row.get("not_before"),
        attributes: row
            .get::<_, Option<serde_json::Value>>("attributes")
            .and_then(|value| serde_json::from_value(value).ok()),
        acr_loa_map: row
            .get::<_, Option<serde_json::Value>>("acr_loa_map")
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

/// A serialised document on its way into a jsonb column.
fn as_document(
    value: Option<Result<serde_json::Value, serde_json::Error>>,
) -> StoreResult<Option<serde_json::Value>> {
    value.transpose().map_err(|_| StoreError::Backend)
}
