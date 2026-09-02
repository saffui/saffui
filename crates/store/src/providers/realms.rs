use deadpool_postgres::Transaction;
use models::entities::realm::{ClientRegistration, RealmModel, RegistrationBounds, SslEnforcement};
use models::paging::Page;
use tokio_postgres::Row;

use crate::error::{StoreError, StoreResult};
use crate::query::list_query::ListQuery;
use crate::query::statement;
use crate::query::write_set::{WriteSet, col};

const COLUMNS: &str = "tenant, realm_id, name, display_name, enabled, \
                       registration_allowed, client_registration, registration_secret, \
                       registration_max_clients, registration_requires_consent, \
                       registration_trusted_hosts, \
                       offline_session_max_lifespan, max_offline_grants, \
                       require_pushed_authorization_requests, \
                       brute_force_protected, max_login_failures, lockout_seconds, \
                       max_lockout_seconds, failure_reset_seconds, \
                       register_email_as_username, verify_email, \
                       login_with_email_allowed, duplicated_email_allowed, \
                       edit_user_name_allowed, reset_password_allowed, remember_me, \
                       ssl_enforcement, password_policy, \
                       revoke_refresh_token, refresh_token_max_reuse, access_token_lifespan, \
                       refresh_token_lifespan, session_max_lifespan, \
                       offline_session_lifespan, \
                       action_tokens_lifespan, access_code_lifespan, \
                       access_code_lifespan_user_action, access_code_lifespan_login, \
                       events_enabled, admin_events_enabled, not_before, \
                       attributes, acr_loa_map, \
                       browser_flow, otp_policy, webauthn_policy, \
                       mail_templates, device_code_lifespan, device_poll_interval, \
                       supported_locales, default_locale, \
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

/// The realm this transaction is scoped to, read off the tenancy setting:
/// for engine code that holds a scoped transaction and no realm name.
pub async fn of_context(transaction: &Transaction<'_>) -> StoreResult<Option<RealmModel>> {
    let statement = format!(
        "SELECT {COLUMNS} FROM realms \
         WHERE realm_id = current_setting('saffui.current_realm', true)"
    );
    Ok(transaction
        .query_opt(statement.as_str(), &[])
        .await
        .map_err(|_| StoreError::Backend)?
        .map(read))
}

/// Take a realm away. The schema cascades: everything keyed under the
/// realm goes with the row, which is the point of deleting one.
pub async fn delete(transaction: &Transaction<'_>, realm_id: &str) -> StoreResult<bool> {
    let gone = transaction
        .execute("DELETE FROM realms WHERE realm_id = $1", &[&realm_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(gone > 0)
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
    let supported_locales =
        as_document(realm.supported_locales.as_ref().map(serde_json::to_value))?;
    let otp_policy = as_document(realm.otp_policy.as_ref().map(serde_json::to_value))?;
    let webauthn_policy = as_document(realm.webauthn_policy.as_ref().map(serde_json::to_value))?;
    let mail_templates = as_document(realm.mail_templates.as_ref().map(serde_json::to_value))?;
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
            col(
                "require_pushed_authorization_requests",
                &realm.require_pushed_authorization_requests,
            ),
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
                "registration_max_clients",
                &realm.registration_bounds.max_clients,
            ),
            col(
                "registration_requires_consent",
                &realm.registration_bounds.requires_consent,
            ),
            col(
                "registration_trusted_hosts",
                &realm.registration_bounds.trusted_hosts,
            ),
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
            col("refresh_token_lifespan", &realm.refresh_token_lifespan),
            col("session_max_lifespan", &realm.session_max_lifespan),
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
            col("events_enabled", &realm.events_enabled),
            col("admin_events_enabled", &realm.admin_events_enabled),
            col("not_before", &realm.not_before),
            col("attributes", &attributes),
            col("acr_loa_map", &acr_loa_map),
            col("browser_flow", &realm.browser_flow),
            col("otp_policy", &otp_policy),
            col("webauthn_policy", &webauthn_policy),
            col("mail_templates", &mail_templates),
            col("device_code_lifespan", &realm.device_code_lifespan),
            col("device_poll_interval", &realm.device_poll_interval),
            col("supported_locales", &supported_locales),
            col("default_locale", &realm.default_locale),
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
        registration_bounds: RegistrationBounds {
            max_clients: row.get("registration_max_clients"),
            requires_consent: row.get("registration_requires_consent"),
            trusted_hosts: row.get("registration_trusted_hosts"),
        },
        offline_session_max_lifespan: row.get("offline_session_max_lifespan"),
        max_offline_grants: row.get("max_offline_grants"),
        require_pushed_authorization_requests: row.get("require_pushed_authorization_requests"),
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
        refresh_token_lifespan: row.get("refresh_token_lifespan"),
        session_max_lifespan: row.get("session_max_lifespan"),
        offline_session_lifespan: row.get("offline_session_lifespan"),
        action_tokens_lifespan: row.get("action_tokens_lifespan"),
        access_code_lifespan: row.get("access_code_lifespan"),
        access_code_lifespan_user_action: row.get("access_code_lifespan_user_action"),
        access_code_lifespan_login: row.get("access_code_lifespan_login"),
        browser_flow: row.get("browser_flow"),
        otp_policy: row
            .get::<_, Option<serde_json::Value>>("otp_policy")
            .and_then(|held| serde_json::from_value(held).ok()),
        mail_templates: row
            .get::<_, Option<serde_json::Value>>("mail_templates")
            .and_then(|held| serde_json::from_value(held).ok()),
        device_code_lifespan: row.get("device_code_lifespan"),
        device_poll_interval: row.get("device_poll_interval"),
        webauthn_policy: row
            .get::<_, Option<serde_json::Value>>("webauthn_policy")
            .and_then(|held| serde_json::from_value(held).ok()),
        supported_locales: row
            .get::<_, Option<serde_json::Value>>("supported_locales")
            .and_then(|held| serde_json::from_value(held).ok()),
        default_locale: row.get("default_locale"),
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

/// The realm's theme tokens, or nothing when it wears the default.
pub async fn theme_of(
    transaction: &Transaction<'_>,
    realm_id: &str,
) -> StoreResult<Option<serde_json::Value>> {
    let row = transaction
        .query_opt("SELECT theme FROM realms WHERE realm_id = $1", &[&realm_id])
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(row.and_then(|row| row.get("theme")))
}

/// Dress or undress the realm; absent is the default look.
pub async fn set_theme(
    transaction: &Transaction<'_>,
    realm_id: &str,
    theme: Option<&serde_json::Value>,
) -> StoreResult<bool> {
    let changed = transaction
        .execute(
            "UPDATE realms SET theme = $2 WHERE realm_id = $1",
            &[&realm_id, &theme],
        )
        .await
        .map_err(|_| StoreError::Backend)?;
    Ok(changed > 0)
}
