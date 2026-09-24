//! The realm itself as the admin plane changes it: born with everything it
//! cannot work without, taken away, bound to the flow a login starts at,
//! dressed, and counted for the console's overview.

use config::serving::RealmCeiling;
use crypto::envelope::Envelope;
use crypto::provider::CryptoProvider;
use models::auditable::AuditableModel;
use models::entities::realm::{RealmCreateModel, RealmModel};
use store::error::StoreError;
use store::providers::directory::users;
use store::providers::events::outbox;
use store::providers::governance::requests;
use store::providers::protocol::sessions;
use store::providers::realms::{auth_flows, tenants};
use store::providers::{clients, realms};
use store::tenancy::UnitOfWork;

use crate::realm::provisioning::{self, AccountConsole, AdminConsole};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unrealmed {
    #[error("a realm with this identifier already exists")]
    AlreadyExists,
    #[error("this tenant holds the {0} realms it is allowed")]
    AtCeiling(i64),
    #[error("no such realm")]
    NotFound,
    /// In words the administrator is meant to read.
    #[error("{0}")]
    Invalid(String),
    #[error("the store could not be read or written")]
    Backend,
}

/// Who changed a realm, as the tenant's chain records it.
pub struct Witness<'a> {
    pub actor: &'a str,
    pub actor_realm: &'a str,
    pub party: Option<&'a str>,
}

/// What a realm is born from.
pub struct RealmBirth<'a> {
    pub tenant: &'a str,
    pub asked: RealmCreateModel,
    pub administrator_name: &'a str,
    pub administrator_email: &'a str,
    /// The deployment's console, where it names one.
    pub admin_console: Option<AdminConsole<'a>>,
    pub account_console: AccountConsole,
}

/// The counts the console's overview shows, each the realm's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overview {
    pub users: i64,
    pub clients: i64,
    pub sessions: i64,
    pub pending_requests: i64,
    pub waiting_events: i64,
}

/// A realm born ready or not at all: the row, the standard scopes, the
/// consoles, a signing key, the flows and the levels, then its first
/// administrator, whose password this answers once. The tenant's own ceiling
/// is held under a lock taken before the count, so two births one below it
/// cannot both read a count that passes.
pub async fn bear_realm(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    envelope: &Envelope,
    ceiling: RealmCeiling,
    birth: RealmBirth<'_>,
    witness: &Witness<'_>,
    now: i64,
) -> Result<(RealmModel, String), Unrealmed> {
    let backend = |_| Unrealmed::Backend;
    let (tenant, realm_id) = (birth.tenant, birth.asked.name.clone());
    if realms::load(transaction, &realm_id)
        .await
        .map_err(backend)?
        .is_some()
    {
        return Err(Unrealmed::AlreadyExists);
    }
    tenants::hold_realms(transaction, tenant)
        .await
        .map_err(backend)?;
    let named = tenants::load(transaction)
        .await
        .map_err(backend)?
        .and_then(|held| held.limits)
        .and_then(|limits| limits.max_realms);
    if let Some(ceiling) = ceiling.against(named)
        && tenants::count_realms(transaction).await.map_err(backend)? >= ceiling
    {
        return Err(Unrealmed::AtCeiling(ceiling));
    }
    let realm = birth.asked.into_model(
        realm_id.clone(),
        AuditableModel::from_creator(tenant.to_owned(), witness.actor.to_owned()),
    );
    realms::create(transaction, &realm)
        .await
        .map_err(|why| match why {
            StoreError::AlreadyExists => Unrealmed::AlreadyExists,
            _ => Unrealmed::Backend,
        })?;
    provisioning::provision_standard_scopes(transaction, tenant, &realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)?;
    if let Some(console) = &birth.admin_console {
        provisioning::provision_admin_console(transaction, tenant, &realm_id, console)
            .await
            .map_err(|_| Unrealmed::Backend)?;
    }
    provisioning::provision_account_console(transaction, tenant, &realm_id, &birth.account_console)
        .await
        .map_err(|_| Unrealmed::Backend)?;
    provisioning::provision_signing_key(transaction, provider, envelope, tenant, &realm_id, now)
        .await
        .map_err(|_| Unrealmed::Backend)?;
    provisioning::provision_browser_flow(transaction, tenant, &realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)?;
    provisioning::provision_offered_flows(transaction, tenant, &realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)?;
    provisioning::provision_levels(transaction, &realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)?;
    // Last, so a realm that fails to become usable does not leave a password
    // in an operator's hands for an account that was never committed.
    let password = provisioning::provision_first_administrator(
        transaction,
        provider,
        tenant,
        &realm_id,
        birth.administrator_name,
        birth.administrator_email,
    )
    .await
    .map_err(|_| Unrealmed::Backend)?;
    record_realm_event(transaction, witness, &realm_id, "realm.created", now).await?;
    Ok((realm, password))
}

/// Take the realm away. The schema cascades, so everything keyed under it
/// goes with the row, and the tenant's chain records it in the same
/// transaction.
pub async fn take_realm_away(
    transaction: &UnitOfWork,
    realm_id: &str,
    witness: &Witness<'_>,
    now: i64,
) -> Result<(), Unrealmed> {
    if !realms::delete(transaction, realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)?
    {
        return Err(Unrealmed::NotFound);
    }
    record_realm_event(transaction, witness, realm_id, "realm.deleted", now).await
}

/// Write what happened to a realm where it will still be readable afterwards.
///
/// The tenant's chain, not the realm's: a realm's own chain is keyed to it and
/// cascades with it, so the entry recording a deletion would be deleted by the
/// statement it records. The served plane may append here and may not read,
/// which keeps a neighbouring realm's existence as unknowable as the guard
/// makes it.
async fn record_realm_event(
    transaction: &UnitOfWork,
    witness: &Witness<'_>,
    realm_id: &str,
    kind: &str,
    at: i64,
) -> Result<(), Unrealmed> {
    store::tenant_chain::append(
        transaction,
        &serde_json::json!({
            "kind": kind,
            "occurred_at": at as f64,
            "realm": realm_id,
            "actor": witness.actor,
            "actor_realm": witness.actor_realm,
            "party": witness.party,
        }),
    )
    .await
    .map(|_| ())
    .map_err(|_| Unrealmed::Backend)
}

/// Refuse a flow a login cannot start at: it must exist here and be top
/// level. Checked at the door, not at the first login it would break.
pub async fn refuse_unstartable_flow(
    transaction: &UnitOfWork,
    alias: &str,
) -> Result<(), Unrealmed> {
    let usable = auth_flows::flow_by_alias(transaction, alias)
        .await
        .map_err(|_| Unrealmed::Backend)?
        .is_some_and(|flow| flow.top_level == Some(true));
    if usable {
        return Ok(());
    }
    Err(Unrealmed::Invalid(format!(
        "no top-level flow is aliased {alias}"
    )))
}

pub async fn read_theme(
    transaction: &UnitOfWork,
    realm_id: &str,
) -> Result<Option<serde_json::Value>, Unrealmed> {
    realms::theme_of(transaction, realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)
}

/// Keep the realm's theme tokens, or clear them back to the default look.
pub async fn write_theme(
    transaction: &UnitOfWork,
    realm_id: &str,
    theme: Option<&serde_json::Value>,
) -> Result<(), Unrealmed> {
    realms::set_theme(transaction, realm_id, theme)
        .await
        .map_err(|_| Unrealmed::Backend)?
        .then_some(())
        .ok_or(Unrealmed::NotFound)
}

/// The realm's mark and its media type, when it keeps one.
pub async fn read_logo(
    transaction: &UnitOfWork,
    realm_id: &str,
) -> Result<Option<(Vec<u8>, String)>, Unrealmed> {
    realms::logo_of(transaction, realm_id)
        .await
        .map_err(|_| Unrealmed::Backend)
}

/// Keep the realm's mark, already weighed, or take it away.
pub async fn write_logo(
    transaction: &UnitOfWork,
    realm_id: &str,
    logo: Option<(&[u8], &str)>,
) -> Result<(), Unrealmed> {
    realms::set_logo(transaction, realm_id, logo)
        .await
        .map_err(|_| Unrealmed::Backend)?
        .then_some(())
        .ok_or(Unrealmed::NotFound)
}

/// Every count keyed with the realm, so each is the realm's size rather than
/// the deployment's.
pub async fn read_overview(transaction: &UnitOfWork) -> Result<Overview, Unrealmed> {
    let backend = |_| Unrealmed::Backend;
    Ok(Overview {
        users: users::count(transaction).await.map_err(backend)?,
        clients: clients::count(transaction).await.map_err(backend)?,
        sessions: sessions::count_standing(transaction)
            .await
            .map_err(backend)?,
        pending_requests: requests::count_pending(transaction)
            .await
            .map_err(backend)?,
        waiting_events: outbox::count_waiting(transaction).await.map_err(backend)?,
    })
}
