//! What an administrator does with the clients of a realm.

use super::Client;
use super::register::{NewServiceClient, register_service_client};
use super::store::ListWindow;
use crate::app::App;
use crate::authz::admin::AdminCaller;
use crate::error::{ErrorCode, Failure};
use crate::secret::Secret;
use crate::tenancy::RealmScope;

/// Lists the clients of a realm, and counts them when asked. The count is
/// read by the unit of work that reads the page: both see one state.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_clients(
    app: &App,
    scope: RealmScope,
    window: ListWindow,
    counted: bool,
) -> Result<(Vec<Client>, Option<u64>), Failure> {
    let mut work = app.storage.begin_snapshot(scope).await?;
    let clients = work.list_clients(window).await?;
    let total = if counted {
        Some(work.count_clients().await?)
    } else {
        None
    };
    Ok((clients, total))
}

/// Reads one client.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientNotFound`], or the storage failure.
pub async fn find_client(app: &App, scope: RealmScope, client_id: &str) -> Result<Client, Failure> {
    let mut work = app.storage.begin(scope).await?;
    super::read_named_client(work.as_mut(), client_id)
        .await?
        .ok_or_else(|| Failure::new(ErrorCode::ClientNotFound))
}

/// Creates a service client on behalf of an administrator.
///
/// # Errors
///
/// Returns [`ErrorCode::CapabilityMissing`] when the caller would grant a
/// capability it does not hold itself: nobody hands out more than they have.
/// Otherwise as [`register_service_client`].
pub async fn create_client(
    app: &App,
    caller: &AdminCaller,
    wanted: NewServiceClient<'_>,
) -> Result<(Client, Secret), Failure> {
    if wanted
        .capabilities
        .iter()
        .any(|granted| !caller.client.capabilities.contains(granted))
    {
        return Err(Failure::new(ErrorCode::CapabilityMissing));
    }
    let mut work = app.storage.begin(caller.scope).await?;
    let created = register_service_client(app, work.as_mut(), wanted).await?;
    work.commit().await?;
    Ok(created)
}
