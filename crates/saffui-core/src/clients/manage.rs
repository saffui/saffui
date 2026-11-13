//! What an administrator does with the clients of a realm.

use serde_json::json;

use super::Client;
use super::register::{NewClient, register_client};
use super::store::ListWindow;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::capability::{Capability, check_capabilities_held};
use crate::authz::roles::describe_operator;
use crate::claims::rules::check_scope_capabilities;
use crate::error::{ErrorCode, Failure};
use crate::secret::Secret;
use crate::tenancy::RealmScope;
use crate::tenancy::resolve::resolve_realm;

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

/// Creates a client on behalf of an administrator, who is named in the
/// event that records it.
///
/// # Errors
///
/// Returns [`ErrorCode::CapabilityMissing`] when the caller would grant a
/// capability it does not hold itself, or a scope that makes tokens say what
/// it may not read: nobody hands out more than they have. Otherwise as
/// [`register_client`].
pub async fn create_client(
    app: &App,
    caller: &AdminCaller,
    wanted: NewClient<'_>,
) -> Result<(Client, Option<Secret>), Failure> {
    let held = &caller.client.capabilities;
    check_capabilities_held(held, wanted.capabilities)?;
    check_scope_capabilities(wanted.scopes, held)?;
    let mut work = app.storage.begin(caller.scope).await?;
    let wanted = NewClient {
        created_by: Some(&caller.client.client_id),
        ..wanted
    };
    let created = register_client(app, work.as_mut(), wanted).await?;
    work.commit().await?;
    Ok(created)
}

/// Gives a client of the realm of that name the capabilities it lacks among
/// `granted`, as the operator asks: no client of the administration plane
/// hands out what it does not hold, so a capability that came after every
/// client of a realm reaches it this way. Nothing is taken away.
///
/// # Errors
///
/// Returns [`ErrorCode::RealmNotFound`], [`ErrorCode::ClientNotFound`],
/// [`ErrorCode::RequestInvalid`] for an application, which acts in the name
/// of people and holds no capability, or the storage failure.
pub async fn grant_capabilities_as_operator(
    app: &App,
    realm: &str,
    client_id: &str,
    granted: &[Capability],
) -> Result<Client, Failure> {
    let (_name, scope) = resolve_realm(app, realm).await?;
    let mut work = app.storage.begin(scope).await?;
    let not_found = || Failure::new(ErrorCode::ClientNotFound);
    // Taken until the commit: a writer of its mappers, which weighs its
    // capabilities, waits and reads them as they are kept.
    if super::check_client_identifier(client_id).is_err()
        || work.lock_client(client_id).await?.is_none()
    {
        return Err(not_found());
    }
    let mut client = work.read_client(client_id).await?.ok_or_else(not_found)?;
    if client.allows_authorization_code {
        return Err(Failure::new(ErrorCode::RequestInvalid));
    }
    let added: Vec<Capability> = Capability::ALL
        .into_iter()
        .filter(|capability| {
            granted.contains(capability) && !client.capabilities.contains(capability)
        })
        .collect();
    if added.is_empty() {
        return Ok(client);
    }
    client.capabilities = Capability::ALL
        .into_iter()
        .filter(|capability| client.capabilities.contains(capability) || added.contains(capability))
        .collect();
    if !work
        .write_client_capabilities(client_id, &client.capabilities)
        .await?
    {
        return Err(not_found());
    }
    let names = |capabilities: &[Capability]| -> Vec<&'static str> {
        capabilities
            .iter()
            .map(|capability| capability.name())
            .collect()
    };
    let told = json!({
        "actor": describe_operator(),
        "capabilities": names(&client.capabilities),
        "client_id": client.client_id,
        "granted": names(&added),
    });
    record_event(
        app,
        work.as_mut(),
        EventKind::ClientCapabilitiesGranted,
        told,
    )
    .await?;
    work.commit().await?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::grant_capabilities_as_operator;
    use crate::authz::capability::Capability;
    use crate::clients::register::{NewServiceClient, register_service_client};
    use crate::error::ErrorCode;
    use crate::tenancy::RealmScope;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{Application, create_realm, register_application};
    use crate::testkit::memory::MemoryStorage;

    /// What the chain says of the grants of the operator, oldest first.
    fn read_grants(storage: &MemoryStorage, scope: RealmScope) -> Vec<Value> {
        storage
            .read_audit_envelopes(scope.realm())
            .into_iter()
            .filter(|event| event["kind"] == "client.capabilities_granted")
            .map(|event| event["payload"].clone())
            .collect()
    }

    #[test]
    fn the_operator_gives_a_client_what_it_lacks_once_and_the_chain_says_it_once() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        complete(register_service_client(
            &app,
            work.as_mut(),
            NewServiceClient {
                client_id: "keeper",
                name: "keeper",
                scopes: &[],
                capabilities: &[Capability::RealmRead],
            },
        ))
        .expect("a client");
        complete(work.commit()).expect("a commit");
        let asked = [Capability::KeyWrite, Capability::RealmRead];

        let granted = complete(grant_capabilities_as_operator(
            &app, "acme", "keeper", &asked,
        ))
        .expect("a grant");
        let again = complete(grant_capabilities_as_operator(
            &app, "acme", "keeper", &asked,
        ))
        .expect("the same grant");

        assert_eq!(
            granted.capabilities,
            [Capability::RealmRead, Capability::KeyWrite]
        );
        assert_eq!(again.capabilities, granted.capabilities);
        assert_eq!(
            read_grants(&storage, scope),
            [json!({
                "actor": { "operator": "command line" },
                "capabilities": ["realm:read", "key:write"],
                "client_id": "keeper",
                "granted": ["key:write"],
            })],
            "what it held already is not granted again, and a grant of nothing is not said"
        );
    }

    #[test]
    fn the_operator_gives_an_application_nothing() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        complete(register_application(
            &app,
            scope,
            Application {
                client_id: "webapp",
                redirect_uri: "https://app.example.org/callback",
                post_logout_redirect_uri: None,
                public: true,
                requires_consent: false,
            },
        ));

        let refused = complete(grant_capabilities_as_operator(
            &app,
            "acme",
            "webapp",
            &[Capability::KeyWrite],
        ))
        .map(|_| ())
        .map_err(|failure| failure.code);

        assert_eq!(refused, Err(ErrorCode::RequestInvalid));
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        let held = complete(work.read_client("webapp"))
            .expect("a read")
            .expect("the application")
            .capabilities;
        assert!(held.is_empty(), "{held:?}");
        assert!(read_grants(&storage, scope).is_empty());
    }
}
