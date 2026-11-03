use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use super::{Client, check_client_identifier, check_scope_token};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::capability::Capability;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::storage::{StorageError, UnitOfWork};
use crate::secret::Secret;

pub struct NewServiceClient<'a> {
    pub client_id: &'a str,
    pub name: &'a str,
    pub scopes: &'a [String],
    pub capabilities: &'a [Capability],
}

/// Registers a client that authenticates as itself, and returns the secret
/// the realm generated for it. The secret is returned here and never again:
/// only its digest is kept.
///
/// # Errors
///
/// Returns the code of what is refused, [`ErrorCode::ClientIdentifierTaken`]
/// when the realm has that client already, or the storage failure.
pub async fn register_service_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    wanted: NewServiceClient<'_>,
) -> Result<(Client, Secret), Failure> {
    check_client_identifier(wanted.client_id)?;
    for scope in wanted.scopes {
        check_scope_token(scope)?;
    }
    let name = wanted.name.trim();
    if !(1..=120).contains(&name.chars().count()) || name.chars().any(char::is_control) {
        return Err(Failure::new(ErrorCode::ClientNameInvalid));
    }

    // 256 bits from the generator: nothing a client chose, so a plain digest
    // is enough to keep it, and checking it costs one hash per token request.
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    let secret = Secret::new(URL_SAFE_NO_PAD.encode(random).into_bytes());

    let client = Client {
        id: mint_id(app)?,
        client_id: wanted.client_id.to_owned(),
        name: name.to_owned(),
        secret_digest: app.digester.sha256(secret.expose()).to_vec(),
        allows_client_credentials: true,
        scopes: wanted.scopes.to_vec(),
        capabilities: wanted.capabilities.to_vec(),
        enabled: true,
        created_at: app.now(),
    };
    work.insert_client(&client)
        .await
        .map_err(|error| match error {
            StorageError::Taken("client identifier") => {
                Failure::new(ErrorCode::ClientIdentifierTaken)
            }
            other => other.into(),
        })?;
    let capabilities: Vec<&str> = client
        .capabilities
        .iter()
        .map(|granted| granted.name())
        .collect();
    let created = json!({
        "client_id": client.client_id,
        "scopes": client.scopes,
        "capabilities": capabilities,
    });
    record_event(app, work, EventKind::ClientCreated, created).await?;
    Ok((client, secret))
}

#[cfg(test)]
mod tests {
    use super::{NewServiceClient, register_service_client};
    use crate::error::ErrorCode;
    use crate::ports::crypto::Digester;
    use crate::testkit::digest::WeakDigester;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::create_realm;
    use crate::testkit::memory::MemoryStorage;

    #[test]
    fn a_service_client_is_kept_with_the_digest_of_its_secret_and_its_creation_recorded() {
        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let scopes = ["invoices:read".to_owned()];
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");

        let (client, secret) = complete(register_service_client(
            &app,
            work.as_mut(),
            NewServiceClient {
                client_id: "billing",
                name: "Billing",
                scopes: &scopes,
                capabilities: &[],
            },
        ))
        .expect("a client");
        complete(work.commit()).expect("a commit");

        assert_eq!(secret.expose().len(), 43, "256 bits in base64url");
        assert_eq!(client.secret_digest, WeakDigester.sha256(secret.expose()));
        assert!(client.allows_client_credentials && client.enabled);
        let kinds: Vec<String> = storage
            .read_audit_envelopes(scope.realm())
            .iter()
            .filter_map(|event| event["kind"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(kinds.last().map(String::as_str), Some("client.created"));
    }

    #[test]
    fn a_name_or_an_identifier_that_cannot_be_used_and_one_already_taken_are_refused() {
        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let register = |client_id, name| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            let refused = complete(register_service_client(
                &app,
                work.as_mut(),
                NewServiceClient {
                    client_id,
                    name,
                    scopes: &[],
                    capabilities: &[],
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code);
            let _ = complete(work.commit());
            refused
        };

        assert_eq!(register("billing", "Billing"), Ok(()));
        assert_eq!(
            register("billing", "Another"),
            Err(ErrorCode::ClientIdentifierTaken)
        );
        assert_eq!(
            register("bill ing", "Billing"),
            Err(ErrorCode::ClientIdentifierInvalid)
        );
        assert_eq!(register("ledger", "  "), Err(ErrorCode::ClientNameInvalid));
    }
}
