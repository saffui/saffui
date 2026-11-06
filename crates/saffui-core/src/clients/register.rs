use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

use super::{
    Client, check_client_identifier, check_redirect_uri, check_scope_token, is_unshowable,
};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::capability::Capability;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::ports::storage::{StorageError, UnitOfWork};
use crate::secret::Secret;

/// A client to register. With redirect URIs it sends people through the
/// authorization endpoint; without, it asks for tokens as itself.
pub struct NewClient<'a> {
    pub client_id: &'a str,
    pub name: &'a str,
    pub scopes: &'a [String],
    pub capabilities: &'a [Capability],
    pub redirect_uris: &'a [String],
    pub post_logout_redirect_uris: &'a [String],
    /// A public application runs where no secret can be kept: it gets none.
    pub public: bool,
    /// Each person is asked before the client gets a code in their name.
    pub requires_consent: bool,
    /// The client of the administration plane that asks, when one does.
    pub created_by: Option<&'a str>,
}

pub struct NewServiceClient<'a> {
    pub client_id: &'a str,
    pub name: &'a str,
    pub scopes: &'a [String],
    pub capabilities: &'a [Capability],
}

/// Registers a client, and returns the secret the realm generated for it
/// unless it is public. The secret is returned here and never again: only
/// its digest is kept.
///
/// # Errors
///
/// Returns the code of what is refused, [`ErrorCode::ClientIdentifierTaken`]
/// when the realm has that client already, or the storage failure.
pub async fn register_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    wanted: NewClient<'_>,
) -> Result<(Client, Option<Secret>), Failure> {
    check_client_identifier(wanted.client_id)?;
    for scope in wanted.scopes {
        check_scope_token(scope)?;
    }
    for uri in wanted
        .redirect_uris
        .iter()
        .chain(wanted.post_logout_redirect_uris)
    {
        check_redirect_uri(uri)?;
    }
    // Only a client that signs people in has anyone to send back after they
    // sign out, or anyone to ask.
    if wanted.redirect_uris.is_empty()
        && (!wanted.post_logout_redirect_uris.is_empty() || wanted.requires_consent)
    {
        return Err(Failure::new(ErrorCode::RequestInvalid));
    }
    let name = wanted.name.trim();
    if !(1..=120).contains(&name.chars().count()) || name.chars().any(is_unshowable) {
        return Err(Failure::new(ErrorCode::ClientNameInvalid));
    }
    // A client without a secret proves nothing about itself: it only takes
    // part in a flow that returns to an address it registered.
    if wanted.public && wanted.redirect_uris.is_empty() {
        return Err(Failure::new(ErrorCode::RequestInvalid));
    }
    // A capability is held by a client that acts as itself. An application
    // gets tokens in the name of people: granted one, it would lend it to
    // every person of the realm.
    if !wanted.redirect_uris.is_empty() && !wanted.capabilities.is_empty() {
        return Err(Failure::new(ErrorCode::RequestInvalid));
    }

    let secret = if wanted.public {
        None
    } else {
        // 256 bits from the generator: nothing a client chose, so a plain
        // digest is enough to keep it, and checking it costs one hash.
        let mut random = [0_u8; 32];
        app.random
            .fill(&mut random)
            .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
        Some(Secret::new(URL_SAFE_NO_PAD.encode(random).into_bytes()))
    };
    let client = Client {
        id: mint_id(app)?,
        client_id: wanted.client_id.to_owned(),
        name: name.to_owned(),
        secret_digest: secret
            .as_ref()
            .map(|secret| app.digester.sha256(secret.expose()).to_vec()),
        allows_client_credentials: !wanted.public && wanted.redirect_uris.is_empty(),
        allows_authorization_code: !wanted.redirect_uris.is_empty(),
        redirect_uris: wanted.redirect_uris.to_vec(),
        post_logout_redirect_uris: wanted.post_logout_redirect_uris.to_vec(),
        requires_consent: wanted.requires_consent,
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
    let mut created = json!({
        "client_id": client.client_id,
        "scopes": client.scopes,
        "capabilities": capabilities,
        "public": wanted.public,
        "requires_consent": client.requires_consent,
    });
    if let Some(actor) = wanted.created_by {
        created["actor"] = json!({ "client_id": actor });
    }
    record_event(app, work, EventKind::ClientCreated, created).await?;
    Ok((client, secret))
}

/// Registers a client that authenticates as itself, and returns the secret
/// the realm generated for it, once.
///
/// # Errors
///
/// As [`register_client`].
pub async fn register_service_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    wanted: NewServiceClient<'_>,
) -> Result<(Client, Secret), Failure> {
    let (client, secret) = register_client(
        app,
        work,
        NewClient {
            client_id: wanted.client_id,
            name: wanted.name,
            scopes: wanted.scopes,
            capabilities: wanted.capabilities,
            redirect_uris: &[],
            post_logout_redirect_uris: &[],
            public: false,
            requires_consent: false,
            created_by: None,
        },
    )
    .await?;
    // A client that is not public is always given a secret.
    let secret = secret.ok_or(Failure::new(ErrorCode::Internal))?;
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
        assert_eq!(
            client.secret_digest,
            Some(WeakDigester.sha256(secret.expose()).to_vec())
        );
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

    #[test]
    fn an_application_is_sent_back_only_where_it_registered_and_a_public_one_keeps_no_secret() {
        use super::{NewClient, register_client};

        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let scopes = ["openid".to_owned()];
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");

        let (client, secret) = complete(register_client(
            &app,
            work.as_mut(),
            NewClient {
                client_id: "webapp",
                name: "Web app",
                scopes: &scopes,
                capabilities: &[],
                redirect_uris: &callbacks,
                post_logout_redirect_uris: &[],
                public: true,
                requires_consent: false,
                created_by: Some("operator"),
            },
        ))
        .expect("an application");
        complete(work.commit()).expect("a commit");

        assert!(secret.is_none() && client.secret_digest.is_none());
        assert!(client.allows_authorization_code && !client.allows_client_credentials);
        assert_eq!(client.redirect_uris, callbacks);
        let created = storage
            .read_audit_envelopes(scope.realm())
            .last()
            .cloned()
            .expect("an event");
        assert_eq!(created["payload"]["public"], true);
        assert_eq!(created["payload"]["actor"]["client_id"], "operator");
    }

    #[test]
    fn an_application_holds_no_capability_and_a_public_client_must_send_people_somewhere() {
        use crate::authz::capability::Capability;

        use super::{NewClient, register_client};

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |redirect_uris: &[String], capabilities: &[Capability], public: bool| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(register_client(
                &app,
                work.as_mut(),
                NewClient {
                    client_id: "webapp",
                    name: "Web app",
                    scopes: &[],
                    capabilities,
                    redirect_uris,
                    post_logout_redirect_uris: &[],
                    public,
                    requires_consent: false,
                    created_by: None,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };

        assert_eq!(
            register(&callbacks, &[Capability::UserRead], false),
            Err(ErrorCode::RequestInvalid),
            "it would lend the capability to every person of the realm"
        );
        assert_eq!(register(&[], &[], true), Err(ErrorCode::RequestInvalid));
        assert_eq!(
            register(&["http://app.example.org/cb".to_owned()], &[], true),
            Err(ErrorCode::RedirectUriInvalid)
        );
    }

    #[test]
    fn an_address_after_sign_out_is_checked_and_belongs_to_an_application_only() {
        use super::{NewClient, register_client};

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |redirect_uris: &[String], goodbye: &str| {
            let goodbyes = [goodbye.to_owned()];
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(register_client(
                &app,
                work.as_mut(),
                NewClient {
                    client_id: "webapp",
                    name: "Web app",
                    scopes: &[],
                    capabilities: &[],
                    redirect_uris,
                    post_logout_redirect_uris: &goodbyes,
                    public: false,
                    requires_consent: false,
                    created_by: None,
                },
            ))
            .map(|(client, _)| client.post_logout_redirect_uris)
            .map_err(|failure| failure.code)
        };

        assert_eq!(
            register(&[], "https://app.example.org/goodbye"),
            Err(ErrorCode::RequestInvalid),
            "a service signs nobody out"
        );
        assert_eq!(
            register(&callbacks, "https://app.example.org/goodbye#part"),
            Err(ErrorCode::RedirectUriInvalid)
        );
        assert_eq!(
            register(&callbacks, "https://app.example.org/goodbye"),
            Ok(vec!["https://app.example.org/goodbye".to_owned()])
        );
    }

    #[test]
    fn only_an_application_asks_people_for_their_consent() {
        use super::{NewClient, register_client};

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |client_id, redirect_uris: &[String]| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(register_client(
                &app,
                work.as_mut(),
                NewClient {
                    client_id,
                    name: "Partner",
                    scopes: &[],
                    capabilities: &[],
                    redirect_uris,
                    post_logout_redirect_uris: &[],
                    public: false,
                    requires_consent: true,
                    created_by: None,
                },
            ))
            .map(|(client, _)| client.requires_consent)
            .map_err(|failure| failure.code)
        };

        assert_eq!(
            register("billing", &[]),
            Err(ErrorCode::RequestInvalid),
            "a service signs nobody in"
        );
        assert_eq!(register("partner", &callbacks), Ok(true));
    }
}
