//! What an administrator does with the clients of a realm.

use serde_json::json;

use super::register::{
    ClientChecker, NewClient, check_new_client, keep_client_secret, make_client_secret,
    register_client,
};
use super::store::ListWindow;
use super::{Client, ClientAuthMethod};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::capability::{Capability, check_capabilities_held};
use crate::authz::roles::{describe_actor, describe_operator};
use crate::claims::rules::check_scope_capabilities;
use crate::error::{ErrorCode, Failure};
use crate::ports::storage::UnitOfWork;
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
/// [`check_new_client`] and [`register_client`].
pub async fn create_client(
    app: &App,
    caller: &AdminCaller,
    wanted: NewClient<'_>,
) -> Result<(Client, Option<Secret>), Failure> {
    let held = &caller.client.capabilities;
    check_capabilities_held(held, wanted.capabilities)?;
    check_scope_capabilities(wanted.scopes, held)?;
    let wanted = NewClient {
        created_by: Some(&caller.client.client_id),
        ..wanted
    };
    let checked = check_new_client(
        app,
        ClientChecker::Administrator(caller.scope.tenant()),
        wanted,
    )
    .await?;
    let mut work = app.storage.begin(caller.scope).await?;
    let created = register_client(app, work.as_mut(), checked).await?;
    work.commit().await?;
    Ok(created)
}

/// Takes the row of a client until the commit, and reads it for a caller
/// who holds every capability of it: whoever changes how a client proves
/// itself may act as it. An operator who grants the client more meanwhile
/// waits, and what is weighed is what is kept.
async fn lock_client_in_reach(
    work: &mut dyn UnitOfWork,
    caller: &AdminCaller,
    client_id: &str,
) -> Result<Client, Failure> {
    let locked = if super::check_client_identifier(client_id).is_ok() {
        work.read_client_for_update(client_id).await?
    } else {
        None
    };
    let locked = locked.ok_or_else(|| Failure::new(ErrorCode::ClientNotFound))?;
    check_capabilities_held(&caller.client.capabilities, &locked.capabilities)?;
    Ok(locked)
}

/// Gives a client a new secret and returns it: the one time it is shown.
/// The secret it replaces proves nothing from the commit on.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientNotFound`], [`ErrorCode::CapabilityMissing`]
/// for a client that holds a capability the caller does not,
/// [`ErrorCode::ClientHasNoSecret`] for a client that keeps none, or the
/// storage failure.
pub async fn rotate_client_secret(
    app: &App,
    caller: &AdminCaller,
    client_id: &str,
) -> Result<Secret, Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    let client = lock_client_in_reach(work.as_mut(), caller, client_id).await?;
    if !client.auth_method.keeps_secret() {
        return Err(Failure::new(ErrorCode::ClientHasNoSecret));
    }
    let secret = make_client_secret(app)?;
    let kept =
        keep_client_secret(app, work.as_mut(), client.id, client.auth_method, &secret).await?;
    let written = work
        .write_client_secret(
            client_id,
            kept.secret_digest.as_deref(),
            kept.sealed_secret.as_deref(),
        )
        .await?;
    if !written {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "client_id": client_id,
    });
    record_event(app, work.as_mut(), EventKind::ClientSecretRotated, told).await?;
    work.commit().await?;
    Ok(secret)
}

/// Changes how a client presents its secret, between the Basic scheme and
/// the form, with the same secret: nothing is drawn, nothing is shown. A
/// client that signs, holds a key or proves nothing keeps its method. A
/// client of the form is not heard at the decision point, which reads the
/// Basic scheme alone.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientNotFound`], [`ErrorCode::CapabilityMissing`]
/// for a client that holds a capability the caller does not,
/// [`ErrorCode::AuthMethodInvalid`] for a method or a client other than
/// these two, or the storage failure.
pub async fn change_client_auth_method(
    app: &App,
    caller: &AdminCaller,
    client_id: &str,
    method: ClientAuthMethod,
) -> Result<Client, Failure> {
    let presents_secret = |method| {
        matches!(
            method,
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost
        )
    };
    if !presents_secret(method) {
        return Err(Failure::new(ErrorCode::AuthMethodInvalid));
    }
    let mut work = app.storage.begin(caller.scope).await?;
    let mut client = lock_client_in_reach(work.as_mut(), caller, client_id).await?;
    if !presents_secret(client.auth_method) {
        return Err(Failure::new(ErrorCode::AuthMethodInvalid));
    }
    if client.auth_method == method {
        return Ok(client);
    }
    if !work.write_client_auth_method(client_id, method).await? {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "client_id": client_id,
        "from": client.auth_method.name(),
        "to": method.name(),
    });
    record_event(app, work.as_mut(), EventKind::ClientAuthMethodChanged, told).await?;
    work.commit().await?;
    client.auth_method = method;
    Ok(client)
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
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use async_trait::async_trait;
    use serde_json::{Value, json};

    use super::grant_capabilities_as_operator;
    use crate::authz::capability::Capability;
    use crate::clients::ClientAuthMethod;
    use crate::clients::register::{NewClient, NewServiceClient, register_service_client};
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::ports::crypto::{
        CryptoFailure, GeneratedSigningKey, KeyCheckLane, KeyMakingFailure, KeyMakingGuard,
        SignatureAlgorithm, Signer,
    };
    use crate::secret::Secret;
    use crate::tenancy::RealmScope;
    use crate::testkit::crypto::WeakSigner;
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

    #[test]
    fn nobody_takes_the_secret_of_a_client_that_holds_more_than_they_do() {
        use super::rotate_client_secret;
        use crate::authz::admin::authorize_admin_call;
        use crate::oidc::scenario::Scenario;
        use crate::testkit::fixtures::create_administrator;

        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "keeper",
            &Capability::ALL,
        ));
        let keeper = complete(authorize_admin_call(
            &scenario.app,
            "acme",
            Some(&token),
            Capability::ClientWrite,
        ))
        .expect("an administrator of everything");
        let read_digest = || {
            let mut work =
                complete(scenario.app.storage.begin(scenario.scope)).expect("a unit of work");
            complete(work.read_client_with_proof("keeper"))
                .expect("a read")
                .and_then(|(_, proof)| proof.secret_digest)
        };
        let before = read_digest();

        let refused = complete(rotate_client_secret(&scenario.app, &operator, "keeper"))
            .map(|_| ())
            .map_err(|failure| failure.code);

        assert_eq!(refused, Err(ErrorCode::CapabilityMissing));
        assert_eq!(read_digest(), before, "its secret stays");
        assert!(
            !scenario
                .read_event_kinds()
                .iter()
                .any(|kind| kind == "client.secret_rotated")
        );
        assert!(
            complete(rotate_client_secret(&scenario.app, &keeper, "keeper")).is_ok(),
            "a caller that holds all it holds"
        );
        assert_ne!(read_digest(), before);
    }

    #[test]
    fn only_a_client_that_keeps_a_secret_is_given_a_new_one() {
        use super::rotate_client_secret;
        use crate::oidc::scenario::Scenario;

        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        let rotate = |client_id| {
            complete(rotate_client_secret(&scenario.app, &operator, client_id))
                .map(|_| ())
                .map_err(|failure| failure.code)
        };

        assert_eq!(rotate("webapp"), Err(ErrorCode::ClientHasNoSecret));
        assert_eq!(rotate("nobody"), Err(ErrorCode::ClientNotFound));
        assert_eq!(rotate("no body"), Err(ErrorCode::ClientNotFound));
        assert_eq!(rotate("billing"), Ok(()));
        let rotated = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .last()
            .cloned()
            .expect("an event");
        assert_eq!(rotated["kind"], "client.secret_rotated");
        assert_eq!(
            rotated["payload"],
            json!({ "actor": { "client_id": "operator" }, "client_id": "billing" })
        );
    }

    #[test]
    fn a_client_moves_its_secret_between_the_header_and_the_form_and_nowhere_else() {
        use super::change_client_auth_method;
        use crate::clients::ClientAuthMethod;
        use crate::clients::authenticate::PresentedSecret;
        use crate::oidc::scenario::Scenario;
        use crate::oidc::token::{TokenRequest, grant_token};
        use crate::testkit::fixtures::create_administrator;

        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "keeper",
            &Capability::ALL,
        ));
        let change = |client_id, method| {
            complete(change_client_auth_method(
                &scenario.app,
                &operator,
                client_id,
                method,
            ))
            .map(|client| client.auth_method)
            .map_err(|failure| failure.code)
        };
        let ask = |secret| {
            let request = TokenRequest {
                grant_type: Some("client_credentials"),
                client_id: Some("billing"),
                client_secret: Some(secret),
                ..TokenRequest::default()
            };
            complete(grant_token(&scenario.app, "acme", request)).is_ok()
        };
        let changes = || {
            scenario
                .storage
                .read_audit_envelopes(scenario.scope.realm())
                .into_iter()
                .filter(|event| event["kind"] == "client.auth_method_changed")
                .map(|event| event["payload"].clone())
                .collect::<Vec<_>>()
        };

        assert_eq!(
            change("billing", ClientAuthMethod::ClientSecretPost),
            Ok(ClientAuthMethod::ClientSecretPost)
        );
        assert!(ask(PresentedSecret::Posted(scenario.copy_service_secret())));
        assert!(!ask(PresentedSecret::Basic(scenario.copy_service_secret())));
        assert_eq!(
            change("billing", ClientAuthMethod::ClientSecretPost),
            Ok(ClientAuthMethod::ClientSecretPost),
            "asked again, nothing changes"
        );
        for (client_id, method, code) in [
            (
                "billing",
                ClientAuthMethod::None,
                ErrorCode::AuthMethodInvalid,
            ),
            (
                "billing",
                ClientAuthMethod::ClientSecretJwt,
                ErrorCode::AuthMethodInvalid,
            ),
            (
                "webapp",
                ClientAuthMethod::ClientSecretBasic,
                ErrorCode::AuthMethodInvalid,
            ),
            (
                "keeper",
                ClientAuthMethod::ClientSecretPost,
                ErrorCode::CapabilityMissing,
            ),
            (
                "nobody",
                ClientAuthMethod::ClientSecretPost,
                ErrorCode::ClientNotFound,
            ),
        ] {
            assert_eq!(change(client_id, method), Err(code), "{client_id}");
        }
        assert_eq!(
            changes(),
            [json!({
                "actor": { "client_id": "operator" },
                "client_id": "billing",
                "from": "client_secret_basic",
                "to": "client_secret_post",
            })],
            "one change, said once"
        );
    }

    /// A signer that answers every check of keys as it is told, and notes
    /// how many units of work were begun, and how many open, as it checked.
    struct CheckingSigner {
        storage: Arc<MemoryStorage>,
        answer: Result<bool, KeyMakingFailure>,
        seen: Mutex<Vec<(usize, usize)>>,
        signer: WeakSigner,
    }

    #[async_trait]
    impl Signer for CheckingSigner {
        fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool {
            self.signer.signs_in(algorithm)
        }

        async fn generate_key(
            &self,
            algorithm: SignatureAlgorithm,
            guard: KeyMakingGuard,
        ) -> Result<GeneratedSigningKey, KeyMakingFailure> {
            self.signer.generate_key(algorithm, guard).await
        }

        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            private_key: &Secret,
            message: &[u8],
        ) -> Result<Vec<u8>, CryptoFailure> {
            self.signer.sign(algorithm, private_key, message)
        }

        async fn check_client_keys(
            &self,
            _keys: Vec<(SignatureAlgorithm, Value)>,
            _lane: KeyCheckLane,
            _guard: KeyMakingGuard,
        ) -> Result<bool, KeyMakingFailure> {
            let seen = (
                self.storage.count_units_of_work(),
                self.storage.count_live_units_of_work(),
            );
            self.seen.lock().expect("the notes").push(seen);
            self.answer
        }

        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            public_jwk: &Value,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoFailure> {
            self.signer
                .verify(algorithm, public_jwk, message, signature)
        }
    }

    #[test]
    fn the_keys_of_a_client_are_checked_before_any_unit_of_work_opens() {
        use super::create_client;
        use crate::clients::ClientAuthMethod;
        use crate::clients::register::NewClient;
        use crate::oidc::scenario::Scenario;

        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        let key = complete(
            scenario
                .app
                .signer
                .generate_key(SignatureAlgorithm::Es256, Box::new(())),
        )
        .expect("a key");
        let jwks = json!({ "keys": [key.public_jwk] });

        for (answer, outcome) in [
            (Ok(false), Err(ErrorCode::ClientJwksInvalid)),
            (Err(KeyMakingFailure::Busy), Err(ErrorCode::KeyMakingBusy)),
            (
                Err(KeyMakingFailure::Failed),
                Err(ErrorCode::CryptoUnavailable),
            ),
            (Ok(true), Ok(())),
        ] {
            let checking = Arc::new(CheckingSigner {
                storage: Arc::clone(&scenario.storage),
                answer,
                seen: Mutex::default(),
                signer: WeakSigner::default(),
            });
            scenario.app.signer = checking.clone();
            let begun = scenario.storage.count_units_of_work();

            let created = complete(create_client(
                &scenario.app,
                &operator,
                NewClient {
                    client_id: "keyed",
                    name: "A service of a key",
                    scopes: &[],
                    capabilities: &[],
                    redirect_uris: &[],
                    post_logout_redirect_uris: &[],
                    frontchannel_logout_uri: None,
                    response_types: &[],
                    public: false,
                    requires_consent: false,
                    id_token_signed_response_alg: None,
                    auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
                    jwks: Some(&jwks),
                    jwks_uri: None,
                    auth_signing_alg: None,
                    request_object_signing_alg: None,
                    require_signed_request_object: false,
                    require_pkce: true,
                    created_by: None,
                },
            ))
            .map(|_| ())
            .map_err(|failure| failure.code);

            assert_eq!(created, outcome, "{answer:?}");
            assert_eq!(
                *checking.seen.lock().expect("the notes"),
                [(begun, 0)],
                "checked once, before any unit of work was begun: {answer:?}"
            );
            assert_eq!(
                scenario.storage.count_units_of_work() - begun,
                usize::from(outcome.is_ok()),
                "a set refused opens no unit of work: {answer:?}"
            );
        }
    }

    /// The signer of a scenario. Told to, it holds the next key it makes or
    /// set of keys it checks at a gate until the gate opens, its guard kept
    /// as a key maker keeps it, apart from the caller; it counts the sets it
    /// is asked to check.
    struct GatedSigner {
        signer: Arc<dyn Signer>,
        gated: AtomicBool,
        open: AtomicBool,
        held: Mutex<Option<KeyMakingGuard>>,
        checks: AtomicUsize,
    }

    impl GatedSigner {
        async fn pass_gate(&self, guard: KeyMakingGuard) -> KeyMakingGuard {
            if !self.gated.swap(false, Ordering::SeqCst) {
                return guard;
            }
            *self.held.lock().expect("the guard") = Some(guard);
            std::future::poll_fn(|_| {
                if self.open.load(Ordering::SeqCst) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            self.held
                .lock()
                .expect("the guard")
                .take()
                .expect("the guard, kept until the gate opens")
        }
    }

    #[async_trait]
    impl Signer for GatedSigner {
        fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool {
            self.signer.signs_in(algorithm)
        }

        async fn generate_key(
            &self,
            algorithm: SignatureAlgorithm,
            guard: KeyMakingGuard,
        ) -> Result<GeneratedSigningKey, KeyMakingFailure> {
            let guard = self.pass_gate(guard).await;
            self.signer.generate_key(algorithm, guard).await
        }

        fn sign(
            &self,
            algorithm: SignatureAlgorithm,
            private_key: &Secret,
            message: &[u8],
        ) -> Result<Vec<u8>, CryptoFailure> {
            self.signer.sign(algorithm, private_key, message)
        }

        async fn check_client_keys(
            &self,
            keys: Vec<(SignatureAlgorithm, Value)>,
            lane: KeyCheckLane,
            guard: KeyMakingGuard,
        ) -> Result<bool, KeyMakingFailure> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            let guard = self.pass_gate(guard).await;
            self.signer.check_client_keys(keys, lane, guard).await
        }

        fn verify(
            &self,
            algorithm: SignatureAlgorithm,
            public_jwk: &Value,
            message: &[u8],
            signature: &[u8],
        ) -> Result<bool, CryptoFailure> {
            self.signer
                .verify(algorithm, public_jwk, message, signature)
        }
    }

    /// Wires `scenario` on a gated signer, its gate shut for the next work,
    /// and returns the set of keys of a client and the signer.
    fn shut_gate(scenario: &mut Scenario) -> (Value, Arc<GatedSigner>) {
        let key = complete(
            scenario
                .app
                .signer
                .generate_key(SignatureAlgorithm::Es256, Box::new(())),
        )
        .expect("a key");
        let gated = Arc::new(GatedSigner {
            signer: Arc::clone(&scenario.app.signer),
            gated: AtomicBool::new(true),
            open: AtomicBool::new(false),
            held: Mutex::default(),
            checks: AtomicUsize::new(0),
        });
        scenario.app.signer = gated.clone();
        (json!({ "keys": [key.public_jwk] }), gated)
    }

    /// A service named `client_id` that proves itself with `jwks`.
    fn ask_keyed<'a>(client_id: &'a str, jwks: &'a Value) -> NewClient<'a> {
        NewClient {
            client_id,
            name: "A service of a key",
            scopes: &[],
            capabilities: &[],
            redirect_uris: &[],
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: None,
            response_types: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: Some(ClientAuthMethod::PrivateKeyJwt),
            jwks: Some(jwks),
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            require_pkce: true,
            created_by: None,
        }
    }

    #[test]
    fn a_tenant_checks_one_set_of_keys_at_a_time_and_leaves_other_tenants_theirs() {
        use super::create_client;
        use crate::authz::admin::{AdminCaller, authorize_admin_call};
        use crate::testkit::fixtures::create_administrator;

        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        let other = complete(create_realm(&scenario.app, "globex"));
        let token = complete(create_administrator(
            &scenario.app,
            "globex",
            other,
            "operator",
            &[Capability::ClientWrite],
        ));
        let elsewhere = complete(authorize_admin_call(
            &scenario.app,
            "globex",
            Some(&token),
            Capability::ClientWrite,
        ))
        .expect("an administrator of another tenant");
        let (jwks, gated) = shut_gate(&mut scenario);
        let twins = json!({ "keys": [jwks["keys"][0], jwks["keys"][0]] });
        let create = |caller: &AdminCaller, wanted: NewClient<'_>| {
            complete(create_client(&scenario.app, caller, wanted))
                .map(|_| ())
                .map_err(|failure| failure.code)
        };

        {
            let mut first = pin!(create_client(
                &scenario.app,
                &operator,
                ask_keyed("first", &jwks)
            ));
            let polled = first.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            assert!(polled.is_pending(), "the first set is held at the gate");

            assert_eq!(
                create(&operator, ask_keyed("second", &jwks)),
                Err(ErrorCode::KeyMakingBusy),
                "one set at a time for a tenant"
            );
            assert_eq!(
                create(&operator, ask_keyed("twins", &twins)),
                Err(ErrorCode::ClientJwksInvalid),
                "a set of the wrong form is refused on its form, before any share"
            );
            let plain = NewClient {
                auth_method: None,
                jwks: None,
                ..ask_keyed("plain", &jwks)
            };
            assert_eq!(
                create(&operator, plain),
                Ok(()),
                "a client without keys takes no share"
            );
            assert_eq!(
                gated.checks.load(Ordering::SeqCst),
                1,
                "and none of them reached the signer"
            );
            assert_eq!(
                create(&elsewhere, ask_keyed("third", &jwks)),
                Ok(()),
                "another tenant is served meanwhile"
            );
            gated.open.store(true, Ordering::SeqCst);
            let polled = first.as_mut().poll(&mut Context::from_waker(Waker::noop()));
            assert!(
                matches!(polled, Poll::Ready(Ok(_))),
                "the first set is kept once the gate opens"
            );
        }
        assert_eq!(
            create(&operator, ask_keyed("second", &jwks)),
            Ok(()),
            "its check done, the tenant has its share again"
        );
    }

    #[test]
    fn a_tenant_turning_a_key_over_checks_no_keys_of_a_client_meanwhile() {
        use super::create_client;
        use crate::keys::rotate::rotate_signing_key;

        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite, Capability::KeyWrite]);
        let (jwks, gated) = shut_gate(&mut scenario);
        let create = || {
            complete(create_client(
                &scenario.app,
                &operator,
                ask_keyed("keyed", &jwks),
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };

        {
            let mut turning = pin!(rotate_signing_key(
                &scenario.app,
                &operator,
                SignatureAlgorithm::Rs256
            ));
            let polled = turning
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            assert!(polled.is_pending(), "the key is held at the gate");

            assert_eq!(
                create(),
                Err(ErrorCode::KeyMakingBusy),
                "one share for a key made and a set checked"
            );
            assert_eq!(
                gated.checks.load(Ordering::SeqCst),
                0,
                "and the set never reached the signer"
            );
            gated.open.store(true, Ordering::SeqCst);
            let polled = turning
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            assert!(
                matches!(polled, Poll::Ready(Ok(_))),
                "the key is made once the gate opens"
            );
        }
        assert_eq!(create(), Ok(()), "the key made, the set is checked");
    }

    #[test]
    fn a_creation_given_up_while_its_keys_are_checked_keeps_the_share_of_its_tenant() {
        use super::create_client;

        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        let (jwks, gated) = shut_gate(&mut scenario);
        let create = || {
            complete(create_client(
                &scenario.app,
                &operator,
                ask_keyed("keyed", &jwks),
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        };

        // Polled once, to the signer, then dropped: a caller that hangs up.
        {
            let mut given_up = pin!(create_client(
                &scenario.app,
                &operator,
                ask_keyed("keyed", &jwks)
            ));
            let polled = given_up
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            assert!(polled.is_pending(), "the set is being checked");
        }

        assert_eq!(
            create(),
            Err(ErrorCode::KeyMakingBusy),
            "the share went with the check"
        );
        assert_eq!(
            gated.checks.load(Ordering::SeqCst),
            1,
            "and no set more was checked"
        );
        drop(gated.held.lock().expect("the guard").take());
        assert_eq!(create(), Ok(()), "the check done, the tenant is served");
    }
}
