use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use uuid::Uuid;

use super::assertion::read_key_set;
use super::authenticate::CLIENT_SECRET_PURPOSE;
use super::{
    AssertionAlgorithm, Client, ClientAuthMethod, KeptProof, check_client_identifier,
    check_redirect_uri, check_scope_token, is_unshowable,
};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::capability::Capability;
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::keys::rotate::list_active_algorithms;
use crate::ports::crypto::{
    KeyCheckLane, KeyMakingFailure, KeyMakingGuard, SealPlace, SignatureAlgorithm,
};
use crate::ports::storage::{StorageError, UnitOfWork};
use crate::secret::Secret;
use crate::tenancy::{RealmId, TenantId};

/// Who asks for a client to be checked, and so on whose share its keys are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientChecker {
    /// An administrator of a realm of this tenant, who proved who they are:
    /// the share of the tenant, on the key makers of the node.
    Administrator(TenantId),
    /// The client itself, registering in this realm through the protocol:
    /// the share of the realm, on a lane that takes no key maker.
    Registration(RealmId),
}

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
    /// The algorithm of its identity tokens. The realm must have a key of it.
    pub id_token_signed_response_alg: Option<SignatureAlgorithm>,
    /// How it proves itself. None: by a secret in the Basic scheme, unless
    /// it is public.
    pub auth_method: Option<ClientAuthMethod>,
    /// The public keys of a client that proves itself with a key.
    pub jwks: Option<&'a Value>,
    /// An address to fetch keys from: refused, keys are given inline.
    pub jwks_uri: Option<&'a str>,
    /// The one algorithm its assertions may be signed in.
    pub auth_signing_alg: Option<AssertionAlgorithm>,
    /// The client of the administration plane that asks, when one does.
    pub created_by: Option<&'a str>,
}

pub struct NewServiceClient<'a> {
    pub client_id: &'a str,
    pub name: &'a str,
    pub scopes: &'a [String],
    pub capabilities: &'a [Capability],
}

/// Chooses how a client proves itself, from what it asked: a public client
/// proves nothing, and a confidential one presents a secret in the Basic
/// scheme unless it named another way.
fn choose_auth_method(wanted: &NewClient<'_>) -> Result<ClientAuthMethod, Failure> {
    match (wanted.public, wanted.auth_method) {
        (true, None | Some(ClientAuthMethod::None)) => Ok(ClientAuthMethod::None),
        (false, None) => Ok(ClientAuthMethod::ClientSecretBasic),
        (false, Some(method)) if method != ClientAuthMethod::None => Ok(method),
        _ => Err(Failure::new(ErrorCode::AuthMethodInvalid)),
    }
}

/// Checks the one algorithm a client signs its assertions in: the secret
/// signs in HS256, a key in a signature this build serves, and a client that
/// signs nothing names none.
fn check_assertion_algorithm(
    app: &App,
    method: ClientAuthMethod,
    algorithm: Option<AssertionAlgorithm>,
) -> Result<(), Failure> {
    match (method, algorithm) {
        (_, None) | (ClientAuthMethod::ClientSecretJwt, Some(AssertionAlgorithm::Hs256)) => Ok(()),
        (ClientAuthMethod::PrivateKeyJwt, Some(AssertionAlgorithm::Signed(signed))) => {
            if app.signer.signs_in(signed) {
                Ok(())
            } else {
                Err(Failure::new(ErrorCode::AlgorithmUnknown))
            }
        }
        _ => Err(Failure::new(ErrorCode::AuthMethodInvalid)),
    }
}

/// The key set a client is kept with: given inline, by a client that proves
/// itself with a key and by no other. Each key is read by the rules, then
/// checked by the signer for its algorithm, on the share and the lane of
/// whoever asks. Nothing is read from storage.
async fn keep_client_keys(
    app: &App,
    checker: ClientChecker,
    method: ClientAuthMethod,
    jwks: Option<&Value>,
    registered: Option<AssertionAlgorithm>,
) -> Result<Option<Value>, Failure> {
    let invalid = || Failure::new(ErrorCode::ClientJwksInvalid);
    match (method, jwks) {
        (ClientAuthMethod::PrivateKeyJwt, Some(jwks)) => {
            let keys = read_key_set(jwks, registered).ok_or_else(invalid)?;
            // A set an assertion could not choose in is of no use: of the one
            // algorithm registered, and each key named once when there are several.
            let mut named: Vec<&str> = keys
                .iter()
                .filter_map(|(_, key)| key.get("kid").and_then(Value::as_str))
                .collect();
            named.sort_unstable();
            named.dedup();
            let usable = keys.iter().all(|(algorithm, _)| {
                registered.is_none_or(|wanted| wanted == AssertionAlgorithm::Signed(*algorithm))
            }) && (keys.len() == 1 || named.len() == keys.len());
            if !usable {
                return Err(invalid());
            }
            let busy = || Failure::new(ErrorCode::KeyMakingBusy);
            let (lane, share): (KeyCheckLane, KeyMakingGuard) = match checker {
                ClientChecker::Administrator(tenant) => (
                    KeyCheckLane::KeyMakers,
                    Box::new(app.key_shares.take(tenant).ok_or_else(busy)?),
                ),
                ClientChecker::Registration(realm) => (
                    KeyCheckLane::Registration,
                    Box::new(app.registration_key_shares.take(realm).ok_or_else(busy)?),
                ),
            };
            match app
                .signer
                .check_client_keys(keys.clone(), lane, share)
                .await
            {
                Ok(true) => {}
                Ok(false) => return Err(invalid()),
                Err(KeyMakingFailure::Busy) => return Err(Failure::new(ErrorCode::KeyMakingBusy)),
                Err(KeyMakingFailure::Failed) => {
                    return Err(Failure::with_detail(
                        ErrorCode::CryptoUnavailable,
                        "the keys of a client cannot be checked",
                    ));
                }
            }
            let keys: Vec<Value> = keys.into_iter().map(|(_, key)| key).collect();
            Ok(Some(json!({ "keys": keys })))
        }
        (ClientAuthMethod::PrivateKeyJwt, None) | (_, Some(_)) => Err(invalid()),
        (_, None) => Ok(None),
    }
}

/// 256 bits from the generator: nothing a client chose.
pub(crate) fn make_client_secret(app: &App) -> Result<Secret, Failure> {
    let mut random = [0_u8; 32];
    app.random
        .fill(&mut random)
        .map_err(|_| Failure::new(ErrorCode::RandomUnavailable))?;
    Ok(Secret::new(URL_SAFE_NO_PAD.encode(random).into_bytes()))
}

/// Keeps a secret as its method needs it: its digest when the client
/// presents it, sealed for the row of the client when the realm checks a
/// signature with it.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientHasNoSecret`] for a method that keeps none,
/// [`ErrorCode::CryptoUnavailable`] when the secret cannot be sealed, or the
/// storage failure.
pub(crate) async fn keep_client_secret(
    app: &App,
    work: &mut dyn UnitOfWork,
    client_row: Uuid,
    method: ClientAuthMethod,
    secret: &Secret,
) -> Result<KeptProof, Failure> {
    match method {
        // Drawn by the realm, never chosen: a plain digest is enough to keep
        // it, and checking it costs one hash.
        ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost => Ok(KeptProof {
            secret_digest: Some(app.digester.sha256(secret.expose()).to_vec()),
            sealed_secret: None,
            jwks: None,
        }),
        ClientAuthMethod::ClientSecretJwt => {
            let unavailable = |detail| Failure::with_detail(ErrorCode::CryptoUnavailable, detail);
            let scope = work.scope();
            let data_key = work
                .read_data_key()
                .await?
                .ok_or_else(|| unavailable("the realm has no data key"))?;
            let place = SealPlace {
                tenant: scope.tenant().as_uuid(),
                realm: scope.realm().as_uuid(),
                purpose: CLIENT_SECRET_PURPOSE,
                row: client_row,
            };
            let sealed = app
                .sealer
                .seal(&data_key, &place, secret)
                .map_err(|_| unavailable("a client secret cannot be sealed"))?;
            Ok(KeptProof {
                secret_digest: None,
                sealed_secret: Some(sealed),
                jwks: None,
            })
        }
        ClientAuthMethod::PrivateKeyJwt | ClientAuthMethod::None => {
            Err(Failure::new(ErrorCode::ClientHasNoSecret))
        }
    }
}

/// A client to register that passed every check needing no unit of work,
/// its keys among them. Only [`check_new_client`] makes one.
pub struct CheckedClient<'a> {
    wanted: NewClient<'a>,
    name: &'a str,
    method: ClientAuthMethod,
    jwks: Option<Value>,
    checker: ClientChecker,
}

impl<'a> CheckedClient<'a> {
    /// The keys the client will be kept with, as the rules wrote them.
    #[must_use]
    pub fn kept_keys(&self) -> Option<&Value> {
        self.jwks.as_ref()
    }

    /// The client as checked, with the scopes its realm lets it have when it
    /// is written, each checked as a scope.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorCode::ScopeInvalid`].
    pub fn with_scopes<'b>(self, scopes: &'b [String]) -> Result<CheckedClient<'b>, Failure>
    where
        'a: 'b,
    {
        for scope in scopes {
            check_scope_token(scope)?;
        }
        Ok(CheckedClient {
            wanted: NewClient {
                scopes,
                ..self.wanted
            },
            name: self.name,
            method: self.method,
            jwks: self.jwks,
            checker: self.checker,
        })
    }
}

/// Checks a client to register as far as it can be checked without a unit
/// of work. It runs before one opens: an RSA key costs a core for a while
/// to check, and no connection waits in a transaction meanwhile.
///
/// # Errors
///
/// Returns the code of what is refused, [`ErrorCode::KeyMakingBusy`] while
/// the share of `checker` makes or checks other keys or every place of its
/// lane is at work, or [`ErrorCode::CryptoUnavailable`].
pub async fn check_new_client<'a>(
    app: &App,
    checker: ClientChecker,
    wanted: NewClient<'a>,
) -> Result<CheckedClient<'a>, Failure> {
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
    // An address of keys is to be read from outside, away from any unit of
    // work, by the one path that reaches outside: none reads it yet. Keys
    // read there pass `Signer::check_client_keys` before they serve.
    if wanted.jwks_uri.is_some() {
        return Err(Failure::new(ErrorCode::ClientJwksInvalid));
    }
    let method = choose_auth_method(&wanted)?;
    check_assertion_algorithm(app, method, wanted.auth_signing_alg)?;
    let jwks = keep_client_keys(app, checker, method, wanted.jwks, wanted.auth_signing_alg).await?;
    Ok(CheckedClient {
        wanted,
        name,
        method,
        jwks,
        checker,
    })
}

/// Refuses an algorithm of identity tokens the realm has no active key of:
/// a token is never signed in another algorithm than the one registered, so
/// one the realm cannot sign in now is refused here, not at a sign-in.
async fn check_id_token_algorithm(
    app: &App,
    work: &mut dyn UnitOfWork,
    algorithm: Option<SignatureAlgorithm>,
) -> Result<(), Failure> {
    let Some(algorithm) = algorithm else {
        return Ok(());
    };
    let keys = work.list_signing_keys().await?;
    if list_active_algorithms(app.signer.as_ref(), &keys).contains(&algorithm) {
        Ok(())
    } else {
        Err(Failure::new(ErrorCode::KeyAlgorithmUnavailable))
    }
}

/// Registers a client checked by [`check_new_client`], and returns the
/// secret the realm generated for it when its method keeps one. The secret
/// is returned here and never again: it is kept as a digest, or sealed.
///
/// # Errors
///
/// Returns [`ErrorCode::KeyAlgorithmUnavailable`] for an algorithm of
/// identity tokens the realm cannot sign in,
/// [`ErrorCode::ClientIdentifierTaken`] when the realm has that client
/// already, or the storage failure.
pub async fn register_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    checked: CheckedClient<'_>,
) -> Result<(Client, Option<Secret>), Failure> {
    let (client, secret, created) = insert_checked_client(app, work, checked).await?;
    record_event(app, work, EventKind::ClientCreated, created).await?;
    Ok((client, secret))
}

/// As [`register_client`], and records no event: returns what the event of
/// the creation says, for the caller to say it in its own.
pub(crate) async fn insert_checked_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    checked: CheckedClient<'_>,
) -> Result<(Client, Option<Secret>, Value), Failure> {
    let CheckedClient {
        wanted,
        name,
        method,
        jwks,
        checker,
    } = checked;
    check_id_token_algorithm(app, work, wanted.id_token_signed_response_alg).await?;

    let id = mint_id(app)?;
    let (secret, proof) = if method.keeps_secret() {
        let secret = make_client_secret(app)?;
        let proof = keep_client_secret(app, work, id, method, &secret).await?;
        (Some(secret), proof)
    } else {
        let proof = KeptProof {
            secret_digest: None,
            sealed_secret: None,
            jwks,
        };
        (None, proof)
    };
    let client = Client {
        id,
        client_id: wanted.client_id.to_owned(),
        name: name.to_owned(),
        auth_method: method,
        auth_signing_alg: wanted.auth_signing_alg,
        allows_client_credentials: method != ClientAuthMethod::None
            && wanted.redirect_uris.is_empty(),
        allows_authorization_code: !wanted.redirect_uris.is_empty(),
        redirect_uris: wanted.redirect_uris.to_vec(),
        post_logout_redirect_uris: wanted.post_logout_redirect_uris.to_vec(),
        requires_consent: wanted.requires_consent,
        scopes: wanted.scopes.to_vec(),
        capabilities: wanted.capabilities.to_vec(),
        id_token_signed_response_alg: wanted.id_token_signed_response_alg,
        enabled: true,
        self_registered: matches!(checker, ClientChecker::Registration(_)),
        created_at: app.now(),
    };
    work.insert_client(&client, &proof)
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
        "auth_method": method.name(),
    });
    if let Some(actor) = wanted.created_by {
        created["actor"] = json!({ "client_id": actor });
    }
    if let Some(algorithm) = client.id_token_signed_response_alg {
        created["id_token_signed_response_alg"] = json!(algorithm.name());
    }
    Ok((client, secret, created))
}

/// Rewrites the client of the row `kept`, read and taken in `work`, with
/// what [`check_new_client`] let through of its metadata, and returns it
/// with the keys it is now kept with. Its identifier, its method, its
/// secret, its grants and capabilities, whether it asks each person and
/// whether it is enabled stay as they were kept: a client that would prove
/// itself another way registers again.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientMetadataInvalid`] for another method than
/// kept, [`ErrorCode::KeyAlgorithmUnavailable`],
/// [`ErrorCode::ClientNotFound`], or the storage failure.
pub async fn rewrite_client(
    app: &App,
    work: &mut dyn UnitOfWork,
    kept: Client,
    checked: CheckedClient<'_>,
) -> Result<(Client, Option<Value>), Failure> {
    let CheckedClient {
        wanted,
        name,
        method,
        jwks,
        ..
    } = checked;
    if method != kept.auth_method {
        return Err(Failure::with_detail(
            ErrorCode::ClientMetadataInvalid,
            "token_endpoint_auth_method",
        ));
    }
    check_id_token_algorithm(app, work, wanted.id_token_signed_response_alg).await?;
    let client = Client {
        name: name.to_owned(),
        auth_signing_alg: wanted.auth_signing_alg,
        redirect_uris: wanted.redirect_uris.to_vec(),
        post_logout_redirect_uris: wanted.post_logout_redirect_uris.to_vec(),
        scopes: wanted.scopes.to_vec(),
        id_token_signed_response_alg: wanted.id_token_signed_response_alg,
        ..kept
    };
    if !work.write_client_metadata(&client, jwks.as_ref()).await? {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    Ok((client, jwks))
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
    let checked = check_new_client(
        app,
        ClientChecker::Administrator(work.scope().tenant()),
        NewClient {
            client_id: wanted.client_id,
            name: wanted.name,
            scopes: wanted.scopes,
            capabilities: wanted.capabilities,
            redirect_uris: &[],
            post_logout_redirect_uris: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            created_by: None,
        },
    )
    .await?;
    let (client, secret) = register_client(app, work, checked).await?;
    // A client that presents its secret in the Basic scheme is always given one.
    let secret = secret.ok_or(Failure::new(ErrorCode::Internal))?;
    Ok((client, secret))
}

#[cfg(test)]
mod tests {
    use super::{NewServiceClient, register_service_client};
    use crate::clients::{AssertionAlgorithm, Client, ClientAuthMethod};
    use crate::error::ErrorCode;
    use crate::ports::crypto::{Digester, SignatureAlgorithm, Signer};
    use crate::secret::Secret;
    use crate::testkit::crypto::WeakSigner;
    use crate::testkit::digest::WeakDigester;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{check_and_register_client, create_realm};
    use crate::testkit::memory::MemoryStorage;

    /// What the realm keeps to check that `client_id` of `acme` is who it says.
    fn read_proof(app: &crate::app::App, client_id: &str) -> crate::clients::KeptProof {
        let scope = complete(crate::tenancy::resolve::resolve_realm(app, "acme"))
            .expect("the realm")
            .1;
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        complete(work.read_client_with_proof(client_id))
            .expect("a read")
            .expect("the client")
            .1
    }

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
            read_proof(&app, "billing").secret_digest,
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
        use super::NewClient;

        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let scopes = ["openid".to_owned()];
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");

        let (client, secret) = complete(check_and_register_client(
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
                id_token_signed_response_alg: None,
                auth_method: None,
                jwks: None,
                jwks_uri: None,
                auth_signing_alg: None,
                created_by: Some("operator"),
            },
        ))
        .expect("an application");
        complete(work.commit()).expect("a commit");

        assert!(secret.is_none() && read_proof(&app, "webapp").secret_digest.is_none());
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

        use super::NewClient;

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |redirect_uris: &[String], capabilities: &[Capability], public: bool| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(check_and_register_client(
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
                    id_token_signed_response_alg: None,
                    auth_method: None,
                    jwks: None,
                    jwks_uri: None,
                    auth_signing_alg: None,
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
        use super::NewClient;

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |redirect_uris: &[String], goodbye: &str| {
            let goodbyes = [goodbye.to_owned()];
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(check_and_register_client(
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
                    id_token_signed_response_alg: None,
                    auth_method: None,
                    jwks: None,
                    jwks_uri: None,
                    auth_signing_alg: None,
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
        use super::NewClient;

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |client_id, redirect_uris: &[String]| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            complete(check_and_register_client(
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
                    id_token_signed_response_alg: None,
                    auth_method: None,
                    jwks: None,
                    jwks_uri: None,
                    auth_signing_alg: None,
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

    /// How a service of the realm `acme` asks to prove itself.
    #[derive(Clone, Copy)]
    struct Proof<'a> {
        method: Option<ClientAuthMethod>,
        jwks: Option<&'a serde_json::Value>,
        jwks_uri: Option<&'a str>,
        signing: Option<AssertionAlgorithm>,
    }

    const BY_DEFAULT: Proof<'static> = Proof {
        method: None,
        jwks: None,
        jwks_uri: None,
        signing: None,
    };

    fn register_proven(
        app: &crate::app::App,
        client_id: &str,
        proof: Proof<'_>,
    ) -> Result<(Client, Option<Secret>), ErrorCode> {
        use super::NewClient;

        let scope = complete(crate::tenancy::resolve::resolve_realm(app, "acme"))
            .expect("the realm")
            .1;
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        let registered = complete(check_and_register_client(
            app,
            work.as_mut(),
            NewClient {
                client_id,
                name: "A service",
                scopes: &[],
                capabilities: &[],
                redirect_uris: &[],
                post_logout_redirect_uris: &[],
                public: false,
                requires_consent: false,
                id_token_signed_response_alg: None,
                auth_method: proof.method,
                jwks: proof.jwks,
                jwks_uri: proof.jwks_uri,
                auth_signing_alg: proof.signing,
                created_by: None,
            },
        ))
        .map_err(|failure| failure.code)?;
        complete(work.commit()).expect("a commit");
        Ok(registered)
    }

    /// A key of its own: two signers just made would make the same one.
    fn make_key(signer: &WeakSigner, algorithm: SignatureAlgorithm) -> serde_json::Value {
        complete(signer.generate_key(algorithm, Box::new(())))
            .expect("a key")
            .public_jwk
    }

    fn make_key_set(algorithm: SignatureAlgorithm) -> serde_json::Value {
        serde_json::json!({ "keys": [make_key(&WeakSigner::default(), algorithm)] })
    }

    #[test]
    fn only_the_methods_that_keep_a_secret_are_given_one_in_the_form_their_method_keeps() {
        use crate::clients::authenticate::CLIENT_SECRET_PURPOSE;
        use crate::ports::crypto::{SealPlace, Sealer};
        use crate::testkit::crypto::TransparentSealer;

        let (app, storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let method = |method| Proof {
            method: Some(method),
            ..BY_DEFAULT
        };
        let keys = make_key_set(SignatureAlgorithm::Es256);

        for (client_id, presented) in [
            ("basic", ClientAuthMethod::ClientSecretBasic),
            ("posted", ClientAuthMethod::ClientSecretPost),
        ] {
            let (client, secret) =
                register_proven(&app, client_id, method(presented)).expect("a client");
            let secret = secret.expect("a secret, shown once");
            assert_eq!(client.auth_method, presented);
            let proof = read_proof(&app, client_id);
            assert_eq!(
                proof.secret_digest,
                Some(WeakDigester.sha256(secret.expose()).to_vec())
            );
            assert_eq!(proof.sealed_secret, None);
        }
        let (signer, secret) =
            register_proven(&app, "signer", method(ClientAuthMethod::ClientSecretJwt))
                .expect("a client");
        let secret = secret.expect("a secret, shown once");
        let proof = read_proof(&app, "signer");
        assert_eq!(proof.secret_digest, None, "kept sealed, not digested");
        let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
        let data_key = complete(work.read_data_key())
            .expect("a read")
            .expect("a data key");
        let place = SealPlace {
            tenant: scope.tenant().as_uuid(),
            realm: scope.realm().as_uuid(),
            purpose: CLIENT_SECRET_PURPOSE,
            row: signer.id,
        };
        let opened = TransparentSealer
            .open(
                &data_key,
                &place,
                &proof.sealed_secret.expect("a sealed secret"),
            )
            .expect("it opens for its row");
        assert_eq!(opened.expose(), secret.expose());
        let (keyed, secret) = register_proven(
            &app,
            "keyed",
            Proof {
                jwks: Some(&keys),
                ..method(ClientAuthMethod::PrivateKeyJwt)
            },
        )
        .expect("a client");
        let proof = read_proof(&app, "keyed");
        assert_eq!(keyed.auth_method, ClientAuthMethod::PrivateKeyJwt);
        assert!(secret.is_none() && proof.secret_digest.is_none() && proof.sealed_secret.is_none());
        assert_eq!(proof.jwks.expect("its keys")["keys"][0]["alg"], "ES256");
        let created = storage
            .read_audit_envelopes(scope.realm())
            .last()
            .cloned()
            .expect("an event");
        assert_eq!(created["payload"]["auth_method"], "private_key_jwt");
    }

    #[test]
    fn what_a_client_shows_of_itself_holds_none_of_what_proves_it() {
        let (app, _storage) = MemoryStorage::wire();
        complete(create_realm(&app, "acme"));
        let method = |method| Proof {
            method: Some(method),
            ..BY_DEFAULT
        };
        let keys = make_key_set(SignatureAlgorithm::Es256);
        let with_keys = Proof {
            jwks: Some(&keys),
            ..method(ClientAuthMethod::PrivateKeyJwt)
        };

        let (basic, _) =
            register_proven(&app, "basic", method(ClientAuthMethod::ClientSecretBasic))
                .expect("a client");
        let (signer, _) =
            register_proven(&app, "signer", method(ClientAuthMethod::ClientSecretJwt))
                .expect("a client");
        let (keyed, _) = register_proven(&app, "keyed", with_keys).expect("a client");

        let digest = read_proof(&app, "basic").secret_digest.expect("a digest");
        let sealed = read_proof(&app, "signer")
            .sealed_secret
            .expect("a sealed secret");
        let key = keys["keys"][0]["x"].as_str().expect("a key").to_owned();
        for (client, proof) in [
            (basic, format!("{digest:?}")),
            (signer, format!("{sealed:?}")),
            (keyed, key),
        ] {
            let shown = format!("{client:?}");
            assert!(!shown.contains(&proof), "{shown}");
        }
    }

    #[test]
    fn a_way_of_proving_that_does_not_fit_the_client_is_refused() {
        let (app, _storage) = MemoryStorage::wire();
        complete(create_realm(&app, "acme"));
        let keys = make_key_set(SignatureAlgorithm::Es256);
        let proven = |method, signing, jwks, jwks_uri| {
            register_proven(
                &app,
                "odd",
                Proof {
                    method,
                    jwks,
                    jwks_uri,
                    signing,
                },
            )
            .map(|_| ())
        };
        let (basic, signed, keyed) = (
            Some(ClientAuthMethod::ClientSecretBasic),
            Some(ClientAuthMethod::ClientSecretJwt),
            Some(ClientAuthMethod::PrivateKeyJwt),
        );

        for (refused, code, why) in [
            (
                proven(Some(ClientAuthMethod::None), None, None, None),
                ErrorCode::AuthMethodInvalid,
                "a confidential client proves something",
            ),
            (
                proven(keyed, Some(AssertionAlgorithm::Hs256), Some(&keys), None),
                ErrorCode::AuthMethodInvalid,
                "a key does not sign with a secret",
            ),
            (
                proven(signed, AssertionAlgorithm::parse("ES256"), None, None),
                ErrorCode::AuthMethodInvalid,
                "a secret does not sign as a key",
            ),
            (
                proven(basic, Some(AssertionAlgorithm::Hs256), None, None),
                ErrorCode::AuthMethodInvalid,
                "a client that signs nothing names no algorithm",
            ),
            (
                proven(keyed, None, None, None),
                ErrorCode::ClientJwksInvalid,
                "a client of a key without keys",
            ),
            (
                proven(basic, None, Some(&keys), None),
                ErrorCode::ClientJwksInvalid,
                "keys for a client of a secret",
            ),
            (
                proven(
                    keyed,
                    None,
                    Some(&keys),
                    Some("https://keys.example.org/jwks"),
                ),
                ErrorCode::ClientJwksInvalid,
                "an address of keys, read by nothing yet",
            ),
        ] {
            assert_eq!(refused, Err(code), "{why}");
        }
    }

    #[test]
    fn a_key_set_is_kept_only_as_the_signer_of_this_build_reads_it() {
        use std::sync::Arc;

        let (mut app, _storage) = MemoryStorage::wire();
        complete(create_realm(&app, "acme"));
        let eddsa = make_key_set(SignatureAlgorithm::EdDsa);
        let es256 = make_key_set(SignatureAlgorithm::Es256);
        // As a `fips-strict` build: no EdDSA, made or read.
        app.signer = Arc::new(WeakSigner::refusing(SignatureAlgorithm::EdDsa));
        let keyed = |client_id, jwks, signing| {
            register_proven(
                &app,
                client_id,
                Proof {
                    method: Some(ClientAuthMethod::PrivateKeyJwt),
                    jwks: Some(jwks),
                    jwks_uri: None,
                    signing,
                },
            )
            .map(|_| ())
        };
        let unread = serde_json::json!({ "keys": [{ "kty": "RSA", "n": "AQAB", "e": "AQAB" }] });

        assert_eq!(
            keyed("eddsa", &eddsa, None),
            Err(ErrorCode::ClientJwksInvalid)
        );
        assert_eq!(
            keyed("unread", &unread, None),
            Err(ErrorCode::ClientJwksInvalid),
            "a key the signer does not read is refused before it is kept"
        );
        assert_eq!(
            keyed("named", &es256, AssertionAlgorithm::parse("EdDSA")),
            Err(ErrorCode::AlgorithmUnknown)
        );
        assert_eq!(keyed("es256", &es256, None), Ok(()));
    }
    #[test]
    fn a_key_set_an_assertion_could_not_choose_in_is_refused() {
        let (app, _storage) = MemoryStorage::wire();
        complete(create_realm(&app, "acme"));
        let signer = WeakSigner::default();
        let (es256, es384, other) = (
            make_key(&signer, SignatureAlgorithm::Es256),
            make_key(&signer, SignatureAlgorithm::Es384),
            make_key(&signer, SignatureAlgorithm::Es256),
        );
        let mut unnamed = other.clone();
        unnamed
            .as_object_mut()
            .expect("an object")
            .remove("kid")
            .expect("a name");
        let mut twin = other.clone();
        twin["kid"] = es256["kid"].clone();
        let keyed = |client_id, keys: &[&serde_json::Value], signing| {
            let jwks = serde_json::json!({ "keys": keys });
            register_proven(
                &app,
                client_id,
                Proof {
                    method: Some(ClientAuthMethod::PrivateKeyJwt),
                    jwks: Some(&jwks),
                    jwks_uri: None,
                    signing,
                },
            )
            .map(|_| ())
        };

        for (refused, why) in [
            (
                keyed("a", &[&es256, &es384], AssertionAlgorithm::parse("ES256")),
                "a key of another algorithm than the one registered",
            ),
            (
                keyed("b", &[&es256, &unnamed], None),
                "a key without a name beside another",
            ),
            (keyed("c", &[&es256, &twin], None), "two keys of one name"),
            (
                keyed("f", &[&es256, &other, &twin], None),
                "two keys of one name, apart",
            ),
        ] {
            assert_eq!(refused, Err(ErrorCode::ClientJwksInvalid), "{why}");
        }
        assert_eq!(keyed("d", &[&es256, &other], None), Ok(()));
        assert_eq!(
            keyed("e", &[&unnamed], None),
            Ok(()),
            "the only key needs no name"
        );
    }

    #[test]
    fn a_public_client_names_no_way_of_proving_but_none() {
        use super::NewClient;

        let (app, _storage) = MemoryStorage::wire();
        let scope = complete(create_realm(&app, "acme"));
        let callbacks = ["https://app.example.org/callback".to_owned()];
        let register = |client_id, method| {
            let mut work = complete(app.storage.begin(scope)).expect("a unit of work");
            let registered = complete(check_and_register_client(
                &app,
                work.as_mut(),
                NewClient {
                    client_id,
                    name: "Web app",
                    scopes: &[],
                    capabilities: &[],
                    redirect_uris: &callbacks,
                    post_logout_redirect_uris: &[],
                    public: true,
                    requires_consent: false,
                    id_token_signed_response_alg: None,
                    auth_method: Some(method),
                    jwks: None,
                    jwks_uri: None,
                    auth_signing_alg: None,
                    created_by: None,
                },
            ))
            .map(|(client, _)| client.auth_method)
            .map_err(|failure| failure.code);
            complete(work.commit()).expect("a commit");
            registered
        };

        assert_eq!(
            register("posted", ClientAuthMethod::ClientSecretPost),
            Err(ErrorCode::AuthMethodInvalid)
        );
        assert_eq!(
            register("webapp", ClientAuthMethod::None),
            Ok(ClientAuthMethod::None)
        );
    }
}
