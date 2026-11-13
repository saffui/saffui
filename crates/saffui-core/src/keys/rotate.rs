//! The keys of a realm, as an administrator turns them over. A new key
//! signs at once; the one it replaces keeps verifying what it signed until
//! it is removed, and only a retired key is ever removed.

use serde_json::{Value, json};

use super::generate::{generate_signing_key, seal_signing_key};
use super::{KeyStatus, MAX_SIGNING_KEYS, SigningKey};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::roles::{describe_actor, describe_operator};
use crate::error::{ErrorCode, Failure};
use crate::ports::crypto::{SignatureAlgorithm, Signer};
use crate::tenancy::RealmScope;
use crate::tenancy::resolve::resolve_realm;

/// Gives the realm a new active key for `algorithm`, and retires the key of
/// that algorithm it replaces. The first key of an algorithm replaces none.
///
/// # Errors
///
/// Returns [`ErrorCode::AlgorithmUnknown`] for an algorithm this build does
/// not sign in, [`ErrorCode::SigningKeyLimitReached`] for a realm that holds
/// [`MAX_SIGNING_KEYS`] already, [`ErrorCode::KeyMakingBusy`] while its
/// tenant makes another key or every key maker is at work,
/// [`ErrorCode::CryptoUnavailable`] when the key cannot be made or sealed,
/// or the storage failure.
pub async fn rotate_signing_key(
    app: &App,
    caller: &AdminCaller,
    algorithm: SignatureAlgorithm,
) -> Result<SigningKey, Failure> {
    turn_key_over(app, caller.scope, algorithm, describe_actor(caller)).await
}

/// As [`rotate_signing_key`], asked by the operator for the realm of that
/// name.
///
/// # Errors
///
/// Returns [`ErrorCode::RealmNotFound`], or as [`rotate_signing_key`].
pub async fn rotate_signing_key_as_operator(
    app: &App,
    realm: &str,
    algorithm: SignatureAlgorithm,
) -> Result<SigningKey, Failure> {
    let (_name, scope) = resolve_realm(app, realm).await?;
    turn_key_over(app, scope, algorithm, describe_operator()).await
}

async fn turn_key_over(
    app: &App,
    scope: RealmScope,
    algorithm: SignatureAlgorithm,
    actor: Value,
) -> Result<SigningKey, Failure> {
    if !app.signer.signs_in(algorithm) {
        return Err(Failure::new(ErrorCode::AlgorithmUnknown));
    }
    let full = || Failure::new(ErrorCode::SigningKeyLimitReached);
    // A first look, so that a realm at its bound costs no key: the count
    // taken under the lock below is the one that holds.
    let held = app
        .storage
        .begin_snapshot(scope)
        .await?
        .count_signing_keys()
        .await?;
    if held >= MAX_SIGNING_KEYS {
        return Err(full());
    }
    let Some(making) = app.key_shares.take(scope.tenant()) else {
        return Err(Failure::new(ErrorCode::KeyMakingBusy));
    };
    // The share goes with the work: a caller that gives up does not free it
    // while its key is made.
    let made = generate_signing_key(app, algorithm, Box::new(making)).await?;

    let mut work = app.storage.begin(scope).await?;
    let data_key = work
        .lock_signing_keys()
        .await?
        .ok_or_else(|| Failure::with_detail(ErrorCode::CryptoUnavailable, "no data key"))?;
    let held = work.list_signing_keys().await?;
    // Retired keys stay until an administrator removes them, and each is
    // published to whoever asks: their number is bounded here.
    if held.len() >= MAX_SIGNING_KEYS {
        return Err(full());
    }
    let sealed = seal_signing_key(app, scope, &data_key, made)?;
    // Retired before the new key is kept: one key of an algorithm signs.
    let mut retired = Vec::new();
    for old in held
        .iter()
        .filter(|old| old.status == KeyStatus::Active && old.algorithm == algorithm)
    {
        if work.retire_signing_key(old.id).await? {
            retired.push(old);
        }
    }
    work.insert_signing_key(&sealed).await?;

    let key = sealed.key;
    let created = json!({ "actor": actor, "alg": algorithm.name(), "kid": key.key_id });
    record_event(app, work.as_mut(), EventKind::SigningKeyCreated, created).await?;
    for old in retired {
        let told = json!({
            "actor": actor,
            "alg": old.algorithm.name(),
            "kid": old.key_id,
            "replaced_by": key.key_id,
        });
        record_event(app, work.as_mut(), EventKind::SigningKeyRetired, told).await?;
    }
    work.commit().await?;
    Ok(key)
}

/// Removes a retired key: what it signed no longer verifies. A key of an
/// algorithm this build does not sign in is retired and removed at once,
/// whatever it was: nothing here could turn it over.
///
/// # Errors
///
/// Returns [`ErrorCode::KeyNotFound`], [`ErrorCode::KeyStillActive`] for a
/// key that signs, or the storage failure.
pub async fn remove_retired_key(
    app: &App,
    caller: &AdminCaller,
    key_id: &str,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    let key = work
        .read_signing_key(key_id)
        .await?
        .ok_or(Failure::new(ErrorCode::KeyNotFound))?;
    let actor = describe_actor(caller);
    let told = json!({ "actor": actor, "alg": key.algorithm.name(), "kid": key.key_id });
    let mut retired = false;
    if key.status == KeyStatus::Active {
        if app.signer.signs_in(key.algorithm) {
            return Err(Failure::new(ErrorCode::KeyStillActive));
        }
        retired = work.retire_signing_key(key.id).await?;
    }
    // Another administrator removed it meanwhile.
    if !work.delete_retired_key(key.id).await? {
        return Err(Failure::new(ErrorCode::KeyNotFound));
    }
    if retired {
        let retirement = told.clone();
        record_event(app, work.as_mut(), EventKind::SigningKeyRetired, retirement).await?;
    }
    record_event(app, work.as_mut(), EventKind::SigningKeyDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

/// Lists the keys of a realm, oldest first: their public halves and status.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_realm_keys(app: &App, scope: RealmScope) -> Result<Vec<SigningKey>, Failure> {
    let mut work = app.storage.begin_snapshot(scope).await?;
    Ok(work.list_signing_keys().await?)
}

/// The algorithms a realm signs in now, in the order of the catalog: those
/// it holds an active key of, and this build signs in.
#[must_use]
pub fn list_active_algorithms(signer: &dyn Signer, keys: &[SigningKey]) -> Vec<SignatureAlgorithm> {
    SignatureAlgorithm::ALL
        .into_iter()
        .filter(|algorithm| {
            signer.signs_in(*algorithm)
                && keys
                    .iter()
                    .any(|key| key.status == KeyStatus::Active && key.algorithm == *algorithm)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Waker};

    use async_trait::async_trait;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::Value;

    use super::{list_active_algorithms, list_realm_keys, remove_retired_key, rotate_signing_key};
    use crate::authz::admin::{AdminCaller, authorize_admin_call};
    use crate::authz::capability::Capability;
    use crate::clients::register::{NewClient, register_client};
    use crate::error::ErrorCode;
    use crate::keys::jwks::publish_key_set;
    use crate::keys::{KeyStatus, MAX_SIGNING_KEYS, SigningKey};
    use crate::oidc::discovery::read_provider_metadata;
    use crate::oidc::introspect::introspect_token;
    use crate::oidc::logout::{Logout, LogoutParameters, begin_logout};
    use crate::oidc::scenario::{CALLBACK, GOODBYE, PASSWORD, Scenario};
    use crate::oidc::token::{TokenRequest, grant_token};
    use crate::oidc::userinfo::read_user_info;
    use crate::ports::crypto::{
        CryptoFailure, GeneratedSigningKey, KeyMakingFailure, KeyMakingGuard, SignatureAlgorithm,
        Signer,
    };
    use crate::secret::Secret;
    use crate::testkit::crypto::WeakSigner;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::{CodeFlow, create_administrator, create_realm, run_code_flow};
    use crate::tokens::verify::verify_access_token;

    const ISSUER: &str = "https://id.example.test/realms/acme";

    /// The signer of a scenario, with as many key makers as a test leaves
    /// free, which counts the keys it made. Told to hold, it keeps the guard
    /// of the next key and never ends.
    struct FewMakers {
        signer: Arc<dyn Signer>,
        free: AtomicUsize,
        made: AtomicUsize,
        holding: AtomicBool,
        held: Mutex<Option<KeyMakingGuard>>,
    }

    #[async_trait]
    impl Signer for FewMakers {
        fn signs_in(&self, algorithm: SignatureAlgorithm) -> bool {
            self.signer.signs_in(algorithm)
        }

        async fn generate_key(
            &self,
            algorithm: SignatureAlgorithm,
            guard: KeyMakingGuard,
        ) -> Result<GeneratedSigningKey, KeyMakingFailure> {
            if self.free.load(Ordering::SeqCst) == 0 {
                return Err(KeyMakingFailure::Busy);
            }
            if self.holding.load(Ordering::SeqCst) {
                // Kept as a key maker keeps it, at work until the test says.
                *self.held.lock().expect("the guard") = Some(guard);
                return std::future::pending().await;
            }
            self.made.fetch_add(1, Ordering::SeqCst);
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

    /// Wires `scenario` on a signer of one free key maker, and returns it.
    fn give_few_makers(scenario: &mut Scenario) -> Arc<FewMakers> {
        let makers = Arc::new(FewMakers {
            signer: Arc::clone(&scenario.app.signer),
            free: AtomicUsize::new(1),
            made: AtomicUsize::new(0),
            holding: AtomicBool::new(false),
            held: Mutex::default(),
        });
        scenario.app.signer = makers.clone();
        makers
    }

    /// A member of the header of a compact token.
    fn read_header(token: &str, member: &str) -> Value {
        let part = token.split('.').next().expect("a header");
        let bytes = URL_SAFE_NO_PAD.decode(part).expect("base64url");
        serde_json::from_slice::<Value>(&bytes).expect("JSON")[member].clone()
    }

    fn rotate(
        scenario: &Scenario,
        operator: &AdminCaller,
        algorithm: SignatureAlgorithm,
    ) -> Result<SigningKey, ErrorCode> {
        complete(rotate_signing_key(&scenario.app, operator, algorithm))
            .map_err(|failure| failure.code)
    }

    fn remove(scenario: &Scenario, operator: &AdminCaller, key_id: &str) -> Result<(), ErrorCode> {
        complete(remove_retired_key(&scenario.app, operator, key_id))
            .map_err(|failure| failure.code)
    }

    fn list_keys(scenario: &Scenario) -> Vec<SigningKey> {
        complete(list_realm_keys(&scenario.app, scenario.scope)).expect("the keys")
    }

    /// Registers the public application `reader`, allowed `openid` and
    /// `profile`, whose identity tokens are signed in `algorithm`.
    fn register_reader(
        scenario: &Scenario,
        algorithm: SignatureAlgorithm,
    ) -> Result<(), ErrorCode> {
        let scopes = ["openid".to_owned(), "profile".to_owned()];
        let redirect_uris = [CALLBACK.to_owned()];
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        let wanted = NewClient {
            client_id: "reader",
            name: "An application that reads one algorithm",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &redirect_uris,
            post_logout_redirect_uris: &[],
            public: true,
            requires_consent: false,
            id_token_signed_response_alg: Some(algorithm),
            created_by: None,
        };
        complete(register_client(&scenario.app, work.as_mut(), wanted))
            .map_err(|failure| failure.code)?;
        complete(work.commit()).expect("a commit");
        Ok(())
    }

    #[test]
    fn a_rotation_signs_with_the_new_key_and_the_old_one_verifies_until_it_is_removed() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let before = scenario.sign_in("openid").tokens.access_token;

        let new = rotate(&scenario, &operator, SignatureAlgorithm::Es256).expect("a new key");

        let old = list_keys(&scenario)
            .into_iter()
            .find(|key| key.key_id != new.key_id && key.algorithm == SignatureAlgorithm::Es256)
            .expect("the first key");
        assert_eq!(old.status, KeyStatus::Retired);
        assert_eq!(new.status, KeyStatus::Active);
        let after = scenario.sign_in("openid").tokens.access_token;
        assert_eq!(
            read_header(&after, "kid"),
            new.key_id.as_str(),
            "the new key signs"
        );
        let verifies = |token: &str| {
            let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
            complete(verify_access_token(
                &scenario.app,
                work.as_mut(),
                ISSUER,
                token,
            ))
            .is_ok()
        };
        assert!(verifies(&before), "the retired key still verifies");
        let published = complete(publish_key_set(&scenario.app, scenario.scope)).expect("a set");
        assert_eq!(
            published.keys.len(),
            3,
            "ES256 twice and RS256: the retired one too"
        );

        assert_eq!(
            remove(&scenario, &operator, &new.key_id),
            Err(ErrorCode::KeyStillActive)
        );
        assert_eq!(remove(&scenario, &operator, &old.key_id), Ok(()));
        assert!(!verifies(&before), "what it signed no longer verifies");
        assert!(verifies(&after));
        assert_eq!(
            remove(&scenario, &operator, &old.key_id),
            Err(ErrorCode::KeyNotFound)
        );
        let published = complete(publish_key_set(&scenario.app, scenario.scope)).expect("a set");
        assert!(
            published
                .keys
                .iter()
                .all(|key| key["kid"] != old.key_id.as_str()),
            "a removed key is published no more"
        );
    }

    #[test]
    fn a_token_signed_by_a_retired_key_stands_wherever_it_is_read_until_the_key_is_removed() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let signed_in = scenario.sign_in("openid");
        let access = signed_in.tokens.access_token.clone();
        let refresh = signed_in
            .tokens
            .refresh_token
            .clone()
            .expect("a refresh token");
        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "keeper",
            &[Capability::KeyWrite],
        ));
        let stands = |access: &str, administrator: &str| {
            let introspected = complete(introspect_token(
                &scenario.app,
                "acme",
                Some("billing"),
                Some(scenario.copy_service_secret()),
                Some(access),
            ))
            .expect("an answer")
            .active;
            let told = complete(read_user_info(&scenario.app, "acme", access)).is_ok();
            let let_in = complete(authorize_admin_call(
                &scenario.app,
                "acme",
                Some(administrator),
                Capability::KeyWrite,
            ))
            .is_ok();
            [introspected, told, let_in]
        };
        let identity = signed_in
            .tokens
            .id_token
            .clone()
            .expect("an identity token");
        // Read back as a hint, it sends the browser to the address of its client.
        let hints = || {
            let parameters = LogoutParameters {
                id_token_hint: Some(&identity),
                post_logout_redirect_uri: Some(GOODBYE),
                state: None,
            };
            complete(begin_logout(&scenario.app, "acme", parameters, None))
                == Ok(Logout::SignedOut {
                    location: Some(GOODBYE.to_owned()),
                })
        };
        let first = read_header(&access, "kid");

        let new = rotate(&scenario, &operator, SignatureAlgorithm::Es256).expect("a new key");
        assert_eq!(
            stands(&access, &token),
            [true; 3],
            "retired, it still verifies"
        );
        assert!(
            hints(),
            "an identity token of the retired key is still a hint"
        );
        let refreshed = complete(grant_token(
            &scenario.app,
            "acme",
            TokenRequest {
                grant_type: Some("refresh_token"),
                client_id: Some("webapp"),
                refresh_token: Some(&refresh),
                ..TokenRequest::default()
            },
        ))
        .expect("a refresh across the rotation");
        assert_eq!(
            read_header(&refreshed.access_token, "kid"),
            new.key_id.as_str(),
            "the refreshed token is signed by the new key"
        );

        assert_eq!(
            remove(&scenario, &operator, first.as_str().expect("a kid")),
            Ok(())
        );
        assert_eq!(
            stands(&access, &token),
            [false; 3],
            "removed, it verifies nothing"
        );
        assert!(!hints(), "nor is it a hint");
        assert_eq!(
            stands(&refreshed.access_token, &token),
            [true, true, false],
            "a token of the new key stands; the administrator's was signed by the old one"
        );
    }

    #[test]
    fn a_client_gets_identity_tokens_in_its_algorithm_once_the_realm_has_a_key_of_it() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);

        assert_eq!(
            register_reader(&scenario, SignatureAlgorithm::Ps256),
            Err(ErrorCode::KeyAlgorithmUnavailable),
            "a realm is born with no PS256 key"
        );
        rotate(&scenario, &operator, SignatureAlgorithm::Ps256).expect("a key");
        assert_eq!(
            register_reader(&scenario, SignatureAlgorithm::Ps256),
            Ok(())
        );

        let signed_in = complete(run_code_flow(
            &scenario.app,
            CodeFlow {
                realm: "acme",
                client_id: "reader",
                client_secret: None,
                redirect_uri: CALLBACK,
                scope: "openid",
                username: "ada",
                password: PASSWORD,
            },
        ));
        let tokens = signed_in.tokens;
        let identity = tokens.id_token.as_deref().expect("an identity token");
        assert_eq!(read_header(identity, "alg"), "PS256");
        assert_eq!(
            read_header(&tokens.access_token, "alg"),
            "ES256",
            "an access token is signed in the default of the realm"
        );
        let refreshed = complete(grant_token(
            &scenario.app,
            "acme",
            TokenRequest {
                grant_type: Some("refresh_token"),
                client_id: Some("reader"),
                refresh_token: tokens.refresh_token.as_deref(),
                ..TokenRequest::default()
            },
        ))
        .expect("a refresh");
        let identity = refreshed.id_token.as_deref().expect("an identity token");
        assert_eq!(read_header(identity, "alg"), "PS256", "and so on refresh");
    }

    #[test]
    fn a_realm_is_born_signing_in_es256_and_rs256_and_says_so() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);

        let document = complete(read_provider_metadata(&scenario.app, "acme")).expect("a document");

        assert_eq!(
            document.id_token_signing_alg_values_supported,
            ["ES256", "RS256"]
        );
        rotate(&scenario, &operator, SignatureAlgorithm::EdDsa).expect("a key");
        let document = complete(read_provider_metadata(&scenario.app, "acme")).expect("a document");
        assert_eq!(
            document.id_token_signing_alg_values_supported,
            ["ES256", "RS256", "EdDSA"]
        );
    }

    #[test]
    fn a_realm_holds_no_more_keys_than_it_may_until_a_retired_one_is_removed() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let held = list_keys(&scenario).len();

        for _ in held..MAX_SIGNING_KEYS {
            rotate(&scenario, &operator, SignatureAlgorithm::Es256).expect("room for one more");
        }
        assert_eq!(
            rotate(&scenario, &operator, SignatureAlgorithm::Es384).map(|_| ()),
            Err(ErrorCode::SigningKeyLimitReached),
            "counted whatever the algorithm"
        );
        let retired = list_keys(&scenario)
            .into_iter()
            .find(|key| key.status == KeyStatus::Retired)
            .expect("a retired key");
        assert_eq!(remove(&scenario, &operator, &retired.key_id), Ok(()));
        assert!(
            rotate(&scenario, &operator, SignatureAlgorithm::Es384).is_ok(),
            "room for one again"
        );
        assert_eq!(list_keys(&scenario).len(), MAX_SIGNING_KEYS);
    }

    #[test]
    fn each_key_made_retired_or_removed_is_recorded_without_its_private_half() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let first = list_keys(&scenario)
            .into_iter()
            .find(|key| key.algorithm == SignatureAlgorithm::Rs256)
            .expect("the first RSA key");

        let new = rotate(&scenario, &operator, SignatureAlgorithm::Rs256).expect("a new key");
        remove(&scenario, &operator, &first.key_id).expect("removed");

        let recorded: Vec<Value> = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .filter(|event| {
                event["kind"]
                    .as_str()
                    .is_some_and(|kind| kind.starts_with("key."))
            })
            .collect();
        let told: Vec<(&str, &Value)> = recorded
            .iter()
            .map(|event| (event["kind"].as_str().expect("a kind"), &event["payload"]))
            .collect();
        let actor = serde_json::json!({ "client_id": "operator" });
        assert_eq!(told.len(), 5, "two at birth, then made, retired, removed");
        assert_eq!(told[2].0, "key.created");
        assert_eq!(
            told[2].1,
            &serde_json::json!({ "actor": actor, "alg": "RS256", "kid": new.key_id })
        );
        assert_eq!(told[3].0, "key.retired");
        assert_eq!(
            told[3].1,
            &serde_json::json!({
                "actor": actor,
                "alg": "RS256",
                "kid": first.key_id,
                "replaced_by": new.key_id,
            })
        );
        assert_eq!(told[4].0, "key.deleted");
        assert_eq!(
            told[4].1,
            &serde_json::json!({ "actor": actor, "alg": "RS256", "kid": first.key_id })
        );
    }

    #[test]
    fn an_algorithm_this_build_does_not_sign_in_is_neither_offered_made_nor_published() {
        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        rotate(&scenario, &operator, SignatureAlgorithm::EdDsa)
            .expect("a key, made by a build that may");

        scenario.app.signer = Arc::new(WeakSigner::refusing(SignatureAlgorithm::EdDsa));

        assert_eq!(
            rotate(&scenario, &operator, SignatureAlgorithm::EdDsa).map(|_| ()),
            Err(ErrorCode::AlgorithmUnknown)
        );
        assert_eq!(
            register_reader(&scenario, SignatureAlgorithm::EdDsa),
            Err(ErrorCode::KeyAlgorithmUnavailable)
        );
        let held = list_keys(&scenario);
        assert_eq!(
            list_active_algorithms(scenario.app.signer.as_ref(), &held),
            [SignatureAlgorithm::Es256, SignatureAlgorithm::Rs256]
        );
        let published = complete(publish_key_set(&scenario.app, scenario.scope)).expect("a set");
        assert_eq!(published.keys.len(), 2);
        assert!(published.keys.iter().all(|key| key["alg"] != "EdDSA"));
        assert_eq!(held.len(), 3, "the key is kept until it is removed");
    }

    #[test]
    fn a_key_this_build_does_not_sign_in_is_retired_and_removed_at_once() {
        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let eddsa = rotate(&scenario, &operator, SignatureAlgorithm::EdDsa).expect("a key");
        scenario.app.signer = Arc::new(WeakSigner::refusing(SignatureAlgorithm::EdDsa));

        assert_eq!(remove(&scenario, &operator, &eddsa.key_id), Ok(()));

        assert!(
            list_keys(&scenario)
                .iter()
                .all(|key| key.key_id != eddsa.key_id)
        );
        let told: Vec<(String, Value)> = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .filter(|event| event["payload"]["kid"] == eddsa.key_id.as_str())
            .map(|event| {
                let kind = event["kind"].as_str().expect("a kind").to_owned();
                (kind, event["payload"].clone())
            })
            .collect();
        let kinds: Vec<&str> = told.iter().map(|(kind, _)| kind.as_str()).collect();
        assert_eq!(kinds, ["key.created", "key.retired", "key.deleted"]);
        assert_eq!(
            told[1].1,
            serde_json::json!({
                "actor": { "client_id": "operator" },
                "alg": "EdDSA",
                "kid": eddsa.key_id,
            }),
            "nothing replaced it"
        );
    }

    #[test]
    fn a_tenant_making_a_key_is_refused_another_at_once_and_waits_for_no_other_tenant() {
        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let other = complete(create_realm(&scenario.app, "globex"));
        let token = complete(create_administrator(
            &scenario.app,
            "globex",
            other,
            "operator",
            &[Capability::KeyWrite],
        ));
        let elsewhere = complete(authorize_admin_call(
            &scenario.app,
            "globex",
            Some(&token),
            Capability::KeyWrite,
        ))
        .expect("an operator of another tenant");
        let makers = give_few_makers(&mut scenario);
        let making = scenario
            .app
            .key_shares
            .take(scenario.scope.tenant())
            .expect("the share of the first tenant");

        // Driven to their end without a wait: a wait would stop them here.
        assert_eq!(
            rotate(&scenario, &operator, SignatureAlgorithm::Rs256).map(|_| ()),
            Err(ErrorCode::KeyMakingBusy),
            "one key at a time for a tenant"
        );
        assert_eq!(makers.made.load(Ordering::SeqCst), 0, "and it made none");
        assert!(
            rotate(&scenario, &elsewhere, SignatureAlgorithm::Rs256).is_ok(),
            "another tenant is served"
        );
        makers.free.store(0, Ordering::SeqCst);
        assert_eq!(
            rotate(&scenario, &elsewhere, SignatureAlgorithm::Rs256).map(|_| ()),
            Err(ErrorCode::KeyMakingBusy),
            "or refused at once, when every maker is at work"
        );
        makers.free.store(1, Ordering::SeqCst);
        drop(making);
        assert_eq!(
            rotate(&scenario, &operator, SignatureAlgorithm::Rs256).map(|_| ()),
            Ok(()),
            "its share given back, the first tenant is served again"
        );
    }

    #[test]
    fn a_rotation_given_up_while_its_key_is_made_keeps_the_share_of_its_tenant() {
        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        let makers = give_few_makers(&mut scenario);
        makers.holding.store(true, Ordering::SeqCst);

        // Polled once, to the key maker, then dropped: a caller that hangs up.
        {
            let mut given_up = pin!(rotate_signing_key(
                &scenario.app,
                &operator,
                SignatureAlgorithm::Rs256
            ));
            let polled = given_up
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()));
            assert!(polled.is_pending(), "the key is being made");
        }
        makers.holding.store(false, Ordering::SeqCst);

        assert_eq!(
            rotate(&scenario, &operator, SignatureAlgorithm::Rs256).map(|_| ()),
            Err(ErrorCode::KeyMakingBusy),
            "the share went with the work"
        );
        assert_eq!(
            makers.made.load(Ordering::SeqCst),
            0,
            "and no key more was made"
        );
        drop(makers.held.lock().expect("the guard").take());
        assert!(
            rotate(&scenario, &operator, SignatureAlgorithm::Rs256).is_ok(),
            "the work done, the tenant is served"
        );
    }

    #[test]
    fn a_realm_at_its_bound_is_refused_before_any_key_is_made() {
        let mut scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::KeyWrite]);
        for _ in list_keys(&scenario).len()..MAX_SIGNING_KEYS {
            rotate(&scenario, &operator, SignatureAlgorithm::Es256).expect("room for one more");
        }
        let makers = give_few_makers(&mut scenario);

        assert_eq!(
            rotate(&scenario, &operator, SignatureAlgorithm::Rs256).map(|_| ()),
            Err(ErrorCode::SigningKeyLimitReached)
        );
        assert_eq!(
            makers.made.load(Ordering::SeqCst),
            0,
            "no key was made for it"
        );
    }

    #[test]
    fn an_answer_in_two_algorithms_opens_the_data_key_once() {
        let scenario = Scenario::start();
        register_reader(&scenario, SignatureAlgorithm::Rs256).expect("a client");
        let flow = |client_id| CodeFlow {
            realm: "acme",
            client_id,
            client_secret: None,
            redirect_uri: CALLBACK,
            scope: "openid",
            username: "ada",
            password: PASSWORD,
        };
        let count_reads = |client_id| {
            let before = scenario.storage.count_data_key_reads();
            let tokens = complete(run_code_flow(&scenario.app, flow(client_id))).tokens;
            (scenario.storage.count_data_key_reads() - before, tokens)
        };

        let (reads, tokens) = count_reads("reader");

        let identity = tokens.id_token.as_deref().expect("an identity token");
        assert_eq!(read_header(identity, "alg"), "RS256");
        assert_eq!(read_header(&tokens.access_token, "alg"), "ES256");
        assert_eq!(reads, 1, "two keys, one data key");
        assert_eq!(count_reads("webapp").0, 1, "one key, one data key");
    }

    #[test]
    fn an_answer_without_openid_opens_the_key_of_its_access_token_alone() {
        let scenario = Scenario::start();
        register_reader(&scenario, SignatureAlgorithm::Rs256).expect("a client");
        let before = scenario.storage.count_private_key_reads();

        let tokens = complete(run_code_flow(
            &scenario.app,
            CodeFlow {
                realm: "acme",
                client_id: "reader",
                client_secret: None,
                redirect_uri: CALLBACK,
                scope: "profile",
                username: "ada",
                password: PASSWORD,
            },
        ))
        .tokens;

        assert!(tokens.id_token.is_none());
        assert_eq!(
            scenario.storage.count_private_key_reads() - before,
            1,
            "no identity token, no key of its algorithm"
        );
    }
}
