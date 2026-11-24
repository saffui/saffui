//! How a client proves itself: by the method it registered, and by no other.
//! A secret in the Basic scheme is no proof for a client that registered
//! the form, nor the reverse, and a secret is no proof for a client that
//! signs. A public client proves nothing: it only names itself.

use super::assertion::{
    ASSERTION_TYPE, CLOCK_SKEW, ReadAssertion, check_assertion_claims, choose_client_key,
    fits_registered_algorithm, read_assertion,
};
use super::{AssertionAlgorithm, Client, ClientAuthMethod, KeptProof, check_client_identifier};
use crate::app::App;
use crate::error::{ErrorCode, Failure};
use crate::ports::crypto::SealPlace;
use crate::ports::storage::UnitOfWork;
use crate::secret::Secret;
use crate::tenancy::RealmScope;

/// What the secret of a client is sealed for, when the realm must open it.
pub(crate) const CLIENT_SECRET_PURPOSE: &str = "client-secret";

/// A secret as a request carried it. Where it came tells the method.
pub enum PresentedSecret {
    /// In the Basic scheme of the `Authorization` header.
    Basic(Secret),
    /// In the body of the form.
    Posted(Secret),
}

/// What a request carries to prove its client, once read.
pub enum ClientProof<'a> {
    Nothing,
    Secret(PresentedSecret),
    /// A signed assertion of the type RFC 7523 names.
    Assertion(&'a str),
}

/// What a request presented to prove its client, as the endpoint read it.
// No `Debug`, here as on the two types above: each carries a secret or an
// assertion.
#[derive(Default)]
pub struct PresentedProof<'a> {
    pub secret: Option<PresentedSecret>,
    pub assertion_type: Option<&'a str>,
    pub assertion: Option<&'a str>,
}

/// A client identified, and the unit of work its request goes on in.
pub type IdentifiedClient = (Client, Box<dyn UnitOfWork>);

/// Reads what a request carries: a secret or an assertion, never both, and
/// an assertion of the one type served.
///
/// # Errors
///
/// Returns [`ErrorCode::RequestInvalid`] for both at once or a type without
/// an assertion, and [`ErrorCode::ClientAuthenticationFailed`] for an
/// assertion of another type.
pub fn read_client_proof(presented: PresentedProof<'_>) -> Result<ClientProof<'_>, Failure> {
    match (
        presented.secret,
        presented.assertion_type,
        presented.assertion,
    ) {
        (Some(_), _, Some(_)) | (_, Some(_), None) => Err(Failure::new(ErrorCode::RequestInvalid)),
        (None, Some(ASSERTION_TYPE), Some(assertion)) => Ok(ClientProof::Assertion(assertion)),
        (None, _, Some(_)) => Err(Failure::new(ErrorCode::ClientAuthenticationFailed)),
        (Some(secret), None, None) => Ok(ClientProof::Secret(secret)),
        (None, None, None) => Ok(ClientProof::Nothing),
    }
}

/// Compares a secret with the digest of the client, for the method it came
/// by. An unknown client, or one of another method, is compared too,
/// against a digest nothing matches: the answer comes no sooner for it.
fn check_presented_secret(
    app: &App,
    found: Option<(Client, KeptProof)>,
    presented: PresentedSecret,
) -> Result<Client, Failure> {
    let (method, secret) = match presented {
        PresentedSecret::Basic(secret) => (ClientAuthMethod::ClientSecretBasic, secret),
        PresentedSecret::Posted(secret) => (ClientAuthMethod::ClientSecretPost, secret),
    };
    let presented_digest = app.digester.sha256(secret.expose());
    let expected = found
        .as_ref()
        .filter(|(known, _)| known.auth_method == method)
        .and_then(|(_, proof)| proof.secret_digest.as_deref())
        .unwrap_or(&[0_u8; 32][..]);
    let matches = app
        .digester
        .equal_in_constant_time(&presented_digest, expected);
    found
        .map(|(client, _)| client)
        .filter(|known| matches && known.enabled)
        .ok_or(Failure::new(ErrorCode::ClientAuthenticationFailed))
}

/// Opens the secret a client that signs with it keeps sealed for its row.
async fn open_client_secret(
    app: &App,
    work: &mut dyn UnitOfWork,
    client: &Client,
    sealed: &[u8],
) -> Result<Secret, Failure> {
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
        row: client.id,
    };
    app.sealer
        .open(&data_key, &place, sealed)
        .map_err(|_| unavailable("a client secret does not open where it is stored"))
}

/// Tells whether `presented` is the secret a client keeps now, in whichever
/// form its method keeps it, compared in constant time. A client that keeps
/// no secret matches none.
///
/// # Errors
///
/// Returns [`ErrorCode::CryptoUnavailable`] when its sealed secret cannot be
/// opened, or the storage failure.
pub(crate) async fn is_current_secret(
    app: &App,
    work: &mut dyn UnitOfWork,
    client: &Client,
    proof: &KeptProof,
    presented: &[u8],
) -> Result<bool, Failure> {
    let kept = match (
        client.auth_method,
        &proof.secret_digest,
        &proof.sealed_secret,
    ) {
        (
            ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost,
            Some(digest),
            _,
        ) => digest.clone(),
        (ClientAuthMethod::ClientSecretJwt, _, Some(sealed)) => {
            let secret = open_client_secret(app, work, client, sealed).await?;
            app.digester.sha256(secret.expose()).to_vec()
        }
        _ => return Ok(false),
    };
    Ok(app
        .digester
        .equal_in_constant_time(&app.digester.sha256(presented), &kept))
}

/// Tells whether the signature of an assertion is the one the client makes:
/// with its sealed secret, or with the key the assertion names.
async fn verify_assertion_signature(
    app: &App,
    work: &mut dyn UnitOfWork,
    client: &Client,
    proof: &KeptProof,
    read: &ReadAssertion,
) -> Result<bool, Failure> {
    match (client.auth_method, read.algorithm) {
        (ClientAuthMethod::ClientSecretJwt, AssertionAlgorithm::Hs256) => {
            let Some(sealed) = &proof.sealed_secret else {
                return Ok(false);
            };
            let unavailable = |detail| Failure::with_detail(ErrorCode::CryptoUnavailable, detail);
            let secret = open_client_secret(app, work, client, sealed).await?;
            let mac = app
                .digester
                .hmac_sha256(&secret, read.signing_input.as_bytes())
                .map_err(|_| unavailable("a client assertion cannot be checked"))?;
            Ok(app.digester.equal_in_constant_time(&mac, &read.signature))
        }
        (ClientAuthMethod::PrivateKeyJwt, AssertionAlgorithm::Signed(algorithm)) => Ok(proof
            .jwks
            .as_ref()
            .and_then(|jwks| choose_client_key(jwks, read))
            .is_some_and(|key| {
                app.signer.verify(
                    algorithm,
                    key,
                    read.signing_input.as_bytes(),
                    &read.signature,
                ) == Ok(true)
            })),
        _ => Ok(false),
    }
}

/// Identifies the client behind a request, for the realm of `issuer`, and
/// returns it with the unit of work the request goes on in. A confidential
/// client proves itself by the method it registered; a public client only
/// names itself. For a secret or nothing, that unit is the one the client
/// was read in. An assertion is spent in that unit, which commits before
/// the client is returned with a fresh one: whatever the request does next,
/// the same assertion never serves again. A request never holds two units.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientAuthenticationFailed`] for a client that does
/// not exist, that is disabled, whose proof is wrong or of another method,
/// or whose assertion was seen before: all answer alike. Returns
/// [`ErrorCode::CryptoUnavailable`] when its sealed secret cannot be opened,
/// or the storage failure.
pub async fn identify_client(
    app: &App,
    scope: RealmScope,
    claimed: Option<&str>,
    proof: ClientProof<'_>,
    issuer: &str,
) -> Result<IdentifiedClient, Failure> {
    let failed = || Failure::new(ErrorCode::ClientAuthenticationFailed);
    let read = match &proof {
        ClientProof::Assertion(text) => {
            let read = read_assertion(text).ok_or_else(failed)?;
            // Its time and its audience need nothing stored: judged before
            // any unit of work is opened.
            if !check_assertion_claims(&read, issuer, app.now()) {
                return Err(failed());
            }
            Some(read)
        }
        ClientProof::Nothing | ClientProof::Secret(_) => None,
    };
    let client_id = match (claimed, &read) {
        (Some(claimed), Some(read)) if claimed != read.client_id => return Err(failed()),
        (Some(claimed), _) => claimed,
        (None, Some(read)) => read.client_id.as_str(),
        (None, None) => return Err(failed()),
    };
    let mut work = app.storage.begin(scope).await?;
    let found = if check_client_identifier(client_id).is_ok() {
        work.read_client_with_proof(client_id).await?
    } else {
        None
    };
    match proof {
        ClientProof::Secret(presented) => {
            let client = check_presented_secret(app, found, presented)?;
            Ok((client, work))
        }
        ClientProof::Nothing => {
            let client = found
                .map(|(client, _)| client)
                .filter(|known| known.enabled && known.is_public())
                .ok_or_else(failed)?;
            Ok((client, work))
        }
        ClientProof::Assertion(_) => {
            let (Some((client, kept)), Some(read)) =
                (found.filter(|(known, _)| known.enabled), read)
            else {
                return Err(failed());
            };
            if !fits_registered_algorithm(client.auth_signing_alg, &read) {
                return Err(failed());
            }
            if !verify_assertion_signature(app, work.as_mut(), &client, &kept, &read).await? {
                return Err(failed());
            }
            // Kept past its expiry by the skew a node may have: one whose
            // clock is behind still finds it.
            let kept_until = read.expires_at + CLOCK_SKEW;
            let first = work
                .record_client_assertion(&client.client_id, &read.token_id, kept_until)
                .await?;
            if !first {
                return Err(failed());
            }
            work.commit().await?;
            let work = app.storage.begin(scope).await?;
            Ok((client, work))
        }
    }
}

/// Identifies a confidential client: a public one is refused like a wrong
/// proof.
///
/// # Errors
///
/// As [`identify_client`].
pub async fn authenticate_client(
    app: &App,
    scope: RealmScope,
    claimed: Option<&str>,
    proof: ClientProof<'_>,
    issuer: &str,
) -> Result<IdentifiedClient, Failure> {
    let (client, work) = identify_client(app, scope, claimed, proof, issuer).await?;
    if client.is_public() {
        return Err(Failure::new(ErrorCode::ClientAuthenticationFailed));
    }
    Ok((client, work))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};

    use super::PresentedSecret;
    use crate::clients::assertion::ASSERTION_TYPE;
    use crate::clients::register::NewClient;
    use crate::clients::{AssertionAlgorithm, ClientAuthMethod};
    use crate::error::ErrorCode;
    use crate::oidc::errors::OAuthError;
    use crate::oidc::scenario::Scenario;
    use crate::oidc::token::{TokenRequest, grant_token};
    use crate::ports::crypto::{GeneratedSigningKey, SignatureAlgorithm};
    use crate::secret::Secret;
    use crate::testkit::drive::complete;
    use crate::testkit::fixtures::check_and_register_client;

    const ISSUER: &str = "https://id.example.test/realms/acme";
    const TOKEN_ENDPOINT: &str = "https://id.example.test/realms/acme/oauth2/token";

    fn make_key(scenario: &Scenario, algorithm: SignatureAlgorithm) -> GeneratedSigningKey {
        complete(scenario.app.signer.generate_key(algorithm, Box::new(()))).expect("a key")
    }

    /// Registers a service that proves itself by `method`, with `keys` when
    /// it holds some, and returns the secret it was shown, if any.
    fn register(
        scenario: &Scenario,
        client_id: &str,
        method: ClientAuthMethod,
        signing: Option<AssertionAlgorithm>,
        keys: &[&GeneratedSigningKey],
    ) -> Result<Option<Secret>, ErrorCode> {
        let jwks =
            json!({ "keys": keys.iter().map(|key| key.public_jwk.clone()).collect::<Vec<_>>() });
        let scopes = ["reports:read".to_owned()];
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        let wanted = NewClient {
            client_id,
            name: "A service that proves itself",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &[],
            post_logout_redirect_uris: &[],
            public: false,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: Some(method),
            jwks: (!keys.is_empty()).then_some(&jwks),
            jwks_uri: None,
            auth_signing_alg: signing,
            created_by: None,
        };
        let (_client, secret) = complete(check_and_register_client(
            &scenario.app,
            work.as_mut(),
            wanted,
        ))
        .map_err(|failure| failure.code)?;
        complete(work.commit()).expect("a commit");
        Ok(secret)
    }

    /// The claims of an assertion of `client_id`, living `lifetime` seconds.
    fn claims(
        scenario: &Scenario,
        client_id: &str,
        jti: &str,
        audience: &Value,
        lifetime: i64,
    ) -> Value {
        json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "jti": jti,
            "exp": scenario.app.now().unix_timestamp() + lifetime,
        })
    }

    fn write_input(header: &Value, claims: &Value) -> String {
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn sign_with_secret(scenario: &Scenario, secret: &Secret, claims: &Value) -> String {
        let input = write_input(&json!({ "alg": "HS256" }), claims);
        let mac = scenario
            .app
            .digester
            .hmac_sha256(secret, input.as_bytes())
            .expect("a mac");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(mac))
    }

    fn sign_with_key(scenario: &Scenario, key: &GeneratedSigningKey, claims: &Value) -> String {
        let header = json!({ "alg": key.algorithm.name(), "kid": key.key_id });
        let input = write_input(&header, claims);
        let signature = scenario
            .app
            .signer
            .sign(key.algorithm, &key.private_key, input.as_bytes())
            .expect("a signature");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn ask_as_service(
        scenario: &Scenario,
        client_id: Option<&str>,
        secret: Option<PresentedSecret>,
        assertion: Option<&str>,
        scope: Option<&str>,
    ) -> Result<String, OAuthError> {
        let request = TokenRequest {
            grant_type: Some("client_credentials"),
            scope,
            client_id,
            client_secret: secret,
            client_assertion_type: assertion.map(|_| ASSERTION_TYPE),
            client_assertion: assertion,
            ..TokenRequest::default()
        };
        complete(grant_token(&scenario.app, "acme", request))
            .map(|tokens| tokens.scope)
            .map_err(|failure| failure.error)
    }

    fn present(scenario: &Scenario, assertion: &str) -> Result<String, OAuthError> {
        ask_as_service(scenario, None, None, Some(assertion), None)
    }

    #[test]
    fn a_client_proves_itself_with_an_assertion_signed_by_its_secret_once() {
        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret, shown once");
        let assertion = sign_with_secret(
            &scenario,
            &secret,
            &claims(&scenario, "signer", "a-1", &json!(ISSUER), 60),
        );

        assert_eq!(
            present(&scenario, &assertion),
            Ok("reports:read".to_owned()),
            "the assertion names its client"
        );
        assert_eq!(
            present(&scenario, &assertion),
            Err(OAuthError::InvalidClient),
            "an assertion serves once"
        );
        let presented = PresentedSecret::Basic(Secret::new(secret.expose().to_vec()));
        assert_eq!(
            ask_as_service(&scenario, Some("signer"), Some(presented), None, None),
            Err(OAuthError::InvalidClient),
            "the secret itself proves nothing for a client that signs with it"
        );
        let forged = sign_with_secret(
            &scenario,
            &Secret::new(b"not-the-secret".to_vec()),
            &claims(&scenario, "signer", "a-2", &json!(ISSUER), 60),
        );
        assert_eq!(present(&scenario, &forged), Err(OAuthError::InvalidClient));
    }

    /// Each assertion is signed with the real secret or the real key: only
    /// its claims refuse it.
    #[test]
    fn an_assertion_signed_for_real_is_refused_for_another_audience_or_outside_its_hour() {
        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let key = make_key(&scenario, SignatureAlgorithm::Es256);
        register(
            &scenario,
            "keyed",
            ClientAuthMethod::PrivateKeyJwt,
            None,
            &[&key],
        )
        .expect("a client");
        let refused = [
            (
                json!(TOKEN_ENDPOINT),
                60,
                "the address of the token endpoint",
            ),
            (json!([ISSUER]), 60, "a list, even of the issuer alone"),
            (
                json!("https://id.example.test/realms/globex"),
                60,
                "another issuer",
            ),
            (json!(ISSUER), 0, "expired"),
            (json!(ISSUER), 3601, "living past the hour"),
        ];

        for (index, (audience, lifetime, why)) in refused.into_iter().enumerate() {
            let jti = format!("r-{index}");
            let by_secret = sign_with_secret(
                &scenario,
                &secret,
                &claims(&scenario, "signer", &jti, &audience, lifetime),
            );
            let by_key = sign_with_key(
                &scenario,
                &key,
                &claims(&scenario, "keyed", &jti, &audience, lifetime),
            );
            assert_eq!(
                present(&scenario, &by_secret),
                Err(OAuthError::InvalidClient),
                "by its secret: {why}"
            );
            assert_eq!(
                present(&scenario, &by_key),
                Err(OAuthError::InvalidClient),
                "by its key: {why}"
            );
        }
        let by_secret = sign_with_secret(
            &scenario,
            &secret,
            &claims(&scenario, "signer", "ok", &json!(ISSUER), 3600),
        );
        let by_key = sign_with_key(
            &scenario,
            &key,
            &claims(&scenario, "keyed", "ok", &json!(ISSUER), 3600),
        );
        assert!(present(&scenario, &by_secret).is_ok(), "the same, standing");
        assert!(present(&scenario, &by_key).is_ok(), "the same, standing");
    }

    #[test]
    fn a_client_proves_itself_with_its_key_and_no_other_client_claims_its_assertion() {
        let scenario = Scenario::start();
        let key = make_key(&scenario, SignatureAlgorithm::Es256);
        let secret = register(
            &scenario,
            "keyed",
            ClientAuthMethod::PrivateKeyJwt,
            AssertionAlgorithm::parse("ES256"),
            &[&key],
        )
        .expect("a client");
        assert!(secret.is_none(), "a client with a key gets no secret");
        // A second client holds the very same key: only the names tell them apart.
        register(
            &scenario,
            "twin",
            ClientAuthMethod::PrivateKeyJwt,
            AssertionAlgorithm::parse("ES256"),
            &[&key],
        )
        .expect("a client of the same key");
        let assertion = sign_with_key(
            &scenario,
            &key,
            &claims(&scenario, "keyed", "k-1", &json!(ISSUER), 60),
        );

        assert_eq!(
            ask_as_service(&scenario, Some("twin"), None, Some(&assertion), None),
            Err(OAuthError::InvalidClient),
            "the client named must be the one that signed"
        );
        assert_eq!(
            ask_as_service(&scenario, Some("keyed"), None, Some(&assertion), None),
            Ok("reports:read".to_owned())
        );
        let another = make_key(&scenario, SignatureAlgorithm::Es256);
        let forged = sign_with_key(
            &scenario,
            &GeneratedSigningKey {
                key_id: key.key_id.clone(),
                ..another
            },
            &claims(&scenario, "keyed", "k-2", &json!(ISSUER), 60),
        );
        assert_eq!(present(&scenario, &forged), Err(OAuthError::InvalidClient));
        assert_eq!(
            present(&scenario, "not.an.assertion"),
            Err(OAuthError::InvalidClient)
        );
    }

    #[test]
    fn an_assertion_in_another_algorithm_than_the_one_the_client_registered_is_refused() {
        use crate::clients::{Client, KeptProof};

        let scenario = Scenario::start();
        let registered = make_key(&scenario, SignatureAlgorithm::Es256);
        let other = make_key(&scenario, SignatureAlgorithm::Es384);
        // Written behind the back of the product, which refuses a key of
        // another algorithm than the one registered.
        let mut work = complete(scenario.app.storage.begin(scenario.scope)).expect("a unit");
        let billing = complete(work.read_client("billing"))
            .expect("a read")
            .expect("billing");
        let keyed = Client {
            id: uuid::Uuid::from_u128(7),
            client_id: "keyed".to_owned(),
            auth_method: ClientAuthMethod::PrivateKeyJwt,
            auth_signing_alg: AssertionAlgorithm::parse("ES256"),
            scopes: vec!["reports:read".to_owned()],
            ..billing
        };
        let kept = KeptProof {
            secret_digest: None,
            sealed_secret: None,
            jwks: Some(json!({ "keys": [registered.public_jwk, other.public_jwk] })),
        };
        complete(work.insert_client(&keyed, &kept)).expect("a client with two keys");
        complete(work.commit()).expect("a commit");

        // Its own key, the one its `kid` names, and a signature that verifies.
        let in_another = sign_with_key(
            &scenario,
            &other,
            &claims(&scenario, "keyed", "x-1", &json!(ISSUER), 60),
        );
        assert_eq!(
            present(&scenario, &in_another),
            Err(OAuthError::InvalidClient)
        );
        let in_its_own = sign_with_key(
            &scenario,
            &registered,
            &claims(&scenario, "keyed", "x-2", &json!(ISSUER), 60),
        );
        assert!(present(&scenario, &in_its_own).is_ok());
    }

    #[test]
    fn an_assertion_is_spent_even_when_the_request_it_proved_is_refused() {
        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let assertion = sign_with_secret(
            &scenario,
            &secret,
            &claims(&scenario, "signer", "s-1", &json!(ISSUER), 60),
        );

        assert_eq!(
            ask_as_service(&scenario, None, None, Some(&assertion), Some("admin")),
            Err(OAuthError::InvalidScope)
        );
        assert_eq!(
            present(&scenario, &assertion),
            Err(OAuthError::InvalidClient),
            "spent by the request that was refused"
        );
    }

    #[test]
    fn the_identifier_of_an_assertion_is_kept_past_its_expiry_by_the_skew_a_node_may_have() {
        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let claims = claims(&scenario, "signer", "k-1", &json!(ISSUER), 60);
        let expires_at =
            time::OffsetDateTime::from_unix_timestamp(claims["exp"].as_i64().expect("an expiry"))
                .expect("an instant");

        let presented = present(&scenario, &sign_with_secret(&scenario, &secret, &claims));

        assert!(presented.is_ok(), "{presented:?}");
        assert_eq!(
            scenario.storage.read_assertion_kept_until("signer", "k-1"),
            Some(expires_at + time::Duration::seconds(30)),
            "a node whose clock is behind still finds it"
        );
    }

    #[test]
    fn a_secret_is_read_only_where_the_client_registered_it() {
        let scenario = Scenario::start();
        let posted = register(
            &scenario,
            "poster",
            ClientAuthMethod::ClientSecretPost,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let copy = |secret: &Secret| Secret::new(secret.expose().to_vec());
        let ask = |client_id, secret| {
            ask_as_service(&scenario, Some(client_id), Some(secret), None, None)
        };

        assert!(
            ask(
                "billing",
                PresentedSecret::Basic(scenario.copy_service_secret())
            )
            .is_ok()
        );
        assert_eq!(
            ask(
                "billing",
                PresentedSecret::Posted(scenario.copy_service_secret())
            ),
            Err(OAuthError::InvalidClient),
            "registered for the Basic scheme"
        );
        assert!(ask("poster", PresentedSecret::Posted(copy(&posted))).is_ok());
        assert_eq!(
            ask("poster", PresentedSecret::Basic(copy(&posted))),
            Err(OAuthError::InvalidClient),
            "registered for the form"
        );
    }

    #[test]
    fn one_proof_is_read_of_the_one_type_served() {
        let scenario = Scenario::start();
        let request =
            |secret: Option<PresentedSecret>, kind: Option<&str>, assertion: Option<&str>| {
                let request = TokenRequest {
                    grant_type: Some("client_credentials"),
                    client_id: Some("billing"),
                    client_secret: secret,
                    client_assertion_type: kind,
                    client_assertion: assertion,
                    ..TokenRequest::default()
                };
                complete(grant_token(&scenario.app, "acme", request))
                    .map(|_| ())
                    .map_err(|failure| failure.error)
            };
        let secret = || Some(PresentedSecret::Basic(scenario.copy_service_secret()));

        assert_eq!(
            request(secret(), Some(ASSERTION_TYPE), Some("a.b.c")),
            Err(OAuthError::InvalidRequest),
            "a secret and an assertion at once"
        );
        assert_eq!(
            request(None, Some("urn:other"), Some("a.b.c")),
            Err(OAuthError::InvalidClient)
        );
        assert_eq!(
            request(None, Some(ASSERTION_TYPE), None),
            Err(OAuthError::InvalidRequest)
        );
        assert_eq!(request(secret(), None, None), Ok(()));
    }

    #[test]
    fn a_client_is_proven_by_an_assertion_at_introspection_and_revocation_too() {
        use crate::clients::authenticate::PresentedProof;
        use crate::oidc::introspect::introspect_token;
        use crate::oidc::revoke::revoke_token;

        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let token = scenario.sign_in("openid").tokens.access_token;
        let assertion = sign_with_secret(
            &scenario,
            &secret,
            &claims(&scenario, "signer", "i-1", &json!(ISSUER), 60),
        );
        let proof = |assertion| PresentedProof {
            secret: None,
            assertion_type: Some(ASSERTION_TYPE),
            assertion: Some(assertion),
        };

        let told = complete(introspect_token(
            &scenario.app,
            "acme",
            None,
            proof(&assertion),
            Some(&token),
        ))
        .expect("an answer");
        assert!(told.active);
        let replayed = complete(revoke_token(
            &scenario.app,
            "acme",
            None,
            proof(&assertion),
            Some("not-a-token"),
        ));
        assert_eq!(
            replayed.map_err(|failure| failure.error),
            Err(OAuthError::InvalidClient),
            "spent at introspection, it serves nowhere else"
        );
        let fresh = sign_with_secret(
            &scenario,
            &secret,
            &claims(&scenario, "signer", "i-2", &json!(ISSUER), 60),
        );
        let revoked = complete(revoke_token(
            &scenario.app,
            "acme",
            None,
            proof(&fresh),
            Some("not-a-token"),
        ));
        assert_eq!(revoked.map_err(|failure| failure.error), Ok(()));
    }

    #[test]
    fn a_secret_proves_its_client_in_one_unit_of_work_and_an_assertion_in_two() {
        use crate::clients::authenticate::PresentedProof;
        use crate::oidc::introspect::introspect_token;

        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let token = scenario.sign_in("openid").tokens.access_token;
        let by_assertion = |jti: &str| {
            sign_with_secret(
                &scenario,
                &secret,
                &claims(&scenario, "signer", jti, &json!(ISSUER), 60),
            )
        };
        let introspect = |client_id, proof| {
            complete(introspect_token(
                &scenario.app,
                "acme",
                client_id,
                proof,
                Some(&token),
            ))
            .is_ok_and(|told| told.active)
        };
        let opened = |before: usize| scenario.storage.count_units_of_work() - before;

        let before = scenario.storage.count_units_of_work();
        let in_basic = PresentedSecret::Basic(scenario.copy_service_secret());
        assert!(ask_as_service(&scenario, Some("billing"), Some(in_basic), None, None).is_ok());
        assert_eq!(
            opened(before),
            1,
            "a grant with a secret goes on in the unit its client was read in"
        );
        let before = scenario.storage.count_units_of_work();
        assert!(present(&scenario, &by_assertion("u-1")).is_ok());
        assert_eq!(
            opened(before),
            2,
            "the unit that spends an assertion commits apart"
        );
        let before = scenario.storage.count_units_of_work();
        assert!(introspect(
            Some("billing"),
            scenario.present_service_secret()
        ));
        assert_eq!(opened(before), 1);
        let assertion = by_assertion("u-2");
        let before = scenario.storage.count_units_of_work();
        assert!(introspect(
            None,
            PresentedProof {
                secret: None,
                assertion_type: Some(ASSERTION_TYPE),
                assertion: Some(&assertion),
            }
        ));
        assert_eq!(opened(before), 2);
    }

    #[test]
    fn an_assertion_out_of_its_time_or_its_audience_opens_no_unit_of_work() {
        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let before = scenario.storage.count_units_of_work();

        for (audience, lifetime) in [(json!(ISSUER), 0), (json!(TOKEN_ENDPOINT), 60)] {
            let refused = sign_with_secret(
                &scenario,
                &secret,
                &claims(&scenario, "signer", "t-1", &audience, lifetime),
            );
            assert_eq!(present(&scenario, &refused), Err(OAuthError::InvalidClient));
        }

        assert_eq!(scenario.storage.count_units_of_work(), before);
    }

    #[test]
    fn an_identifier_longer_than_an_assertion_carries_is_a_refused_client() {
        let scenario = Scenario::start();
        let secret = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let long = "j".repeat(256);

        let presented = present(
            &scenario,
            &sign_with_secret(
                &scenario,
                &secret,
                &claims(&scenario, "signer", &long, &json!(ISSUER), 60),
            ),
        );

        assert_eq!(presented, Err(OAuthError::InvalidClient));
    }

    #[test]
    fn a_turned_over_secret_signs_the_next_assertions_and_the_old_one_none() {
        use crate::authz::capability::Capability;
        use crate::clients::manage::rotate_client_secret;

        let scenario = Scenario::start();
        let old = register(
            &scenario,
            "signer",
            ClientAuthMethod::ClientSecretJwt,
            None,
            &[],
        )
        .expect("a client")
        .expect("a secret");
        let operator = scenario.name_operator(&[Capability::ClientWrite]);

        let new = complete(rotate_client_secret(&scenario.app, &operator, "signer"))
            .expect("a new secret");

        let signed_by = |secret: &Secret, jti: &str| {
            sign_with_secret(
                &scenario,
                secret,
                &claims(&scenario, "signer", jti, &json!(ISSUER), 60),
            )
        };
        assert_eq!(
            present(&scenario, &signed_by(&old, "o-1")),
            Err(OAuthError::InvalidClient)
        );
        assert!(present(&scenario, &signed_by(&new, "n-1")).is_ok());
    }
}
