//! A realm that can actually sign, and a token it actually signed.
//!
//! The guard verifies a bearer against the keys a realm has published, and
//! until now nothing exercised that end to end: the unit tests hand `decide` a
//! `Presented` that was never a token. What that leaves untested is everything
//! between the header and the decision, which is where a plane is opened by
//! accident: the issuer that names a realm, the key identifier that picks one
//! key out of several, the algorithm taken from the key rather than the token.
//!
//! So this mounts a real realm with a real key pair and mints tokens by signing
//! them. A test that wants a token nobody should accept asks for one signed by
//! a key the realm never published, rather than for a string that merely fails
//! to parse.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crypto::envelope::Envelope;
use crypto::jose::jwk::{Jwk, P_256};
use crypto::jose::jws::{ES256, JwsHeader};
use crypto::jose::jwt::{self, JwtPayload};
use crypto::password::storage::StoredPassword;
use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{Argon2Params, CryptoConfig, CryptoProvider, SignAlg};
use deadpool_postgres::{Manager, Object, Pool, Transaction};
use models::auditable::AuditableModel;
use models::entities::authz::{AdminAction, RoleMutationModel};
use models::entities::client::ClientCreateModel;
use models::entities::keys::{KeyStatus, KeyUse, RealmSigningKey};
use models::entities::realm::RealmCreateModel;
use models::entities::tenant::TenantCreateModel;
use models::entities::user::UserCreateModel;
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use secrecy::SecretBox;
use store::keyring;
use store::providers::{clients, realm_keys, realms, roles, sessions, tenants, users};
use store::schema::migrations;
use store::tenancy::{Tenancy, TenantContext};
use tokio::sync::{Mutex, MutexGuard};
use tokio_postgres::{Config, NoTls};
use webauthn_rs::WebauthnBuilder;
use webauthn_rs::prelude::{RegisterPublicKeyCredential, Url, Uuid};

#[allow(dead_code, reason = "only the protocol suite runs a key")]
pub mod soft_key;

/// One database, so the suites take turns on it.
static DATABASE: Mutex<()> = Mutex::const_new(());

const KEK: &str = "a-deployment-wrapping-key-of-decent-length";
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const TENANT: &str = "acme";
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const REALM: &str = "main";
/// What this deployment answers from in the suites. The issuer is built out of
/// it, and the gates take a realm from an issuer only when the prefix is theirs.
pub const ORIGIN: &str = "https://id.test";

/// The client the console asks for its tokens as. What `azp` carries, and a
/// client this realm actually holds: a plane reachable only by a token nobody
/// could obtain is not reachable.
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const PARTY: &str = "saffui-console";
/// Where the console is served, which is the only place its login may land.
#[allow(dead_code, reason = "only the admin suite drives the console")]
pub const CONSOLE_REDIRECT: &str = "https://console.test/callback";
/// A confidential client, its secret, and a public one. What the token endpoint
/// authenticates against.
pub const CONFIDENTIAL: &str = "app";
pub const CLIENT_SECRET: &str = "a-registered-secret";
pub const PUBLIC: &str = "spa";
/// A second confidential client, so a test can present one client's token while
/// authenticating as another.
pub const OTHER: &str = "batch";
/// The one redirect every client here registers. A login may only be sent back
/// to a value the client wrote down.
pub const REDIRECT: &str = "https://app.example/callback";
/// Where a client says a browser may land after logging out. Deliberately not
/// the callback.
pub const AFTER_LOGOUT: &str = "https://app.example/bye";
/// A client whose registration still enables a service account the realm has
/// switched off. The lever an operator reaches for first.
pub const OFFBOARDED: &str = "retired";

/// The login every token here is bound to. A logout closes it, and the plane
/// refuses the token that named it.
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const SESSION: &str = "session-1";
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const SUBJECT: &str = "ada";
/// What the subject answers a password step with.
pub const PASSWORD: &str = "a-password-of-decent-length";
/// What this realm calls the level a password reaches, and one above it that
/// nothing here can reach.
/// The halves the subject's full name is composed from.
pub const GIVEN_NAME: &str = "Ada";
pub const FAMILY_NAME: &str = "Lovelace";
/// The shared secret the subject's authenticator app holds, base32 as an app is
/// handed it.
pub const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
/// A flow that runs a password and then a code, so a test can reach a level the
/// default flow cannot.
pub const STRONG_FLOW: &str = "browser-strong";
/// A flow whose second step is a key rather than a code.
pub const KEYED_FLOW: &str = "browser-keyed";
pub const PASSWORD_ACR: &str = "password";
pub const STRONG_ACR: &str = "mfa";
/// What the browser is bound by. Named here so a test asks for the same cookie
/// the server sets rather than a string that only looks like it.
#[allow(dead_code, reason = "only the protocol suite carries a browser")]
pub const AUTH_SESSION_COOKIE: &str = "saffui_auth_session";
#[allow(dead_code, reason = "only the protocol suite carries a browser")]
pub const SSO_COOKIE: &str = "saffui_session";
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const AUDIENCE: &str = "saffui-admin";
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const SCOPE: &str = "admin";
/// The key the realm publishes, named so a test can ask for a token signed by
/// something else.
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const KID: &str = "kid-1";
/// A second published key, whose private half carries no name of its own, so a
/// token signed with it can name whichever key a test wants it to name.
#[allow(dead_code, reason = "not every suite mounts the admin plane")]
pub const SECOND_KID: &str = "kid-2";

fn owner_config() -> Config {
    std::env::var("SAFFUI_TEST_PG")
        .unwrap_or_else(|_| panic!("these tests need a database: set SAFFUI_TEST_PG"))
        .parse()
        .expect("SAFFUI_TEST_PG is a connection string")
}

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig {
        fips_required: false,
        pkcs11: None,
    })
    .expect("a software provider")
}

#[allow(dead_code, reason = "not every suite mints a token")]
pub fn sealing() -> server::api::config::Sealing {
    let shared: Arc<dyn CryptoProvider> = Arc::new(provider());
    server::api::config::Sealing {
        envelope: Arc::new(Envelope::new(Arc::clone(&shared), KEK).expect("an envelope")),
        provider: shared,
    }
}

fn envelope() -> Envelope {
    Envelope::new(Arc::new(provider()), KEK).expect("an envelope")
}

/// A key pair, kept whole so a token can be signed with the half a realm does
/// not publish.
pub struct SigningKey {
    pub kid: String,
    private: Jwk,
}

impl SigningKey {
    /// A pair whose private half carries its own name, so anything signed with
    /// it names it whatever a caller asks for.
    pub fn generate(kid: &str) -> Self {
        let mut private = Jwk::generate_ec_key(P_256).expect("a key pair");
        private.set_key_id(kid);
        private.set_algorithm("ES256");
        SigningKey {
            kid: kid.to_owned(),
            private,
        }
    }

    /// The same, with the private half carrying no name.
    ///
    /// A signer takes the header's key identifier from the key when the key has
    /// one, so a token cannot be made to name a key other than the one that
    /// signed it. Without a name on the key, the header says what it is told,
    /// which is what lets a test present a real signature under another key's
    /// name.
    pub fn anonymous(published_as: &str) -> Self {
        let mut private = Jwk::generate_ec_key(P_256).expect("a key pair");
        private.set_algorithm("ES256");
        SigningKey {
            kid: published_as.to_owned(),
            private,
        }
    }

    /// An RSA pair, for the algorithm discovery requires of every provider.
    #[allow(
        dead_code,
        reason = "only the protocol suite signs with a second algorithm"
    )]
    pub fn generate_rsa(kid: &str) -> Self {
        let mut private = Jwk::generate_rsa_key(2048).expect("a key pair");
        private.set_key_id(kid);
        private.set_algorithm("RS256");
        SigningKey {
            kid: kid.to_owned(),
            private,
        }
    }

    #[allow(dead_code, reason = "only the protocol suite publishes a second key")]
    pub fn algorithm(&self) -> SignAlg {
        if self.private.key_type() == "RSA" {
            SignAlg::Rs256
        } else {
            SignAlg::Es256
        }
    }

    /// The private half as the store keeps it. Minting opens a PEM out of the
    /// sealed column, so a placeholder there proves the token endpoint parses
    /// its input and nothing about whether it can sign.
    pub fn private_pem(&self) -> Vec<u8> {
        use crypto::jose::jwk::KeyPair;
        use crypto::jose::jwk::alg::ec::EcKeyPair;
        use crypto::jose::jwk::alg::rsa::RsaKeyPair;
        if self.private.key_type() == "RSA" {
            return RsaKeyPair::from_jwk(&self.private)
                .expect("the private half")
                .to_pem_private_key();
        }
        EcKeyPair::from_jwk(&self.private)
            .expect("the private half")
            .to_pem_private_key()
    }

    pub fn public(&self) -> Jwk {
        let mut public = self.private.to_public_key().expect("the public half");
        public.set_key_id(&self.kid);
        public.set_algorithm("ES256");
        public
    }

    /// Sign a payload, naming a key in the header.
    ///
    /// The name is a parameter rather than this key's own, so a test can name
    /// one key and sign with another and prove that picking by name is what
    /// actually happens.
    #[allow(
        dead_code,
        reason = "not every suite mints a token or mounts the plane"
    )]
    pub fn sign(&self, payload: &JwtPayload, named: &str) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(named);
        let signer = ES256.signer_from_jwk(&self.private).expect("a signer");
        jwt::encode_with_signer(payload, &header, &signer).expect("a signed token")
    }
}

/// The claims a token carries, before anything is signed.
///
/// Built complete and then edited, so a test that wants a token missing one
/// thing names that thing rather than assembling a whole payload and getting a
/// second one wrong by accident.
/// Where a login is answered in the suites. Absent would refuse every start,
/// which is what a deployment that configured none does.
#[allow(dead_code, reason = "not every suite mounts the plane")]
pub fn login_ui() -> config::serving::LoginUi {
    config::serving::LoginUi::parse("https://login.test").expect("a usable login ui")
}

#[allow(
    dead_code,
    reason = "not every suite mints a token or mounts the plane"
)]
pub fn origin() -> config::serving::PublicOrigin {
    config::serving::PublicOrigin::parse(ORIGIN).expect("a usable origin")
}

#[allow(
    dead_code,
    reason = "not every suite mints a token or mounts the plane"
)]
pub fn claims() -> JwtPayload {
    let mut payload = JwtPayload::new();
    payload.set_issuer(origin().issuer(REALM));
    payload.set_subject(SUBJECT);
    payload.set_audience(vec![AUDIENCE]);
    payload
        .set_claim("scope", Some(serde_json::json!(format!("openid {SCOPE}"))))
        .expect("a scope claim");
    payload
        .set_claim("azp", Some(serde_json::json!(PARTY)))
        .expect("an authorized party claim");
    // An access token, and the login it belongs to. A token carrying neither is
    // not something this plane accepts, whatever else it carries.
    payload
        .set_claim("typ", Some(serde_json::json!("Bearer")))
        .expect("a token type claim");
    payload
        .set_claim("sid", Some(serde_json::json!(SESSION)))
        .expect("a session claim");
    payload.set_expires_at(&(SystemTime::now() + Duration::from_secs(600)));
    payload
}

/// A migrated database with a realm that signs, and a turn on it.
pub struct Plane {
    pool: Pool,
    _turn: MutexGuard<'static, ()>,
    tenancy: Tenancy,
    /// The key the realm published, private half included so a token can be
    /// signed with it.
    pub key: SigningKey,
    /// A second key the realm also published, whose private half names nothing.
    pub second: SigningKey,
}

impl Plane {
    /// Mint a code the way `/authorize` will, and hand back the raw value.
    ///
    /// The row keeps only the digest, so a test that wants to spend a code has
    /// to be the thing that made it. Everything a redemption re-checks is a
    /// parameter, because every one of them is something a test needs to get
    /// wrong on purpose.
    #[allow(dead_code, reason = "only the protocol suite spends a code")]
    pub async fn mint_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        challenge: Option<(&str, &str)>,
    ) -> String {
        let provider = OpenSslProvider::new(&CryptoConfig {
            fips_required: false,
            pkcs11: None,
        })
        .expect("a software provider");

        // Drawn, not built from the arguments. Two codes minted for one client
        // and one scope would land on the same digest, which is the primary key.
        let mut drawn = [0_u8; 16];
        provider.rand().fill(&mut drawn).expect("a fresh code");
        let raw = data_encoding::HEXLOWER.encode(&drawn);
        let digest = provider
            .digest()
            .hash(crypto::provider::HashAlg::Sha256, raw.as_bytes())
            .expect("a digest");

        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        store::providers::oidc::mint_code(
            &transaction,
            &models::entities::oidc::AuthorizationCode {
                code_hash: data_encoding::HEXLOWER.encode(&digest),
                tenant: TENANT.into(),
                realm_id: REALM.into(),
                client_id: client_id.to_owned(),
                user_id: SUBJECT.into(),
                session_id: SESSION.into(),
                redirect_uri: redirect_uri.to_owned(),
                scope: scope.to_owned(),
                nonce: Some("n-once".into()),
                code_challenge: challenge.map(|(value, _)| value.to_owned()),
                code_challenge_method: challenge.map(|(_, method)| method.to_owned()),
                auth_time: 1_700_000_000,
                acr: Some("password".into()),
                org_id: None,
                org_name: None,
                claims: None,
            },
            chrono::Utc::now() + chrono::Duration::minutes(1),
        )
        .await
        .expect("a minted code");
        transaction.commit().await.unwrap();
        raw
    }

    /// Whether the login is still one a grant would accept.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn login_is_open(&self, session_id: &str) -> bool {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        sessions::load(&transaction, session_id)
            .await
            .expect("the session table")
            .is_some_and(|login| {
                login.state == models::sessions::records::UserSessionState::LoggedIn
            })
    }

    /// Whether the record of the login is still there at all, open or closed.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn login_exists(&self, session_id: &str) -> bool {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        sessions::load(&transaction, session_id)
            .await
            .expect("the session table")
            .is_some()
    }

    /// Enrol a soft key by running the real registration ceremony: the server
    /// side issues the challenge and writes the stored blob, the soft key
    /// attests, and the verifier arbitrates between them.
    #[allow(dead_code, reason = "only the protocol suite enrols one")]
    pub async fn enrol_soft_passkey(&self) -> soft_key::SoftKey {
        let url = Url::parse(ORIGIN).expect("the fixture origin");
        let party = WebauthnBuilder::new(url.domain().expect("a host"), &url)
            .and_then(WebauthnBuilder::build)
            .expect("a relying party");
        // The subject's user handle. Fixed rather than derived: its value only
        // rides inside the ceremony state, and the tests never read it back.
        let (creation, state) = party
            .start_passkey_registration(Uuid::from_u128(0xada), SUBJECT, SUBJECT, None)
            .expect("a registration challenge");

        let key = soft_key::SoftKey::new();
        let attested: RegisterPublicKeyCredential = serde_json::from_value(key.attest(
            &serde_json::to_value(&creation).expect("the wire shape"),
            ORIGIN,
        ))
        .expect("the shape a browser posts");
        let passkey = party
            .finish_passkey_registration(&attested, &state)
            .expect("an attestation the verifier accepts");

        self.enrol_passkey(
            serde_json::to_value(&passkey).expect("the stored shape"),
            passkey.cred_id().as_ref().to_vec(),
        )
        .await;
        key
    }

    /// Enrol a passkey for the subject, as a registration ceremony would leave
    /// it. The blob is the library's own format, which is what the store keeps.
    #[allow(dead_code, reason = "only the protocol suite enrols one")]
    pub async fn enrol_passkey(&self, passkey: serde_json::Value, credential_id: Vec<u8>) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        store::providers::webauthn::enrol(
            &transaction,
            &store::providers::webauthn::EnrolledCredential {
                credential_id,
                user_id: SUBJECT.into(),
                label: "a key".into(),
                passkey,
                sign_count: 0,
                enrolled_at: None,
                last_used_at: None,
            },
        )
        .await
        .expect("the credential table");
        transaction.commit().await.unwrap();
    }

    /// What a login in progress remembers, which is where a challenge's state
    /// lands.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn login_notes(&self, auth_session: &str) -> serde_json::Value {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        store::providers::login::resume(&transaction, auth_session)
            .await
            .expect("the auth session table")
            .map(|login| login.notes)
            .unwrap_or(serde_json::Value::Null)
    }

    /// Point a client's browser login at another flow.
    #[allow(dead_code, reason = "only the protocol suite asks for a second factor")]
    pub async fn bind_browser_flow(&self, client_id: &str, flow: &str) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let mut client = clients::load(&transaction, client_id)
            .await
            .expect("the clients table")
            .expect("a planted client");
        client.auth_flow_binding_overrides = Some(std::collections::HashMap::from([(
            "browser".to_owned(),
            models::entities::attributes::AttributeValue::Str(flow.to_owned()),
        )]));
        clients::update(&transaction, &client)
            .await
            .expect("the clients table");
        transaction.commit().await.unwrap();
    }

    /// Put an instruction on the subject, the way an administrator requires a
    /// credential to be set up at the next login.
    #[allow(dead_code, reason = "only the protocol suite does")]
    pub async fn require_of_subject(&self, action: models::entities::user::RequiredAction) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let mut user = store::providers::users::load(&transaction, SUBJECT)
            .await
            .expect("the users table")
            .expect("the planted subject");
        user.required_actions
            .get_or_insert_with(Vec::new)
            .push(action);
        store::providers::users::update(&transaction, &user)
            .await
            .expect("the users table");
        transaction.commit().await.unwrap();
    }

    /// What still stands against the subject.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn subject_owes(&self) -> Vec<models::entities::user::RequiredAction> {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        store::providers::users::load(&transaction, SUBJECT)
            .await
            .expect("the users table")
            .expect("the planted subject")
            .required_actions
            .unwrap_or_default()
    }

    /// The keys the subject holds, by identifier.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn subject_keys(&self) -> Vec<Vec<u8>> {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        store::providers::webauthn::of_user(&transaction, SUBJECT)
            .await
            .expect("the credential table")
            .into_iter()
            .map(|credential| credential.credential_id)
            .collect()
    }

    /// The authenticator-app secrets the subject holds, base32 as stored.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn subject_totp_secrets(&self) -> Vec<String> {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        store::providers::credentials::load_for_user_of_type(
            &transaction,
            SUBJECT,
            models::entities::credentials::CredentialType::Totp,
        )
        .await
        .expect("the credential table")
        .into_iter()
        .map(|credential| credential.secret.expose().to_owned())
        .collect()
    }

    /// Switch the subject off, the way an administrator shuts down an account.
    #[allow(dead_code, reason = "only the protocol suite does")]
    pub async fn disable_subject(&self) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let mut user = store::providers::users::load(&transaction, SUBJECT)
            .await
            .expect("the users table")
            .expect("the planted subject");
        user.enabled = false;
        store::providers::users::update(&transaction, &user)
            .await
            .expect("the users table");
        transaction.commit().await.unwrap();
    }

    /// Move the planted login's authentication back in time.
    ///
    /// `max_age` asks how long ago the user authenticated, not how long ago the
    /// session began, and the two are only distinguishable when they differ.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn backdate_authentication(&self, session_id: &str, seconds: i64) -> i64 {
        let when = chrono::Utc::now().timestamp() - seconds;
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        sessions::record_authentication(&transaction, session_id, when, None)
            .await
            .expect("the session table");
        transaction.commit().await.unwrap();
        when
    }

    /// Turn a client's authorization-code flow on, off, or back to unset.
    #[allow(dead_code, reason = "only the protocol suite flips it")]
    pub async fn set_standard_flow(&self, client_id: &str, enabled: Option<bool>) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let mut client = clients::load(&transaction, client_id)
            .await
            .expect("the clients table")
            .expect("a planted client");
        client.standard_flow_enabled = enabled;
        clients::update(&transaction, &client)
            .await
            .expect("the clients table");
        transaction.commit().await.unwrap();
    }

    /// Publish one more signing key, active beside the planted one.
    #[allow(
        dead_code,
        reason = "only the protocol suite signs with a second algorithm"
    )]
    pub async fn publish_key(&self, key: &SigningKey) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let ring = keyring::load(&transaction, &envelope(), TENANT, REALM)
            .await
            .expect("the realm's ring");
        realm_keys::create(
            &transaction,
            &ring,
            &envelope(),
            &RealmSigningKey {
                tenant: TENANT.into(),
                realm_id: REALM.into(),
                kid: key.kid.clone(),
                algorithm: key.algorithm(),
                key_use: KeyUse::Sig,
                status: KeyStatus::Active,
                priority: 10,
                private_pem: key.private_pem(),
                public_jwk: serde_json::to_value(key.public().as_ref()).expect("a public jwk"),
                created_at: 1_700_000_000,
            },
        )
        .await
        .expect("the key table");
        transaction.commit().await.unwrap();
    }

    /// Register how a client wants its identity tokens signed.
    #[allow(dead_code, reason = "only the protocol suite asks")]
    pub async fn register_id_token_alg(&self, client_id: &str, algorithm: Option<SignAlg>) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let mut client = clients::load(&transaction, client_id)
            .await
            .expect("the clients table")
            .expect("a planted client");
        client.id_token_signed_response_alg = algorithm;
        clients::update(&transaction, &client)
            .await
            .expect("the clients table");
        transaction.commit().await.unwrap();
    }

    /// End the login every code here was minted from.
    #[allow(dead_code, reason = "only the protocol suite ends one")]
    pub async fn end_login(&self) {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        sessions::set_state(
            &transaction,
            SESSION,
            models::sessions::records::UserSessionState::LoggedOut,
        )
        .await
        .expect("the session table");
        transaction.commit().await.unwrap();
    }

    /// What a token this realm minted actually carries.
    ///
    /// Verified against the published key rather than decoded, so a test reading
    /// a claim has also established that the realm would accept the token the
    /// claim came from.
    #[allow(dead_code, reason = "only the suites that mint read a token back")]
    pub async fn claims_of(&self, token: &str) -> serde_json::Value {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        let keys = realm_keys::published(&transaction, KeyUse::Sig)
            .await
            .expect("the published keys");

        let verified =
            services::token::verify_signature_and_window(&keys, token, chrono::Utc::now())
                .expect("the realm refused a token it had just minted");
        serde_json::Value::Object(verified.claims)
    }

    /// Whether the login a token names is on the table.
    #[allow(dead_code, reason = "only the suites that mint ask")]
    pub async fn session_exists(&self, session_id: &str) -> bool {
        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;
        sessions::load(&transaction, session_id)
            .await
            .expect("the session table")
            .is_some()
    }

    /// A realm with a signing key, a role carrying exactly these actions, and a
    /// user holding it.
    pub async fn with_actions(held: &[AdminAction]) -> Self {
        let turn = DATABASE.lock().await;

        let (owner, connection) = owner_config().connect(NoTls).await.expect("the owner");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        owner
            .batch_execute(
                "DROP SCHEMA public CASCADE; CREATE SCHEMA public; \
                 GRANT ALL ON SCHEMA public TO CURRENT_USER;",
            )
            .await
            .expect("the database resets");

        MigrationRunner::new(migrations())
            .run(
                &owner_config(),
                &PgConnector::disabled(),
                provider().digest(),
            )
            .await
            .expect("the schema applies");
        owner
            .batch_execute("ALTER ROLE saffui_app LOGIN PASSWORD 'saffui_app_test'")
            .await
            .expect("the role gets a password");

        let mut app = owner_config();
        app.user("saffui_app").password("saffui_app_test");
        let pool = Pool::builder(Manager::new(app, NoTls))
            .max_size(4)
            .build()
            .expect("a pool");

        let plane = Plane {
            pool,
            _turn: turn,
            tenancy: Tenancy::unpinned(),
            key: SigningKey::generate(KID),
            second: SigningKey::anonymous(SECOND_KID),
        };
        plane.plant(held).await;
        plane
    }

    pub fn pool(&self) -> Pool {
        self.pool.clone()
    }

    #[allow(
        dead_code,
        reason = "not every suite mints a token or mounts the plane"
    )]
    pub fn tenancy(&self) -> Tenancy {
        self.tenancy.clone()
    }

    pub async fn connection(&self) -> Object {
        self.pool.get().await.expect("a connection")
    }

    pub async fn scoped<'c>(
        &self,
        connection: &'c mut Object,
        context: &TenantContext,
    ) -> Transaction<'c> {
        self.tenancy
            .transaction(connection, context)
            .await
            .expect("a scoped transaction")
    }

    /// A token this realm signed, naming the key it published.
    #[allow(
        dead_code,
        reason = "not every suite mints a token or mounts the plane"
    )]
    pub fn token(&self, payload: &JwtPayload) -> String {
        self.key.sign(payload, &self.key.kid)
    }

    async fn plant(&self, held: &[AdminAction]) {
        let metadata = || AuditableModel::from_creator(TENANT.to_owned(), "root".to_owned());

        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::tenant_wide(TENANT))
            .await;

        let tenant: models::entities::tenant::TenantModel = TenantCreateModel {
            tenant_id: TENANT.into(),
            display_name: "Acme".into(),
            region: None,
            limits: None,
            created_by: Some("root".into()),
        }
        .into();
        tenants::create(&transaction, &tenant).await.unwrap();

        let realm = RealmCreateModel {
            name: REALM.into(),
            display_name: "Main".into(),
            enabled: true,
        }
        .into_model(REALM.into(), metadata());
        realms::create(&transaction, &realm).await.unwrap();

        // What this realm calls its levels. Without a map nothing can be asked
        // for and nothing can be attested, so `acr` would be absent everywhere
        // and every test about it would pass for the wrong reason.
        let mut settings = realms::load(&transaction, REALM).await.unwrap().unwrap();
        settings.acr_loa_map = Some(models::entities::acr::AcrLoaMap::from_pairs([
            (PASSWORD_ACR, 1),
            (STRONG_ACR, 2),
        ]));
        realms::update(&transaction, &settings).await.unwrap();
        transaction.commit().await.unwrap();
        drop(connection);

        let mut connection = self.connection().await;
        let transaction = self
            .scoped(&mut connection, &TenantContext::new(TENANT, REALM))
            .await;

        // The realm's own ring first: a signing key is stored sealed under it,
        // so there is nowhere to write one until it exists.
        let envelope = envelope();
        keyring::provision(&transaction, &envelope, TENANT, REALM)
            .await
            .unwrap();
        let ring = keyring::load(&transaction, &envelope, TENANT, REALM)
            .await
            .unwrap();

        // Two published keys, because one is not enough to tell "the key the
        // header names is tried" from "some published key is tried". The second
        // is passive, which is the shape that matters: a rotated key stays
        // published so tokens it already signed still verify, and it is exactly
        // the key that must not be reachable by a token naming another one.
        for (key, status, priority) in [
            (&self.key, KeyStatus::Active, 10),
            (&self.second, KeyStatus::Passive, 5),
        ] {
            realm_keys::create(
                &transaction,
                &ring,
                &envelope,
                &RealmSigningKey {
                    tenant: TENANT.into(),
                    realm_id: REALM.into(),
                    kid: key.kid.clone(),
                    algorithm: SignAlg::Es256,
                    key_use: KeyUse::Sig,
                    status,
                    priority,
                    // Read by the token endpoint, which has to open it to sign.
                    // The guard never does: it verifies against the published
                    // public half.
                    private_pem: key.private_pem(),
                    public_jwk: serde_json::to_value(key.public().as_ref()).expect("a public jwk"),
                    created_at: 1_700_000_000,
                },
            )
            .await
            .unwrap();
        }

        for (client_id, secret, public, account_enabled) in [
            (CONFIDENTIAL, Some(CLIENT_SECRET), false, true),
            (OTHER, Some(CLIENT_SECRET), false, true),
            (PUBLIC, None, true, true),
            (OFFBOARDED, Some(CLIENT_SECRET), false, false),
        ] {
            let mut client = ClientCreateModel {
                name: client_id.into(),
                display_name: client_id.into(),
                description: String::new(),
                enabled: Some(true),
            }
            .into_model(client_id.to_owned(), REALM.into(), metadata());
            clients::create(&transaction, &client).await.unwrap();
            if let Some(secret) = secret {
                let StoredPassword::Argon2id { encoded } = StoredPassword::hash_argon2id(
                    &provider(),
                    Argon2Params::default(),
                    &SecretBox::new(Box::new(secret.to_owned())),
                )
                .expect("a hashed secret") else {
                    unreachable!("hash_argon2id returns the argon2id shape")
                };
                clients::rotate_secret(&transaction, client_id, &encoded, None)
                    .await
                    .unwrap();
            }

            // Neither `public_client` nor `service_account_enabled` is on the
            // create payload: one decides whether a secret is expected at all,
            // the other whether this client may act for itself.
            client.public_client = Some(public);
            client.redirect_uris = Some(vec![REDIRECT.to_owned()]);
            // Its own list. A logout landing page is usually not a callback, and
            // one set would make every logout destination a place to deliver a
            // code.
            client.post_logout_redirect_uris = Some(vec![AFTER_LOGOUT.to_owned()]);
            client.standard_flow_enabled = Some(true);
            // Both, including the public one. An operator can tick a service
            // account on a public client, and what refuses that has to be the
            // rule about public clients rather than the tick being absent.
            client.service_account_enabled = Some(true);
            clients::update(&transaction, &client).await.unwrap();

            // Every one of them, the public client included. If the public one
            // had no account, the lookup would be what refuses it and the rule
            // about public clients would never be reached.
            //
            // Reached by the link and not by a name built from the client id, so
            // renaming it does not silently point the client at somebody else.
            let mut account = UserCreateModel {
                user_name: format!("service-account-{client_id}"),
                enabled: account_enabled,
                email: String::new(),
                email_verified: None,
                phone_number: None,
                phone_number_verified: None,
                required_actions: None,
                not_before: None,
                user_storage: None,
                attributes: None,
                is_service_account: Some(true),
                service_account_client_link: Some(client_id.to_owned()),
            }
            .into_model(
                format!("service-account-{client_id}"),
                REALM.into(),
                metadata(),
            );
            account.email = format!("service-account-{client_id}@example.test");
            users::create(&transaction, &account).await.unwrap();
        }

        // The scopes a realm gets, planted the way a deployment plants them. Only
        // `profile` is attached below: the gate is exercised only when a client
        // asks for something nothing attached to it.
        services::provisioning::provision_standard_scopes(&transaction, TENANT, REALM)
            .await
            .unwrap();
        for client_id in [CONFIDENTIAL, OTHER, PUBLIC] {
            store::providers::client_scopes::attach_scope(
                &transaction,
                client_id,
                "profile",
                false,
            )
            .await
            .unwrap();
        }
        // Optional, so a test has to ask for it: what exercises a scope that
        // is granted only by name.
        store::providers::client_scopes::attach_scope(&transaction, CONFIDENTIAL, "address", true)
            .await
            .unwrap();

        // The console and the scope the admin plane requires, planted the way a
        // deployment plants them rather than by hand. The suite that mounts the
        // plane then reaches it the way a console does, and a change that made
        // the scope unobtainable would fail here instead of passing against a
        // token no protocol could have minted.
        services::provisioning::provision_admin_console(
            &transaction,
            TENANT,
            REALM,
            &services::provisioning::AdminConsole {
                client_id: PARTY,
                scope: SCOPE,
                redirect_uris: vec![CONSOLE_REDIRECT.to_owned()],
            },
        )
        .await
        .unwrap();

        // The flow a browser login runs. `/authorize` refuses a realm that has
        // none rather than opening a login nothing can advance.
        let flow = models::entities::auth::AuthenticationFlowMutationModel {
            alias: "browser".into(),
            provider_id: "basic-flow".into(),
            description: String::new(),
            top_level: Some(true),
            built_in: Some(false),
        }
        .into_model("browser".into(), REALM.into(), metadata());
        store::providers::auth_flows::create_flow(&transaction, &flow)
            .await
            .unwrap();

        // One required password step, which is the smallest flow that can admit
        // anybody and the one the end to end suite answers.
        let execution = models::entities::auth::AuthenticationExecutionMutationModel {
            alias: "the-password".into(),
            flow_id: "browser".into(),
            priority: 10,
            step: models::entities::auth::ExecutionStep::Authenticator {
                authenticator: "password".into(),
                config_id: None,
            },
            requirement: models::entities::auth::AuthenticatorRequirement::Required,
        }
        .into_model("exec-1".into(), REALM.into(), metadata());
        store::providers::auth_flows::create_execution(&transaction, &execution)
            .await
            .unwrap();

        // A flow whose second step is a key. What exercises a challenge the
        // server issues and has to remember, which a code never needed.
        let keyed = models::entities::auth::AuthenticationFlowMutationModel {
            alias: KEYED_FLOW.into(),
            provider_id: "basic-flow".into(),
            description: String::new(),
            top_level: Some(true),
            built_in: Some(false),
        }
        .into_model(KEYED_FLOW.into(), REALM.into(), metadata());
        store::providers::auth_flows::create_flow(&transaction, &keyed)
            .await
            .unwrap();
        for (id, authenticator, priority) in [
            ("exec-keyed-1", "password", 10),
            ("exec-keyed-2", "webauthn", 20),
        ] {
            let step = models::entities::auth::AuthenticationExecutionMutationModel {
                alias: id.into(),
                flow_id: KEYED_FLOW.into(),
                priority,
                step: models::entities::auth::ExecutionStep::Authenticator {
                    authenticator: authenticator.into(),
                    config_id: None,
                },
                requirement: models::entities::auth::AuthenticatorRequirement::Required,
            }
            .into_model(id.into(), REALM.into(), metadata());
            store::providers::auth_flows::create_execution(&transaction, &step)
                .await
                .unwrap();
        }

        // A second flow, password then a code. What lets a test reach a level
        // the first flow cannot, which is what `acr_values` asks about.
        let strong = models::entities::auth::AuthenticationFlowMutationModel {
            alias: STRONG_FLOW.into(),
            provider_id: "basic-flow".into(),
            description: String::new(),
            top_level: Some(true),
            built_in: Some(false),
        }
        .into_model(STRONG_FLOW.into(), REALM.into(), metadata());
        store::providers::auth_flows::create_flow(&transaction, &strong)
            .await
            .unwrap();
        for (id, authenticator, priority) in [
            ("exec-strong-1", "password", 10),
            ("exec-strong-2", "totp", 20),
        ] {
            let step = models::entities::auth::AuthenticationExecutionMutationModel {
                alias: id.into(),
                flow_id: STRONG_FLOW.into(),
                priority,
                step: models::entities::auth::ExecutionStep::Authenticator {
                    authenticator: authenticator.into(),
                    config_id: None,
                },
                requirement: models::entities::auth::AuthenticatorRequirement::Required,
            }
            .into_model(id.into(), REALM.into(), metadata());
            store::providers::auth_flows::create_execution(&transaction, &step)
                .await
                .unwrap();
        }

        let user = UserCreateModel {
            user_name: SUBJECT.into(),
            enabled: true,
            email: "ada@example.test".into(),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            // What the `profile` scope releases. Held as attributes because that
            // is where the realm keeps them, so the claim set is composed rather
            // than read off columns that do not exist.
            attributes: Some(std::collections::HashMap::from([
                (
                    models::entities::user::profile::FIRST_NAME.to_owned(),
                    models::entities::attributes::AttributeValue::Str(GIVEN_NAME.into()),
                ),
                (
                    models::entities::user::profile::LAST_NAME.to_owned(),
                    models::entities::attributes::AttributeValue::Str(FAMILY_NAME.into()),
                ),
            ])),
            is_service_account: None,
            service_account_client_link: None,
        }
        .into_model(SUBJECT.into(), REALM.into(), metadata());
        users::create(&transaction, &user).await.unwrap();

        let StoredPassword::Argon2id { encoded } = StoredPassword::hash_argon2id(
            &provider(),
            Argon2Params::default(),
            &SecretBox::new(Box::new(PASSWORD.to_owned())),
        )
        .expect("a hashed password") else {
            unreachable!("hash_argon2id returns the argon2id shape")
        };
        store::providers::credentials::create(
            &transaction,
            &models::entities::credentials::CredentialModel {
                credential_id: "cred-1".into(),
                realm_id: REALM.into(),
                user_id: SUBJECT.into(),
                credential_type: models::entities::credentials::CredentialType::Password,
                secret: models::entities::credentials::CredentialSecret::new(encoded),
                user_label: None,
                otp: None,
                priority: 0,
                metadata: metadata(),
            },
        )
        .await
        .unwrap();

        // A second factor for the subject. The secret is base32 because that is
        // what an authenticator app is handed and what the store keeps.
        store::providers::credentials::create(
            &transaction,
            &models::entities::credentials::CredentialModel::otp(
                "cred-totp".into(),
                REALM.into(),
                SUBJECT.into(),
                models::entities::credentials::CredentialSecret::new(TOTP_SECRET.to_owned()),
                models::entities::credentials::OtpAlgorithm::Sha1,
                models::entities::credentials::OtpParameters::totp(6, 30)
                    .expect("a usable time step"),
                metadata(),
            ),
        )
        .await
        .unwrap();

        // The login the tokens are bound to. The plane refuses a token whose
        // login it cannot find, so without this every test here refuses for a
        // reason none of them is about.
        sessions::open(
            &transaction,
            &models::sessions::records::UserSessionModel {
                tenant: TENANT.into(),
                session_id: SESSION.into(),
                realm_id: REALM.into(),
                user_id: SUBJECT.into(),
                login_username: SUBJECT.into(),
                broker_session_id: None,
                broker_user_id: None,
                auth_method: None,
                ip_address: None,
                started_at: chrono::Utc::now().timestamp(),
                auth_time: None,
                loa: None,
                expiration: None,
                state: models::sessions::records::UserSessionState::LoggedIn,
                remember_me: None,
                last_session_refresh: None,
                is_offline: None,
                notes: None,
            },
        )
        .await
        .unwrap();

        // One role carrying exactly what was asked for. An empty list is a real
        // case: a caller holding a role that grants nothing is not the same as
        // one holding no role at all.
        let role = RoleMutationModel {
            name: "admins".into(),
            display_name: "Admins".into(),
            description: String::new(),
            client_id: None,
            admin_actions: Some(held.to_vec()),
        }
        .into_model("admins".into(), REALM.into(), metadata());
        roles::create(&transaction, &role).await.unwrap();
        roles::grant_to_user(&transaction, SUBJECT, "admins")
            .await
            .unwrap();

        transaction.commit().await.unwrap();
    }
}

/// Percent encode a query value.
///
/// Written out rather than pulled in, because what a test needs is the encoding
/// a browser performs and not whatever a dependency decided the unreserved set
/// is this release.
#[allow(
    dead_code,
    reason = "only the suites that drive a browser encode a query"
)]
pub fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

/// The value of one `Set-Cookie`, or nothing when it was not set.
#[allow(
    dead_code,
    reason = "only the suites that drive a browser read cookies"
)]
pub fn cookie_value(set: &[String], named: &str) -> Option<String> {
    set.iter()
        .find(|header| header.starts_with(&format!("{named}=")))
        .map(|header| {
            header
                .split_once('=')
                .unwrap()
                .1
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        })
        .filter(|value| !value.is_empty())
}

/// The verifier and its S256 challenge, the pair RFC 7636 §4 describes.
#[allow(dead_code, reason = "only the suites that spend a code prove one")]
pub fn pkce_pair() -> (String, String) {
    let verifier = "a-verifier-of-at-least-forty-three-characters-long";
    let digest = provider()
        .digest()
        .hash(crypto::provider::HashAlg::Sha256, verifier.as_bytes())
        .expect("a digest");
    (
        verifier.to_owned(),
        data_encoding::BASE64URL_NOPAD.encode(&digest),
    )
}
