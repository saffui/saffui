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
use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, CryptoProvider, SignAlg};
use deadpool_postgres::{Manager, Object, Pool, Transaction};
use models::auditable::AuditableModel;
use models::entities::authz::{AdminAction, RoleMutationModel};
use models::entities::keys::{KeyStatus, KeyUse, RealmSigningKey};
use models::entities::realm::RealmCreateModel;
use models::entities::tenant::TenantCreateModel;
use models::entities::user::UserCreateModel;
use pgcore::migrations::MigrationRunner;
use pgcore::tls::PgConnector;
use store::keyring;
use store::providers::{realm_keys, realms, roles, tenants, users};
use store::schema::migrations;
use store::tenancy::{Tenancy, TenantContext};
use tokio::sync::{Mutex, MutexGuard};
use tokio_postgres::{Config, NoTls};

/// One database, so the suites take turns on it.
static DATABASE: Mutex<()> = Mutex::const_new(());

const KEK: &str = "a-deployment-wrapping-key-of-decent-length";
pub const TENANT: &str = "acme";
pub const REALM: &str = "main";

/// The client the console asks for its tokens as. What `azp` carries.
pub const PARTY: &str = "saffui-console";
pub const SUBJECT: &str = "ada";
pub const AUDIENCE: &str = "saffui-admin";
pub const SCOPE: &str = "admin";
/// The key the realm publishes, named so a test can ask for a token signed by
/// something else.
pub const KID: &str = "kid-1";
/// A second published key, whose private half carries no name of its own, so a
/// token signed with it can name whichever key a test wants it to name.
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
pub fn claims() -> JwtPayload {
    let mut payload = JwtPayload::new();
    payload.set_issuer(REALM);
    payload.set_subject(SUBJECT);
    payload.set_audience(vec![AUDIENCE]);
    payload
        .set_claim("scope", Some(serde_json::json!(format!("openid {SCOPE}"))))
        .expect("a scope claim");
    payload
        .set_claim("azp", Some(serde_json::json!(PARTY)))
        .expect("an authorized party claim");
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
                    // Never read by the guard, which verifies against the
                    // published public half. Present because the column is.
                    private_pem: b"-----BEGIN PRIVATE KEY-----test-----END PRIVATE KEY-----"
                        .to_vec(),
                    public_jwk: serde_json::to_value(key.public().as_ref()).expect("a public jwk"),
                    created_at: 1_700_000_000,
                },
            )
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
            attributes: None,
            is_service_account: None,
            service_account_client_link: None,
        }
        .into_model(SUBJECT.into(), REALM.into(), metadata());
        users::create(&transaction, &user).await.unwrap();

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
