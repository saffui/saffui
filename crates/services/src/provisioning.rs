use crypto::envelope::Envelope;
use crypto::jose::jwk::alg::ec::EcKeyPair;
use crypto::jose::jwk::alg::rsa::RsaKeyPair;
use crypto::jose::jwk::{KeyPair, P_256};
use crypto::provider::{CryptoProvider, SignAlg};
use crypto::thumbprint::jwk_sha256_thumbprint;
use deadpool_postgres::Transaction;
use models::auditable::AuditableModel;
use models::entities::acr::AcrLoaMap;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticationFlowMutationModel,
    AuthenticatorRequirement, ExecutionStep,
};
use models::entities::client::{ClientCreateModel, ClientScopeModel, Protocol};
use models::entities::keys::{
    JweAlgorithm, KeyStatus, KeyUse, RealmEncryptionKey, RealmSigningKey,
};
use models::entities::realm::{
    ClientRegistration, RealmCreateModel, RealmModel, RegistrationBounds,
};
use models::entities::tenant::{TenantCreateModel, TenantModel};
use secrecy::SecretBox;
use store::error::{StoreError, StoreResult};
use store::keyring;

use crate::admin;
use models::entities::authz::{AdminAction, RoleModel};
use store::providers::{
    auth_flows, client_scopes, clients, realm_keys, realms, roles, tenants, users,
};

/// Who the audit trail names for rows nobody typed in.
const PROVISIONER: &str = "provisioner";
/// The alias `/authorize` runs when a client binds no other.
const BROWSER_FLOW: &str = "browser";

/// What the admin plane requires on a token unless a deployment renames it.
///
/// The same default `SAFFUI_ADMIN_SCOPE` falls back to. Two spellings of one
/// string would let a deployment provision a scope its own plane refuses.
pub const ADMIN_SCOPE: &str = "admin";

/// The console a realm is administered from.
///
/// The client id is both halves of what the plane matches on. An access token
/// is minted for the client that asked for it and nothing adds a second
/// audience, so this one string is what `SAFFUI_ADMIN_PARTIES` and
/// `SAFFUI_ADMIN_AUDIENCES` both have to name.
#[derive(Debug, Clone)]
pub struct AdminConsole<'a> {
    /// What `azp` and `aud` will carry on every token this console obtains.
    pub client_id: &'a str,
    /// The scope the plane requires, passed in rather than read off the
    /// constant, so a deployment that renamed it provisions the name it asks for.
    pub scope: &'a str,
    /// Where the console is served. The operator's, because nothing else knows
    /// it, and a login is only sent back to a value written down here.
    pub redirect_uris: Vec<String>,
}

/// The scopes OIDC Core §5.4 defines, and what a fresh realm needs to honour
/// them.
///
/// Without these rows a realm entitles nobody to anything: `/authorize`
/// intersects the request with what a client is attached to, so a request for
/// `profile` is dropped and `/userinfo` releases a subject and nothing else.
///
/// `profile` and `email` are defaults, which is what every client gets without
/// asking. `phone` is not: §5.4 gates a number behind a scope a client has to
/// name, and a default would hand it out to every registration.
pub const STANDARD_SCOPES: [(&str, bool, &str); 5] = [
    ("profile", true, "Basic profile claims"),
    ("email", true, "Email address and whether it is verified"),
    ("phone", false, "Phone number and whether it is verified"),
    ("address", false, "Postal address"),
    // Never a default: it hands out a credential that outlives the login.
    ("offline_access", false, "Renewing while the user is away"),
];

/// Create a realm and everything it cannot work without.
///
/// One transaction, because a realm whose scopes failed to seed is not a
/// half-provisioned realm: it is one whose clients are entitled to nothing and
/// whose tokens carry a subject and no claims, and nothing about it says so.
///
/// Idempotent throughout, so a deployment that renames its console or adds a
/// redirect can run it again.
pub async fn provision_realm(
    transaction: &Transaction<'_>,
    realm: &RealmModel,
    console: &AdminConsole<'_>,
) -> StoreResult<()> {
    let tenant = &realm.metadata.tenant;
    if realms::load(transaction, &realm.realm_id).await?.is_none() {
        realms::create(transaction, realm).await?;
    }
    provision_standard_scopes(transaction, tenant, &realm.realm_id).await?;
    provision_admin_console(transaction, tenant, &realm.realm_id, console).await
}

/// The realm's own row, and nothing else it needs.
///
/// Apart from [`provision_realm`] because it runs somewhere else: a realm
/// cannot be scoped to before it exists, so the row is written tenant wide and
/// everything that belongs inside it is written after, scoped to it.
pub async fn provision_realm_row(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_name: &str,
) -> StoreResult<bool> {
    if realms::load(transaction, realm_name).await?.is_some() {
        return Ok(false);
    }
    let realm = RealmCreateModel {
        name: realm_name.to_owned(),
        display_name: realm_name.to_owned(),
        enabled: true,
    }
    .into_model(
        realm_name.to_owned(),
        AuditableModel::from_creator(tenant.to_owned(), PROVISIONER.to_owned()),
    );
    realms::create(transaction, &realm).await?;
    Ok(true)
}

/// The scopes a client can be attached to, and nothing attached yet.
///
/// Which clients hold which is a registration decision. This only makes the
/// decision possible: a scope that does not exist cannot be granted, so a realm
/// without these rows silently answers every request with less than was asked.
pub async fn provision_standard_scopes(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<()> {
    let metadata = AuditableModel::from_creator(tenant.to_owned(), "system".to_owned());

    for (name, default, description) in STANDARD_SCOPES {
        if client_scopes::load_scope(transaction, name)
            .await?
            .is_some()
        {
            continue;
        }
        client_scopes::create_scope(
            transaction,
            &ClientScopeModel {
                client_scope_id: name.to_owned(),
                realm_id: realm_id.to_owned(),
                name: name.to_owned(),
                description: description.to_owned(),
                protocol: Protocol::OpenId,
                default_scope: Some(default),
                configs: None,
                metadata: metadata.clone(),
            },
        )
        .await?;
    }
    Ok(())
}

/// Give a realm its admin scope and a console entitled to it./// Give a realm its admin scope and a console entitled to it.
///
/// Idempotent, and idempotent in the direction that matters: what already
/// exists is left as it stands. An operator who pointed the console at a
/// different address or made it confidential keeps that, and only the
/// attachment is re-asserted, which is the one thing this is here to guarantee.
///
/// The attachment is not optional, so the console carries the scope without
/// asking for it. That is what lets the plane require the scope by default
/// rather than every admin UI having to remember to ask.
pub async fn provision_admin_console(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    console: &AdminConsole<'_>,
) -> StoreResult<()> {
    let metadata = AuditableModel::from_creator(tenant.to_owned(), "system".to_owned());

    if client_scopes::load_scope(transaction, console.scope)
        .await?
        .is_none()
    {
        client_scopes::create_scope(
            transaction,
            &ClientScopeModel {
                client_scope_id: console.scope.to_owned(),
                realm_id: realm_id.to_owned(),
                name: console.scope.to_owned(),
                description: "Administration plane access".to_owned(),
                protocol: Protocol::OpenId,
                // Not a realm default. A default is offered to every client
                // registered afterwards, and a scope that opens the admin plane
                // is the last one to hand out by registration.
                default_scope: Some(false),
                configs: None,
                metadata: metadata.clone(),
            },
        )
        .await?;
    }

    if clients::load(transaction, console.client_id)
        .await?
        .is_none()
    {
        let mut client = ClientCreateModel {
            name: console.client_id.to_owned(),
            display_name: "Admin Console".to_owned(),
            description: "The console this realm is administered from".to_owned(),
            enabled: Some(true),
        }
        .into_model(
            console.client_id.to_owned(),
            realm_id.to_owned(),
            metadata.clone(),
        );
        client.protocol = Some(Protocol::OpenId);
        // A browser application, so there is nowhere to keep a secret and the
        // code is bound to the browser that started the login instead. Being
        // public is what makes `/authorize` insist on a challenge.
        client.public_client = Some(true);
        client.standard_flow_enabled = Some(true);
        // A console acts for the administrator using it and never for itself, so
        // it gets no service account and no direct grant.
        client.service_account_enabled = Some(false);
        client.direct_access_grants_enabled = Some(false);
        client.implicit_flow_enabled = Some(false);
        client.redirect_uris = Some(console.redirect_uris.clone());

        clients::create(transaction, &client).await?;
        // Twice, because the insert writes the identifying columns and the rest
        // are an update. Everything above that decides what this client may do
        // lives in the second half.
        clients::update(transaction, &client).await?;
    }

    client_scopes::attach_scope(transaction, console.client_id, console.scope, false).await
}

/// The role a provisioned administrator holds. One name on both sides: the
/// role this creates and the grant it re-asserts.
pub const ADMINISTRATOR_ROLE: &str = "administrator";

/// Give a realm its administrator role and grant it to one user.
///
/// The role carries every admin plane action, because the first administrator
/// is the one who will hand out narrower ones. Idempotent the same way the
/// console is: a role the operator reshaped keeps its shape, and only the
/// grant is re-asserted, which is the one thing a deployment cannot log in
/// to fix.
pub async fn provision_realm_administration(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
    user_id: &str,
) -> StoreResult<bool> {
    let created = match roles::load(transaction, ADMINISTRATOR_ROLE).await? {
        Some(mut held) => {
            // The catalogue grows, and a role materialised under an older one
            // silently lacks the newest capabilities. A role no operator ever
            // touched is the provisioner's to keep current; one an operator
            // reshaped keeps its shape, and the update trail is what tells
            // the two apart.
            let untouched = held
                .metadata
                .updated_by
                .as_deref()
                .is_none_or(|by| by == PROVISIONER);
            let current = AdminAction::ALL.to_vec();
            if untouched && held.admin_actions.as_deref() != Some(current.as_slice()) {
                held.admin_actions = Some(current);
                held.metadata.updated_by = Some(PROVISIONER.to_owned());
                roles::update(transaction, &held).await?;
            }
            false
        }
        None => {
            roles::create(
                transaction,
                &RoleModel {
                    role_id: ADMINISTRATOR_ROLE.to_owned(),
                    realm_id: realm_id.to_owned(),
                    name: ADMINISTRATOR_ROLE.to_owned(),
                    description: "Every admin plane action".to_owned(),
                    display_name: "Administrator".to_owned(),
                    client_id: None,
                    admin_actions: Some(AdminAction::ALL.to_vec()),
                    metadata: AuditableModel::from_creator(
                        tenant.to_owned(),
                        PROVISIONER.to_owned(),
                    ),
                },
            )
            .await?;
            true
        }
    };
    roles::grant_to_user(transaction, user_id, ADMINISTRATOR_ROLE).await?;
    Ok(created)
}

/// A tenant, created unless it already is. Runs tenant wide, because a realm
/// cannot be scoped to before its tenant exists.
pub async fn provision_tenant(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    display_name: &str,
) -> StoreResult<bool> {
    if tenants::exists(transaction).await? {
        return Ok(false);
    }
    let tenant: TenantModel = TenantCreateModel {
        tenant_id: tenant_id.to_owned(),
        display_name: display_name.to_owned(),
        region: None,
        limits: None,
        created_by: Some(PROVISIONER.to_owned()),
    }
    .into();
    tenants::create(transaction, &tenant).await?;
    Ok(true)
}

/// The realm's first signing key, unless it already publishes one.
///
/// The ring comes first: a key is stored sealed under it, so there is nowhere
/// to write one until it exists. The key is ES256, the one algorithm every
/// relying party must support; its name is its RFC 7638 thumbprint, so the
/// same key is never written twice under two names; and the private half
/// never leaves this transaction unsealed.
pub async fn provision_signing_key(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    envelope: &Envelope,
    tenant: &str,
    realm_id: &str,
    now: i64,
) -> StoreResult<bool> {
    keyring::provision(transaction, envelope, tenant, realm_id).await?;
    let ring = keyring::load(transaction, envelope, tenant, realm_id).await?;
    let published = realm_keys::published(transaction, KeyUse::Sig).await?;

    // One key per algorithm a fresh realm signs with: RS256, which Discovery
    // §3 requires of every provider, and ES256. A realm already holding one of
    // them keeps it.
    let mut made = false;
    for algorithm in [SignAlg::Rs256, SignAlg::Es256] {
        if published.iter().any(|key| key.algorithm == algorithm) {
            continue;
        }
        let (mut private, private_pem) = match algorithm {
            SignAlg::Rs256 => {
                let pair = RsaKeyPair::generate(2048).map_err(|_| StoreError::Backend)?;
                (pair.to_jwk_key_pair(), pair.to_pem_private_key())
            }
            _ => {
                let pair = EcKeyPair::generate(P_256).map_err(|_| StoreError::Backend)?;
                (pair.to_jwk_key_pair(), pair.to_pem_private_key())
            }
        };
        let mut public = private.to_public_key().map_err(|_| StoreError::Backend)?;
        let kid = jwk_sha256_thumbprint(provider, &public).map_err(|_| StoreError::Backend)?;
        private.set_key_id(&kid);
        private.set_algorithm(algorithm.name());
        public.set_key_id(&kid);
        public.set_algorithm(algorithm.name());

        realm_keys::create(
            transaction,
            &ring,
            envelope,
            &RealmSigningKey {
                tenant: tenant.to_owned(),
                realm_id: realm_id.to_owned(),
                kid,
                algorithm,
                key_use: KeyUse::Sig,
                status: KeyStatus::Active,
                priority: 10,
                private_pem,
                public_jwk: serde_json::to_value(public.as_ref())
                    .map_err(|_| StoreError::Backend)?,
                created_at: now,
            },
        )
        .await?;
        made = true;
    }

    // One key to be encrypted to, so a client may register an encrypted
    // request object at all. RSA-OAEP-256: every relying party's library has
    // it, and it needs no agreement about a curve.
    if realm_keys::published_encryption(transaction)
        .await?
        .is_empty()
    {
        let pair = RsaKeyPair::generate(2048).map_err(|_| StoreError::Backend)?;
        let (mut private, private_pem) = (pair.to_jwk_key_pair(), pair.to_pem_private_key());
        let mut public = private.to_public_key().map_err(|_| StoreError::Backend)?;
        let kid = jwk_sha256_thumbprint(provider, &public).map_err(|_| StoreError::Backend)?;
        let named = JweAlgorithm::RsaOaep256;
        private.set_key_id(&kid);
        private.set_algorithm(named.as_str());
        public.set_key_id(&kid);
        public.set_algorithm(named.as_str());
        public.set_key_use("enc");

        realm_keys::create_encryption(
            transaction,
            &ring,
            envelope,
            &RealmEncryptionKey {
                kid,
                algorithm: named,
                private_pem,
                public_jwk: serde_json::to_value(public.as_ref())
                    .map_err(|_| StoreError::Backend)?,
            },
        )
        .await?;
        made = true;
    }
    Ok(made)
}

/// What this realm calls its levels, unless it already says.
///
/// A realm mapping nothing can be asked for nothing and attests to nothing:
/// `acr_values` is refused and no `acr` is ever issued. Two levels, one per
/// factor a fresh realm can run, so a login says how strong it was.
pub async fn provision_levels(transaction: &Transaction<'_>, realm_id: &str) -> StoreResult<bool> {
    let Some(mut realm) = realms::load(transaction, realm_id).await? else {
        return Ok(false);
    };
    if realm.acr_loa_map.is_some() {
        return Ok(false);
    }
    realm.acr_loa_map = Some(AcrLoaMap::from_pairs([("password", 1), ("mfa", 2)]));
    realms::update(transaction, &realm).await?;
    Ok(true)
}

/// The flow a browser login runs: one required password step, unless the
/// realm already has a flow by that alias. `/authorize` refuses a realm that
/// has none rather than opening a login nothing can advance.
pub async fn provision_browser_flow(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<bool> {
    if auth_flows::flow_by_alias(transaction, BROWSER_FLOW)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let metadata = AuditableModel::from_creator(tenant.to_owned(), PROVISIONER.to_owned());
    let flow = AuthenticationFlowMutationModel {
        alias: BROWSER_FLOW.to_owned(),
        provider_id: "basic-flow".to_owned(),
        description: "Username and password".to_owned(),
        top_level: Some(true),
        built_in: Some(true),
    }
    .into_model(
        BROWSER_FLOW.to_owned(),
        realm_id.to_owned(),
        metadata.clone(),
    );
    auth_flows::create_flow(transaction, &flow).await?;

    let step = AuthenticationExecutionMutationModel {
        alias: "password".to_owned(),
        flow_id: BROWSER_FLOW.to_owned(),
        priority: 10,
        step: ExecutionStep::Authenticator {
            authenticator: "password".to_owned(),
            config_id: None,
        },
        requirement: AuthenticatorRequirement::Required,
    }
    .into_model(
        format!("{BROWSER_FLOW}-password"),
        realm_id.to_owned(),
        metadata,
    );
    auth_flows::create_execution(transaction, &step).await?;
    Ok(true)
}

/// Offer a mailed link as an alternative to the password.
///
/// Its own call, and never on by default. Accepting a link wherever a password
/// is accepted moves what a login costs from something the person knows to
/// whoever can read their mail, which is a realm's decision and not a
/// deployment's.
///
/// Both steps become alternatives: leaving the password required would make the
/// link a second factor rather than another way in.
pub async fn provision_mailed_login(
    transaction: &Transaction<'_>,
    tenant: &str,
    realm_id: &str,
) -> StoreResult<bool> {
    let existing = auth_flows::executions_of(transaction, BROWSER_FLOW).await?;
    if existing.is_empty() {
        return Ok(false);
    }
    if existing.iter().any(|execution| {
        matches!(&execution.step, ExecutionStep::Authenticator { authenticator, .. }
                 if authenticator == "magic-link")
    }) {
        return Ok(false);
    }

    let metadata = AuditableModel::from_creator(tenant.to_owned(), PROVISIONER.to_owned());
    for execution in existing {
        auth_flows::set_requirement(
            transaction,
            &execution.execution_id,
            AuthenticatorRequirement::Alternative,
        )
        .await?;
    }
    let step = AuthenticationExecutionMutationModel {
        alias: "magic-link".to_owned(),
        flow_id: BROWSER_FLOW.to_owned(),
        priority: 20,
        step: ExecutionStep::Authenticator {
            authenticator: "magic-link".to_owned(),
            config_id: None,
        },
        requirement: AuthenticatorRequirement::Alternative,
    }
    .into_model(
        format!("{BROWSER_FLOW}-magic-link"),
        realm_id.to_owned(),
        metadata,
    );
    auth_flows::create_execution(transaction, &step).await?;
    Ok(true)
}

/// A relying party to register. Confidential when it has a secret, public
/// when it has none.
pub struct Registration<'a> {
    pub client_id: &'a str,
    pub secret: Option<&'a SecretBox<String>>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    /// Where a logout token is posted when a login this client took part in
    /// ends.
    pub backchannel_logout_uri: Option<String>,
    pub frontchannel_logout_uri: Option<String>,
    /// Whether this client may receive what the authorization endpoint mints.
    /// Never on by default: it is a second permission, not a shape of the
    /// first.
    pub implicit: bool,
}

/// Let clients register themselves here. Says whether it changed anything.
pub async fn open_client_registration(
    transaction: &Transaction<'_>,
    realm_id: &str,
    bounds: &RegistrationBounds,
) -> StoreResult<bool> {
    let Some(mut realm) = realms::load(transaction, realm_id).await? else {
        return Ok(false);
    };
    let bounded = realm.registration_bounds.max_clients == bounds.max_clients
        && realm.registration_bounds.requires_consent == bounds.requires_consent
        && realm.registration_bounds.trusted_hosts == bounds.trusted_hosts;
    if realm.client_registration == ClientRegistration::Open && bounded {
        return Ok(false);
    }
    realm.client_registration = ClientRegistration::Open;
    realm.registration_bounds = bounds.clone();
    realms::update(transaction, &realm).await
}

/// Register a client, unless one by that id exists, and attach it to every
/// scope a fresh realm grants by default.
pub async fn provision_client(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    registration: &Registration<'_>,
) -> StoreResult<bool> {
    if clients::load(transaction, registration.client_id)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let spec = admin::clients::Spec {
        name: None,
        confidential: registration.secret.is_some(),
        redirect_uris: registration.redirect_uris.clone(),
        post_logout_redirect_uris: registration.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: registration.backchannel_logout_uri.clone(),
        frontchannel_logout_uri: registration.frontchannel_logout_uri.clone(),
        registered: admin::clients::Registered {
            consent_required: None,
            id_token_encryption: None,
            userinfo_encryption: None,
            request_object_encryption: None,
            implicit: registration.implicit,
            ..Default::default()
        },
    };
    let secret = match registration.secret {
        Some(given) => admin::clients::Secret::Given(given),
        None => admin::clients::Secret::Drawn,
    };
    admin::clients::register(
        transaction,
        provider,
        tenant,
        realm_id,
        PROVISIONER,
        registration.client_id,
        &spec,
        secret,
    )
    .await
    .map_err(|_| StoreError::Backend)?;

    Ok(true)
}

/// Register a client wearing the FAPI 2.0 Security Profile: confidential,
/// authenticating by a key it published, ES256 identity tokens, and the
/// profile flag the doors read. The private half stays with the client; what
/// arrives here is the published set.
pub async fn provision_fapi_client(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    client_id: &str,
    public_jwks: serde_json::Value,
    redirect_uris: Vec<String>,
) -> StoreResult<bool> {
    if clients::load(transaction, client_id).await?.is_some() {
        return Ok(false);
    }
    let spec = admin::clients::Spec {
        name: None,
        confidential: true,
        redirect_uris,
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        frontchannel_logout_uri: None,
        registered: admin::clients::Registered::default(),
    };
    admin::clients::register(
        transaction,
        provider,
        tenant,
        realm_id,
        PROVISIONER,
        client_id,
        &spec,
        admin::clients::Secret::Drawn,
    )
    .await
    .map_err(|_| StoreError::Backend)?;
    let mut client = clients::load(transaction, client_id)
        .await?
        .ok_or(StoreError::Backend)?;
    client.client_authenticator_type = Some("private-key-jwt".into());
    client.jwks = Some(public_jwks);
    client.id_token_signed_response_alg = Some(crypto::provider::SignAlg::Es256);
    client.configs.get_or_insert_with(Default::default).insert(
        "profile".to_owned(),
        models::entities::attributes::AttributeValue::Str("fapi2".to_owned()),
    );
    clients::update(transaction, &client).await?;
    Ok(true)
}

/// A person who can log in.
pub struct Person<'a> {
    pub user_name: &'a str,
    pub email: &'a str,
    pub password: &'a SecretBox<String>,
    /// What the `profile` scope releases, when a deployment has it to release.
    pub given_name: Option<&'a str>,
    pub family_name: Option<&'a str>,
    /// What the `phone` scope releases. Verified by being written here.
    pub phone: Option<&'a str>,
    /// Anything else the realm holds of them, by attribute name.
    pub attributes: Vec<(&'a str, &'a str)>,
}

/// Create a user with a password, unless one by that name exists.
pub async fn provision_user(
    transaction: &Transaction<'_>,
    provider: &dyn CryptoProvider,
    tenant: &str,
    realm_id: &str,
    person: &Person<'_>,
) -> StoreResult<bool> {
    if users::load_by_name(transaction, person.user_name)
        .await?
        .is_some()
    {
        return Ok(false);
    }
    let spec = admin::users::Spec {
        user_name: None,
        email: Some(person.email.to_owned()),
        email_verified: Some(true),
        enabled: Some(true),
        given_name: person.given_name.map(str::to_owned),
        family_name: person.family_name.map(str::to_owned),
        phone: person.phone.map(str::to_owned),
        required_actions: None,
        attributes: person
            .attributes
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    };
    let born = admin::users::create(
        transaction,
        provider,
        tenant,
        realm_id,
        PROVISIONER,
        person.user_name,
        &spec,
    )
    .await
    .map_err(|_| StoreError::Backend)?;
    // Provisioned numbers are the operator's own, so they count as verified.
    // Reached by the identifier the birth answered, which a name no longer is.
    if person.phone.is_some() {
        let mut user = users::load(transaction, &born.user_id)
            .await?
            .ok_or(StoreError::Backend)?;
        user.phone_number_verified = Some(true);
        users::update(transaction, &user).await?;
    }
    admin::users::set_password(
        transaction,
        provider,
        tenant,
        realm_id,
        PROVISIONER,
        person.user_name,
        person.password,
    )
    .await
    .map_err(|_| StoreError::Backend)?;
    Ok(true)
}
