//! What most tests start from: a realm, and a client in it.

use crate::app::App;
use crate::clients::register::{NewServiceClient, register_service_client};
use crate::secret::Secret;
use crate::tenancy::RealmScope;
use crate::tenancy::realm::{NewRealm, provision_first_realm};
use crate::tenancy::resolve::resolve_realm;

/// Creates a realm of that name and returns its scope.
///
/// # Panics
///
/// Panics when the realm cannot be created.
pub async fn create_realm(app: &App, name: &str) -> RealmScope {
    provision_first_realm(
        app,
        NewRealm {
            tenant_name: "Tenant under test",
            realm_name: name,
        },
    )
    .await
    .expect("a realm");
    resolve_realm(app, name)
        .await
        .expect("the realm resolves")
        .1
}

/// Registers a service client in the realm and returns its secret.
///
/// # Panics
///
/// Panics when the client cannot be registered.
pub async fn create_service_client(
    app: &App,
    scope: RealmScope,
    client_id: &str,
    scopes: &[&str],
) -> Secret {
    let scopes: Vec<String> = scopes.iter().map(|scope| (*scope).to_owned()).collect();
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let (_client, secret) = register_service_client(
        app,
        work.as_mut(),
        NewServiceClient {
            client_id,
            name: "A service under test",
            scopes: &scopes,
            capabilities: &[],
        },
    )
    .await
    .expect("a client");
    work.commit().await.expect("a commit");
    secret
}

/// Registers a client that may call the administration plane with these
/// capabilities, and returns a token it was just given.
///
/// # Panics
///
/// Panics when the client cannot be registered or the token granted.
pub async fn create_administrator(
    app: &App,
    realm: &str,
    scope: RealmScope,
    client_id: &str,
    capabilities: &[crate::authz::capability::Capability],
) -> String {
    use crate::oidc::token::{TokenRequest, grant_token};

    let scopes = [crate::authz::admin::ADMIN_SCOPE.to_owned()];
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let wanted = NewServiceClient {
        client_id,
        name: "An administrator under test",
        scopes: &scopes,
        capabilities,
    };
    let (_client, secret) = register_service_client(app, work.as_mut(), wanted)
        .await
        .expect("a client");
    work.commit().await.expect("a commit");
    let request = TokenRequest {
        grant_type: Some("client_credentials"),
        scope: None,
        client_id: Some(client_id),
        client_secret: Some(secret),
        ..TokenRequest::default()
    };
    grant_token(app, realm, request)
        .await
        .expect("a token")
        .access_token
}

/// Creates a person with a password, and an address made from the name.
///
/// # Panics
///
/// Panics when the person cannot be created.
pub async fn create_person(
    app: &App,
    scope: RealmScope,
    username: &str,
    password: &str,
) -> crate::directory::Person {
    use crate::directory::create::{NewPerson, create_person as create};

    let wanted = NewPerson {
        username,
        email: Some(&format!("{username}@example.org")),
        display_name: Some("A person under test"),
        password: Some(Secret::new(password.as_bytes().to_vec())),
        created_by: None,
    };
    create(app, scope, wanted).await.expect("a person")
}

/// As many attributes as a person may have, whose compact JSON is `bytes`
/// long: at `MAX_DOCUMENT_BYTES`, the largest the rules admit.
///
/// # Panics
///
/// Panics for a length they cannot fill.
#[must_use]
pub fn fill_attributes(bytes: usize) -> serde_json::Map<String, serde_json::Value> {
    use crate::claims::rules::MAX_ATTRIBUTES;

    let text = |length: usize| serde_json::Value::String("x".repeat(length));
    let mut attributes: serde_json::Map<String, serde_json::Value> = (0..MAX_ATTRIBUTES)
        .map(|index| (format!("attr-{index:02}"), text(240)))
        .collect();
    let written = serde_json::to_vec(&attributes).expect("JSON").len();
    let short = bytes
        .checked_sub(written)
        .expect("a length 64 attributes reach");
    attributes.insert("attr-00".to_owned(), text(240 + short));
    attributes
}

/// Gives a person `count` roles of the realm, written straight to the
/// storage in one unit of work: more than the use cases would take time for.
///
/// # Panics
///
/// Panics when the storage refuses.
pub async fn grant_many_roles(app: &App, scope: RealmScope, person: uuid::Uuid, count: u32) {
    use crate::authz::grants::{Grant, RoleGrant, RoleHolder};
    use crate::authz::roles::Role;

    let now = app.now();
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for index in 0..count {
        let role = Role {
            id: uuid::Uuid::from_u128(u128::from(index) + 1),
            client_id: None,
            name: format!("role-{index:04}"),
            description: None,
            created_at: now,
        };
        assert_eq!(work.insert_role(&role).await, Ok(true));
        let given = RoleGrant {
            role: role.id,
            holder: RoleHolder::Person(person),
            grant: Grant {
                valid_from: now,
                valid_until: None,
                granted_by: "operator".to_owned(),
                reason: None,
                granted_at: now,
            },
        };
        work.write_role_grant(&given).await.expect("a grant");
    }
    work.commit().await.expect("a commit");
}

/// An application to register.
pub struct Application<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub post_logout_redirect_uri: Option<&'a str>,
    pub public: bool,
    /// Each person is asked before it gets a code in their name.
    pub requires_consent: bool,
}

/// Registers an application allowed the scopes `openid`, `profile`, `email`,
/// `roles` and `offline_access`, and returns its secret unless it is public.
///
/// # Panics
///
/// Panics when the application cannot be registered.
pub async fn register_application(
    app: &App,
    scope: RealmScope,
    wanted: Application<'_>,
) -> Option<Secret> {
    use crate::clients::register::{NewClient, register_client};

    let scopes = ["openid", "profile", "email", "roles", "offline_access"].map(str::to_owned);
    let callbacks = [wanted.redirect_uri.to_owned()];
    let goodbyes: Vec<String> = wanted
        .post_logout_redirect_uri
        .map(str::to_owned)
        .into_iter()
        .collect();
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let (_client, secret) = register_client(
        app,
        work.as_mut(),
        NewClient {
            client_id: wanted.client_id,
            name: wanted.client_id,
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &goodbyes,
            public: wanted.public,
            requires_consent: wanted.requires_consent,
            created_by: None,
        },
    )
    .await
    .expect("an application");
    work.commit().await.expect("a commit");
    secret
}

/// Registers an application that sends people back to `callback`, and
/// returns its secret unless it is public.
///
/// # Panics
///
/// Panics when the application cannot be registered.
pub async fn create_application(
    app: &App,
    scope: RealmScope,
    client_id: &str,
    callback: &str,
    public: bool,
) -> Option<Secret> {
    let wanted = Application {
        client_id,
        redirect_uri: callback,
        post_logout_redirect_uri: None,
        public,
        requires_consent: false,
    };
    register_application(app, scope, wanted).await
}

/// One person going through the authorization endpoint of a client, from the
/// request to the exchange of the code.
pub struct CodeFlow<'a> {
    pub realm: &'a str,
    pub client_id: &'a str,
    pub client_secret: Option<&'a Secret>,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub username: &'a str,
    pub password: &'a str,
}

/// What a browser and an application hold after a whole code flow.
pub struct SignedInApplication {
    pub tokens: crate::oidc::token::TokenResponse,
    pub ticket: crate::login::session::SessionTicket,
    /// The code the exchange spent, for a test that presents it again.
    pub code: String,
}

/// Runs a whole code flow: the authorization request, the sign-in, and the
/// exchange of the code.
///
/// # Panics
///
/// Panics when a step is refused.
pub async fn run_code_flow(app: &App, flow: CodeFlow<'_>) -> SignedInApplication {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::oidc::authorize::{
        Authorization, AuthorizationParameters, SignInAnswer, TypedSignIn, begin_authorization,
        finish_sign_in,
    };
    use crate::oidc::token::{TokenRequest, grant_token};

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    let challenge = URL_SAFE_NO_PAD.encode(app.digester.sha256(VERIFIER.as_bytes()));
    let parameters = AuthorizationParameters {
        response_type: Some("code"),
        client_id: Some(flow.client_id),
        redirect_uri: Some(flow.redirect_uri),
        scope: Some(flow.scope),
        nonce: Some("a-nonce"),
        code_challenge: Some(&challenge),
        code_challenge_method: Some("S256"),
        ..AuthorizationParameters::default()
    };
    let begun = begin_authorization(app, flow.realm, parameters, None)
        .await
        .expect("a pending request");
    let Authorization::SignInRequired {
        request,
        browser_secret,
    } = begun
    else {
        panic!("a person without a session must sign in: {begun:?}");
    };
    let typed = TypedSignIn {
        answer: SignInAnswer::Password {
            name: flow.username,
            password: Secret::new(flow.password.as_bytes().to_vec()),
        },
        caller: None,
        known_browsers: &[],
    };
    let signed_in = finish_sign_in(app, flow.realm, request, &browser_secret, typed)
        .await
        .expect("a signed-in person")
        .into_finished()
        .expect("a person who owes no code");
    let code = signed_in
        .location
        .split_once("code=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("a code in the redirection")
        .to_owned();
    let exchange = TokenRequest {
        grant_type: Some("authorization_code"),
        client_id: Some(flow.client_id),
        client_secret: flow
            .client_secret
            .map(|secret| Secret::new(secret.expose().to_vec())),
        code: Some(&code),
        redirect_uri: Some(flow.redirect_uri),
        code_verifier: Some(VERIFIER),
        ..TokenRequest::default()
    };
    let tokens = grant_token(app, flow.realm, exchange)
        .await
        .expect("tokens for the code");
    SignedInApplication {
        tokens,
        ticket: signed_in.ticket,
        code,
    }
}

/// The code verifier of the consented flows.
const CONSENTED_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

/// Runs a code flow up to its code, in which the client asks the person to
/// consent again (`prompt=consent`) and the person allows it on the page.
/// Returns the code, and the ticket of the session they signed in with.
///
/// # Panics
///
/// Panics when a step is refused.
pub async fn allow_consented_code(
    app: &App,
    flow: &CodeFlow<'_>,
) -> (String, crate::login::session::SessionTicket) {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::consent::answer::{ConsentDecision, answer_consent};
    use crate::oidc::authorize::{
        Authorization, AuthorizationParameters, SignInAnswer, SignInStep, TypedSignIn,
        begin_authorization, finish_sign_in,
    };

    let challenge = URL_SAFE_NO_PAD.encode(app.digester.sha256(CONSENTED_VERIFIER.as_bytes()));
    let parameters = AuthorizationParameters {
        response_type: Some("code"),
        client_id: Some(flow.client_id),
        redirect_uri: Some(flow.redirect_uri),
        scope: Some(flow.scope),
        code_challenge: Some(&challenge),
        code_challenge_method: Some("S256"),
        prompt: Some("consent"),
        ..AuthorizationParameters::default()
    };
    let begun = begin_authorization(app, flow.realm, parameters, None)
        .await
        .expect("a pending request");
    let Authorization::SignInRequired {
        request,
        browser_secret,
    } = begun
    else {
        panic!("a person without a session must sign in: {begun:?}");
    };
    let typed = TypedSignIn {
        answer: SignInAnswer::Password {
            name: flow.username,
            password: Secret::new(flow.password.as_bytes().to_vec()),
        },
        caller: None,
        known_browsers: &[],
    };
    let step = finish_sign_in(app, flow.realm, request, &browser_secret, typed)
        .await
        .expect("a signed-in person");
    let SignInStep::ConsentRequired(signed_in) = step else {
        panic!("asked to consent again, the person answers on the page: {step:?}");
    };
    let location = answer_consent(
        app,
        flow.realm,
        request,
        &browser_secret,
        Some(&signed_in.ticket),
        ConsentDecision::Allow,
    )
    .await
    .expect("an allowed client");
    let code = location
        .split_once("code=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("a code in the redirection")
        .to_owned();
    (code, signed_in.ticket)
}

/// Runs a whole code flow in which the client asks the person to consent
/// again (`prompt=consent`), and the person allows it on the page.
///
/// # Panics
///
/// Panics when a step is refused.
pub async fn run_consented_code_flow(app: &App, flow: CodeFlow<'_>) -> SignedInApplication {
    use crate::oidc::token::{TokenRequest, grant_token};

    let (code, ticket) = allow_consented_code(app, &flow).await;
    let exchange = TokenRequest {
        grant_type: Some("authorization_code"),
        client_id: Some(flow.client_id),
        client_secret: flow
            .client_secret
            .map(|secret| Secret::new(secret.expose().to_vec())),
        code: Some(&code),
        redirect_uri: Some(flow.redirect_uri),
        code_verifier: Some(CONSENTED_VERIFIER),
        ..TokenRequest::default()
    };
    let tokens = grant_token(app, flow.realm, exchange)
        .await
        .expect("tokens for the code");
    SignedInApplication {
        tokens,
        ticket,
        code,
    }
}
