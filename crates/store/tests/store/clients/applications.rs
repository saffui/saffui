//! What the database itself refuses of a client, and of a request that
//! waits for one, whatever the product writes: the rules of applications
//! hold for a write from anywhere.

use pgcore::APP_ROLE;
use pgcore::pool::PoolSettings;
use pgcore::testkit::TestDatabase;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::{Client, ClientAuthMethod, KeptProof};
use saffui_core::ids::mint_id;
use saffui_core::oidc::code::PendingAuthorization;
use saffui_core::oidc::response::{ResponseMode, ResponseType};
use saffui_core::ports::storage::StorageError;
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::create_realm;
use time::Duration;
use tokio_postgres::error::SqlState;
use uuid::Uuid;

use crate::support;

/// Runs `update`, which names the row `id` as `$1`, as the owner of the
/// schema under `scope`, and rolls it back. Returns the rule that refused
/// it, or nothing when the row took it.
async fn update_as_owner(
    database: &TestDatabase,
    scope: RealmScope,
    update: &str,
    id: Uuid,
) -> Option<String> {
    let mut owner = database
        .plan("saffui_owner")
        .connect_directly()
        .await
        .expect("a connection");
    let writing = owner.transaction().await.expect("a transaction");
    writing
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    let changed = writing.execute(update, &[&id]).await;
    writing.rollback().await.expect("a rollback");
    match changed {
        Ok(rows) => {
            assert_eq!(rows, 1, "{update}: the row is reached");
            None
        }
        Err(refused) => {
            assert_eq!(
                refused.code(),
                Some(&SqlState::CHECK_VIOLATION),
                "{refused}"
            );
            refused
                .as_db_error()
                .and_then(|refused| refused.constraint())
                .map(str::to_owned)
        }
    }
}

#[tokio::test]
async fn an_application_with_a_capability_a_service_without_a_secret_and_a_flow_with_nowhere_to_return_are_refused()
 {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let application = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "webapp".to_owned(),
        name: "Web app".to_owned(),
        auth_method: ClientAuthMethod::None,
        auth_signing_alg: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec!["https://app.example.org/callback".to_owned()],
        response_types: vec![ResponseType::Code],
        post_logout_redirect_uris: vec!["https://app.example.org/goodbye".to_owned()],
        frontchannel_logout_uri: None,
        requires_consent: true,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: false,
        require_pkce: true,
        enabled: true,
        self_registered: false,
        created_at: app.now(),
    };
    let insert = |client: Client| {
        let app = app.clone();
        // A client of the Basic scheme keeps a digest, a public one nothing.
        let digest =
            (client.auth_method == ClientAuthMethod::ClientSecretBasic).then(|| vec![7; 32]);
        async move {
            let proof = KeptProof {
                secret_digest: digest,
                sealed_secret: None,
                jwks: None,
            };
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.insert_client(&client, &proof).await
        }
    };

    assert_eq!(insert(application.clone()).await, Ok(()));
    for refused in [
        Client {
            capabilities: vec![Capability::UserRead],
            ..application.clone()
        },
        Client {
            allows_client_credentials: true,
            ..application.clone()
        },
        Client {
            redirect_uris: Vec::new(),
            ..application.clone()
        },
        Client {
            allows_authorization_code: false,
            ..application.clone()
        },
        Client {
            allows_authorization_code: false,
            allows_client_credentials: true,
            auth_method: ClientAuthMethod::ClientSecretBasic,
            redirect_uris: Vec::new(),
            ..application.clone()
        },
        // A service that would ask people for their consent: it signs nobody in.
        Client {
            allows_authorization_code: false,
            allows_client_credentials: true,
            auth_method: ClientAuthMethod::ClientSecretBasic,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            frontchannel_logout_uri: None,
            ..application.clone()
        },
        // A client registered by anyone is handed back a code alone.
        Client {
            self_registered: true,
            response_types: vec![ResponseType::Code, ResponseType::IdToken],
            ..application.clone()
        },
        Client {
            response_types: Vec::new(),
            ..application.clone()
        },
    ] {
        assert_eq!(
            insert(refused).await,
            Err(StorageError::Failed),
            "a rule of applications is held by the database"
        );
    }
}

/// Only an application that signs people in is loaded in a frame when a
/// session ends: a service has no session to be told of.
#[tokio::test]
async fn a_service_is_given_no_address_to_be_loaded_at_whatever_writes_it() {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let service = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "billing".to_owned(),
        name: "Billing".to_owned(),
        auth_method: ClientAuthMethod::ClientSecretBasic,
        auth_signing_alg: None,
        allows_client_credentials: true,
        allows_authorization_code: false,
        redirect_uris: Vec::new(),
        response_types: vec![ResponseType::Code],
        post_logout_redirect_uris: Vec::new(),
        frontchannel_logout_uri: None,
        requires_consent: false,
        scopes: vec!["invoices:read".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: false,
        require_pkce: true,
        enabled: true,
        self_registered: false,
        created_at: app.now(),
    };
    let insert = |client: Client| {
        let app = app.clone();
        async move {
            let proof = KeptProof {
                secret_digest: Some(vec![7; 32]),
                sealed_secret: None,
                jwks: None,
            };
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.insert_client(&client, &proof).await
        }
    };

    assert_eq!(
        insert(Client {
            frontchannel_logout_uri: Some("https://billing.example.org/out".to_owned()),
            ..service.clone()
        })
        .await,
        Err(StorageError::Failed),
        "a service with an address to be loaded at"
    );
    assert_eq!(insert(service).await, Ok(()), "the same service without");
}

#[tokio::test]
async fn a_client_is_handed_back_six_known_types_at_most_whatever_writes_it() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let application = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "webapp".to_owned(),
        name: "Web app".to_owned(),
        auth_method: ClientAuthMethod::None,
        auth_signing_alg: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec!["https://app.example.org/callback".to_owned()],
        response_types: vec![ResponseType::Code],
        post_logout_redirect_uris: Vec::new(),
        frontchannel_logout_uri: None,
        requires_consent: false,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: false,
        require_pkce: true,
        enabled: true,
        self_registered: false,
        created_at: app.now(),
    };
    let nothing = KeptProof {
        secret_digest: None,
        sealed_secret: None,
        jwks: None,
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_client(&application, &nothing)
        .await
        .expect("an application");
    work.commit().await.expect("a commit");
    let change = |set: &str| {
        let update = format!("UPDATE clients SET {set} WHERE client_row_id = $1");
        let database = &database;
        async move { update_as_owner(database, scope, &update, application.id).await }
    };

    assert_eq!(
        change("response_types = '{code,\"code id_token token\"}'").await,
        None
    );
    for refused in [
        "response_types = '{code,token}'",
        "response_types = '{code,code,code,code,code,code,code}'",
    ] {
        assert_eq!(
            change(refused).await.as_deref(),
            Some("clients_response_types_known"),
            "{refused}"
        );
    }
}

#[tokio::test]
async fn a_waiting_request_asks_a_known_type_in_a_mode_it_may_travel_in_whatever_writes_it() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let pending = PendingAuthorization {
        id: mint_id(&app).expect("an identifier"),
        browser_digest: vec![4; 32],
        client_id: "webapp".to_owned(),
        redirect_uri: "https://app.example.org/callback".to_owned(),
        scopes: vec!["openid".to_owned()],
        state: None,
        nonce: None,
        response_type: ResponseType::Code,
        response_mode: ResponseMode::Query,
        code_challenge: Some("c".repeat(43)),
        expires_at: app.now() + Duration::minutes(10),
        expected_person: None,
        first_factor: None,
        key_proof: None,
        consent_prompted: false,
        consent_session: None,
        claims: None,
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_pending_authorization(&pending)
        .await
        .expect("a pending request");
    work.commit().await.expect("a commit");
    let change = |set: &str| {
        let update = format!("UPDATE authorization_requests SET {set} WHERE request_id = $1");
        let database = &database;
        async move { update_as_owner(database, scope, &update, pending.id).await }
    };

    assert_eq!(change("response_mode = 'form_post'").await, None);
    assert_eq!(
        change("code_challenge = NULL").await,
        None,
        "a code of a client let off is bound to no challenge"
    );
    for (refused, rule) in [
        (
            "response_type = 'code token'",
            "authorization_requests_response_mode_known",
        ),
        (
            "response_type = 'id_token', response_mode = 'fragment'",
            "authorization_requests_challenge_only_for_a_code",
        ),
        (
            "response_type = 'token', response_mode = 'fragment', code_challenge = NULL",
            "authorization_requests_response_type_known",
        ),
    ] {
        assert_eq!(change(refused).await.as_deref(), Some(rule), "{refused}");
    }
}

/// Only a confidential client an administrator made is let off binding its
/// codes to a verifier, whatever writes it, and the role that serves never
/// changes the setting once the client is made.
#[tokio::test]
async fn a_client_is_let_off_its_verifier_when_it_keeps_a_secret_and_was_vetted_and_never_after() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let confidential = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "portal".to_owned(),
        name: "Portal".to_owned(),
        auth_method: ClientAuthMethod::ClientSecretBasic,
        auth_signing_alg: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec!["https://app.example.org/callback".to_owned()],
        response_types: vec![ResponseType::Code],
        post_logout_redirect_uris: Vec::new(),
        frontchannel_logout_uri: None,
        requires_consent: false,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
        request_object_signing_alg: None,
        require_signed_request_object: false,
        require_pkce: true,
        enabled: true,
        self_registered: false,
        created_at: app.now(),
    };
    let public = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "spa".to_owned(),
        auth_method: ClientAuthMethod::None,
        ..confidential.clone()
    };
    let registered = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "partner".to_owned(),
        requires_consent: true,
        self_registered: true,
        ..confidential.clone()
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for client in [&confidential, &public, &registered] {
        let proof = KeptProof {
            secret_digest: (!client.is_public()).then(|| vec![7; 32]),
            sealed_secret: None,
            jwks: None,
        };
        work.insert_client(client, &proof).await.expect("a client");
    }
    work.commit().await.expect("a commit");

    for (client, rule) in [
        (&confidential, None),
        (&public, Some("clients_public_require_pkce")),
        (&registered, Some("clients_registered_require_pkce")),
    ] {
        let refused = update_as_owner(
            &database,
            scope,
            "UPDATE clients SET require_pkce = false WHERE client_row_id = $1",
            client.id,
        )
        .await;
        assert_eq!(refused.as_deref(), rule, "{}", client.client_id);
    }

    let mut serving = support::connect(&database, APP_ROLE).await;
    let writing = serving.transaction().await.expect("a transaction");
    writing
        .execute(
            "SELECT set_config('saffui.tenant', $1, true), set_config('saffui.realm', $2, true)",
            &[
                &scope.tenant().as_uuid().to_string(),
                &scope.realm().as_uuid().to_string(),
            ],
        )
        .await
        .expect("the scope");
    assert_eq!(
        writing
            .execute(
                "UPDATE clients SET capabilities = capabilities WHERE client_row_id = $1",
                &[&confidential.id],
            )
            .await
            .expect("a column the role may change"),
        1,
        "the row is reached"
    );
    let changed = writing
        .execute(
            "UPDATE clients SET require_pkce = false WHERE client_row_id = $1",
            &[&confidential.id],
        )
        .await
        .expect_err("a change of the setting");
    assert_eq!(
        changed.code(),
        Some(&SqlState::INSUFFICIENT_PRIVILEGE),
        "the serving role changes no setting of a verifier: {changed}"
    );
}
