//! What the database itself refuses of a client, and of a request that
//! waits for one, whatever the product writes: the rules of applications
//! hold for a write from anywhere.

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

mod support;

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
        requires_consent: true,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
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
        requires_consent: false,
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        id_token_signed_response_alg: None,
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
    for (refused, rule) in [
        (
            "response_type = 'code token'",
            "authorization_requests_response_mode_known",
        ),
        (
            "code_challenge = NULL",
            "authorization_requests_challenge_for_a_code",
        ),
        (
            "response_type = 'id_token', response_mode = 'fragment'",
            "authorization_requests_challenge_for_a_code",
        ),
        (
            "response_type = 'token', response_mode = 'fragment', code_challenge = NULL",
            "authorization_requests_response_type_known",
        ),
    ] {
        assert_eq!(change(refused).await.as_deref(), Some(rule), "{refused}");
    }
}
