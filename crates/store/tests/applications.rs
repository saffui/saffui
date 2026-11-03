//! What the database itself refuses of a client, whatever the product
//! writes: the rules of applications hold for a write from anywhere.

use pgcore::pool::PoolSettings;
use saffui_core::authz::capability::Capability;
use saffui_core::clients::Client;
use saffui_core::ids::mint_id;
use saffui_core::ports::storage::StorageError;
use saffui_core::testkit::fixtures::create_realm;

mod support;

#[tokio::test]
async fn an_application_with_a_capability_a_service_without_a_secret_and_a_flow_with_nowhere_to_return_are_refused()
 {
    let (app, _database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let application = Client {
        id: mint_id(&app).expect("an identifier"),
        client_id: "webapp".to_owned(),
        name: "Web app".to_owned(),
        secret_digest: None,
        allows_client_credentials: false,
        allows_authorization_code: true,
        redirect_uris: vec!["https://app.example.org/callback".to_owned()],
        scopes: vec!["openid".to_owned()],
        capabilities: Vec::new(),
        enabled: true,
        created_at: app.now(),
    };
    let insert = |client: Client| {
        let app = app.clone();
        async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.insert_client(&client).await
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
    ] {
        assert_eq!(
            insert(refused).await,
            Err(StorageError::Failed),
            "a rule of applications is held by the database"
        );
    }
}
