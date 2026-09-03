
#[allow(unused_imports)]
use super::support;
use std::process::ExitCode;

use actix_web::{App, HttpServer, test};
use models::entities::authz::AdminAction;
use saffui::cli::{AdminCmd, PlaneArgs, Shown, run};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use super::support::Plane;

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        // The CLI client is named to the plane the way an operator names it
        // in the serve configuration: its tokens carry its own id as both
        // audience and party.
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![
                support::AUDIENCE.to_owned(),
                support::CONFIDENTIAL.to_owned(),
            ],
            parties: vec![support::PARTY.to_owned(), support::CONFIDENTIAL.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

/// Run one CLI command against the live plane and hand back what it printed.
fn commanded(server: &str, command: &AdminCmd) -> (ExitCode, Value) {
    let plane = PlaneArgs {
        server: Some(server.to_owned()),
        realm: Some(REALM.to_owned()),
        client: Some(support::CONFIDENTIAL.to_owned()),
        secret: Some(support::CLIENT_SECRET.to_owned()),
        context: None,
        // Spelled, so the answer does not depend on where the test's stdout
        // happens to land.
        format: Some(Shown::Json),
    };
    let mut printed = Vec::new();
    let code = run(&plane, command, &mut printed);
    let body = serde_json::from_slice(&printed).unwrap_or(Value::Null);
    (code, body)
}

/// The whole operator's day, from a terminal: sign in as the service
/// client, read the realm, turn a key, carry the realm out as a document
/// and land it back beside itself, and be told apart when refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_plane_is_operated_from_a_terminal() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmList,
        AdminAction::RealmExport,
        AdminAction::RealmImport,
        AdminAction::RealmKeysRead,
        AdminAction::RealmKeysWrite,
        AdminAction::FeatureRead,
        AdminAction::ClientRead,
    ])
    .await;

    // The commands authenticate as the client itself, so the capabilities
    // must sit on its service account, the way an operator grants them.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::roles::grant_to_user(
            &transaction,
            &format!("service-account-{}", support::CONFIDENTIAL),
            "admins",
        )
        .await
        .unwrap();
        // The plane's scope, attached as always-carried: what lets a machine
        // grant that never asks at a login still arrive entitled. The world
        // may already hold the row; the attachment is what this test adds.
        if store::providers::client_scopes::load_scope(&transaction, support::SCOPE)
            .await
            .unwrap()
            .is_none()
        {
            plant_admin_scope(&transaction).await;
        }
        store::providers::client_scopes::attach_scope(
            &transaction,
            support::CONFIDENTIAL,
            support::SCOPE,
            false,
        )
        .await
        .unwrap();
        transaction.commit().await.unwrap();
    }

    #[allow(dead_code)]
    async fn plant_admin_scope(transaction: &deadpool_postgres::Transaction<'_>) {
        store::providers::client_scopes::create_scope(
            transaction,
            &models::entities::client::ClientScopeModel {
                client_scope_id: support::SCOPE.to_owned(),
                realm_id: REALM.to_owned(),
                name: support::SCOPE.to_owned(),
                description: String::new(),
                protocol: models::entities::client::Protocol::OpenId,
                default_scope: Some(false),
                configs: None,
                metadata: models::auditable::AuditableModel::from_creator(
                    support::TENANT.to_owned(),
                    "test".to_owned(),
                ),
            },
        )
        .await
        .unwrap();
    }

    let served = mounted(&plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let server = HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(server);
    let base = format!("http://127.0.0.1:{port}");

    // Blocking calls, parked off the runtime the server answers on.
    let answered = |command: AdminCmd| {
        let base = base.clone();
        tokio::task::spawn_blocking(move || commanded(&base, &command))
    };

    let (code, told) = answered(AdminCmd::Realms).await.unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(
        told.as_array()
            .into_iter()
            .flatten()
            .chain(told["items"].as_array().into_iter().flatten())
            .any(|realm| realm["realm_id"] == REALM),
        "the realm is not listed: {told}"
    );

    let (code, told) = answered(AdminCmd::Keys).await.unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let before = told["signing"].as_array().expect("a key set").len();

    let (code, minted) = answered(AdminCmd::Rotate {
        algorithm: "RS256".to_owned(),
    })
    .await
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS, "{minted}");
    assert_eq!(minted["algorithm"], "RS256");
    let (_, told) = answered(AdminCmd::Keys).await.unwrap();
    assert_eq!(
        told["signing"].as_array().expect("a key set").len(),
        before + 1,
        "the turn left no successor: {told}"
    );

    let landing = std::env::temp_dir().join(format!("saffui-cli-export-{port}.json"));
    let (code, _) = answered(AdminCmd::Export {
        realm: None,
        out: Some(landing.clone()),
    })
    .await
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let document: Value =
        serde_json::from_str(&std::fs::read_to_string(&landing).expect("the document landed"))
            .expect("a readable document");
    assert_eq!(document["realm"]["realm_id"], REALM);

    let (code, told) = answered(AdminCmd::Import {
        file: landing.clone(),
        landed_as: Some("twin".to_owned()),
    })
    .await
    .unwrap();
    assert_eq!(code, ExitCode::SUCCESS, "{told}");
    assert_eq!(told["realm_id"], "twin");
    let _ = std::fs::remove_file(&landing);

    let (code, told) = answered(AdminCmd::Features).await.unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(told.as_array().expect("a registry").len(), 5);

    // The same answer as a table: a header a person scans, one line per
    // capability, and nothing a JSON parser would want.
    let table_plane = PlaneArgs {
        server: Some(base.clone()),
        realm: Some(REALM.to_owned()),
        client: Some(support::CONFIDENTIAL.to_owned()),
        secret: Some(support::CLIENT_SECRET.to_owned()),
        context: None,
        format: Some(Shown::Table),
    };
    let drawn = tokio::task::spawn_blocking(move || {
        let mut printed = Vec::new();
        let code = run(&table_plane, &AdminCmd::Features, &mut printed);
        (code, String::from_utf8(printed).expect("printable"))
    })
    .await
    .unwrap();
    assert_eq!(drawn.0, ExitCode::SUCCESS);
    assert!(
        drawn.1.starts_with("SLUG") && drawn.1.lines().count() == 6,
        "not a five-row table under its header: {}",
        drawn.1
    );

    // Refusals are told apart in the exit code: what the role does not
    // grant, and what does not exist.
    let (code, _) = answered(AdminCmd::Users).await.unwrap();
    assert_eq!(code, ExitCode::from(4), "user:read was never granted");
    let (code, _) = answered(AdminCmd::Disable {
        kid: "nobody".to_owned(),
    })
    .await
    .unwrap();
    assert_eq!(code, ExitCode::from(5));

    // The wrong secret is an authentication trouble, not a generic one.
    let wrong = PlaneArgs {
        server: Some(base.clone()),
        realm: Some(REALM.to_owned()),
        client: Some(support::CONFIDENTIAL.to_owned()),
        secret: Some("not-it".to_owned()),
        context: None,
        format: Some(Shown::Json),
    };
    let code = tokio::task::spawn_blocking(move || {
        let mut sink = Vec::new();
        run(&wrong, &AdminCmd::Realms, &mut sink)
    })
    .await
    .unwrap();
    assert_eq!(code, ExitCode::from(3));

    let _ = test::TestRequest::default();
}
