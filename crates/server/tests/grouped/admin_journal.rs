#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};

const REALM: &str = support::REALM;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        sealing: support::sealing(),
        ceiling: support::ceiling(),
        egress: config::serving::Egress::Outward,
    }
}

async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let mut asking = test::TestRequest::default()
        .method(method)
        .uri(path)
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        asking = asking.set_json(body);
    }
    let response = test::call_service(&app, asking.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

async fn journalled(plane: &Plane, bearer: &str) -> (i64, Value) {
    let (status, told) = asked(
        plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/journal?max=50&count=true"),
        bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    (told["total"].as_i64().expect("a paid count"), told)
}

/// The plane journals itself: an admin write lands in the realm's audit
/// chain with who, what and how it ended; a read lands nowhere; the chain
/// verifies whole; and anchoring publishes the head and is itself an entry.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn what_happens_to_a_realm_outlives_it() {
    let plane = Plane::with_actions(&[AdminAction::RealmCreate, AdminAction::RealmDelete]).await;
    let bearer = plane.token(&support::claims());

    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({
            "name": "ephemeral", "display_name": "Ephemeral", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@ephemeral.test" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    // Its own administrator takes it away, which is the only shape the
    // boundary leaves. Planted rather than born, because a realm the plane
    // made sealed its keys under an envelope this harness does not hold.
    plane.plant_realm("vanishing").await;
    plane
        .plant_credential_in("vanishing", &[AdminAction::RealmDelete])
        .await;
    let inside = plane.token(&support::claims_in("vanishing"));
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/vanishing?confirm=vanishing",
        &inside,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The realm's own chain went with the cascade. The tenant's did not.
    //
    // Read as the owner, because the served role holds no select on this
    // table: that absence is the design, and a test that could read it as
    // `saffui_app` would be testing a plane that leaked its neighbours.
    let (owner, connection) = support::owner()
        .connect(tokio_postgres::NoTls)
        .await
        .expect("the owner");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let rows = owner
        .query(
            "SELECT envelope FROM tenant_events WHERE tenant = $1 ORDER BY seq ASC",
            &[&support::TENANT],
        )
        .await
        .expect("the owner reads the chain");
    let kinds: Vec<(String, String)> = rows
        .iter()
        .map(|row| {
            let envelope: serde_json::Value = row.get("envelope");
            (
                envelope["kind"].as_str().unwrap_or_default().to_owned(),
                envelope["realm"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert!(
        kinds.contains(&("realm.created".to_owned(), "ephemeral".to_owned())),
        "the birth left no trace above the realms: {kinds:?}"
    );
    assert!(
        kinds.contains(&("realm.deleted".to_owned(), "vanishing".to_owned())),
        "a realm vanished without a word anywhere: {kinds:?}"
    );

    // And the served plane genuinely cannot read it, which is what keeps a
    // neighbouring realm's existence as unknowable as the guard makes it.
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &store::tenancy::TenantContext::tenant_wide(support::TENANT),
        )
        .await;
    assert!(
        store::tenant_chain::list_entries(&transaction, 0, 50)
            .await
            .is_err(),
        "the served role can read what happened to other realms"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn making_a_realm_lands_in_the_maker_s_own_chain() {
    let plane = Plane::with_actions(&[AdminAction::RealmCreate, AdminAction::JournalRead]).await;
    let bearer = plane.token(&support::claims());

    let (before, _) = journalled(&plane, &bearer).await;
    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({
            "name": "chronicle", "display_name": "Chronicle", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@chronicle.test" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    // The path names no realm, so nothing could be read off it. The entry
    // belongs to the realm the maker came from, which is where an auditor
    // looks for what this realm's administrators did.
    let (after, told) = journalled(&plane, &bearer).await;
    assert_eq!(
        after,
        before + 1,
        "making a realm left no trace in any chain: {told}"
    );
    let newest = &told["items"].as_array().expect("entries")[0]["entry"];
    assert_eq!(newest["kind"], "admin.write", "{newest}");
    assert_eq!(newest["method"], "POST", "{newest}");
    assert_eq!(newest["status"], 201, "{newest}");
    assert_eq!(newest["path"], "/admin/realms", "{newest}");
    assert_eq!(newest["actor"], support::SUBJECT, "{newest}");
    // The password is never a fact anyone keeps, the journal included.
    let written = serde_json::to_string(newest).expect("an entry renders");
    let password = born["administrator"]["password"]
        .as_str()
        .expect("a password");
    assert!(!written.contains(password), "the journal kept the password");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_plane_journals_its_own_writes() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
        AdminAction::JournalRead,
        AdminAction::JournalWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}");

    // A write worth remembering, and a refused one: both are acts.
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/theme"),
        &bearer,
        Some(serde_json::json!({ "light": { "brand-primary": "#12305e" } })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/theme"),
        &bearer,
        Some(serde_json::json!({ "light": { "made-up": "#fff" } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let (total, told) = journalled(&plane, &bearer).await;
    assert!(total >= 2, "{told}");
    let entries = told["items"].as_array().expect("entries");
    let newest = &entries[0]["entry"];
    assert_eq!(newest["kind"], "admin.write", "{newest}");
    assert_eq!(newest["actor"], support::SUBJECT, "{newest}");
    assert_eq!(newest["method"], "PUT", "{newest}");
    assert_eq!(newest["status"], 422, "{newest}");
    assert!(
        newest["pattern"]
            .as_str()
            .is_some_and(|held| held.ends_with("/theme")),
        "{newest}"
    );
    assert!(
        entries.iter().any(|entry| entry["entry"]["status"] == 204),
        "the accepted write was not journalled: {told}"
    );

    // Reading the journal writes nothing.
    let (unchanged, _) = journalled(&plane, &bearer).await;
    assert_eq!(unchanged, total, "a read grew the journal");

    // The chain verifies whole.
    let (status, verified) = asked(
        &plane,
        Method::GET,
        &format!("{base}/journal/verify"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{verified}");
    assert_eq!(verified["holds"], true, "{verified}");
    assert_eq!(verified["entries"], total, "{verified}");

    // Anchoring publishes the head, remembers where, and is itself an entry.
    let (status, anchored) = asked(
        &plane,
        Method::POST,
        &format!("{base}/journal/anchors"),
        &bearer,
        Some(
            serde_json::json!({ "witness": "https://witness.example/log",
            "receipt": "r-2026-09-02" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{anchored}");
    assert_eq!(anchored["seq"].as_i64(), Some(total), "{anchored}");
    let (status, anchors) = asked(
        &plane,
        Method::GET,
        &format!("{base}/journal/anchors"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{anchors}");
    assert_eq!(
        anchors["anchors"][0]["receipt"], "r-2026-09-02",
        "{anchors}"
    );
    let (grown, _) = journalled(&plane, &bearer).await;
    assert_eq!(grown, total + 1, "the anchoring itself was not journalled");
}

/// Forensic mode: with admin_events_enabled the chain records reads too,
/// spelled admin.read; without it, reads leave no trace, which is the
/// default every realm starts with. Writes land either way.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn reads_land_in_the_chain_only_in_forensic_mode() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
        AdminAction::JournalRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let journal = format!("/admin/realms/{REALM}/journal?first=0&max=50");

    // A read before the switch: nothing lands.
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}?briefRepresentation=false"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, held) = asked(&plane, Method::GET, &journal, &bearer, None).await;
    assert!(
        !held.to_string().contains("admin.read"),
        "a read was journalled before the switch: {held}"
    );

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}"),
        &bearer,
        Some(serde_json::json!({ "admin_events_enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}?briefRepresentation=false"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, held) = asked(&plane, Method::GET, &journal, &bearer, None).await;
    assert!(
        held.to_string().contains("admin.read"),
        "forensic mode did not journal the read: {held}"
    );
}
