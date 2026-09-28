#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};

const REALM: &str = support::REALM;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    })))
    .await;
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
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

/// A scope's whole life over the plane: born under a name its protocol owns,
/// renamed only onto free ground, held by a client in either manner, refused
/// deletion while held, and gone once released.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_lives_and_dies_over_the_plane() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");
    let client = support::CONFIDENTIAL;

    // The provisioned world already owns this name, and the write answers for
    // rows the plane did not write.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "profile" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "client.scope.already_exists");

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "employment", "description": "where a person works" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let scope_id = born["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    assert_eq!(born["protocol"], "openid-connect", "the resting protocol");

    // The same word means something else to another protocol, and may exist.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "employment", "protocol": "docker" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let docker_id = told["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();

    // A name that could never ride the scope parameter is refused.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "two words" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(
        told.as_array()
            .expect("a listing")
            .iter()
            .filter(|scope| scope["name"] == "employment")
            .count(),
        2,
        "both protocols' scopes are listed: {told}"
    );

    // A rename may not land on ground its protocol already holds.
    let (status, second) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "clearance" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{second}");
    let second_id = second["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{second_id}"),
        &bearer,
        Some(json!({ "name": "employment" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // Keeping its own name is not a collision with itself.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{second_id}"),
        &bearer,
        Some(json!({ "name": "clearance", "description": "renamed onto itself" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["description"], "renamed onto itself");
    assert!(
        told["metadata"]["version"].as_i64().unwrap_or(1) > 1,
        "the rewrite left no trace: {told}"
    );

    // Held as required first, then corrected to optional: one attachment,
    // whose manner the second call rewrites.
    let held = format!("/admin/realms/{REALM}/clients/{client}/scopes");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{held}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, told) = asked(&plane, Method::GET, &held, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let mine = |told: &Value| {
        told.as_array()
            .expect("attachments")
            .iter()
            .find(|scope| scope["name"] == "employment")
            .cloned()
            .expect("the attached scope")
    };
    let count_before = told.as_array().expect("attachments").len();
    assert_eq!(mine(&told)["optional"], false);
    assert!(
        told.as_array()
            .expect("attachments")
            .iter()
            .any(|scope| scope["name"] == "profile"),
        "the provisioned attachment is listed beside the new one: {told}"
    );
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{held}/{scope_id}"),
        &bearer,
        Some(json!({ "optional": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (_, told) = asked(&plane, Method::GET, &held, &bearer, None).await;
    assert_eq!(
        told.as_array().expect("attachments").len(),
        count_before,
        "the second attachment corrected the first rather than adding: {told}"
    );
    assert_eq!(mine(&told)["optional"], true);

    // Each absent end is named as itself.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/clients/nobody/scopes/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "client.not_found");
    let (status, told) = asked(&plane, Method::PUT, &format!("{held}/none"), &bearer, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "client.scope.not_found");

    let (status, usage) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{scope_id}/usage?max=1&count=true"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{usage}");
    assert_eq!(usage["total"], 1);
    assert_eq!(usage["items"][0]["kind"], "client");
    assert_eq!(usage["items"][0]["client_id"], client);

    // Deletion is told no while a client holds the scope.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");
    assert_eq!(told["error_code"], "directory.still_granted");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{held}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    // An attachment that was never made is missing, not silently confirmed.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{held}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("{base}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (status, _) = asked(
        &plane,
        Method::GET,
        &format!("{base}/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    for leftover in [second_id, docker_id] {
        let (status, _) = asked(
            &plane,
            Method::DELETE,
            &format!("{base}/{leftover}"),
            &bearer,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
}

/// Reading the catalogue does not grant writing it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_scope_capabilities_split_where_they_should() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");

    let (status, told) = asked(&plane, Method::GET, &base, &bearer, None).await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let (status, _) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "anything" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = asked(
        &plane,
        Method::PUT,
        &format!(
            "/admin/realms/{REALM}/clients/{}/scopes/anything",
            support::CONFIDENTIAL
        ),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// What the catalogue calls a default reaches every client registered after
/// it, attached as required; the rest of the standard set stays optional, and
/// a custom scope nobody marked default reaches nobody by itself.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_new_client_carries_the_catalogue_defaults() {
    use actix_web::{App, test};
    use server::api::config::register;
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    plane
        .allow_registration(models::entities::realm::ClientRegistration::Open, None)
        .await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");

    for (name, default) in [("employment", true), ("clearance", false)] {
        let (status, told) = asked(
            &plane,
            Method::POST,
            &base,
            &bearer,
            Some(json!({ "name": name, "default_scope": default })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
    }

    let registered = |body: Value| {
        let plane = &plane;
        async move {
            let app =
                test::init_service(App::new().configure(register(&server::api::config::Plane {
                    tenancy: plane.tenancy(),
                    policy: server::middleware::admin_policy::AdminPolicy {
                        audiences: vec![support::AUDIENCE.to_owned()],
                        parties: vec![support::PARTY.to_owned()],
                        scope: support::SCOPE.to_owned(),
                    },
                    origin: support::origin(),
                    login_ui: support::login_ui(),
                    hops: config::proxying::Proxying::none(),
                    egress: config::serving::Egress::Outward,
                    sealing: support::sealing(),
                    ceiling: support::ceiling(),
                })))
                .await;
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri(&format!("/realms/{REALM}/protocol/openid-connect/register"))
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::CREATED);
            let told: Value = test::read_body_json(response).await;
            told["client_id"].as_str().expect("an identity").to_owned()
        }
    };

    let newcomer = registered(json!({
        "client_name": "a fresh application",
        "redirect_uris": ["https://fresh.example/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }))
    .await;

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/clients/{newcomer}/scopes"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    let manner = |name: &str| {
        held.as_array()
            .expect("attachments")
            .iter()
            .find(|scope| scope["name"] == name)
            .map(|scope| scope["optional"].as_bool().expect("a manner"))
    };
    for offered in [
        "profile",
        "email",
        "employment",
        "phone",
        "address",
        "offline_access",
    ] {
        assert_eq!(manner(offered), Some(true), "{offered} waits to be asked");
    }
    assert_eq!(
        manner("clearance"),
        None,
        "an unmarked scope reached a client"
    );

    // Offered is not granted: a request naming less gets exactly what it
    // named, and one naming the admin's default gets it like any other.
    let transaction = plane
        .scoped(&store::tenancy::TenantContext::new(support::TENANT, REALM))
        .await;
    assert_eq!(
        services::oidc::authorize::granted_scope(&transaction, &newcomer, "openid email")
            .await
            .unwrap(),
        "openid email",
        "a scope merely offered was granted unasked"
    );
    assert_eq!(
        services::oidc::authorize::granted_scope(&transaction, &newcomer, "openid employment")
            .await
            .unwrap(),
        "openid employment"
    );
    drop(transaction);

    // The flag is read live: unmade after, a default stops reaching the next
    // client, and the one already registered keeps what it was given.
    let employment_id = {
        let (_, listed) = asked(&plane, Method::GET, &base, &bearer, None).await;
        listed
            .as_array()
            .expect("a listing")
            .iter()
            .find(|scope| scope["name"] == "employment")
            .and_then(|scope| scope["client_scope_id"].as_str())
            .expect("the employment scope")
            .to_owned()
    };
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/{employment_id}"),
        &bearer,
        Some(json!({ "name": "employment", "default_scope": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    let second = registered(json!({
        "client_name": "a later application",
        "redirect_uris": ["https://later.example/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }))
    .await;
    let (_, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/clients/{second}/scopes"),
        &bearer,
        None,
    )
    .await;
    assert!(
        held.as_array()
            .expect("attachments")
            .iter()
            .all(|scope| scope["name"] != "employment"),
        "an unmade default still reached the next client: {held}"
    );
}

/// A new client takes the standard scope that holds its name, even one an
/// operator made again under a drawn identifier.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_new_client_takes_the_standard_scope_holding_its_name() {
    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{base}/profile"),
        &bearer,
        Some(json!({ "name": "profile-before" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "profile" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    let (status, made) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/clients"),
        &bearer,
        Some(json!({ "client_id": "newcomer", "redirect_uris": ["https://newcomer.example/cb"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{made}");
    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{REALM}/clients/newcomer/scopes"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    let names: Vec<&str> = held
        .as_array()
        .expect("attachments")
        .iter()
        .filter_map(|scope| scope["name"].as_str())
        .collect();
    assert!(
        names.contains(&"profile") && !names.contains(&"profile-before"),
        "{held}"
    );
}

/// A scope of another protocol held by an OpenID Connect client is no part of
/// what `/authorize` grants it: neither named by the request nor carried as a
/// required attachment.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_of_another_protocol_is_no_part_of_an_openid_grant() {
    let plane = Plane::with_actions(&[]).await;
    {
        let transaction = plane
            .scoped(&store::tenancy::TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::clients::client_scopes::create_scope(
            &transaction,
            &models::entities::client::ClientScopeModel {
                client_scope_id: "registry".to_owned(),
                realm_id: REALM.to_owned(),
                name: "registry".to_owned(),
                description: String::new(),
                protocol: models::entities::client::Protocol::Docker,
                default_scope: Some(false),
                configs: None,
                metadata: models::auditable::AuditableModel::from_creator(
                    support::TENANT.to_owned(),
                    "test".to_owned(),
                ),
            },
        )
        .await
        .expect("a docker scope");
        store::providers::clients::client_scopes::attach_scope(
            &transaction,
            support::CONFIDENTIAL,
            "registry",
            false,
        )
        .await
        .expect("the docker scope held as required");
        transaction.commit().await.expect("the attachment kept");
    }

    let granted = support::granted_scope_of(
        &plane,
        &[
            ("client_id", support::CONFIDENTIAL),
            ("response_type", "code"),
            ("redirect_uri", "https://app.example/callback"),
            ("scope", "openid registry"),
            ("state", "s"),
        ],
    )
    .await;
    let held: Vec<&str> = granted.split_whitespace().collect();
    assert!(held.contains(&"openid"), "{granted}");
    assert!(held.contains(&"profile"), "{granted}");
    assert!(
        !held.contains(&"registry"),
        "a docker scope was granted: {granted}"
    );
}

/// What still reads a scope is named to a caller who may read it: its clients
/// under the capability this route costs, its authorization policies only to a
/// caller who also holds uma:read, and counted for any other, so a refused
/// deletion still says why. Pages are bounded, and an absent scope is named.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_scope_s_policies_are_named_only_to_who_may_read_them() {
    use models::auditable::AuditableModel;
    use models::entities::authz::RoleMutationModel;
    use store::providers::directory::roles;
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::ClientRead, AdminAction::ClientWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("/admin/realms/{REALM}/client-scopes");
    let client = support::CONFIDENTIAL;

    let (status, born) = asked(
        &plane,
        Method::POST,
        &base,
        &bearer,
        Some(json!({ "name": "clearance" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let scope_id = born["client_scope_id"]
        .as_str()
        .expect("an identity")
        .to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/clients/{client}/scopes/{scope_id}"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, REALM))
            .await;
        transaction
            .execute(
                "INSERT INTO resource_servers (tenant, realm_id, server_id) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[&support::TENANT, &REALM, &client],
            )
            .await
            .unwrap();
        let rule = json!({ "policy_type": "client-scope", "client_scopes": [scope_id] });
        transaction
            .execute(
                "INSERT INTO policies \
                     (tenant, realm_id, server_id, policy_id, name, policy_type, rule, \
                      policy_owner) \
                 VALUES ($1, $2, $3, 'needs-clearance', 'Needs clearance', 'client-scope', \
                         $4, $3)",
                &[&support::TENANT, &REALM, &client, &rule],
            )
            .await
            .unwrap();
        transaction
            .execute(
                "INSERT INTO policies_client_scopes \
                     (tenant, realm_id, server_id, policy_id, policy_type, client_scope_id) \
                 VALUES ($1, $2, $3, 'needs-clearance', 'client-scope', $4)",
                &[&support::TENANT, &REALM, &client, &scope_id],
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }

    let usage = format!("{base}/{scope_id}/usage");
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{usage}?count=true"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["total"], 1, "{told}");
    assert_eq!(told["items"].as_array().map(Vec::len), Some(1), "{told}");
    assert_eq!(told["items"][0]["kind"], "client");
    assert_eq!(
        told["withheld_policies"], 1,
        "a policy holding the scope went unsaid: {told}"
    );

    {
        let transaction = plane
            .scoped(&TenantContext::new(support::TENANT, REALM))
            .await;
        let role = RoleMutationModel {
            name: "policy-readers".into(),
            display_name: "Policy readers".into(),
            description: String::new(),
            client_id: None,
            admin_actions: Some(vec![AdminAction::UmaRead]),
        }
        .into_model(
            "policy-readers".into(),
            REALM.into(),
            AuditableModel::from_creator(support::TENANT.to_owned(), "root".to_owned()),
        );
        roles::create(&transaction, &role).await.unwrap();
        roles::grant_to_user(&transaction, support::SUBJECT, "policy-readers")
            .await
            .unwrap();
        transaction.commit().await.unwrap();
    }
    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{usage}?count=true"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["total"], 2, "{told}");
    assert_eq!(told["withheld_policies"], 0, "{told}");
    assert_eq!(told["items"][1]["kind"], "policy", "{told}");
    assert_eq!(told["items"][1]["server_id"], client);
    assert_eq!(told["items"][1]["policy_id"], "needs-clearance");
    assert_eq!(told["items"][1]["name"], "Needs clearance");

    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{usage}?first=1&max=1"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["items"].as_array().map(Vec::len), Some(1), "{told}");
    assert_eq!(
        told["items"][0]["kind"], "policy",
        "the second page is not the second entry: {told}"
    );

    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("{base}/nobody/usage"),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "client.scope.not_found");
}
