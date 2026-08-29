mod support;

use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};
use support::Plane;

const REALM: &str = support::REALM;
const ALIAS: &str = "upstream";

/// The one mount both sides share: the in-process side answers the browser,
/// and the spawned side answers the broker's own dials. Egress is open
/// because the upstream lives on the loopback here.
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
        egress: config::serving::Egress::Anywhere,
        sealing: support::sealing(),
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
    let told = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, told)
}

/// One query value out of a location header.
fn param(location: &str, name: &str) -> Option<String> {
    let (_, query) = location.split_once('?')?;
    query.split('&').find_map(|pair| {
        let (held, value) = pair.split_once('=')?;
        (held == name).then(|| {
            value
                .replace('+', " ")
                .split('%')
                .enumerate()
                .map(|(index, part)| {
                    if index == 0 {
                        part.to_owned()
                    } else if part.len() >= 2 {
                        let byte = u8::from_str_radix(&part[..2], 16).unwrap_or(b'?');
                        format!("{}{}", byte as char, &part[2..])
                    } else {
                        part.to_owned()
                    }
                })
                .collect::<String>()
        })
    })
}

/// Open this realm's own login and hand back its cookie.
async fn opened_login(plane: &Plane) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/auth?client_id={}&redirect_uri={}\
                 &response_type=code&scope=openid&state=s&nonce=n-local",
                support::CONFIDENTIAL,
                support::urlencode(support::REDIRECT),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = response
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE)
        .expect("a login")
        .to_owned()
}

/// The whole road: a login leaves for the upstream, comes back with a code,
/// the broker redeems it server to server against a live listener, verifies
/// the identity token against the upstream's published keys, creates the
/// person on first arrival and finds them again on the second, and the
/// login the browser left open lands admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_crosses_to_the_upstream_and_comes_back_admitted() {
    let plane = Plane::with_actions(&[
        AdminAction::IdpRead,
        AdminAction::IdpWrite,
        AdminAction::RoleWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    // The upstream: this very world, answering on a real socket.
    let served = mounted(&plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let upstream = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(upstream);

    // The provider over the plane: the issuer is what the tokens say, the
    // endpoints are where the listener answers.
    let base = format!("http://127.0.0.1:{port}/realms/{REALM}/protocol/openid-connect");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        &bearer,
        Some(json!({
            "provider_id": ALIAS,
            "name": ALIAS,
            "display_name": "This realm, from outside",
            "description": "",
            "trust_email": false,
            "configs": {
                "issuer": { "Str": support::origin().issuer(REALM) },
                "authorization_endpoint": { "Str": format!("{base}/auth") },
                "token_endpoint": { "Str": format!("{base}/token") },
                "jwks_uri": { "Str": format!("{base}/certs") },
                "client_id": { "Str": support::CONFIDENTIAL },
                "client_secret": { "Str": support::CLIENT_SECRET },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");

    // What the provider's rules will write on arrival: a role to hold and
    // an upstream claim carried onto the person.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(json!({ "name": "arrival" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let role_id = told["role_id"].as_str().expect("an identity").to_owned();
    let rules = format!("/admin/realms/{REALM}/identity-providers/{ALIAS}/mappers");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &rules,
        &bearer,
        Some(
            json!({ "name": "hold-arrival", "mapper_type": "oidc-hardcoded-role-idp-mapper",
                     "configs": { "role": { "Str": role_id } } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let (status, carried) = asked(
        &plane,
        Method::POST,
        &rules,
        &bearer,
        Some(
            json!({ "name": "carry-acr", "mapper_type": "oidc-user-attribute-idp-mapper",
                     "configs": { "claim": { "Str": "acr" },
                                  "user.attribute": { "Str": "upstream.acr" } } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{carried}");
    let carried_id = carried["mapper_id"]
        .as_str()
        .expect("an identity")
        .to_owned();

    let crossing = |cookie: String| {
        let plane = &plane;
        let base = base.clone();
        async move {
            let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!(
                        "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/login"
                    ))
                    .insert_header((
                        "cookie",
                        format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
                    ))
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let location = response
                .headers()
                .get("location")
                .and_then(|held| held.to_str().ok())
                .expect("a departure")
                .to_owned();
            assert!(location.starts_with(&format!("{base}/auth?")), "{location}");
            let state = param(&location, "state").expect("a state");
            let nonce = param(&location, "nonce").expect("a nonce");
            let challenge = param(&location, "code_challenge").expect("a challenge");

            // The upstream's own leg, compressed: a code for this arrival.
            let code = plane
                .mint_code_with_nonce(
                    support::CONFIDENTIAL,
                    &format!(
                        "{}/protocol/openid-connect/broker/{ALIAS}/endpoint",
                        support::origin().issuer(REALM)
                    ),
                    "openid",
                    Some((&challenge, "S256")),
                    &nonce,
                )
                .await;

            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!(
                        "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/endpoint?code={}&state={}",
                        support::urlencode(&code),
                        support::urlencode(&state),
                    ))
                    .to_request(),
            )
            .await;
            let status = response.status();
            let cookies: Vec<String> = response
                .headers()
                .get_all("set-cookie")
                .filter_map(|value| value.to_str().ok())
                .map(str::to_owned)
                .collect();
            let location = response
                .headers()
                .get("location")
                .and_then(|held| held.to_str().ok())
                .map(str::to_owned);
            (status, cookies, location, state)
        }
    };

    let cookie = opened_login(&plane).await;
    let (status, cookies, location, spent_state) = crossing(cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location:?}");
    let location = location.expect("a landing");
    assert!(
        location.starts_with(support::REDIRECT),
        "the login did not land back at its client: {location}"
    );
    assert!(param(&location, "code").is_some(), "{location}");
    assert!(
        support::cookie_value(&cookies, "saffui_session").is_some(),
        "no session cookie was set: {cookies:?}"
    );

    // First arrival made a person and a link.
    let (linked, named) = {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let linked =
            store::providers::brokering::linked_user(&transaction, ALIAS, support::SUBJECT)
                .await
                .unwrap()
                .expect("a link was written");
        let person = store::providers::users::load(&transaction, &linked)
            .await
            .unwrap()
            .expect("the person the link names");
        (linked, person.user_name)
    };
    assert_eq!(named, format!("{ALIAS}-{}", support::SUBJECT));
    {
        use models::entities::attributes::AttributeValue;
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let person = store::providers::users::load(&transaction, &linked)
            .await
            .unwrap()
            .expect("the person");
        assert_eq!(
            person
                .attributes
                .as_ref()
                .and_then(|held| held.get("upstream.acr")),
            Some(&AttributeValue::Str("password".into())),
            "the attribute rule did not write on first arrival"
        );
        assert!(
            store::providers::roles::effective_roles(&transaction, &linked)
                .await
                .unwrap()
                .iter()
                .any(|role| role.role_id == role_id),
            "the role rule did not grant on first arrival"
        );
        // Scrub the carried attribute, so the next crossings show whether a
        // rule writes again.
        let mut person = person;
        person
            .attributes
            .get_or_insert_with(Default::default)
            .insert(
                "upstream.acr".into(),
                AttributeValue::Str("scrubbed".into()),
            );
        assert!(
            store::providers::users::update(&transaction, &person)
                .await
                .unwrap()
        );
        transaction.commit().await.unwrap();
    }

    // A replayed state finds nothing: it was spent on the way through.
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/endpoint?code=again&state={}",
                support::urlencode(&spent_state),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // The second crossing finds the same person rather than making another.
    let cookie = opened_login(&plane).await;
    let (status, _, _, _) = crossing(cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let again = {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::brokering::linked_user(&transaction, ALIAS, support::SUBJECT)
            .await
            .unwrap()
            .expect("the link still stands")
    };
    assert_eq!(again, linked, "a second arrival made a second person");
    let read_back = || async {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::users::load(&transaction, &linked)
            .await
            .unwrap()
            .expect("the person")
            .attributes
            .as_ref()
            .and_then(|held| held.get("upstream.acr"))
            .and_then(models::entities::attributes::AttributeValue::as_str)
            .map(str::to_owned)
    };
    assert_eq!(
        read_back().await.as_deref(),
        Some("scrubbed"),
        "an import rule wrote again for somebody already known"
    );

    // Told to force, the same rule takes the upstream as authoritative on
    // the very next arrival.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("{rules}/{carried_id}"),
        &bearer,
        Some(
            json!({ "name": "carry-acr", "mapper_type": "oidc-user-attribute-idp-mapper",
                     "configs": { "claim": { "Str": "acr" },
                                  "user.attribute": { "Str": "upstream.acr" },
                                  "syncMode": { "Str": "force" } } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let cookie = opened_login(&plane).await;
    let (status, _, _, _) = crossing(cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        read_back().await.as_deref(),
        Some("password"),
        "a forced rule did not take the upstream as authoritative"
    );
}
