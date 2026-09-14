#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use serde_json::{Value, json};
use server::api::config::{Plane as Mounted, register};

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
        ceiling: support::ceiling(),
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
        AdminAction::IgaWrite,
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
                    .insert_header((
                        "cookie",
                        format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
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
    let (status, cookies, location, spent_state) = crossing(cookie.clone()).await;
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
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
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

    // An upstream token that does assert something person-shaped is kept
    // whole as this person's aggregated claim source, replaced on each
    // arrival: carried as the upstream's word, never restated.
    let cookie = opened_login(&plane).await;
    {
        let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
        let state = param(&location, "state").expect("a state");
        let nonce = param(&location, "nonce").expect("a nonce");
        let challenge = param(&location, "code_challenge").expect("a challenge");
        let code = plane
            .mint_code_claimed(
                support::CONFIDENTIAL,
                &format!(
                    "{}/protocol/openid-connect/broker/{ALIAS}/endpoint",
                    support::origin().issuer(REALM)
                ),
                "openid profile",
                Some((&challenge, "S256")),
                &nonce,
                Some(json!({ "id_token": { "given_name": null } })),
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
                .insert_header((
                    "cookie",
                    format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let sources = store::providers::brokering::claim_sources_of(&transaction, &linked)
            .await
            .unwrap();
        assert_eq!(sources.len(), 1, "one source per provider per person");
        let kept = &sources[0];
        assert_eq!(kept.source_id, format!("idp-{ALIAS}-{linked}"));
        assert_eq!(kept.claims, vec!["given_name".to_owned()]);
        assert!(
            kept.jwt
                .as_deref()
                .is_some_and(|jwt| jwt.split('.').count() == 3),
            "the upstream's own compact document is what is kept"
        );
    }

    // A forced rule that would hand the person the other half of a separation
    // withholds that role, not the sign-in: the arrival still lands.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(json!({ "name": "keeper" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let keeper = told["role_id"].as_str().expect("an identity").to_owned();
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{REALM}/iga/sod/rules/custody"),
        &bearer,
        Some(json!({ "roles": [role_id, keeper] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &rules,
        &bearer,
        Some(
            json!({ "name": "hold-keeper", "mapper_type": "oidc-hardcoded-role-idp-mapper",
                     "configs": { "role": { "Str": keeper }, "syncMode": { "Str": "force" } } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let cookie = opened_login(&plane).await;
    let (status, _, _, _) = crossing(cookie).await;
    assert_eq!(
        status,
        StatusCode::SEE_OTHER,
        "a withheld role refused the sign-in"
    );
    let held: Vec<String> = {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::roles::effective_roles(&transaction, &linked)
            .await
            .unwrap()
            .into_iter()
            .map(|role| role.role_id)
            .collect()
    };
    assert!(held.contains(&role_id), "the first half was taken away");
    assert!(
        !held.contains(&keeper),
        "a mapper handed over the other half of a separation"
    );
}

/// An upstream logout reaches down: the provider posts its logout token at
/// the broker's own back channel, and every local login the dismissed
/// subject stood behind through that provider ends, this realm's own
/// downstream clients told in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_upstream_logout_reaches_down() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());

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

    // The upstream client is registered to be told of logouts, which is
    // what makes the upstream's own machinery mint a token to carry over.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let mut client = store::providers::clients::load(&transaction, support::CONFIDENTIAL)
            .await
            .unwrap()
            .expect("the client");
        client.backchannel_logout_uri = Some("https://nowhere.example/bye".to_owned());
        assert!(
            store::providers::clients::update(&transaction, &client)
                .await
                .unwrap()
        );
        transaction.commit().await.unwrap();
    }

    // One brokered login, so somebody local stands behind the upstream.
    let cookie = opened_login(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
    let state = param(&location, "state").expect("a state");
    let nonce = param(&location, "nonce").expect("a nonce");
    let challenge = param(&location, "code_challenge").expect("a challenge");
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
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    async fn standing(plane: &Plane) -> Vec<String> {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::sessions::brokered(&transaction, ALIAS, support::SUBJECT)
            .await
            .unwrap()
    }
    assert_eq!(standing(&plane).await.len(), 1, "one login stands behind");

    // The logout token, minted by the upstream's own logout machinery for
    // the client the broker is: real issuer, real key, real audience. Each
    // call mints a fresh one, fresh jti included.
    async fn minted_logout(plane: &Plane) -> String {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let sealing = support::sealing();
        let ring = store::keyring::load(&transaction, &sealing.envelope, support::TENANT, REALM)
            .await
            .expect("the realm's ring");
        let signing = services::grant::Signing {
            provider: sealing.provider.as_ref(),
            ring: &ring,
            envelope: &sealing.envelope,
        };
        let notices = services::logout::notices_for(
            &transaction,
            &signing,
            &support::origin().issuer(REALM),
            support::SESSION,
            chrono::Utc::now(),
        )
        .await;
        transaction.commit().await.unwrap();
        notices
            .into_iter()
            .find(|notice| notice.client_id == support::CONFIDENTIAL)
            .expect("the upstream minted a notice for the broker client")
            .logout_token
    }
    let logout_token = minted_logout(&plane).await;

    // Garbage is refused the same flat way; the real token lands.
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/backchannel-logout"
            ))
            .set_form([("logout_token", "not.a.token")])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/nowhere/backchannel-logout"
            ))
            .set_form([("logout_token", logout_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/backchannel-logout"
            ))
            .set_form([("logout_token", logout_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        standing(&plane).await.is_empty(),
        "the dismissed subject still stands behind the upstream"
    );

    // The same token again is a replay, and a replay is refused with the
    // same face as a bad token.
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/backchannel-logout"
            ))
            .set_form([("logout_token", logout_token.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // A fresh telling of the same fact closes nobody and is still not an
    // error: the state it asks for is the state that holds.
    let fresh = minted_logout(&plane).await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/backchannel-logout"
            ))
            .set_form([("logout_token", fresh.as_str())])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// A first arrival the store cannot write is answered as unavailable, not as
/// a refusal the person would take for their own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_first_arrival_the_store_cannot_write_is_not_refused() {
    let plane = Plane::with_actions(&[AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
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

    let cookie = opened_login(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
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
    let state = param(&location, "state").expect("a state");
    let nonce = param(&location, "nonce").expect("a nonce");
    let challenge = param(&location, "code_challenge").expect("a challenge");
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

    // The account table refuses the application its write, the way a store
    // that cannot take one would.
    let (owner, connection) = support::owner()
        .connect(tokio_postgres::NoTls)
        .await
        .expect("the owner");
    tokio::spawn(connection);
    owner
        .batch_execute("REVOKE INSERT ON users FROM saffui_app")
        .await
        .expect("the write withheld");

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{ALIAS}/endpoint?code={}&state={}",
                support::urlencode(&code),
                support::urlencode(&state),
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// A provider speaking plain OAuth 2.0: this very world, told to answer who
/// arrived through its account API rather than an identity token.
async fn plain_provider(plane: &Plane, bearer: &str, alias: &str, base: &str, extra: Value) {
    let mut configs = json!({
        "protocol": { "Str": "oauth2" },
        "authorization_endpoint": { "Str": format!("{base}/auth") },
        "token_endpoint": { "Str": format!("{base}/token") },
        "userinfo_endpoint": { "Str": format!("{base}/userinfo") },
        "client_id": { "Str": support::CONFIDENTIAL },
        "client_secret": { "Str": support::CLIENT_SECRET },
        "scope": { "Str": "openid" },
        "subject_pointer": { "Str": "/sub" },
        "username_pointer": { "Str": "/preferred_username" },
        "email_pointer": { "Str": "/email" },
    });
    for (key, value) in extra.as_object().expect("extra configs") {
        configs[key] = value.clone();
    }
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        bearer,
        Some(json!({
            "provider_id": alias,
            "name": alias,
            "display_name": alias,
            "description": "",
            "trust_email": true,
            "configs": configs,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
}

/// This world, answering on a real socket for the broker's own dials.
fn served_upstream(plane: &Plane) -> String {
    let served = mounted(plane);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let upstream = actix_web::HttpServer::new(move || App::new().configure(register(&served)))
        .listen(listener)
        .expect("a listener")
        .workers(1)
        .disable_signals()
        .run();
    tokio::spawn(upstream);
    format!("http://127.0.0.1:{port}/realms/{REALM}/protocol/openid-connect")
}

/// One login through a provider: it leaves for the upstream, the upstream's
/// own leg is compressed into a code, and the callback answers. What comes
/// back is the callback's status, where it lands, and where the login left for.
async fn crossed(plane: &Plane, alias: &str) -> (StatusCode, Option<String>, String) {
    let cookie = opened_login(plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{alias}/login"
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned();
    let state = param(&departure, "state").expect("a state");
    let challenge = param(&departure, "code_challenge");
    let code = plane
        .mint_code(
            support::CONFIDENTIAL,
            &format!(
                "{}/protocol/openid-connect/broker/{alias}/endpoint",
                support::origin().issuer(REALM)
            ),
            "openid",
            challenge.as_deref().map(|held| (held, "S256")),
        )
        .await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{alias}/endpoint?code={}&state={}",
                support::urlencode(&code),
                support::urlencode(&state),
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    let landing = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .map(str::to_owned);
    (response.status(), landing, departure)
}

/// A plain OAuth 2.0 upstream gives no identity token: the login leaves with
/// no nonce, the broker asks the account API with the access token, and the
/// person arrives under the provider's stable subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_crosses_a_plain_oauth2_upstream_and_comes_back_admitted() {
    use store::tenancy::TenantContext;
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = served_upstream(&plane);

    // The same upstream twice: with the defaults, then with the secret posted
    // in the form and no PKCE, the way some providers want it.
    for (alias, tuned, challenged) in [
        ("plain", json!({}), true),
        (
            "posted",
            json!({
                "token_auth": { "Str": "client_secret_post" },
                "pkce": { "Str": "false" },
            }),
            false,
        ),
    ] {
        plain_provider(&plane, &bearer, alias, &base, tuned).await;
        let (status, landing, departure) = crossed(&plane, alias).await;
        assert!(
            departure.starts_with(&format!("{base}/auth?")),
            "{departure}"
        );
        assert!(param(&departure, "nonce").is_none(), "{departure}");
        assert_eq!(
            param(&departure, "code_challenge").is_some(),
            challenged,
            "{departure}"
        );
        assert_eq!(status, StatusCode::SEE_OTHER, "{alias}: {landing:?}");
        let landing = landing.expect("a landing");
        assert!(landing.starts_with(support::REDIRECT), "{landing}");
        assert!(param(&landing, "code").is_some(), "{landing}");

        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let linked =
            store::providers::brokering::linked_user(&transaction, alias, support::SUBJECT)
                .await
                .expect("the link table")
                .expect("the arrival was linked under its subject");
        assert_ne!(
            linked,
            support::SUBJECT,
            "{alias}: an untrusted arrival took over the local account"
        );
    }
}

/// An address counts only when the provider's list marks it primary and
/// verified: a verified one links the arrival to the local account holding
/// it, an unverified one does not, whatever the operator trusts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_plain_oauth2_upstream_links_only_by_an_address_its_list_verifies() {
    use store::tenancy::TenantContext;
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = served_upstream(&plane);
    let email = {
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        store::providers::users::load(&transaction, support::SUBJECT)
            .await
            .expect("the account table")
            .expect("the local account")
            .email
    };
    assert!(!email.is_empty(), "the local account holds no address");

    // The provider's list of addresses, one route verifying the address and
    // one not, both refusing a call that brings no access token.
    let listed = email.clone();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let addresses = actix_web::HttpServer::new(move || {
        let listed = listed.clone();
        App::new().route(
            "/emails/{verified}",
            actix_web::web::get().to(
                move |request: actix_web::HttpRequest, verified: actix_web::web::Path<bool>| {
                    let listed = listed.clone();
                    async move {
                        let bearing = request
                            .headers()
                            .get("authorization")
                            .and_then(|held| held.to_str().ok())
                            .is_some_and(|held| held.starts_with("Bearer "));
                        if !bearing {
                            return actix_web::HttpResponse::Unauthorized().finish();
                        }
                        actix_web::HttpResponse::Ok().json(json!([
                            { "email": "someone.else@example.test", "primary": false, "verified": true },
                            { "email": listed, "primary": true, "verified": verified.into_inner() },
                        ]))
                    }
                },
            ),
        )
    })
    .listen(listener)
    .expect("a listener")
    .workers(1)
    .disable_signals()
    .run();
    tokio::spawn(addresses);

    for (alias, verified) in [("listed", true), ("unlisted", false)] {
        plain_provider(
            &plane,
            &bearer,
            alias,
            &base,
            json!({
                "emails_endpoint": { "Str": format!("http://127.0.0.1:{port}/emails/{verified}") },
            }),
        )
        .await;
        let (status, landing, _) = crossed(&plane, alias).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{alias}: {landing:?}");

        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
            .await;
        let linked =
            store::providers::brokering::linked_user(&transaction, alias, support::SUBJECT)
                .await
                .expect("the link table")
                .expect("the arrival was linked");
        assert_eq!(
            linked == support::SUBJECT,
            verified,
            "{alias}: the arrival was linked to the wrong account"
        );
    }
}

/// The door the sign-in page shows for a provider opens where the broker
/// answers: followed from the page this server renders for an open login, with
/// the login's cookie, it leaves for the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_door_on_the_sign_in_page_leaves_for_the_upstream() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = format!("https://upstream.example/realms/{REALM}/protocol/openid-connect");
    plain_provider(&plane, &bearer, ALIAS, &base, json!({})).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;

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
    let binding = format!(
        "{}={}",
        support::AUTH_SESSION_COOKIE,
        support::cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
    );
    let page_path = format!("/realms/{REALM}/protocol/openid-connect/login");

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&page_path)
            .insert_header(("cookie", binding.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    let door = page
        .split(r#"class="idp-door" href=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a door on the page");
    let followed = if door.starts_with('/') {
        door.to_owned()
    } else {
        format!("{}/{door}", page_path.rsplit_once('/').expect("a parent").0)
    };

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&followed)
            .insert_header(("cookie", binding))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the door {door} opens nowhere"
    );
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure");
    assert!(
        departure.starts_with(&format!("{base}/auth?")),
        "{departure}"
    );
}

/// The way back belongs to the browser that left: without that login's cookie,
/// or with another login's, it is refused before anything is spent, and the
/// browser that left then comes back admitted with the same code and state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_way_back_is_refused_in_a_browser_that_did_not_leave() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let base = served_upstream(&plane);
    plain_provider(&plane, &bearer, "plain", &base, json!({})).await;
    let cookie = opened_login(&plane).await;
    let other = opened_login(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/plain/login"
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned();
    let state = param(&departure, "state").expect("a state");
    let challenge = param(&departure, "code_challenge");
    let code = plane
        .mint_code(
            support::CONFIDENTIAL,
            &format!(
                "{}/protocol/openid-connect/broker/plain/endpoint",
                support::origin().issuer(REALM)
            ),
            "openid",
            challenge.as_deref().map(|held| (held, "S256")),
        )
        .await;
    let way_back = format!(
        "/realms/{REALM}/protocol/openid-connect/broker/plain/endpoint?code={}&state={}",
        support::urlencode(&code),
        support::urlencode(&state),
    );

    for presented in [None, Some(other.as_str())] {
        let mut asked = test::TestRequest::get().uri(&way_back);
        if let Some(held) = presented {
            asked =
                asked.insert_header(("cookie", format!("{}={held}", support::AUTH_SESSION_COOKIE)));
        }
        let response = test::call_service(&app, asked.to_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{presented:?}");
    }
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&way_back)
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the refused ways back spent what the browser that left still needed"
    );
}

/// A SAML provider is shown the realm as its service provider at the address its
/// entity identifier names: the same document each time, its consumer and logout
/// under that address, the realm's signing and encryption keys certified in it; a
/// provider that is not SAML, or no provider, is shown nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_saml_provider_is_shown_the_realm_as_its_service_provider() {
    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    plant_saml_provider(&plane, &bearer, "corp").await;
    plain_provider(&plane, &bearer, "plain", "https://upstream.test", json!({})).await;

    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    // The world signs with elliptic keys only, and a realm answers a SAML provider
    // with an RSA key: until it holds one, it cannot describe itself.
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/broker/corp/saml/metadata"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    plane
        .publish_key(&support::SigningKey::generate_rsa("saml-rsa"))
        .await;
    let mut shown = Vec::new();
    for _ in 0..2 {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/realms/{REALM}/broker/corp/saml/metadata"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/samlmetadata+xml")
        );
        let body = test::read_body(response).await;
        shown.push(String::from_utf8(body.to_vec()).expect("UTF-8"));
    }
    assert_eq!(shown[0], shown[1], "the realm described itself two ways");
    let base = format!("{}/broker/corp/saml", support::origin().issuer(REALM));
    for expected in [
        format!(r#"entityID="{base}/metadata""#),
        format!(r#"Location="{base}/acs""#),
        format!(r#"Location="{base}/slo""#),
        r#"use="signing""#.to_owned(),
        r#"use="encryption""#.to_owned(),
    ] {
        assert!(
            shown[0].contains(&expected),
            "{expected} is not in {}",
            shown[0]
        );
    }

    for alias in ["plain", "nobody"] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("/realms/{REALM}/broker/{alias}/saml/metadata"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{alias}");
    }
}

/// Plant a SAML provider through the admin API, trusting a certificate the crypto
/// crate issues for a key it generates, and hand back the key to answer as that
/// provider.
async fn plant_saml_provider(
    plane: &Plane,
    bearer: &str,
    alias: &str,
) -> crypto::jose::jwk::alg::rsa::RsaKeyPair {
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::{PrivateKey, PublicKey};
    use crypto::x509::{Issuance, issue_certificate};

    let key = RsaKeyPair::generate(2048).expect("an RSA key");
    let certificate = issue_certificate(&Issuance {
        subject_key: &PublicKey::from_der(key.to_der_public_key()),
        subject_name: "idp.test",
        issuer_key: &PrivateKey::from_der(key.to_der_private_key()),
        issuer_name: "idp.test",
        serial: &[1],
        not_before: 1_789_372_800,
        not_after: 2_104_992_000,
    })
    .expect("a certificate issued by the crypto crate");
    let idp_metadata = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.test/metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/slo" ResponseLocation="https://idp.test/slo/answers"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#,
        data_encoding::BASE64.encode(&certificate)
    );
    let (status, told) = asked(
        plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/identity-providers"),
        bearer,
        Some(json!({
            "provider_id": alias,
            "name": alias,
            "display_name": alias,
            "description": "",
            "trust_email": false,
            "configs": {
                "protocol": { "Str": "saml" },
                "idp_metadata": { "Str": idp_metadata },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    key
}

/// A login leaves for a SAML provider through the door on the sign-in page: to the
/// provider's sign-on address, carrying an authentication request on a query signed
/// by the key the realm's metadata certifies, and the request is kept for the login
/// that left; a browser with no open login does not leave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_login_leaves_for_a_saml_provider_on_a_request_the_realm_signs() {
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    plant_saml_provider(&plane, &bearer, "corp").await;
    plane
        .publish_key(&support::SigningKey::generate_rsa("saml-rsa"))
        .await;
    let cookie = opened_login(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let door = format!("/realms/{REALM}/protocol/openid-connect/broker/corp/login");

    let response = test::call_service(&app, test::TestRequest::get().uri(&door).to_request()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&door)
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned();
    let (address, query) = departure.split_once('?').expect("a query");
    assert_eq!(address, "https://idp.test/sso");
    let received =
        saml::redirect::decode_query(query, saml::xml::Limits::MESSAGE).expect("a Redirect query");

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/broker/corp/saml/metadata"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let metadata = String::from_utf8(test::read_body(response).await.to_vec()).expect("UTF-8");
    let certified = metadata
        .split(r#"use="signing""#)
        .nth(1)
        .and_then(|rest| rest.split("<ds:X509Certificate>").nth(1))
        .and_then(|rest| rest.split("</ds:X509Certificate>").next())
        .expect("a signing certificate");
    let key = crypto::x509::public_key_of(
        &data_encoding::BASE64
            .decode(certified.as_bytes())
            .expect("base64"),
    )
    .expect("a certified key");
    let signature = received.signature.as_ref().expect("a signed query");
    assert_eq!(
        saml::redirect::verify_query_signature(
            support::sealing().provider.as_ref(),
            signature,
            &[key]
        ),
        Ok(())
    );

    let document = saml::xml::read_message(&received.message, saml::xml::Limits::MESSAGE)
        .expect("well-formed");
    let request_id = document
        .root_element()
        .attribute("ID")
        .expect("an identifier")
        .to_owned();
    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let kept: Vec<(String, String, String)> = transaction
        .query(
            "SELECT request_id, provider_alias, auth_session FROM saml_login_requests",
            &[],
        )
        .await
        .expect("a census")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(kept, [(request_id, "corp".to_owned(), cookie)]);
}

/// What the SAML identity provider at `https://idp.test/metadata` answers a request
/// with when its assertion carries the note alone.
fn answer_saml_request(
    key: &crypto::jose::jwk::alg::rsa::RsaKeyPair,
    alias: &str,
    request_id: &str,
    name: &str,
) -> String {
    answer_saml_request_carrying(key, alias, request_id, name, &[])
}

/// What the SAML identity provider at `https://idp.test/metadata` answers a request
/// with: a success naming `name` persistently, its assertion addressed to the
/// realm's entity for `alias`, confirmed for that provider's consumer and this
/// request for five minutes, carrying a note long enough to outgrow the form ceiling
/// a framework picks by default and each of `attributes` with its values, signed
/// with `key`, and encoded as the POST binding carries it. The assertion is named
/// after the request, so no two answers carry the same one.
fn answer_saml_request_carrying(
    key: &crypto::jose::jwk::alg::rsa::RsaKeyPair,
    alias: &str,
    request_id: &str,
    name: &str,
    attributes: &[(&str, &[&str])],
) -> String {
    use crypto::jose::jwk::KeyPair;
    use crypto::provider::{PrivateKey, SignAlg};

    let base = format!("{}/broker/{alias}/saml", support::origin().issuer(REALM));
    let instant = |offset: i64| {
        (chrono::Utc::now() + chrono::Duration::seconds(offset))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    let (now, closing) = (instant(0), instant(300));
    let note = "n".repeat(24 * 1024);
    let assertion_id = format!("{request_id}-assertion");
    let carried: String = attributes
        .iter()
        .map(|(attribute, values)| {
            let values: String = values
                .iter()
                .map(|value| format!("<saml:AttributeValue>{value}</saml:AttributeValue>"))
                .collect();
            format!(r#"<saml:Attribute Name="{attribute}">{values}</saml:Attribute>"#)
        })
        .collect();
    let response = format!(
        r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="{now}" Destination="{base}/acs" InResponseTo="{request_id}"><saml:Issuer>https://idp.test/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{now}"><saml:Issuer>https://idp.test/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">{name}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="{closing}" Recipient="{base}/acs" InResponseTo="{request_id}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="{now}" NotOnOrAfter="{closing}"><saml:AudienceRestriction><saml:Audience>{base}/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="{now}" SessionIndex="_session-at-idp"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="note"><saml:AttributeValue>{note}</saml:AttributeValue></saml:Attribute>{carried}</saml:AttributeStatement></saml:Assertion></samlp:Response>"#
    );
    let sealing = support::sealing();
    let private = PrivateKey::from_der(key.to_der_private_key());
    let sign = |octets: &[u8]| {
        sealing
            .provider
            .signer()
            .sign(SignAlg::Rs256, &private, octets)
            .ok()
    };
    let signed = saml::dsig::sign_enveloped(
        sealing.provider.as_ref(),
        &response,
        &assertion_id,
        SignAlg::Rs256,
        &sign,
    )
    .expect("the assertion signed");
    data_encoding::BASE64.encode(signed.as_bytes())
}

/// A SAML provider's signed answer admits the login that left for it. The
/// provider's post, which a browser sends without the login's Lax cookie, is posted
/// once more from this origin to the consumer alone; an answer signed with another
/// key, the second post still without the cookie, and a post from another browser
/// are refused without spending the request. The login then lands with its session,
/// the person is linked by the persistent name, what the provider named the login by
/// is kept, and the same answer posted again is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_saml_answer_admits_the_login_that_left_for_it() {
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use store::tenancy::TenantContext;

    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let identity_provider = plant_saml_provider(&plane, &bearer, "corp").await;
    plane
        .publish_key(&support::SigningKey::generate_rsa("saml-rsa"))
        .await;
    let cookie = opened_login(&plane).await;
    let other = opened_login(&plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/corp/login"
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned();
    let (_, query) = departure.split_once('?').expect("a query");
    let received =
        saml::redirect::decode_query(query, saml::xml::Limits::MESSAGE).expect("a Redirect query");
    let request_id = saml::xml::read_message(&received.message, saml::xml::Limits::MESSAGE)
        .expect("well-formed")
        .root_element()
        .attribute("ID")
        .expect("an identifier")
        .to_owned();

    let consumer = format!("/realms/{REALM}/broker/corp/saml/acs");
    let posted = |answer: &str, bounced: bool, presented: Option<&str>| {
        let mut fields = vec![("SAMLResponse", answer.to_owned())];
        if bounced {
            fields.push(("bounced", "1".to_owned()));
        }
        let mut asked = test::TestRequest::post().uri(&consumer).set_form(fields);
        if let Some(held) = presented {
            asked =
                asked.insert_header(("cookie", format!("{}={held}", support::AUTH_SESSION_COOKIE)));
        }
        asked.to_request()
    };
    let answer = answer_saml_request(&identity_provider, "corp", &request_id, "AAdzZWNyZXQx");
    let forged = answer_saml_request(
        &RsaKeyPair::generate(2048).expect("another RSA key"),
        "corp",
        &request_id,
        "AAdzZWNyZXQx",
    );

    let response = test::call_service(&app, posted(&answer, false, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let absolute = format!("{}/broker/corp/saml/acs", support::origin().issuer(REALM));
    let policy = response
        .headers()
        .get("content-security-policy")
        .and_then(|held| held.to_str().ok())
        .expect("a policy")
        .to_owned();
    assert!(
        policy.contains(&format!("form-action {absolute};")),
        "{policy}"
    );
    let page = String::from_utf8(test::read_body(response).await.to_vec()).expect("UTF-8");
    assert!(page.contains(&format!(r#"action="{absolute}""#)), "{page}");
    assert!(
        page.contains(&format!(
            r#"<input type="hidden" name="SAMLResponse" value="{answer}">"#
        )),
        "{page}"
    );
    assert!(
        page.contains(r#"<input type="hidden" name="bounced" value="1">"#),
        "{page}"
    );

    for (sent, presented) in [
        (forged.as_str(), Some(cookie.as_str())),
        (answer.as_str(), None),
        (answer.as_str(), Some(other.as_str())),
    ] {
        let response = test::call_service(&app, posted(sent, true, presented)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{presented:?}");
    }

    let response = test::call_service(&app, posted(&answer, true, Some(&cookie))).await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the refused answers spent what the browser that left still needed"
    );
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
        .expect("a landing")
        .to_owned();
    assert!(location.starts_with(support::REDIRECT), "{location}");
    assert!(param(&location, "code").is_some(), "{location}");
    let session = support::cookie_value(&cookies, "saffui_session")
        .expect("a session cookie")
        .to_owned();

    let response = test::call_service(&app, posted(&answer, true, Some(&cookie))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("/realms/{REALM}/broker/corp/saml/form-post.js"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    assert!(
        store::providers::brokering::linked_user(&transaction, "corp", "AAdzZWNyZXQx")
            .await
            .expect("a read")
            .is_some(),
        "the persistent name was not linked"
    );
    let named = store::providers::saml_brokering::read_broker_session(&transaction, &session)
        .await
        .expect("a read")
        .expect("what the provider named the login by");
    assert_eq!(
        (
            named.provider_alias.as_str(),
            named.name_id.as_str(),
            named.name_id_format.as_deref(),
            named.session_index.as_deref(),
        ),
        (
            "corp",
            "AAdzZWNyZXQx",
            Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"),
            Some("_session-at-idp"),
        )
    );
    let open: i64 = transaction
        .query_one("SELECT count(*) FROM saml_login_requests", &[])
        .await
        .expect("a census")
        .get(0);
    assert_eq!(open, 0);
}

/// Sign in once through the SAML provider at `alias`, which answers for `name` with
/// `attributes`, and say how the realm took the answer.
async fn signed_in_through_saml(
    plane: &Plane,
    key: &crypto::jose::jwk::alg::rsa::RsaKeyPair,
    alias: &str,
    name: &str,
    attributes: &[(&str, &[&str])],
) -> StatusCode {
    let cookie = opened_login(plane).await;
    let app = test::init_service(App::new().configure(register(&mounted(plane)))).await;
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{REALM}/protocol/openid-connect/broker/{alias}/login"
            ))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let departure = response
        .headers()
        .get("location")
        .and_then(|held| held.to_str().ok())
        .expect("a departure")
        .to_owned();
    let (_, query) = departure.split_once('?').expect("a query");
    let received =
        saml::redirect::decode_query(query, saml::xml::Limits::MESSAGE).expect("a Redirect query");
    let request_id = saml::xml::read_message(&received.message, saml::xml::Limits::MESSAGE)
        .expect("well-formed")
        .root_element()
        .attribute("ID")
        .expect("an identifier")
        .to_owned();
    let answer = answer_saml_request_carrying(key, alias, &request_id, name, attributes);
    test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!("/realms/{REALM}/broker/{alias}/saml/acs"))
            .insert_header((
                "cookie",
                format!("{}={cookie}", support::AUTH_SESSION_COOKIE),
            ))
            .set_form(vec![("SAMLResponse", answer), ("bounced", "1".to_owned())])
            .to_request(),
    )
    .await
    .status()
}

/// The attributes, and the roles granted directly, of the person `alias` links
/// `name` to.
async fn read_mapped_person(
    plane: &Plane,
    alias: &str,
    name: &str,
) -> (models::entities::attributes::AttributesMap, Vec<String>) {
    use store::tenancy::TenantContext;

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    let user_id = store::providers::brokering::linked_user(&transaction, alias, name)
        .await
        .expect("a read")
        .expect("a linked person");
    let person = store::providers::users::load(&transaction, &user_id)
        .await
        .expect("a read")
        .expect("the person");
    let roles = store::providers::roles::direct_roles_of(&transaction, &user_id)
        .await
        .expect("a read");
    (person.attributes.unwrap_or_default(), roles)
}

/// A SAML provider's rules act on what its assertions carry. The plane refuses a
/// claim rule for the provider, a SAML rule reworked into one, and a role rule
/// naming a role nobody made. At the first sign-in an attribute is written, one marked
/// multivalued as a list, and a role is granted while the provider asserts its
/// value; at the next, a rule written once keeps what it wrote, while the forced
/// rules rewrite their attribute, still a list for a single value, and withdraw
/// the role no longer asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_saml_provider_s_rules_follow_what_its_assertions_carry() {
    use models::entities::attributes::AttributeValue;

    let plane = Plane::with_actions(&[
        AdminAction::IdpRead,
        AdminAction::IdpWrite,
        AdminAction::RoleWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let identity_provider = plant_saml_provider(&plane, &bearer, "corp").await;
    plane
        .publish_key(&support::SigningKey::generate_rsa("saml-rsa"))
        .await;
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{REALM}/roles"),
        &bearer,
        Some(json!({ "name": "staff" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{told}");
    let staff = told["role_id"].as_str().expect("an identity").to_owned();

    let rules = format!("/admin/realms/{REALM}/identity-providers/corp/mappers");
    let mut written = Vec::new();
    for rule in [
        json!({ "name": "carry-department", "mapper_type": "saml-user-attribute-idp-mapper",
                "configs": { "attribute.name": { "Str": "department" },
                             "user.attribute": { "Str": "department" } } }),
        json!({ "name": "carry-groups", "mapper_type": "saml-user-attribute-idp-mapper",
                "configs": { "attribute.name": { "Str": "memberOf" },
                             "user.attribute": { "Str": "groups" },
                             "multivalued": { "Str": "true" },
                             "syncMode": { "Str": "force" } } }),
        json!({ "name": "staff-while-member", "mapper_type": "saml-role-idp-mapper",
                "configs": { "attribute.name": { "Str": "memberOf" },
                             "attribute.value": { "Str": "staff" },
                             "role": { "Str": staff },
                             "syncMode": { "Str": "force" } } }),
    ] {
        let (status, told) = asked(&plane, Method::POST, &rules, &bearer, Some(rule)).await;
        assert_eq!(status, StatusCode::CREATED, "{told}");
        written.push(told["mapper_id"].as_str().expect("an identity").to_owned());
    }
    for (method, path, rule, holds) in [
        (
            Method::POST,
            rules.clone(),
            json!({ "name": "carry-acr", "mapper_type": "oidc-user-attribute-idp-mapper",
                    "configs": { "claim": { "Str": "acr" },
                                 "user.attribute": { "Str": "upstream.acr" } } }),
            "not claims",
        ),
        (
            Method::PUT,
            format!("{rules}/{}", written[0]),
            json!({ "name": "carry-department", "mapper_type": "oidc-user-attribute-idp-mapper",
                    "configs": { "claim": { "Str": "department" },
                                 "user.attribute": { "Str": "department" } } }),
            "not claims",
        ),
        (
            Method::POST,
            rules.clone(),
            json!({ "name": "nobody-while-member", "mapper_type": "saml-role-idp-mapper",
                    "configs": { "attribute.name": { "Str": "memberOf" },
                                 "attribute.value": { "Str": "staff" },
                                 "role": { "Str": "nobody" } } }),
            "no role answers to nobody",
        ),
    ] {
        let (status, told) = asked(&plane, method, &path, &bearer, Some(rule)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|why| why.contains(holds)),
            "the refusal does not say {holds}: {told}"
        );
    }

    assert_eq!(
        signed_in_through_saml(
            &plane,
            &identity_provider,
            "corp",
            "AAdzZWNyZXQx",
            &[
                ("department", &["Research"][..]),
                ("memberOf", &["staff", "readers"][..]),
            ],
        )
        .await,
        StatusCode::SEE_OTHER
    );
    let (attributes, roles) = read_mapped_person(&plane, "corp", "AAdzZWNyZXQx").await;
    assert_eq!(
        (attributes.get("department"), attributes.get("groups")),
        (
            Some(&AttributeValue::Str("Research".into())),
            Some(&AttributeValue::ListStr(vec![
                "staff".into(),
                "readers".into()
            ])),
        )
    );
    assert!(roles.contains(&staff), "{roles:?}");

    assert_eq!(
        signed_in_through_saml(
            &plane,
            &identity_provider,
            "corp",
            "AAdzZWNyZXQx",
            &[
                ("department", &["Sales"][..]),
                ("memberOf", &["readers"][..]),
            ],
        )
        .await,
        StatusCode::SEE_OTHER
    );
    let (attributes, roles) = read_mapped_person(&plane, "corp", "AAdzZWNyZXQx").await;
    assert_eq!(
        (attributes.get("department"), attributes.get("groups")),
        (
            Some(&AttributeValue::Str("Research".into())),
            Some(&AttributeValue::ListStr(vec!["readers".into()])),
        )
    );
    assert!(!roles.contains(&staff), "{roles:?}");
}

/// A logout request the SAML identity provider at `https://idp.test/metadata` writes
/// for `name` under `id`, addressed to the realm's logout address for `alias`.
fn write_idp_logout_request(alias: &str, id: &str, name: &str) -> String {
    let destination = format!(
        "{}/broker/{alias}/saml/slo",
        support::origin().issuer(REALM)
    );
    saml::logout::write_logout_request(&saml::logout::LogoutRequest {
        id,
        issue_instant: chrono::Utc::now().timestamp(),
        destination: &destination,
        issuer: "https://idp.test/metadata",
        name_id: &saml::name_id::NameId {
            value: name.to_owned(),
            format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_owned()),
            name_qualifier: None,
            sp_name_qualifier: None,
        },
        session_index: Some("_session-at-idp"),
    })
    .expect("a logout request")
}

/// `message` on a Redirect query signed with `key`, as a SAML provider sends it.
fn redirect_signed_by(
    key: &crypto::jose::jwk::alg::rsa::RsaKeyPair,
    carried: saml::redirect::Carried,
    message: &str,
    relay_state: Option<&str>,
) -> String {
    use crypto::jose::jwk::KeyPair;
    use crypto::provider::{PrivateKey, SignAlg};

    let sealing = support::sealing();
    let private = PrivateKey::from_der(key.to_der_private_key());
    saml::redirect::encode_query(carried, message, relay_state, SignAlg::Rs256, &|octets| {
        sealing
            .provider
            .signer()
            .sign(SignAlg::Rs256, &private, octets)
            .ok()
    })
    .expect("a query")
}

/// The logins still standing through `alias` under `name`.
async fn read_standing_logins(plane: &Plane, alias: &str, name: &str) -> Vec<String> {
    use store::tenancy::TenantContext;

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(&mut connection, &TenantContext::new(support::TENANT, REALM))
        .await;
    store::providers::saml_brokering::find_named_sessions(&transaction, alias, name, &[])
        .await
        .expect("a read")
}

/// A SAML provider's logout request ends the logins it names and is answered where
/// the provider takes answers. Signed on a Redirect query, it ends the login, and the
/// browser carries back a success the realm signs, naming the request and its relay
/// state; the same request again and one signed with another key are refused. Posted
/// with an enveloped signature, a relay state past what the binding allows is
/// refused without ending anything, and the request then ends the next login.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_saml_provider_s_logout_request_ends_the_logins_it_names() {
    use crypto::jose::jwk::KeyPair;
    use crypto::jose::jwk::alg::rsa::RsaKeyPair;
    use crypto::provider::{PrivateKey, PublicKey, SignAlg};
    use saml::redirect::Carried;

    let plane = Plane::with_actions(&[AdminAction::IdpRead, AdminAction::IdpWrite]).await;
    let bearer = plane.token(&support::claims());
    let identity_provider = plant_saml_provider(&plane, &bearer, "corp").await;
    let realm_key = support::SigningKey::generate_rsa("saml-rsa");
    plane.publish_key(&realm_key).await;
    let realm_public = PublicKey::from_der(
        RsaKeyPair::from_pem(realm_key.private_pem())
            .expect("the realm's RSA key")
            .to_der_public_key(),
    );
    let sealing = support::sealing();
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;
    let logout = format!("/realms/{REALM}/broker/corp/saml/slo");
    let entity = format!(
        "{}/broker/corp/saml/metadata",
        support::origin().issuer(REALM)
    );
    let answer_of = |response: &actix_web::dev::ServiceResponse, request_id: &str| {
        let answered = response
            .headers()
            .get("location")
            .and_then(|held| held.to_str().ok())
            .expect("an answer")
            .to_owned();
        let (address, query) = answered.split_once('?').expect("a query");
        assert_eq!(address, "https://idp.test/slo/answers");
        let received = saml::redirect::decode_query(query, saml::xml::Limits::MESSAGE)
            .expect("a Redirect query");
        let outcome = saml::logout::accept_logout_response(
            sealing.provider.as_ref(),
            saml::logout::Delivered::Redirected(&received),
            &saml::logout::ExpectedLogout {
                issuer: &entity,
                destination: "https://idp.test/slo/answers",
                trusted: std::slice::from_ref(&realm_public),
                now: chrono::Utc::now().timestamp(),
                skew: 180,
            },
            request_id,
        );
        (received.relay_state, outcome)
    };

    assert_eq!(
        signed_in_through_saml(&plane, &identity_provider, "corp", "AAdzZWNyZXQx", &[]).await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        read_standing_logins(&plane, "corp", "AAdzZWNyZXQx")
            .await
            .len(),
        1
    );
    let query = redirect_signed_by(
        &identity_provider,
        Carried::Request,
        &write_idp_logout_request("corp", "_idp-logout-1", "AAdzZWNyZXQx"),
        Some("idp-state"),
    );
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("{logout}?{query}"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        answer_of(&response, "_idp-logout-1"),
        (
            Some("idp-state".to_owned()),
            Ok(saml::logout::LoggedOut::Everywhere)
        )
    );
    assert!(
        read_standing_logins(&plane, "corp", "AAdzZWNyZXQx")
            .await
            .is_empty()
    );

    let foreign = RsaKeyPair::generate(2048).expect("another RSA key");
    for refused in [
        query.clone(),
        redirect_signed_by(
            &foreign,
            Carried::Request,
            &write_idp_logout_request("corp", "_idp-logout-2", "AAdzZWNyZXQx"),
            None,
        ),
    ] {
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!("{logout}?{refused}"))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    assert_eq!(
        signed_in_through_saml(&plane, &identity_provider, "corp", "AAdzZWNyZXQx", &[]).await,
        StatusCode::SEE_OTHER
    );
    let identity_private = PrivateKey::from_der(identity_provider.to_der_private_key());
    let posted = |id: &str, relay_state: String| {
        let signed = saml::dsig::sign_enveloped(
            sealing.provider.as_ref(),
            &write_idp_logout_request("corp", id, "AAdzZWNyZXQx"),
            id,
            SignAlg::Rs256,
            &|octets| {
                sealing
                    .provider
                    .signer()
                    .sign(SignAlg::Rs256, &identity_private, octets)
                    .ok()
            },
        )
        .expect("the logout request signed");
        test::TestRequest::post()
            .uri(&logout)
            .set_form(vec![
                (
                    "SAMLRequest",
                    data_encoding::BASE64.encode(signed.as_bytes()),
                ),
                ("RelayState", relay_state),
            ])
            .to_request()
    };
    let response = test::call_service(&app, posted("_idp-logout-3", "r".repeat(81))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        read_standing_logins(&plane, "corp", "AAdzZWNyZXQx")
            .await
            .len(),
        1
    );
    let response =
        test::call_service(&app, posted("_idp-logout-4", "posted-state".to_owned())).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        answer_of(&response, "_idp-logout-4"),
        (
            Some("posted-state".to_owned()),
            Ok(saml::logout::LoggedOut::Everywhere)
        )
    );
    assert!(
        read_standing_logins(&plane, "corp", "AAdzZWNyZXQx")
            .await
            .is_empty()
    );
}
