#[allow(unused_imports)]
use super::support;
use super::support::Plane;
use actix_web::http::{Method, StatusCode};
use models::entities::authz::AdminAction;
use serde_json::Value;

/// Ask the plane, with a body or without one.
async fn asked(
    plane: &Plane,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    asked_under(
        plane,
        config::proxying::Proxying::none(),
        method,
        path,
        bearer,
        body,
    )
    .await
}

/// The same, on a plane that stands behind the given proxies.
async fn asked_under(
    plane: &Plane,
    hops: config::proxying::Proxying,
    method: Method,
    path: &str,
    bearer: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops,
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

/// A realm is born ready or not at all: the row, the standard scopes, this
/// deployment's console and a signing key arrive together, a second create
/// is a conflict, and the switches are rewritten in place afterwards.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_birth_hands_back_the_one_way_into_what_it_made() {
    let plane = Plane::with_actions(&[AdminAction::RealmCreate, AdminAction::UserRead]).await;
    let bearer = plane.token(&support::claims());

    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({
            "name": "annex", "display_name": "Annex", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@annex.test" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    let password = born["administrator"]["password"]
        .as_str()
        .expect("the birth handed back a password")
        .to_owned();
    assert!(password.len() >= 40, "a drawn password, not a placeholder");

    // The creator gained nothing. Its token was minted by another realm and
    // still reaches nothing here, which is the whole point of handing a
    // password back rather than letting the maker walk in.
    let (status, _) = asked(
        &plane,
        Method::GET,
        "/admin/realms/annex/users",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let mut connection = plane.connection().await;
    let transaction = plane
        .scoped(
            &mut connection,
            &store::tenancy::TenantContext::new(support::TENANT, "annex"),
        )
        .await;
    let root = store::providers::users::load_by_name(&transaction, "root")
        .await
        .expect("the store answered")
        .expect("the annex holds its administrator");
    assert!(root.enabled, "the drawn administrator is switched off");

    // The password is worth one login: the account carries the instruction to
    // replace it, and the login engine puts that ahead of everything else.
    assert!(
        root.required_actions
            .clone()
            .unwrap_or_default()
            .contains(&models::entities::user::RequiredAction::UpdatePassword),
        "the first login is not made to replace the drawn password: {:?}",
        root.required_actions
    );

    // Only the hash was kept, so what was handed back cannot be read again.
    let stored = store::providers::credentials::load_for_user_of_type(
        &transaction,
        &root.user_id,
        models::entities::credentials::CredentialType::Password,
    )
    .await
    .expect("the store answered");
    let kept = stored.first().expect("a password was stored");
    assert!(
        !kept.secret.expose().contains(&password),
        "the drawn password was kept in the clear"
    );

    // And the account may actually administer the realm it was drawn for.
    let held = store::providers::roles::direct_roles_of(&transaction, &root.user_id)
        .await
        .expect("the store answered");
    assert!(
        held.iter().any(|role| role == "administrator"),
        "the drawn administrator administers nothing: {held:?}"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_is_taken_away_by_the_realm_itself() {
    let plane = Plane::with_actions(&[AdminAction::RealmCreate, AdminAction::RealmDelete]).await;
    let bearer = plane.token(&support::claims());

    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({
            "name": "doomed", "display_name": "Doomed", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@doomed.test" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    // The maker cannot take it away, confirmation or not: that would be a
    // token reaching a realm it was not minted by, which is refused before
    // the handler ever sees the name.
    let (status, _) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/doomed?confirm=doomed",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Its own administrator can, and only by naming it back. The realm is
    // planted rather than born here: a realm the plane made sealed its keys
    // under the server's envelope, and this harness holds another, so a
    // token it signs is one that realm cannot verify.
    plane.plant_realm("condemned").await;
    plane
        .plant_credential_in(
            "condemned",
            &[AdminAction::RealmDelete, AdminAction::RealmRead],
        )
        .await;
    let inside = plane.token(&support::claims_in("condemned"));
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/condemned",
        &inside,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        "/admin/realms/condemned?confirm=condemned",
        &inside,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // And it is gone, which the same token now learns the way any caller
    // learns of a realm that is not there.
    let (status, _) = asked(
        &plane,
        Method::GET,
        "/admin/realms/condemned",
        &inside,
        None,
    )
    .await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_overview_answers_its_numbers_together() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}/overview", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    for named in ["users", "clients", "sessions", "pending_requests"] {
        assert!(told[named].is_i64(), "{named} is not a number: {told}");
    }
    // The provisioned world holds people and a console, so two of these are
    // positive rather than merely present.
    assert!(told["users"].as_i64().unwrap_or(0) > 0, "{told}");
    assert!(told["clients"].as_i64().unwrap_or(0) > 0, "{told}");

    // The reading from the histogram is there in a build that measures, and
    // absent in one that does not, which is what the console reads to decide
    // whether the box appears at all.
    if cfg!(feature = "metrics") {
        assert!(
            told["slow_tail_millis"].is_i64() || told.get("slow_tail_millis").is_none(),
            "the slow tail is neither a number nor absent: {told}"
        );
    } else {
        assert!(told.get("slow_tail_millis").is_none(), "{told}");
    }

    // And it is behind the boundary like everything else.
    let (status, _) = asked(
        &plane,
        Method::GET,
        "/admin/realms/nowhere/overview",
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_tenant_stops_at_the_ceiling_it_set_itself() {
    let plane = Plane::with_actions(&[AdminAction::RealmCreate]).await;
    let bearer = plane.token(&support::claims());

    // A deployment that configured nothing still has a ceiling: fifty, which
    // this world is nowhere near, so the first call goes through and says so.
    let (status, _) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(serde_json::json!({
            "name": "roomy", "display_name": "Roomy", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@roomy.test" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The provisioned world already holds two realms now, so a ceiling of two
    // is reached before the next call rather than by it.
    plane.cap_realms(2).await;
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "overflow", "display_name": "Overflow", "enabled": true,
                "administrator": { "user_name": "root", "email": "root@example.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Raised, the same call goes through: the refusal was the ceiling and
    // not something else about the request.
    plane.cap_realms(3).await;
    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "overflow", "display_name": "Overflow", "enabled": true,
                "administrator": { "user_name": "root", "email": "root@example.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_is_created_ready_and_reshaped_in_place() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmCreate,
        AdminAction::RealmWrite,
        AdminAction::RealmDelete,
        AdminAction::RealmRead,
        AdminAction::ClientRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    // A name that will not survive a URL is refused before anything is made.
    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "no spaces", "display_name": "x", "enabled": true,
                "administrator": { "user_name": "root", "email": "root@example.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "staging", "display_name": "Staging", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@staging.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");
    assert_eq!(born["name"], "staging", "{born}");

    let (status, told) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "staging", "display_name": "Again", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@staging.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{told}");

    // Born ready, read from the store rather than over a door: this token
    // belongs to another realm, and no token administers a realm it did not
    // come from. What is under test is what provisioning wrote.
    {
        use store::tenancy::TenantContext;
        let mut connection = plane.connection().await;
        let transaction = plane
            .scoped(
                &mut connection,
                &TenantContext::new(support::TENANT, "staging"),
            )
            .await;
        let scopes = store::providers::client_scopes::list_scopes(&transaction)
            .await
            .expect("a scope catalogue");
        let names: Vec<&str> = scopes.iter().map(|held| held.name.as_str()).collect();
        for wanted in ["profile", "email", "offline_access", support::SCOPE] {
            assert!(names.contains(&wanted), "{wanted} missing from {names:?}");
        }
        assert!(
            store::providers::clients::load(&transaction, support::PARTY)
                .await
                .expect("a client read")
                .is_some(),
            "the console was not registered in the new realm"
        );
    }

    // And the door itself refuses, which is the same statement from the
    // other side: a realm is created here and administered from its own.
    let (status, _) = asked(
        &plane,
        Method::GET,
        "/admin/realms/staging/client-scopes",
        &bearer,
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the creating token administered the realm it made"
    );

    // Reshaped: the mentioned switches move, the name does not.
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "display_name": "Staging ground",
            "access_token_lifespan": 600,
            "refresh_token_lifespan": 900,
            "session_max_lifespan": 28800,
            "require_pushed_authorization_requests": true,
            "registration_bounds": {
                "max_clients": 5,
                "requires_consent": true,
                "trusted_hosts": ["apps.test"]
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(
        shaped["name"],
        support::REALM,
        "a reshape renamed the realm: {shaped}"
    );
    assert_eq!(shaped["display_name"], "Staging ground", "{shaped}");
    assert_eq!(shaped["access_token_lifespan"], 600, "{shaped}");
    assert_eq!(shaped["refresh_token_lifespan"], 900, "{shaped}");
    assert_eq!(shaped["session_max_lifespan"], 28800, "{shaped}");
    assert_eq!(shaped["require_pushed_authorization_requests"], true);
    assert_eq!(shaped["registration_bounds"]["max_clients"], 5, "{shaped}");

    let (status, read) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}?briefRepresentation=false", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{read}");
    assert_eq!(read["access_token_lifespan"], 600, "{read}");
    assert_eq!(read["display_name"], "Staging ground", "{read}");

    // The OTP policy is bounded by what an authenticator app will honour.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "otp_policy": { "digits": 9, "period": 30 } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "otp_policy": { "digits": 8, "period": 60, "algorithm": "SHA256", "window": 2 }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["otp_policy"]["digits"], 8, "{shaped}");
    assert_eq!(shaped["otp_policy"]["algorithm"], "SHA256", "{shaped}");

    // A reworded mail keeps its link or is refused; sound words round-trip.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "mail_templates": { "magic_link": { "fr": { "subject": "Lien", "body": "sans lien" } } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "mail_templates": {
                "magic_link": { "fr": { "subject": "Votre lien", "body": "Suivez : {{link}}" } }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(
        shaped["mail_templates"]["magic_link"]["fr"]["subject"], "Votre lien",
        "{shaped}"
    );

    // Device pacing is bounded to what a waiting screen can live with.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "device_code_lifespan": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "device_code_lifespan": 300, "device_poll_interval": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["device_code_lifespan"], 300, "{shaped}");
    assert_eq!(shaped["device_poll_interval"], 10, "{shaped}");

    // Backchannel pacing stands on the same footing.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "ciba_expiry": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "ciba_expiry": 120, "ciba_interval": 9 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["ciba_expiry"], 120, "{shaped}");
    assert_eq!(shaped["ciba_interval"], 9, "{shaped}");

    // The key ceremony's shown name is bounded; the subdomain switch rides.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "webauthn_policy": { "rp_name": "x".repeat(65) } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "webauthn_policy": { "rp_name": "Acme Staging", "allow_subdomains": true }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(
        shaped["webauthn_policy"]["rp_name"], "Acme Staging",
        "{shaped}"
    );
    assert_eq!(shaped["webauthn_policy"]["allow_subdomains"], true);

    // The realm's browser binding: a named flow must exist and stand top
    // level; the seeded flow does, a ghost does not, and empty clears.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "browser_flow": "ghost" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "browser_flow": "browser" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["browser_flow"], "browser", "{shaped}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "browser_flow": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(shaped["browser_flow"].is_null(), "{shaped}");

    // The relay test refuses in words when no settings stand, and wants an
    // address that is one.
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{}/mail/test", support::REALM),
        &bearer,
        Some(serde_json::json!({ "to": "nobody" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, told) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{}/mail/test", support::REALM),
        &bearer,
        Some(serde_json::json!({ "to": "someone@acme.test" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");

    // A realm this token did not come from is refused before anything is
    // looked up, so one that does not exist and one that does answer alike.
    // The door cannot be walked to learn which realms the deployment holds,
    // and reshaping what is not yours is certainly not creating it.
    for named in ["nowhere", "staging"] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("/admin/realms/{named}"),
            &bearer,
            Some(serde_json::json!({ "display_name": "ghost" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{named}: {told}");
    }

    // The registration secret is drawn, answered once, and never read back.
    let (status, drawn) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{}/registration-secret", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{drawn}");
    let first = drawn["registration_secret"]
        .as_str()
        .expect("a secret answered once")
        .to_owned();

    let (status, drawn) = asked(
        &plane,
        Method::POST,
        &format!("/admin/realms/{}/registration-secret", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        drawn["registration_secret"].as_str().unwrap(),
        first,
        "a rotation answered the same secret twice"
    );

    let (status, read) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}?briefRepresentation=false", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        read.get("registration_secret").is_none(),
        "the stored secret is serialised: {read}"
    );

    let (status, _) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{}/registration-secret", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // A deletion that names nothing back is refused. Everything keyed under
    // the realm goes with the row, so the confirmation is the last thing
    // standing between a wrong click and a deployment.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Naming a different realm back is not naming this one.
    let (status, told) = asked(
        &plane,
        Method::DELETE,
        &format!("/admin/realms/{}?confirm=somewhere-else", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    // And it is still standing: a refusal that left the realm half removed
    // would be worse than the deletion it refused.
    let (status, still) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}?briefRepresentation=false", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{still}");
    assert_eq!(still["enabled"], true, "{still}");
}

/// A realm speaks over the pages: the accepted words reach the render, and
/// words nothing reads are refused at the door.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_speaks_over_its_pages() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    // The catalogue lists what may be spoken over.
    let (status, keys) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}/page-keys", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{keys}");
    assert!(
        keys["keys"]
            .as_array()
            .expect("a listing")
            .iter()
            .any(|row| row["name"] == "login-title"),
        "{keys}"
    );

    // A key nobody reads, a tongue nobody renders: both refused in words.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "page_overrides": { "en": { "no-such-key": "x" } } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "page_overrides": { "eo": { "login-title": "x" } } })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // Spoken, and the page wears it.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "page_overrides": { "en": { "login-title": "The Acme door" } }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");

    use actix_web::{App, test};
    use server::api::config::register;
    use server::middleware::admin_policy::AdminPolicy;
    let app = test::init_service(App::new().configure(register(&server::api::config::Plane {
        pool: plane.pool(),
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
    let request = test::TestRequest::get()
        .uri(&format!(
            "/realms/{}/protocol/openid-connect/login",
            support::REALM
        ))
        .to_request();
    let response = test::call_service(&app, request).await;
    let body = String::from_utf8(test::read_body(response).await.to_vec()).expect("a page");
    assert!(
        body.contains("The Acme door"),
        "the override missed the render"
    );
    assert!(
        !body.contains("{{"),
        "the rest of the page lost its words: {body}"
    );
}

/// A realm is not switched off from its own console, and the one it is switched
/// off from can switch it back on.
///
/// The resolvers filter on `enabled`, so a disabled realm stops establishing
/// the very token its console runs on, and the next one cannot be minted either
/// because minting goes through that realm's own authorize endpoint. Refusing
/// here rather than making it recoverable is what guarantees the way back:
/// demanding another realm to turn one off means there is one there to turn it
/// on again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_is_not_switched_off_from_its_own_console() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmCreate,
        AdminAction::RealmWrite,
        AdminAction::RealmRead,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let own = format!("/admin/realms/{}", support::REALM);

    // Its own: refused, and told why rather than left to a broken console.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own,
        &bearer,
        Some(serde_json::json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|said| said.contains("another realm")),
        "the refusal did not say where to go: {told}"
    );

    // Everything else about its own realm still writes: the guard is about the
    // one switch, not about the console being unable to edit itself.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own,
        &bearer,
        Some(serde_json::json!({ "display_name": "Still editable", "enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["display_name"], "Still editable", "{told}");

    // Another realm is not switched off from here either, and not because
    // of the guard above: it is refused before the switch is even read. The
    // console that turns a realm off is the one that realm holds.
    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "other", "display_name": "Other", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@other.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    let (status, told) = asked(
        &plane,
        Method::PUT,
        "/admin/realms/other",
        &bearer,
        Some(serde_json::json!({ "enabled": false })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{told}");
}

/// Insisting on https is refused where nothing could ever check it.
///
/// This server never terminates TLS on its HTTP listener, so a request's
/// scheme is a fact only a named proxy can state. A deployment that named no
/// scheme header and no peers would store the setting, show it, and never
/// once consult it. The refusal names what to configure; a deployment that
/// configured it is taken at its word.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn insisting_on_https_needs_a_proxy_that_can_say_the_scheme() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());
    let own = format!("/admin/realms/{}", support::REALM);

    // Nothing configured: the ask is refused and the answer says what to set.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own,
        &bearer,
        Some(serde_json::json!({ "ssl_enforcement": "all" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");
    assert!(
        told["message"]
            .as_str()
            .is_some_and(|said| said.contains("SAFFUI_PROXY_SCHEME_HEADER")),
        "the refusal did not name the configuration: {told}"
    );

    // Configured: the same ask is taken, and turning it back off never needs
    // the proxy at all.
    let behind = config::proxying::Proxying::behind_peers(
        1,
        config::proxying::ProxyHeader::XForwardedFor,
        vec![config::proxying::Peer::parse("127.0.0.1").expect("an address")],
    )
    .saying_the_scheme_in("x-forwarded-proto");
    let (status, told) = asked_under(
        &plane,
        behind,
        Method::PUT,
        &own,
        &bearer,
        Some(serde_json::json!({ "ssl_enforcement": "all" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["ssl_enforcement"], "all", "{told}");

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &own,
        &bearer,
        Some(serde_json::json!({ "ssl_enforcement": "none" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["ssl_enforcement"], "none", "{told}");
}
/// The privacy door only opens on terms the register can honour.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_privacy_door_refuses_terms_it_cannot_honour() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmCreate,
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());
    let (status, born) = asked(
        &plane,
        Method::POST,
        "/admin/realms",
        &bearer,
        Some(
            serde_json::json!({ "name": "doored", "display_name": "Doored", "enabled": true,
            "administrator": { "user_name": "root", "email": "root@doored.test" } }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{born}");

    // A law nobody named cannot be the clock.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "dsar_jurisdiction": "atlantis" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // A law that fixes no window needs the realm to fix one.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "dsar_jurisdiction": "ng" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "dsar_jurisdiction": "ng", "dsar_response_days": 10 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["dsar_jurisdiction"], "ng", "{shaped}");
    assert_eq!(shaped["dsar_response_days"], 10, "{shaped}");

    // Clearing the window from under a windowless law is the same lie told
    // in a second step, and is refused the same way.
    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "dsar_response_days": 0 })),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{told}");

    // The confirmation mail is a realm's to reword, like its siblings.
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "mail_templates": {
                "subject_request": { "fr": { "subject": "Confirmez", "body": "Suivez : {{link}}" } }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");

    // A law with its own clock needs nothing more, and an empty name
    // closes the door.
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "dsar_jurisdiction": "eu", "dsar_response_days": 0 })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["dsar_jurisdiction"], "eu", "{shaped}");
    assert!(shaped["dsar_response_days"].is_null(), "{shaped}");
    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "dsar_jurisdiction": "" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert!(shaped["dsar_jurisdiction"].is_null(), "{shaped}");
}

/// The texting brakes only take shapes the send gate can hold.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_texting_brakes_hold_their_shapes() {
    let plane = Plane::with_actions(&[
        AdminAction::RealmCreate,
        AdminAction::RealmRead,
        AdminAction::RealmWrite,
    ])
    .await;
    let bearer = plane.token(&support::claims());

    for refused in [
        serde_json::json!({ "sms_daily_cap": -1 }),
        serde_json::json!({ "sms_per_number_cap": 0 }),
        serde_json::json!({ "sms_blocked_prefixes": ["22890"] }),
        serde_json::json!({ "sms_blocked_prefixes": ["+abc"] }),
        serde_json::json!({ "sms_templates": { "ussd": { "en": "{{code}}" } } }),
        serde_json::json!({ "sms_templates": { "sms_otp": { "en": "a code with no place for it" } } }),
        serde_json::json!({ "sms_templates": { "ciba_doorbell": { "en": "a doorbell with no way there {{code}}" } } }),
        serde_json::json!({ "sms_templates": { "sms_otp": { "en": format!("{}{}", "x".repeat(155), "{{code}}") } } }),
    ] {
        let (status, told) = asked(
            &plane,
            Method::PUT,
            &format!("/admin/realms/{}", support::REALM),
            &bearer,
            Some(refused.clone()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "accepted: {refused} -> {told}"
        );
    }

    let (status, shaped) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({
            "sms_daily_cap": 100,
            "sms_per_number_cap": 3,
            "sms_blocked_prefixes": ["+88213", "+979"],
            "sms_templates": {
                "sms_otp": { "fr": "Votre code: {{code}}" },
                "ciba_doorbell": { "fr": "On sonne : {{link}}" },
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{shaped}");
    assert_eq!(shaped["sms_daily_cap"], 100, "{shaped}");
    assert_eq!(shaped["sms_per_number_cap"], 3, "{shaped}");
    assert_eq!(shaped["sms_blocked_prefixes"][1], "+979", "{shaped}");
    assert_eq!(
        shaped["sms_templates"]["sms_otp"]["fr"], "Votre code: {{code}}",
        "{shaped}"
    );
}

/// The agent switch round-trips through the plane: turned on, read back on.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_agent_switch_round_trips() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(
        &plane,
        Method::PUT,
        &format!("/admin/realms/{}", support::REALM),
        &bearer,
        Some(serde_json::json!({ "agent_exchange_enabled": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["agent_exchange_enabled"], true, "echo: {told}");

    let (status, held) = asked(
        &plane,
        Method::GET,
        &format!("/admin/realms/{}?briefRepresentation=false", support::REALM),
        &bearer,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{held}");
    assert_eq!(held["agent_exchange_enabled"], true, "read back: {held}");
}
