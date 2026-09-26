#[allow(unused_imports)]
use super::support;
use super::support::{CarrierSays, Plane, StandInCarrier, Textbox, cookie_value, urlencode};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticatorRequirement, ExecutionStep,
};
use models::entities::authz::AdminAction;
use server::api::config::{Plane as Mounted, register};
use std::sync::Arc;
use store::tenancy::TenantContext;

fn mounted(plane: &Plane, textbox: &Textbox, egress: config::serving::Egress) -> Mounted {
    Mounted {
        tenancy: plane.tenancy(),
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress,
        ceiling: support::ceiling(),
        sealing: support::sealing_carrying(
            None,
            Some(Arc::new(textbox.clone()) as Arc<dyn auth::messaging::Texter>),
        ),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

/// One request to the realm's SIM swap settings, and what came back.
async fn asked(
    plane: &Plane,
    bearer: &str,
    method: Method,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(
        plane,
        &Textbox::default(),
        config::serving::Egress::Outward,
    ))))
    .await;
    let mut request = test::TestRequest::default()
        .method(method)
        .uri(&format!("/admin/realms/{}/sim-swap", support::REALM))
        .insert_header(("authorization", format!("Bearer {bearer}")));
    if let Some(body) = body {
        request = request.set_json(body);
    }
    let response = test::call_service(&app, request.to_request()).await;
    let status = response.status();
    let body = test::read_body(response).await;
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

fn wanted() -> serde_json::Value {
    serde_json::json!({
        "client_id": "saffui-at-the-carrier",
        "authorize_url": "https://carrier.example/bc-authorize",
        "token_url": "https://carrier.example/token",
        "check_url": "https://carrier.example/sim-swap/v2/check",
    })
}

/// A process that does not run the experimental guard never asks the
/// carrier, whatever the realm holds, and the settings say it does not run.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_process_that_does_not_run_the_guard_never_asks_the_carrier() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    let carrier = StandInCarrier::saying(CarrierSays::Changed);
    {
        let transaction = plane.scoped(&within()).await;
        let sealing = support::sealing();
        let ring = store::keyring::load(
            &transaction,
            &sealing.envelope,
            support::TENANT,
            support::REALM,
        )
        .await
        .expect("a keyring");
        store::providers::realms::sms::keep(
            &transaction,
            &ring,
            &sealing.envelope,
            &models::entities::sms::SmsSettings {
                url: "https://gateway.example/send".to_owned(),
                sender: "saffui".to_owned(),
                token: None,
            },
        )
        .await
        .expect("the gateway kept");
        let (authorize_url, token_url, check_url) = carrier.endpoints();
        services::admin::sim_swap::write(
            &transaction,
            &ring,
            &sealing.envelope,
            sealing.provider.as_ref(),
            services::admin::sim_swap::Wanted {
                client_id: "saffui-at-the-carrier".to_owned(),
                authorize_url,
                token_url,
                check_url,
                max_age_hours: None,
                when_unanswered: None,
            },
        )
        .await
        .expect("the carrier kept");
        store::providers::directory::users::set_phone(
            &transaction,
            support::SUBJECT,
            Some("+22890123456"),
            true,
        )
        .await
        .expect("the phone kept");
        let step = AuthenticationExecutionMutationModel {
            alias: "sms-otp".to_owned(),
            flow_id: "browser".to_owned(),
            priority: 30,
            step: ExecutionStep::Authenticator {
                authenticator: "sms-otp".to_owned(),
                config_id: None,
            },
            requirement: AuthenticatorRequirement::Required,
        }
        .into_model(
            "browser-sms-otp".to_owned(),
            support::REALM.to_owned(),
            AuditableModel::from_creator(support::TENANT.to_owned(), "test".to_owned()),
        );
        store::providers::realms::auth_flows::create_execution(&transaction, &step)
            .await
            .expect("the step kept");
        transaction.commit().await.expect("the arrangement kept");
    }
    let textbox = Textbox::default();
    let app = test::init_service(App::new().configure(register(&mounted(
        &plane,
        &textbox,
        config::serving::Egress::Anywhere,
    ))))
    .await;
    let opened = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/auth\
                 ?client_id={}&response_type=code&redirect_uri={}&scope=openid&state=s",
                support::REALM,
                support::CONFIDENTIAL,
                urlencode("https://app.example/callback"),
            ))
            .to_request(),
    )
    .await;
    let cookies: Vec<String> = opened
        .headers()
        .get_all("set-cookie")
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    let binding = cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login");
    let answered = test::call_service(
        &app,
        test::TestRequest::post()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/login",
                support::REALM
            ))
            .insert_header((
                "cookie",
                format!("{}={binding}", support::AUTH_SESSION_COOKIE),
            ))
            .set_json(serde_json::json!({
                "username": support::SUBJECT,
                "password": support::PASSWORD,
            }))
            .to_request(),
    )
    .await;
    let told: serde_json::Value = test::read_body_json(answered).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(
        textbox.held().len(),
        1,
        "the code waited on a guard nobody runs"
    );
    assert!(carrier.heard().is_empty(), "the carrier was asked");

    let bearer = plane.token(&support::claims());
    let (status, brief) = asked(&plane, &bearer, Method::GET, None).await;
    assert_eq!(status, StatusCode::OK, "{brief}");
    assert_eq!(brief["running"], false, "{brief}");
}

/// Every setting the carrier could not use is refused in words; the key is
/// drawn once and kept across edits; forgetting forgets it with the rest and
/// the key set goes with it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_settings_are_held_to_what_a_carrier_can_use() {
    let plane = Plane::with_actions(&[AdminAction::RealmRead, AdminAction::RealmWrite]).await;
    let bearer = plane.token(&support::claims());

    let (status, told) = asked(&plane, &bearer, Method::GET, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(told["error_code"], "realm.sim_swap.not_found", "{told}");

    for (field, value, said) in [
        ("client_id", serde_json::json!(" "), "client id"),
        (
            "check_url",
            serde_json::json!("http://carrier.example/check"),
            "https",
        ),
        (
            "token_url",
            serde_json::json!("carrier.example/token"),
            "https",
        ),
        ("max_age_hours", serde_json::json!(0), "2400"),
        ("max_age_hours", serde_json::json!(2401), "2400"),
    ] {
        let mut body = wanted();
        body[field] = value;
        let (status, told) = asked(&plane, &bearer, Method::PUT, Some(body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{field}: {told}");
        assert!(
            told["message"]
                .as_str()
                .is_some_and(|held| held.contains(said)),
            "{field}: refused in other words: {told}"
        );
    }

    let (status, told) = asked(&plane, &bearer, Method::PUT, Some(wanted())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{told}");
    let (_, first) = asked(&plane, &bearer, Method::GET, None).await;
    assert_eq!(first["max_age_hours"], 72, "{first}");
    assert_eq!(first["when_unanswered"], "send", "{first}");
    let mut edited = wanted();
    edited["max_age_hours"] = serde_json::json!(24);
    edited["when_unanswered"] = serde_json::json!("hold");
    asked(&plane, &bearer, Method::PUT, Some(edited)).await;
    let (_, second) = asked(&plane, &bearer, Method::GET, None).await;
    assert_eq!(second["kid"], first["kid"], "an edit drew another key");
    assert_eq!(
        (
            second["max_age_hours"].as_i64(),
            second["when_unanswered"].as_str()
        ),
        (Some(24), Some("hold"))
    );

    let published = || {
        let plane = &plane;
        async move {
            let app = test::init_service(App::new().configure(register(&mounted(
                plane,
                &Textbox::default(),
                config::serving::Egress::Outward,
            ))))
            .await;
            test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!(
                        "/realms/{}/protocol/openid-connect/sim-swap-keys",
                        support::REALM
                    ))
                    .to_request(),
            )
            .await
            .status()
        }
    };
    assert_eq!(published().await, StatusCode::OK);
    let (status, _) = asked(&plane, &bearer, Method::DELETE, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, told) = asked(&plane, &bearer, Method::GET, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{told}");
    assert_eq!(
        published().await,
        StatusCode::NOT_FOUND,
        "the key outlived its settings"
    );
}
