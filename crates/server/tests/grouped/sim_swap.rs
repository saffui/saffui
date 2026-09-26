#[allow(unused_imports)]
use super::support;
use super::support::{
    CarrierHeard, CarrierSays, Plane, StandInCarrier, Textbox, cookie_value, urlencode,
};
use actix_web::http::{Method, StatusCode};
use actix_web::{App, test};
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticatorRequirement, ExecutionStep,
};
use models::entities::authz::AdminAction;
use models::entities::sim_swap::WhenUnanswered;
use models::entities::user::RequiredAction;
use server::api::config::{Plane as Mounted, register};
use std::sync::Arc;
use store::tenancy::TenantContext;

const REDIRECT: &str = "https://app.example/callback";
const PHONE: &str = "+22890123456";
const CLIENT: &str = "saffui-at-the-carrier";

/// The guard is experimental and off unless the process runs it, so this
/// binary turns it on before anything else asks: every case here calls this
/// first, and the first call decides for the whole process.
fn guarded() {
    server::api::config::install_features(
        commons::feature::FeatureSet::resolve("+sim-swap-guard", |_| false)
            .expect("a set that resolves"),
    );
    assert!(
        server::api::config::features().is_enabled(commons::feature::Feature::SimSwapGuard),
        "the process does not run the guard"
    );
}

fn mounted(plane: &Plane, textbox: &Textbox) -> Mounted {
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
        egress: config::serving::Egress::Anywhere,
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

/// A realm that texts, asks this carrier and does `silence` when it says
/// nothing, and a subject whose phone is proven.
async fn arrange(plane: &Plane, carrier: &StandInCarrier, silence: WhenUnanswered) {
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
            client_id: CLIENT.to_owned(),
            authorize_url,
            token_url,
            check_url,
            max_age_hours: None,
            when_unanswered: Some(silence),
        },
    )
    .await
    .expect("the carrier kept");
    store::providers::directory::users::set_phone(
        &transaction,
        support::SUBJECT,
        Some(PHONE),
        true,
    )
    .await
    .expect("the phone kept");
    transaction.commit().await.expect("the arrangement kept");
}

/// Append one step to the browser flow.
async fn add_step(
    plane: &Plane,
    authenticator: &str,
    priority: i32,
    requirement: AuthenticatorRequirement,
) {
    let transaction = plane.scoped(&within()).await;
    let step = AuthenticationExecutionMutationModel {
        alias: authenticator.to_owned(),
        flow_id: "browser".to_owned(),
        priority,
        step: ExecutionStep::Authenticator {
            authenticator: authenticator.to_owned(),
            config_id: None,
        },
        requirement,
    }
    .into_model(
        format!("browser-{authenticator}"),
        support::REALM.to_owned(),
        AuditableModel::from_creator(support::TENANT.to_owned(), "test".to_owned()),
    );
    store::providers::realms::auth_flows::create_execution(&transaction, &step)
        .await
        .expect("the step kept");
    transaction.commit().await.expect("the flow kept");
}

/// A login waiting to be answered.
struct Login<'a> {
    plane: &'a Plane,
    textbox: &'a Textbox,
    binding: String,
}

impl<'a> Login<'a> {
    async fn open(plane: &'a Plane, textbox: &'a Textbox) -> Self {
        let app =
            test::init_service(App::new().configure(register(&mounted(plane, textbox)))).await;
        let response = test::call_service(
            &app,
            test::TestRequest::get()
                .uri(&format!(
                    "/realms/{}/protocol/openid-connect/auth\
                     ?client_id={}&response_type=code&redirect_uri={}&scope=openid&state=s",
                    support::REALM,
                    support::CONFIDENTIAL,
                    urlencode(REDIRECT),
                ))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let cookies: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .filter_map(|value| value.to_str().ok())
            .map(str::to_owned)
            .collect();
        Login {
            plane,
            textbox,
            binding: cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login"),
        }
    }

    /// The credentials, and whatever else this round carries beside them.
    async fn answer(&self, beside: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let mut body =
            serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD });
        if let (Some(body), Some(beside)) = (body.as_object_mut(), beside.as_object()) {
            body.extend(beside.clone());
        }
        let app =
            test::init_service(App::new().configure(register(&mounted(self.plane, self.textbox))))
                .await;
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri(&format!(
                    "/realms/{}/protocol/openid-connect/login",
                    support::REALM
                ))
                .insert_header((
                    "cookie",
                    format!("{}={}", support::AUTH_SESSION_COOKIE, self.binding),
                ))
                .set_json(&body)
                .to_request(),
        )
        .await;
        let status = response.status();
        (status, test::read_body_json(response).await)
    }
}

/// The login events of one kind, as their details.
async fn events(plane: &Plane, kind: &str) -> Vec<serde_json::Value> {
    let transaction = plane.scoped(&within()).await;
    transaction
        .query(
            "SELECT detail FROM login_events WHERE kind = $1 ORDER BY recorded_at",
            &[&kind],
        )
        .await
        .expect("the events")
        .into_iter()
        .map(|row| {
            row.get::<_, Option<serde_json::Value>>(0)
                .unwrap_or_default()
        })
        .collect()
}

/// An assertion the carrier was handed, verified with the key the realm
/// publishes for it, and its claims.
async fn verified(plane: &Plane, heard: &CarrierHeard) -> serde_json::Value {
    let transaction = plane.scoped(&within()).await;
    let public = store::providers::realms::sim_swap::public_key(&transaction)
        .await
        .expect("the settings")
        .expect("a key");
    let key = crypto::jose::jwk::Jwk::from_map(public.as_object().expect("a key").clone())
        .expect("a JWK");
    let verifier = crypto::jose::jws::ES256
        .verifier_from_jwk(&key)
        .expect("a verifier");
    let assertion = heard
        .form()
        .get("client_assertion")
        .cloned()
        .expect("an assertion");
    let (payload, _) = crypto::jose::jwt::decode_with_verifier(&assertion, &verifier)
        .expect("an assertion the realm's key signed");
    serde_json::Value::Object(payload.claims_set().clone())
}

/// An unchanged SIM lets the code go, and the carrier is asked the way CAMARA
/// says: a backchannel request naming the number with one purpose, a token
/// earned for it, the check under that token, and at each endpoint an
/// assertion the realm's key signed for that endpoint alone.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unchanged_sim_lets_the_code_go_after_the_carrier_is_asked_as_camara_says() {
    guarded();
    let plane = Plane::with_actions(&[]).await;
    let carrier = StandInCarrier::saying(CarrierSays::Unchanged);
    arrange(&plane, &carrier, WhenUnanswered::Send).await;
    add_step(&plane, "sms-otp", 30, AuthenticatorRequirement::Required).await;
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["asks"]["code_sent_to"], "\u{2026}56", "{told}");
    assert_eq!(textbox.held().len(), 1, "the code did not go");

    let heard = carrier.heard();
    let paths: Vec<&str> = heard.iter().map(|held| held.path.as_str()).collect();
    assert_eq!(paths, ["/bc-authorize", "/token", "/check"]);
    let (authorize_url, token_url, _) = carrier.endpoints();

    let asked = heard[0].form();
    assert_eq!(
        asked.get("login_hint").map(String::as_str),
        Some("tel:+22890123456")
    );
    assert_eq!(
        asked.get("scope").map(String::as_str),
        Some("openid dpv:FraudPreventionAndDetection sim-swap:check")
    );
    assert_eq!(
        asked.get("client_assertion_type").map(String::as_str),
        Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
    );
    let claims = verified(&plane, &heard[0]).await;
    assert_eq!(
        (claims["iss"].as_str(), claims["sub"].as_str()),
        (Some(CLIENT), Some(CLIENT))
    );
    assert_eq!(claims["aud"], serde_json::json!(authorize_url), "{claims}");
    let lasts =
        claims["exp"].as_i64().unwrap_or_default() - claims["iat"].as_i64().unwrap_or_default();
    assert!(
        (1..=300).contains(&lasts),
        "an assertion standing {lasts} seconds"
    );
    assert!(claims["jti"].as_str().is_some_and(|held| !held.is_empty()));

    let polled = heard[1].form();
    assert_eq!(
        polled.get("grant_type").map(String::as_str),
        Some("urn:openid:params:grant-type:ciba")
    );
    assert_eq!(polled.get("auth_req_id").map(String::as_str), Some("req-1"));
    assert_eq!(
        verified(&plane, &heard[1]).await["aud"],
        serde_json::json!(token_url)
    );

    assert_eq!(
        heard[2].header("authorization").as_deref(),
        Some("Bearer at-1")
    );
    assert!(heard[2].header("x-correlator").is_some());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&heard[2].body).expect("a JSON body"),
        serde_json::json!({ "maxAge": 72 })
    );
}

/// A changed SIM holds the code: nothing goes, the step fails, and with
/// nothing else in the flow the login is refused; the hold is on the record
/// and the drawn code is void.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_changed_sim_holds_the_code_and_a_lone_code_step_refuses_the_login() {
    guarded();
    let plane = Plane::with_actions(&[]).await;
    let carrier = StandInCarrier::saying(CarrierSays::Changed);
    arrange(&plane, &carrier, WhenUnanswered::Send).await;
    add_step(&plane, "sms-otp", 30, AuthenticatorRequirement::Required).await;
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox).await;
    let (status, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused", "{told}");
    assert!(
        textbox.held().is_empty(),
        "a code went to a SIM that changed"
    );
    assert_eq!(
        events(&plane, "sim_swapped").await.len(),
        1,
        "the hold is off the record"
    );

    let transaction = plane.scoped(&within()).await;
    let in_flight: i64 = transaction
        .query_one(
            "SELECT count(*) FROM one_time_tokens WHERE purpose = 'sms-otp'",
            &[],
        )
        .await
        .expect("the codes")
        .get(0);
    assert_eq!(in_flight, 0, "the held code still stands");
    let receipts =
        store::providers::events::deliveries::of_user(&transaction, support::SUBJECT, 10)
            .await
            .expect("the receipts");
    assert_eq!(receipts.len(), 1);
    assert!(!receipts[0].delivered);
    assert!(
        receipts[0]
            .detail
            .as_deref()
            .is_some_and(|held| held.starts_with("held:")),
        "{:?}",
        receipts[0].detail
    );
}

/// Where the flow offers another way in, a changed SIM hands the login to it
/// in the same answer.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_changed_sim_hands_the_login_to_the_other_way_in() {
    guarded();
    let plane = Plane::with_actions(&[]).await;
    let carrier = StandInCarrier::saying(CarrierSays::Changed);
    arrange(&plane, &carrier, WhenUnanswered::Send).await;
    add_step(&plane, "sms-otp", 30, AuthenticatorRequirement::Alternative).await;
    add_step(&plane, "totp", 40, AuthenticatorRequirement::Alternative).await;
    plane.enrol_totp("an-app", "JBSWY3DPEHPK3PXP").await;
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox).await;
    let (status, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(told["execution"], "browser-totp", "{told}");
    assert!(
        told.get("asks").is_none() || told["asks"].get("code_sent_to").is_none(),
        "{told}"
    );
    assert!(
        textbox.held().is_empty(),
        "a code went to a SIM that changed"
    );
}

/// A carrier that says nothing sends where the realm sends on silence, with
/// the silence on the record, and holds where the realm holds.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_silent_carrier_does_what_the_realm_says() {
    guarded();
    let carrier = StandInCarrier::saying(CarrierSays::Nothing);

    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, &carrier, WhenUnanswered::Send).await;
    add_step(&plane, "sms-otp", 30, AuthenticatorRequirement::Required).await;
    let textbox = Textbox::default();
    let login = Login::open(&plane, &textbox).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(
        textbox.held().len(),
        1,
        "silence held a code the realm sends on"
    );
    let noted = events(&plane, "sim_swap_unanswered").await;
    assert_eq!(noted.len(), 1);
    assert_eq!(noted[0]["sent"], true, "{noted:?}");
    drop(plane);

    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, &carrier, WhenUnanswered::Hold).await;
    add_step(&plane, "sms-otp", 30, AuthenticatorRequirement::Required).await;
    let textbox = Textbox::default();
    let login = Login::open(&plane, &textbox).await;
    let (status, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert!(
        textbox.held().is_empty(),
        "silence sent a code the realm holds on"
    );
    assert_eq!(events(&plane, "sim_swap_unanswered").await.len(), 1);
}

/// A carrier not yet ready at its token endpoint is asked again after the
/// interval it named.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_carrier_not_yet_ready_is_asked_again() {
    guarded();
    let plane = Plane::with_actions(&[]).await;
    let carrier = StandInCarrier::saying(CarrierSays::NotYetThenUnchanged);
    arrange(&plane, &carrier, WhenUnanswered::Hold).await;
    add_step(&plane, "sms-otp", 30, AuthenticatorRequirement::Required).await;
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(textbox.held().len(), 1);
    let paths: Vec<String> = carrier.heard().into_iter().map(|held| held.path).collect();
    assert_eq!(paths, ["/bc-authorize", "/token", "/token", "/check"]);
}

/// A phone proven to a SIM that changed is left owed: no code, the login
/// goes on, and the number stays unproven with its proof still asked.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proof_to_a_changed_sim_is_left_owed() {
    guarded();
    let plane = Plane::with_actions(&[]).await;
    let carrier = StandInCarrier::saying(CarrierSays::Changed);
    arrange(&plane, &carrier, WhenUnanswered::Send).await;
    {
        let transaction = plane.scoped(&within()).await;
        let mut subject = store::providers::directory::users::load(&transaction, support::SUBJECT)
            .await
            .expect("the users table")
            .expect("a planted subject");
        subject.required_actions = Some(vec![RequiredAction::VerifyPhone]);
        store::providers::directory::users::update(&transaction, &subject)
            .await
            .expect("the instruction kept");
        store::providers::directory::users::set_phone(
            &transaction,
            support::SUBJECT,
            Some(PHONE),
            false,
        )
        .await
        .expect("the phone unproven");
        transaction.commit().await.expect("the arrangement kept");
    }
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["status"], "admitted", "{told}");
    assert!(
        textbox.held().is_empty(),
        "a proving code went to a SIM that changed"
    );
    let transaction = plane.scoped(&within()).await;
    let subject = store::providers::directory::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("the subject");
    assert_eq!(subject.phone_number_verified, Some(false));
    assert!(
        subject
            .required_actions
            .unwrap_or_default()
            .contains(&RequiredAction::VerifyPhone),
        "the proof was taken as made"
    );
}

/// The settings show the key's public half for the carrier's onboarding and
/// say the guard runs; the same half is published as a key set; the private
/// half is in neither.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_settings_show_the_public_key_and_that_the_guard_runs() {
    guarded();
    let plane = Plane::with_actions(&[AdminAction::RealmRead]).await;
    let carrier = StandInCarrier::saying(CarrierSays::Unchanged);
    arrange(&plane, &carrier, WhenUnanswered::Send).await;
    let bearer = plane.token(&support::claims());
    let app =
        test::init_service(App::new().configure(register(&mounted(&plane, &Textbox::default()))))
            .await;

    let response = test::call_service(
        &app,
        test::TestRequest::default()
            .method(Method::GET)
            .uri(&format!("/admin/realms/{}/sim-swap", support::REALM))
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let brief: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(brief["running"], true, "{brief}");
    assert_eq!(brief["public_jwk"]["crv"], "P-256", "{brief}");
    assert_eq!(brief["public_jwk"]["kid"], brief["kid"], "{brief}");
    assert!(
        brief["public_jwk"].get("d").is_none(),
        "the private half was answered"
    );

    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!(
                "/realms/{}/protocol/openid-connect/sim-swap-keys",
                support::REALM
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let published: serde_json::Value = test::read_body_json(response).await;
    assert_eq!(published["keys"][0]["kid"], brief["kid"], "{published}");
    assert!(
        published["keys"][0].get("d").is_none(),
        "the private half was published"
    );
}
