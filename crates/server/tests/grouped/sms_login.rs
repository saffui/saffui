#[allow(unused_imports)]
use super::support;
use super::support::{Plane, Textbox, cookie_value, urlencode};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticatorRequirement, ExecutionStep,
};
use models::entities::user::RequiredAction;
use server::api::config::{Plane as Mounted, register};
use std::sync::Arc;
use store::tenancy::TenantContext;

const REDIRECT: &str = "https://app.example/callback";

fn mounted(plane: &Plane, textbox: &Textbox) -> Mounted {
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
        egress: config::serving::Egress::Outward,
        sealing: support::sealing_carrying(
            None,
            Some(Arc::new(textbox.clone()) as Arc<dyn auth::messaging::Texter>),
        ),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

/// A realm that can text, and a subject whose phone is proven.
async fn arrange(plane: &Plane, phone_verified: bool) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let sealing = support::sealing();
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        support::TENANT,
        support::REALM,
    )
    .await
    .expect("a keyring");
    store::providers::sms::keep(
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
    .expect("the settings kept");
    store::providers::users::set_phone(
        &transaction,
        support::SUBJECT,
        Some("+22890123456"),
        phone_verified,
    )
    .await
    .expect("the phone kept");
    transaction.commit().await.expect("the arrangement kept");
}

/// Append a required texted second factor to the browser flow.
async fn require_sms_otp(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
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
    store::providers::auth_flows::create_execution(&transaction, &step)
        .await
        .expect("the step kept");
    transaction.commit().await.expect("the flow kept");
}

/// Tell this person to prove a phone before their next session completes.
async fn require_verify_phone(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut subject = store::providers::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("a planted subject");
    let mut actions = subject.required_actions.unwrap_or_default();
    actions.push(RequiredAction::VerifyPhone);
    subject.required_actions = Some(actions);
    store::providers::users::update(&transaction, &subject)
        .await
        .expect("the instruction kept");
    transaction.commit().await.expect("the instruction kept");
}

async fn open(plane: &Plane, textbox: &Textbox) -> String {
    let app = test::init_service(App::new().configure(register(&mounted(plane, textbox)))).await;
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
    cookie_value(&cookies, support::AUTH_SESSION_COOKIE).expect("a login")
}

async fn answer(
    plane: &Plane,
    textbox: &Textbox,
    binding: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let app = test::init_service(App::new().configure(register(&mounted(plane, textbox)))).await;
    let response = test::call_service(
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
            .set_json(&body)
            .to_request(),
    )
    .await;
    let status = response.status();
    (status, test::read_body_json(response).await)
}

/// The six digits the message carried.
fn code_in(body: &str) -> String {
    let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
    assert_eq!(digits.len(), 6, "not a code-first body: {body}");
    digits
}

/// Age the one live code past the resend cooldown, so the next pass may send
/// again without the test waiting a minute of wall clock.
async fn age_past_cooldown(plane: &Plane, purpose: &str) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    transaction
        .execute(
            "UPDATE one_time_tokens SET created_at = created_at - interval '61 seconds' \
             WHERE purpose = $1",
            &[&purpose],
        )
        .await
        .expect("the clock moved");
    transaction.commit().await.expect("the clock kept");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_texted_code_finishes_a_login_and_is_spent_with_it() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(
        told["asks"]["code_sent_to"], "\u{2026}56",
        "the screen does not name the phone the code went to: {told}"
    );
    let held = textbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].to, "+22890123456");
    let code = code_in(&held[0].body);

    // Typed with the spaces a person copies, which are theirs to get wrong,
    // and beside the credentials: the flow runs every step against what it
    // was given, and a code alone leaves the password step waiting.
    let spaced = format!("{} {}", &code[..3], &code[3..]);
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "sms_otp": spaced,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted", "{told}");

    // The code went down with the login it finished: presented to a fresh
    // one it is nobody's.
    let second = open(&plane, &textbox).await;
    let (_, told) = answer(
        &plane,
        &textbox,
        &second,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(told["status"], "challenge", "{told}");
    let (status, told) = answer(
        &plane,
        &textbox,
        &second,
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "sms_otp": code,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused", "{told}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn asking_again_inside_the_cooldown_sends_nothing_and_a_login_only_fans_so_far() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let credentials =
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD });
    answer(&plane, &textbox, &binding, credentials.clone()).await;
    assert_eq!(textbox.held().len(), 1);

    // Inside the cooldown: answered the same way, nothing more sent.
    let (_, told) = answer(&plane, &textbox, &binding, credentials.clone()).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(textbox.held().len(), 1, "the cooldown did not hold");

    // Past the cooldown the login may ask again, twice; the fourth ask of
    // this same login is answered like the others and sends nothing.
    for _ in 0..2 {
        age_past_cooldown(&plane, "sms-otp").await;
        answer(&plane, &textbox, &binding, credentials.clone()).await;
    }
    assert_eq!(textbox.held().len(), 3, "the resend window did not reopen");
    age_past_cooldown(&plane, "sms-otp").await;
    let (_, told) = answer(&plane, &textbox, &binding, credentials.clone()).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(
        textbox.held().len(),
        3,
        "one login fanned out more codes than its cap"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unproven_phone_gets_no_code() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, false).await;
    require_sms_otp(&plane).await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert_eq!(told["status"], "refused", "{told}");
    assert!(
        textbox.held().is_empty(),
        "a code was texted at a number nobody proved"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realms_day_budget_stops_the_texts() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    let textbox = Textbox::default();

    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        transaction
            .execute(
                "INSERT INTO sms_spend (tenant, realm_id, day, sent) \
                 SELECT current_setting('saffui.current_tenant', true), \
                        current_setting('saffui.current_realm', true), \
                        current_date, 250",
                &[],
            )
            .await
            .expect("the day spent");
        transaction.commit().await.expect("the day kept");
    }

    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert!(
        textbox.held().is_empty(),
        "a text went out past the realm's day budget"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_person_is_walked_through_proving_a_phone() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, false).await;
    require_verify_phone(&plane).await;
    {
        // The ceremony must ask for a number, so the account starts bare.
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        store::providers::users::set_phone(&transaction, support::SUBJECT, None, false)
            .await
            .expect("the phone cleared");
        transaction.commit().await.expect("the clearing kept");
    }
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let credentials =
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD });
    let (_, told) = answer(&plane, &textbox, &binding, credentials.clone()).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(told["execution"], "verify-phone", "{told}");
    assert_eq!(told["asks"]["ask_phone"], true, "{told}");

    // A number that is not one is said back, and nothing is texted.
    let (_, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "phone": "half past nine",
        }),
    )
    .await;
    assert_eq!(told["asks"]["bad_number"], true, "{told}");
    assert!(textbox.held().is_empty());

    // Offered with the spaces a person types; texted at in the dialled form.
    let (_, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "phone": "+228 90 12 34 56",
        }),
    )
    .await;
    assert_eq!(told["execution"], "verify-phone", "{told}");
    assert_eq!(told["asks"]["code_sent_to"], "\u{2026}56", "{told}");
    let held = textbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].to, "+22890123456");
    let code = code_in(&held[0].body);

    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({
            "username": support::SUBJECT,
            "password": support::PASSWORD,
            "phone_register": code,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted", "{told}");

    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let subject = store::providers::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("the subject");
    assert_eq!(subject.phone_number.as_deref(), Some("+22890123456"));
    assert_eq!(
        subject.phone_number_verified,
        Some(true),
        "the walk ended without the number proven"
    );
    assert!(
        !subject
            .required_actions
            .unwrap_or_default()
            .contains(&RequiredAction::VerifyPhone),
        "the instruction outlived the ceremony that satisfied it"
    );
}

/// Reshape the realm's texting brakes the way an administrator would.
async fn reshape(plane: &Plane, change: impl FnOnce(&mut models::entities::realm::RealmModel)) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    let mut realm = store::providers::realms::load(&transaction, support::REALM)
        .await
        .expect("the realms table")
        .expect("a planted realm");
    change(&mut realm);
    store::providers::realms::update(&transaction, &realm)
        .await
        .expect("the realms table");
    transaction.commit().await.expect("the setting kept");
}

/// The throttle rows the realm's sign-in log holds, brake by brake.
async fn throttles(plane: &Plane) -> Vec<String> {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    transaction
        .query(
            "SELECT detail->>'brake' FROM login_events WHERE kind = 'sms_throttled' \
             ORDER BY recorded_at, id",
            &[],
        )
        .await
        .expect("the sign-in log")
        .into_iter()
        .map(|row| row.get::<_, Option<String>>(0).unwrap_or_default())
        .collect()
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_blocked_prefix_is_never_texted_and_the_throttle_is_on_the_record() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    reshape(&plane, |realm| {
        realm.sms_blocked_prefixes = Some(vec!["+22890".to_owned()]);
    })
    .await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");
    assert!(
        textbox.held().is_empty(),
        "a text went out at a range the realm never texts"
    );
    assert_eq!(
        throttles(&plane).await,
        vec!["blocked-prefix"],
        "the throttle left no record"
    );
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn one_number_only_takes_so_many_in_an_hour() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    reshape(&plane, |realm| {
        realm.sms_per_number_cap = Some(1);
    })
    .await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let credentials =
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD });
    answer(&plane, &textbox, &binding, credentials.clone()).await;
    assert_eq!(textbox.held().len(), 1);

    // Past the cooldown the login may ask again; the number's hour says no.
    age_past_cooldown(&plane, "sms-otp").await;
    let (_, told) = answer(&plane, &textbox, &binding, credentials.clone()).await;
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(
        textbox.held().len(),
        1,
        "one number took more than its hour's cap"
    );
    assert_eq!(throttles(&plane).await, vec!["number-velocity"]);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_day_cap_of_zero_stops_the_sending() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    reshape(&plane, |realm| {
        realm.sms_daily_cap = Some(0);
    })
    .await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    let (status, _) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(textbox.held().is_empty(), "a shut day still sent");
    assert_eq!(throttles(&plane).await, vec!["day-budget"]);
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_realms_own_words_ride_the_text() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_sms_otp(&plane).await;
    reshape(&plane, |realm| {
        realm.default_locale = Some("fr".to_owned());
        realm.sms_templates = Some(
            [(
                "sms_otp".to_owned(),
                [("fr".to_owned(), "Acme: {{code}} pour entrer".to_owned())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
        );
    })
    .await;
    let textbox = Textbox::default();

    let binding = open(&plane, &textbox).await;
    answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": support::SUBJECT, "password": support::PASSWORD }),
    )
    .await;
    let held = textbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    let code = held[0].body.split(' ').nth(1).expect("a worded code");
    assert_eq!(
        held[0].body,
        format!("Acme: {code} pour entrer"),
        "the realm's wording did not carry"
    );
    assert_eq!(code.len(), 6, "the code did not land in the words");
}

/// Offer the texted code beside the password, the way a deployment would.
async fn offer_texted_login(plane: &Plane) {
    let mut connection = plane.connection().await;
    let transaction = plane.scoped(&mut connection, &within()).await;
    assert!(
        services::provisioning::provision_texted_login(
            &transaction,
            support::TENANT,
            support::REALM
        )
        .await
        .expect("the flow reshaped"),
        "the texted alternative was not added"
    );
    transaction.commit().await.expect("the flow kept");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proven_phone_alone_signs_a_person_in() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    offer_texted_login(&plane).await;
    let textbox = Textbox::default();

    // The number is the name, spelled with the spaces a person types, and
    // no password rides the round.
    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": "+228 90 12 34 56" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "{told}");
    assert_eq!(told["asks"]["code_sent_to"], "\u{2026}56", "{told}");
    let held = textbox.held();
    assert_eq!(held.len(), 1, "{held:?}");
    let code = code_in(&held[0].body);

    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": "+228 90 12 34 56", "sms_otp": code }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted", "{told}");
}

#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn an_unproven_or_shared_number_names_nobody() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, false).await;
    offer_texted_login(&plane).await;
    let textbox = Textbox::default();

    // Answered the way any unknown name is: the login stands unadmitted,
    // no code is named on the screen, and nothing is texted.
    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": "+22890123456" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "{told}");
    assert!(told["asks"].get("code_sent_to").is_none(), "{told}");
    assert!(textbox.held().is_empty(), "an unproven number was texted");

    // Proven on two accounts, the number names neither.
    {
        let mut connection = plane.connection().await;
        let transaction = plane.scoped(&mut connection, &within()).await;
        store::providers::users::set_phone(
            &transaction,
            support::SUBJECT,
            Some("+22890123456"),
            true,
        )
        .await
        .expect("the phone proven");
        let other = format!("service-account-{}", support::CONFIDENTIAL);
        store::providers::users::set_phone(&transaction, &other, Some("+22890123456"), true)
            .await
            .expect("the second phone proven");
        transaction.commit().await.expect("the pair kept");
    }
    let binding = open(&plane, &textbox).await;
    let (status, told) = answer(
        &plane,
        &textbox,
        &binding,
        serde_json::json!({ "username": "+22890123456" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "challenge", "{told}");
    assert!(told["asks"].get("code_sent_to").is_none(), "{told}");
    assert!(
        textbox.held().is_empty(),
        "a number two accounts share still rang one of them"
    );
}
