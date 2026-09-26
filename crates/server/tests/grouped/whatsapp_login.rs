#[allow(unused_imports)]
use super::support;
use super::support::{Plane, Textbox, WhatsAppBox, cookie_value, urlencode};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::auditable::AuditableModel;
use models::entities::auth::{
    AuthenticationExecutionMutationModel, AuthenticatorRequirement, ExecutionStep,
};
use models::entities::user::RequiredAction;
use models::messaging::Channel;
use server::api::config::{Plane as Mounted, register};
use std::sync::Arc;
use store::tenancy::TenantContext;

const REDIRECT: &str = "https://app.example/callback";
const PHONE: &str = "+22890123456";

/// Both ways a deployment carries a code, or only the text when `whatsapp`
/// is absent.
fn mounted(plane: &Plane, textbox: &Textbox, whatsapp: Option<&WhatsAppBox>) -> Mounted {
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
        egress: config::serving::Egress::Outward,
        ceiling: support::ceiling(),
        sealing: support::sealing_speaking(
            None,
            Some(Arc::new(textbox.clone()) as Arc<dyn auth::messaging::Texter>),
            whatsapp.map(|held| Arc::new(held.clone()) as Arc<dyn auth::messaging::WhatsAppSender>),
        ),
    }
}

fn within() -> TenantContext {
    TenantContext::new(support::TENANT, support::REALM)
}

/// A realm speaking WhatsApp, with its gateway behind it where `gateway`
/// says, and a subject whose phone is proven.
async fn arrange(plane: &Plane, gateway: bool) {
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
    if gateway {
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
    }
    services::admin::whatsapp::write(
        &transaction,
        &ring,
        &sealing.envelope,
        services::admin::whatsapp::Wanted {
            phone_number_id: "106540352242922".to_owned(),
            template: "sign_in_code".to_owned(),
            languages: vec!["en_US".to_owned(), "fr".to_owned()],
            token: Some("a-system-user-token".to_owned()),
        },
    )
    .await
    .expect("the business number kept");
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

/// Append a required code as a second factor to the browser flow.
async fn require_code(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
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
    transaction.commit().await.expect("the flow kept");
}

/// A login waiting to be answered, and the app that answers it.
struct Login<'a> {
    plane: &'a Plane,
    textbox: &'a Textbox,
    whatsapp: Option<&'a WhatsAppBox>,
    binding: String,
}

impl<'a> Login<'a> {
    async fn open(
        plane: &'a Plane,
        textbox: &'a Textbox,
        whatsapp: Option<&'a WhatsAppBox>,
    ) -> Self {
        let app =
            test::init_service(App::new().configure(register(&mounted(plane, textbox, whatsapp))))
                .await;
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
            whatsapp,
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
        let app = test::init_service(App::new().configure(register(&mounted(
            self.plane,
            self.textbox,
            self.whatsapp,
        ))))
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

    /// The same round posted as the page's own form, as a browser without its
    /// script sends it; answered with where the browser is sent.
    async fn answer_as_a_form(&self, beside: &[(&str, &str)]) -> (StatusCode, String) {
        let minted = support::page_token_for(self.plane, &self.binding).await;
        let mut fields: Vec<(&str, &str)> = vec![
            ("username", support::SUBJECT),
            ("password", support::PASSWORD),
            ("page_token", minted.as_str()),
        ];
        fields.extend_from_slice(beside);
        let app = test::init_service(App::new().configure(register(&mounted(
            self.plane,
            self.textbox,
            self.whatsapp,
        ))))
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
                .set_form(fields)
                .to_request(),
        )
        .await;
        let status = response.status();
        let location = response
            .headers()
            .get("location")
            .and_then(|held| held.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (status, location)
    }
}

/// The six digits a text carried.
fn code_in(body: &str) -> String {
    let digits: String = body.chars().take_while(char::is_ascii_digit).collect();
    assert_eq!(digits.len(), 6, "not a code-first body: {body}");
    digits
}

/// Age the code in flight past the resend cooldown, so the next login may send
/// without the test waiting a minute of wall clock.
async fn age_past_cooldown(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    transaction
        .execute(
            "UPDATE one_time_tokens SET created_at = created_at - interval '61 seconds' \
             WHERE purpose = 'sms-otp'",
            &[],
        )
        .await
        .expect("the clock moved");
    transaction.commit().await.expect("the clock kept");
}

/// Every attempt this person's codes made, oldest first, as channel and
/// outcome.
async fn attempts(plane: &Plane) -> Vec<(Option<Channel>, bool)> {
    let transaction = plane.scoped(&within()).await;
    let mut held =
        store::providers::events::deliveries::of_user(&transaction, support::SUBJECT, 50)
            .await
            .expect("the receipts");
    held.reverse();
    held.into_iter()
        .map(|receipt| (receipt.channel, receipt.delivered))
        .collect()
}

/// WhatsApp goes first where the realm speaks it, in a language the template
/// was approved in, the page says so and offers the other way, the receipt
/// names the way, and the code finishes the login.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_code_goes_by_whatsapp_first_and_finishes_the_login() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (status, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["asks"]["code_sent_to"], "\u{2026}56", "{told}");
    assert_eq!(told["asks"]["sent_by"], "whatsapp", "{told}");
    assert_eq!(told["asks"]["other_way"], "sms", "{told}");
    let held = whatsapp.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(
        (held[0].to.as_str(), held[0].language.as_str()),
        (PHONE, "en_US")
    );
    assert!(
        textbox.held().is_empty(),
        "the gateway sent beside WhatsApp"
    );
    assert_eq!(
        attempts(&plane).await,
        vec![(Some(Channel::WhatsApp), true)]
    );

    let (status, told) = login
        .answer(serde_json::json!({ "sms_otp": held[0].code }))
        .await;
    assert_eq!(status, StatusCode::OK, "{told}");
    assert_eq!(told["status"], "admitted", "{told}");
}

/// Meta refusing hands the same code to the gateway at once, the page is told
/// the way it really went and offers no way back to the one that refused,
/// and each attempt keeps its receipt.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_refusal_from_meta_falls_to_the_gateway_and_the_page_is_told() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::refusing());

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert!(told["asks"].get("other_way").is_none(), "{told}");
    let texted = textbox.held();
    assert_eq!(texted.len(), 1, "{texted:?}");
    assert_eq!(
        attempts(&plane).await,
        vec![(Some(Channel::WhatsApp), false), (Some(Channel::Sms), true)]
    );

    let (_, told) = login
        .answer(serde_json::json!({ "sms_otp": code_in(&texted[0].body) }))
        .await;
    assert_eq!(told["status"], "admitted", "{told}");
}

/// The brakes count a code once, whichever way it went and however many ways
/// it tried.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_brakes_count_a_code_once_whichever_way_it_goes() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::refusing());

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    login.answer(serde_json::json!({})).await;

    let transaction = plane.scoped(&within()).await;
    let today: i32 = transaction
        .query_one("SELECT sent FROM sms_spend", &[])
        .await
        .expect("the day counted")
        .get(0);
    let this_hour: i32 = transaction
        .query_one("SELECT sent FROM sms_velocity", &[])
        .await
        .expect("the number counted")
        .get(0);
    assert_eq!(
        (today, this_hour),
        (1, 1),
        "a code that tried two ways was counted twice"
    );
}

/// A person with no WhatsApp asks for a text: it goes at once with a fresh
/// code the old one no longer matches, the other way is not granted again
/// without waiting, and their next login texts first.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn asking_for_a_text_sends_one_at_once_and_is_remembered() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());

    let first = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    first.answer(serde_json::json!({})).await;
    let over_whatsapp = whatsapp.held()[0].code.clone();

    let (_, told) = first
        .answer(serde_json::json!({ "code_channel": "sms" }))
        .await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert_eq!(told["asks"]["other_way"], "whatsapp", "{told}");
    assert_eq!(textbox.held().len(), 1, "the text did not go at once");

    // Asked back straight away: the one change without waiting is spent.
    let (_, told) = first
        .answer(serde_json::json!({ "code_channel": "whatsapp" }))
        .await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert_eq!(
        (whatsapp.held().len(), textbox.held().len()),
        (1, 1),
        "a second change went without waiting"
    );

    let (status, told) = first
        .answer(serde_json::json!({ "sms_otp": over_whatsapp }))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{told}");

    age_past_cooldown(&plane).await;
    let second = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (_, told) = second.answer(serde_json::json!({})).await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert_eq!(whatsapp.held().len(), 1, "the choice was not remembered");
    let texted = textbox.held();
    assert_eq!(texted.len(), 2, "{texted:?}");
    let (_, told) = second
        .answer(serde_json::json!({ "sms_otp": code_in(&texted[1].body) }))
        .await;
    assert_eq!(told["status"], "admitted", "{told}");
}

/// A choice is kept for the number it was made for: once the account holds
/// another, WhatsApp goes first again.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_remembered_way_holds_only_for_its_number() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());
    {
        let transaction = plane.scoped(&within()).await;
        store::providers::directory::code_channels::choose(
            &transaction,
            support::SUBJECT,
            "+22899999999",
            Channel::Sms,
            chrono::Utc::now(),
        )
        .await
        .expect("a choice for another number");
        transaction.commit().await.expect("the choice kept");
    }

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["asks"]["sent_by"], "whatsapp", "{told}");
    assert_eq!(whatsapp.held().len(), 1);
}

/// A realm with no gateway still sends its codes over WhatsApp, with no other
/// way to offer.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_realm_with_no_gateway_sends_over_whatsapp_alone() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, false).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["asks"]["sent_by"], "whatsapp", "{told}");
    assert!(told["asks"].get("other_way").is_none(), "{told}");
    assert_eq!(whatsapp.held().len(), 1);
}

/// A deployment that does not speak to Meta texts, whatever the realm holds,
/// and never offers a way it cannot carry.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_deployment_that_does_not_speak_to_meta_texts() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox, None).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert!(told["asks"].get("other_way").is_none(), "{told}");
    assert_eq!(textbox.held().len(), 1);

    let (_, told) = login
        .answer(serde_json::json!({ "code_channel": "whatsapp" }))
        .await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert_eq!(
        textbox.held().len(),
        1,
        "an ask for a way nothing carries sent a text"
    );
}

/// The subject owes the proof of an unproven phone, and reads French.
async fn owe_a_proof(plane: &Plane) {
    let transaction = plane.scoped(&within()).await;
    let mut subject = store::providers::directory::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("a planted subject");
    subject.required_actions = Some(vec![RequiredAction::VerifyPhone]);
    let mut attributes = subject.attributes.unwrap_or_default();
    attributes.insert(
        models::entities::user::profile::LOCALE.to_owned(),
        models::entities::attributes::AttributeValue::Str("fr-FR".to_owned()),
    );
    subject.attributes = Some(attributes);
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

/// A phone is proven over WhatsApp the way it is by text, in the person's
/// language where the template speaks it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_phone_is_proven_over_whatsapp() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    owe_a_proof(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["execution"], "verify-phone", "{told}");
    assert_eq!(told["asks"]["sent_by"], "whatsapp", "{told}");
    let held = whatsapp.held();
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].language, "fr", "{held:?}");

    let (_, told) = login
        .answer(serde_json::json!({ "phone_register": held[0].code }))
        .await;
    assert_eq!(told["status"], "admitted", "{told}");
    let transaction = plane.scoped(&within()).await;
    let subject = store::providers::directory::users::load(&transaction, support::SUBJECT)
        .await
        .expect("the users table")
        .expect("the subject");
    assert_eq!(subject.phone_number_verified, Some(true));
}

/// A browser without the script is sent to the code's panel in the words of
/// the way it went, and asks for the other way with the panel's own button.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_browser_without_script_is_shown_the_way_and_can_ask_the_other() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    require_code(&plane).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());

    let login = Login::open(&plane, &textbox, Some(&whatsapp)).await;
    let (status, location) = login.answer_as_a_form(&[]).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.ends_with("#texted-over-whatsapp"), "{location}");

    let (_, location) = login.answer_as_a_form(&[("code_channel", "sms")]).await;
    assert!(location.ends_with("#texted"), "{location}");
    assert_eq!(textbox.held().len(), 1, "the form's ask sent no text");
}

/// The page offers the other way to a browser without its script only where
/// the realm and the deployment both carry a code either way, and never
/// serves its marker for it.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_page_offers_the_other_way_only_where_both_are_carried() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    let (textbox, whatsapp) = (Textbox::default(), WhatsAppBox::default());
    let served = |whatsapp: Option<&WhatsAppBox>| {
        let (plane, textbox) = (&plane, &textbox);
        let whatsapp = whatsapp.cloned();
        async move {
            let login = Login::open(plane, textbox, whatsapp.as_ref()).await;
            let app = test::init_service(App::new().configure(register(&mounted(
                plane,
                textbox,
                whatsapp.as_ref(),
            ))))
            .await;
            let response = test::call_service(
                &app,
                test::TestRequest::get()
                    .uri(&format!(
                        "/realms/{}/protocol/openid-connect/login",
                        support::REALM
                    ))
                    .insert_header((
                        "cookie",
                        format!("{}={}", support::AUTH_SESSION_COOKIE, login.binding),
                    ))
                    .to_request(),
            )
            .await;
            String::from_utf8(test::read_body(response).await.to_vec()).expect("a page")
        }
    };

    let both = served(Some(&whatsapp)).await;
    assert!(
        both.contains("<p id=\"texted-ways\" >"),
        "the other way was hidden"
    );
    assert!(
        both.contains("<p id=\"phone-code-ways\" >"),
        "the other way was hidden"
    );
    let texts_only = served(None).await;
    assert!(
        texts_only.contains("<p id=\"texted-ways\" hidden>"),
        "a way the deployment does not carry was offered"
    );
    assert!(!both.contains("{ways}") && !texts_only.contains("{ways}"));
}

/// The phone's proof takes an ask for a way nothing carries as no ask at all,
/// as the sign-in code does.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_proofs_ask_for_a_way_nothing_carries_sends_nothing() {
    let plane = Plane::with_actions(&[]).await;
    arrange(&plane, true).await;
    owe_a_proof(&plane).await;
    let textbox = Textbox::default();

    let login = Login::open(&plane, &textbox, None).await;
    let (_, told) = login.answer(serde_json::json!({})).await;
    assert_eq!(told["execution"], "verify-phone", "{told}");
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    let (_, told) = login
        .answer(serde_json::json!({ "code_channel": "whatsapp" }))
        .await;
    assert_eq!(told["asks"]["sent_by"], "sms", "{told}");
    assert_eq!(
        textbox.held().len(),
        1,
        "an ask for a way nothing carries sent another proving code"
    );
}
