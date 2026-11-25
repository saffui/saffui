//! What only SQL holds of registration through the protocol: of two
//! requests that present one token, one wins; two registrations of a realm
//! count its clients one after the other, under the row of its settings,
//! and a change waits for a change of the settings; of attempts at once at
//! the bound of the brake, one is counted, and one past a bound reached
//! waits for nobody; two administrators count the live initial tokens one
//! after the other; an answer on the page of consent holds its client; and
//! a client whose registration ended counts until retention removes it.

use std::time::Duration;

use pgcore::APP_ROLE;
use pgcore::pool::PoolSettings;
use saffui_core::app::App;
use saffui_core::clients::registration::{InitialAccessToken, MOST_LIVE_INITIAL_TOKENS};
use saffui_core::clients::{ClientAuthMethod, KeptProof};
use saffui_core::error::ErrorCode;
use saffui_core::ids::mint_id;
use saffui_core::oidc::registration::{
    RegistrationError, RegistrationRequest, register_dynamic_client, update_registered_client,
};
use saffui_core::tenancy::RealmScope;
use saffui_core::testkit::fixtures::{Application, create_realm, register_application};
use serde_json::json;

use crate::support::locks::{ON_A_ROW, wait_for_waiter};
use crate::support::{self, connect};

/// The realm `acme`, open to registration with room for `bound` clients,
/// its application `portal`, made by an administrator, and `registered`, a
/// client that registered itself and whose registration is not written yet.
async fn open_realm(app: &App, bound: u32) -> RealmScope {
    open_realm_with(
        app,
        json!({ "registration": "open", "max_registered_clients": bound }),
    )
    .await
}

/// As [`open_realm`], under these settings.
async fn open_realm_with(app: &App, settings: serde_json::Value) -> RealmScope {
    let scope = create_realm(app, "acme").await;
    let portal = Application {
        client_id: "portal",
        redirect_uri: "https://app.example.org/cb",
        post_logout_redirect_uri: None,
        public: true,
        requires_consent: true,
    };
    register_application(app, scope, portal).await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    let made = work
        .read_client("portal")
        .await
        .expect("a read")
        .expect("portal");
    let registered = saffui_core::clients::Client {
        id: mint_id(app).expect("an identifier"),
        client_id: "registered".to_owned(),
        auth_method: ClientAuthMethod::None,
        self_registered: true,
        ..made
    };
    let nothing = KeptProof {
        secret_digest: None,
        sealed_secret: None,
        jwks: None,
    };
    work.insert_client(&registered, &nothing)
        .await
        .expect("a client that registered itself");
    work.write_realm_settings(&settings)
        .await
        .expect("settings");
    work.commit().await.expect("a commit");
    scope
}

/// What a registration through the protocol answers: the error, and the
/// refusal of the catalog behind it.
async fn register(
    app: &App,
    metadata: serde_json::Value,
) -> Result<(), (RegistrationError, ErrorCode)> {
    let body = metadata.to_string();
    let request = RegistrationRequest {
        caller: None,
        token: None,
        body: body.as_bytes(),
    };
    register_dynamic_client(app, "acme", request)
        .await
        .map(|_| ())
        .map_err(|failure| (failure.error, failure.cause.code))
}

#[tokio::test]
async fn of_two_requests_that_present_one_registration_token_one_replaces_it() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_client_registration("registered", &[6; 32], app.now())
        .await
        .expect("a registration");
    work.commit().await.expect("a commit");
    let observer = connect(&database, APP_ROLE).await;

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        first
            .rotate_registration_token("registered", &[6; 32], &[7; 32])
            .await,
        Ok(true)
    );
    let second = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            let rotated = work
                .rotate_registration_token("registered", &[6; 32], &[8; 32])
                .await;
            work.commit().await.expect("a commit");
            rotated
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    first.commit().await.expect("a commit");

    assert!(waited, "the second waits on the row of the registration");
    assert_eq!(
        second.await.expect("the second request"),
        Ok(false),
        "then finds the token it presents replaced"
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.matches_registration_token("registered", &[7; 32])
            .await,
        Ok(true)
    );
}

#[tokio::test]
async fn of_two_spends_of_the_last_use_of_an_initial_token_one_spends_it() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let token = InitialAccessToken {
        id: mint_id(&app).expect("an identifier"),
        uses_left: 1,
        expires_at: app.now() + time::Duration::hours(1),
        created_at: app.now(),
        created_by: "operator".to_owned(),
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_initial_access_token(&token, &[4; 32])
        .await
        .expect("a token");
    work.commit().await.expect("a commit");
    let observer = connect(&database, APP_ROLE).await;

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        first.spend_initial_access_token(&[4; 32], app.now()).await,
        Ok(Some(token.id))
    );
    let second = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            let spent = work.spend_initial_access_token(&[4; 32], app.now()).await;
            work.commit().await.expect("a commit");
            spent
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    first.commit().await.expect("a commit");

    assert!(waited, "the second waits on the row of the token");
    assert_eq!(second.await.expect("the second spend"), Ok(None));
}

/// A registration in flight holds the row of the settings, with the client
/// it inserted not yet committed: another registration waits for it, then
/// counts that client against the bound of the realm, or of its day.
#[tokio::test]
async fn two_registrations_of_a_realm_count_its_clients_one_after_the_other() {
    for (settings, refused) in [
        (
            json!({ "registration": "open", "max_registered_clients": 1 }),
            ErrorCode::RegistrationQuotaReached,
        ),
        (
            json!({ "registration": "open", "max_daily_registrations": 1 }),
            ErrorCode::RegistrationBudgetSpent,
        ),
    ] {
        count_two_registrations_at_once(settings, refused).await;
    }
}

async fn count_two_registrations_at_once(settings: serde_json::Value, refused: ErrorCode) {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm_with(&app, settings).await;
    let observer = connect(&database, APP_ROLE).await;

    let mut in_flight = app.storage.begin(scope).await.expect("a unit of work");
    in_flight
        .read_realm_settings_for_update()
        .await
        .expect("a read")
        .expect("settings");
    assert_eq!(
        in_flight
            .count_registrations(app.now())
            .await
            .map(|counts| counts.registered),
        Ok(0)
    );
    in_flight
        .insert_client_registration("registered", &[6; 32], app.now())
        .await
        .expect("a registration");
    let second = {
        let app = app.clone();
        tokio::spawn(async move {
            register(
                &app,
                json!({ "redirect_uris": ["https://registered.example.org/cb"] }),
            )
            .await
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    in_flight.commit().await.expect("a commit");

    assert!(waited, "the second waits on the row of the settings");
    assert_eq!(
        second.await.expect("the second registration"),
        Err((RegistrationError::AccessDenied, refused)),
        "then counts the first, which fills the realm"
    );
}

/// The settings change while a registration waits on their row: it is
/// judged by those it finds once it holds the row, not by those that let it
/// in.
#[tokio::test]
async fn a_registration_is_judged_by_the_settings_it_holds_when_it_inserts() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let observer = connect(&database, APP_ROLE).await;
    let spawn_registration = |metadata: serde_json::Value| {
        let app = app.clone();
        tokio::spawn(async move { register(&app, metadata).await })
    };

    for (changed, metadata, refused) in [
        (
            json!({ "registration": "closed" }),
            json!({ "redirect_uris": ["https://registered.example.org/cb"] }),
            (
                RegistrationError::AccessDenied,
                ErrorCode::RegistrationClosed,
            ),
        ),
        (
            json!({ "registration": "open", "max_redirect_uris": 1 }),
            json!({ "redirect_uris": [
                "https://registered.example.org/cb",
                "https://registered.example.org/other",
            ] }),
            (
                RegistrationError::InvalidClientMetadata,
                ErrorCode::ClientMetadataInvalid,
            ),
        ),
        (
            json!({ "registration": "open", "registrable_scopes": ["openid", "profile"] }),
            json!({
                "redirect_uris": ["https://registered.example.org/cb"],
                "scope": "openid email",
            }),
            (
                RegistrationError::InvalidClientMetadata,
                ErrorCode::ScopeNotAllowed,
            ),
        ),
    ] {
        let mut changing = app.storage.begin(scope).await.expect("a unit of work");
        changing
            .write_realm_settings(&changed)
            .await
            .expect("settings changed");
        let waiting = spawn_registration(metadata);
        let waited = wait_for_waiter(&observer, ON_A_ROW, &waiting).await;
        changing.commit().await.expect("a commit");

        assert!(waited, "the registration waits on the row of the settings");
        assert_eq!(waiting.await.expect("the registration"), Err(refused));
        let mut work = app.storage.begin(scope).await.expect("a unit of work");
        work.write_realm_settings(&json!({ "registration": "open" }))
            .await
            .expect("settings opened again");
        work.commit().await.expect("a commit");
    }
}

/// A first attempt at the bound holds the row of its bucket, uncommitted:
/// the second waits for it, then finds the bound reached, and counts nothing.
#[tokio::test]
async fn of_two_attempts_at_once_at_the_bound_of_the_brake_one_is_counted() {
    use saffui_core::login::throttle::{start_bucket, start_window};

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let observer = connect(&database, APP_ROLE).await;
    let now = app.now();
    let counter = [7_u8; 32];

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        first
            .record_attempt_within(&counter, start_bucket(now), start_window(now), 1)
            .await,
        Ok(true)
    );
    let second = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            let recorded = work
                .record_attempt_within(&counter, start_bucket(now), start_window(now), 1)
                .await;
            work.commit().await.expect("a commit");
            recorded
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    first.commit().await.expect("a commit");

    assert!(waited, "the second waits on the bucket of the first");
    assert_eq!(
        second.await.expect("the second attempt"),
        Ok(false),
        "then finds the bound reached"
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        work.count_login_failures(&counter, start_window(now)).await,
        Ok(1),
        "one attempt counted, not two"
    );
}

/// The bound counts a client whose registration ended until retention
/// removes it with its registration, a month after the end.
#[tokio::test]
async fn a_client_whose_registration_ended_holds_its_place_until_retention_removes_it() {
    use pgcore::RETENTION_ROLE;
    use saffui_core::oidc::registration::delete_registered_client;
    use saffui_core::retention::{PurgeCutoffs, Retention};
    use store::retention::PgRetention;

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = create_realm(&app, "acme").await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.write_realm_settings(&json!({ "registration": "open", "max_registered_clients": 1 }))
        .await
        .expect("settings");
    work.commit().await.expect("a commit");
    let body = json!({ "redirect_uris": ["https://registered.example.org/cb"] }).to_string();
    let register = || async {
        let request = RegistrationRequest {
            caller: None,
            token: None,
            body: body.as_bytes(),
        };
        register_dynamic_client(&app, "acme", request)
            .await
            .map(saffui_core::oidc::registration::RegistrationAnswer::into_document)
            .map_err(|failure| (failure.error, failure.cause.code))
    };
    let registered = register().await.expect("a client");
    let read = |name: &str| registered[name].as_str().expect(name).to_owned();
    delete_registered_client(
        &app,
        "acme",
        &read("client_id"),
        None,
        Some(&read("registration_access_token")),
    )
    .await
    .expect("its registration ended");

    assert_eq!(
        register().await.map(|_| ()),
        Err((
            RegistrationError::AccessDenied,
            ErrorCode::RegistrationQuotaReached
        )),
        "the ended one holds its place"
    );
    let retention = PgRetention::new(database.plan(RETENTION_ROLE));
    let not_yet = PurgeCutoffs::at(app.now());
    assert_eq!(
        retention
            .purge_expired(not_yet, Duration::from_mins(1))
            .await
            .map(|report| report.map(|report| report.registered_clients.removed)),
        Ok(Some(0)),
        "kept a month"
    );
    let a_month_later = PurgeCutoffs::at(app.now() + time::Duration::days(31));
    assert_eq!(
        retention
            .purge_expired(a_month_later, Duration::from_mins(1))
            .await
            .map(|report| report.map(|report| report.registered_clients.removed)),
        Ok(Some(1))
    );
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(work.read_client(&read("client_id")).await, Ok(None));
    assert_eq!(
        work.count_registrations(app.now())
            .await
            .map(|counts| counts.registered),
        Ok(0)
    );
    drop(work);
    assert!(register().await.is_ok(), "its place is free");
}

/// A bound reached and committed refuses an attempt before it writes: one
/// refused and still open holds nothing a third one waits for.
#[tokio::test]
async fn an_attempt_past_a_bound_already_reached_waits_for_no_other() {
    use saffui_core::login::throttle::{start_bucket, start_window};

    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let observer = connect(&database, APP_ROLE).await;
    let now = app.now();
    let counter = [9_u8; 32];
    let attempt = async |work: &mut Box<dyn saffui_core::ports::storage::UnitOfWork>| {
        work.record_attempt_within(&counter, start_bucket(now), start_window(now), 1)
            .await
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(attempt(&mut work).await, Ok(true));
    work.commit().await.expect("a commit");

    let mut held = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(attempt(&mut held).await, Ok(false), "the bound is reached");
    let third = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            let recorded = work
                .record_attempt_within(&counter, start_bucket(now), start_window(now), 1)
                .await;
            work.commit().await.expect("a commit");
            recorded
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &third).await;
    drop(held);

    assert!(!waited, "refused at once, the third waits for nobody");
    assert_eq!(third.await.expect("the third attempt"), Ok(false));
}

/// One token short of the bound, an administrator who counts the live
/// tokens holds them: another waits, then counts the token the first made.
#[tokio::test]
async fn two_administrators_one_token_short_of_the_bound_make_one_token_between_them() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let observer = connect(&database, APP_ROLE).await;
    let now = app.now();
    let make = |digest: u32| InitialAccessToken {
        id: mint_id(&app).expect("an identifier"),
        uses_left: 1,
        expires_at: now + time::Duration::hours(1),
        created_at: now,
        created_by: format!("operator-{digest}"),
    };
    let digest_of = |number: u32| {
        let mut digest = [0_u8; 32];
        digest[..4].copy_from_slice(&number.to_be_bytes());
        digest
    };
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    for number in 1..MOST_LIVE_INITIAL_TOKENS {
        let number = u32::try_from(number).expect("a small number");
        work.insert_initial_access_token(&make(number), &digest_of(number))
            .await
            .expect("a live token");
    }
    work.commit().await.expect("a commit");

    let mut first = app.storage.begin(scope).await.expect("a unit of work");
    assert_eq!(
        first.count_live_initial_access_tokens(now).await,
        Ok(MOST_LIVE_INITIAL_TOKENS - 1)
    );
    first
        .insert_initial_access_token(&make(1000), &digest_of(1000))
        .await
        .expect("the last token there is room for");
    let second = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            work.count_live_initial_access_tokens(now).await
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &second).await;
    first.commit().await.expect("a commit");

    assert!(waited, "the second waits on the tokens the first holds");
    assert_eq!(
        second.await.expect("the second count"),
        Ok(MOST_LIVE_INITIAL_TOKENS),
        "then counts the one the first made: the realm is full"
    );
}

/// An answer on the page of consent shares the row of its client until it
/// commits: a change of the client waits for it.
#[tokio::test]
async fn an_answer_on_the_page_of_consent_holds_its_client_until_it_commits() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let observer = connect(&database, APP_ROLE).await;

    let mut answering = app.storage.begin(scope).await.expect("a unit of work");
    assert!(
        answering
            .read_client_for_share("registered")
            .await
            .expect("a read")
            .is_some()
    );
    let changing = {
        let app = app.clone();
        tokio::spawn(async move {
            let mut work = app.storage.begin(scope).await.expect("a unit of work");
            let read = work.read_client_for_update("registered").await;
            work.commit().await.expect("a commit");
            read.map(|client| client.is_some())
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &changing).await;
    answering.commit().await.expect("a commit");

    assert!(waited, "the change waits on the row the answer shares");
    assert_eq!(changing.await.expect("the change"), Ok(true));
}

/// A change of a registration in flight waits on the row of the settings
/// another change of them holds, then is judged by what it wrote.
#[tokio::test]
async fn a_change_of_a_registration_is_judged_by_the_settings_it_holds_when_it_writes() {
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    let observer = connect(&database, APP_ROLE).await;
    let body = json!({ "redirect_uris": ["https://registered.example.org/cb"] }).to_string();
    let request = RegistrationRequest {
        caller: None,
        token: None,
        body: body.as_bytes(),
    };
    let registered = register_dynamic_client(&app, "acme", request)
        .await
        .map(saffui_core::oidc::registration::RegistrationAnswer::into_document)
        .map_err(|failure| failure.error)
        .expect("a client");
    let read = |name: &str| registered[name].as_str().expect(name).to_owned();
    let (client_id, token) = (read("client_id"), read("registration_access_token"));

    let mut changing = app.storage.begin(scope).await.expect("a unit of work");
    changing
        .write_realm_settings(&json!({ "registration": "open", "max_redirect_uris": 1 }))
        .await
        .expect("settings changed");
    let waiting = {
        let app = app.clone();
        tokio::spawn(async move {
            let body = json!({
                "client_id": client_id,
                "redirect_uris": [
                    "https://registered.example.org/cb",
                    "https://registered.example.org/other",
                ],
            })
            .to_string();
            let request = RegistrationRequest {
                caller: None,
                token: Some(&token),
                body: body.as_bytes(),
            };
            update_registered_client(&app, "acme", &client_id, request)
                .await
                .map(|_| ())
                .map_err(|failure| failure.error)
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &waiting).await;
    changing.commit().await.expect("a commit");

    assert!(waited, "the change waits on the row of the settings");
    assert_eq!(
        waiting.await.expect("the change"),
        Err(RegistrationError::InvalidClientMetadata),
        "then is judged by the settings written meanwhile"
    );
}

/// A person answers the page of a client while a change of the client is
/// in flight: the answer waits for the change, then reads the client it
/// wrote, and asks the person again for a host the page never showed.
#[tokio::test]
async fn an_answer_waits_for_a_change_of_its_client_and_holds_only_for_what_its_page_showed() {
    use saffui_core::consent::answer::{ConsentDecision, answer_consent, describe_consent};
    use saffui_core::oidc::authorize::{
        Authorization, AuthorizationParameters, SignInAnswer, SignInStep, TypedSignIn,
        begin_authorization, finish_sign_in,
    };
    use saffui_core::secret::Secret;
    use saffui_core::testkit::fixtures::create_person;

    // The address `registered` was given with the others of `portal`.
    const CALLBACK: &str = "https://app.example.org/cb";
    const PASSWORD: &str = "correct horse battery";
    let (app, database) = support::wire_on_postgres(PoolSettings::default()).await;
    let scope = open_realm(&app, 10).await;
    create_person(&app, scope, "ada", PASSWORD).await;
    let mut work = app.storage.begin(scope).await.expect("a unit of work");
    work.insert_client_registration("registered", &[6; 32], app.now())
        .await
        .expect("its registration");
    work.commit().await.expect("a commit");
    let observer = connect(&database, APP_ROLE).await;
    // The challenge of RFC 7636, appendix B: no code is exchanged here.
    let parameters = AuthorizationParameters {
        response_type: Some("code"),
        client_id: Some("registered"),
        redirect_uri: Some(CALLBACK),
        scope: Some("openid"),
        code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        code_challenge_method: Some("S256"),
        ..AuthorizationParameters::default()
    };
    let Ok(Authorization::SignInRequired {
        request,
        browser_secret,
    }) = begin_authorization(&app, "acme", parameters, None).await
    else {
        panic!("a person without a session signs in first");
    };
    let typed = TypedSignIn {
        answer: SignInAnswer::Password {
            name: "ada",
            password: Secret::new(PASSWORD.as_bytes().to_vec()),
        },
        caller: None,
        known_browsers: &[],
    };
    let step = finish_sign_in(&app, "acme", request, &browser_secret, typed)
        .await
        .expect("a signed-in person");
    let SignInStep::ConsentRequired(signed_in) = step else {
        panic!("a client that registered itself asks the person first: {step:?}");
    };
    let shown = describe_consent(
        &app,
        "acme",
        request,
        &browser_secret,
        Some(&signed_in.ticket),
    )
    .await
    .expect("the page")
    .shown;

    let mut changing = app.storage.begin(scope).await.expect("a unit of work");
    let kept = changing
        .read_client_for_update("registered")
        .await
        .expect("a read")
        .expect("the client");
    let widened = saffui_core::clients::Client {
        redirect_uris: vec![
            CALLBACK.to_owned(),
            "https://elsewhere.example.org/cb".to_owned(),
        ],
        ..kept
    };
    assert_eq!(
        changing.write_client_metadata(&widened, None).await,
        Ok(true)
    );
    let answering = {
        let app = app.clone();
        let ticket = signed_in.ticket;
        tokio::spawn(async move {
            answer_consent(
                &app,
                "acme",
                request,
                &browser_secret,
                Some(&ticket),
                ConsentDecision::Allow { shown },
            )
            .await
            .map(|_| ())
            .map_err(|failure| failure.code)
        })
    };
    let waited = wait_for_waiter(&observer, ON_A_ROW, &answering).await;
    changing.commit().await.expect("a commit");

    assert!(waited, "the answer waits on the row of its client");
    assert_eq!(
        answering.await.expect("the answer"),
        Err(ErrorCode::ConsentPageOutdated),
        "then reads the client as the change wrote it"
    );
}
