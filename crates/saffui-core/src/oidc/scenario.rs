//! What the tests of this folder start from: a realm with a person, an
//! application that signs people in, and a service that asks about tokens.

use std::sync::Arc;

use super::errors::OAuthError;
use super::token::{TokenRequest, TokenResponse, grant_token};
use crate::app::App;
use crate::authz::admin::{AdminCaller, authorize_admin_call};
use crate::authz::capability::Capability;
use crate::clients::authenticate::{PresentedProof, PresentedSecret};
use crate::login::enroll::{
    begin_key_enrollment, begin_totp_enrollment, confirm_totp_enrollment, finish_key_enrollment,
};
use crate::login::session::{SessionTicket, close_session};
use crate::secret::Secret;
use crate::tenancy::RealmScope;
use crate::testkit::clock::FixedClock;
use crate::testkit::crypto::{PredictableCodes, TrustingKeys};
use crate::testkit::drive::complete;
use crate::testkit::fixtures::{
    Application, CodeFlow, SignedInApplication, create_administrator, create_person, create_realm,
    create_service_client, register_application, run_code_flow,
};
use crate::testkit::memory::MemoryStorage;

pub(crate) const CALLBACK: &str = "https://app.example.org/callback";
pub(crate) const GOODBYE: &str = "https://app.example.org/goodbye";
pub(crate) const PASSWORD: &str = "correct horse battery";
pub(crate) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

pub(crate) struct Scenario {
    pub(crate) app: App,
    pub(crate) storage: Arc<MemoryStorage>,
    pub(crate) clock: Arc<FixedClock>,
    pub(crate) scope: RealmScope,
    /// The secret of the service `billing`.
    pub(crate) service_secret: Secret,
}

impl Scenario {
    /// The realm `acme`, the person `ada`, the public application `webapp`
    /// and the service `billing`.
    pub(crate) fn start() -> Self {
        let (app, storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        let webapp = Application {
            client_id: "webapp",
            redirect_uri: CALLBACK,
            post_logout_redirect_uri: Some(GOODBYE),
            public: true,
            requires_consent: false,
        };
        complete(register_application(&app, scope, webapp));
        let service_secret = complete(create_service_client(
            &app,
            scope,
            "billing",
            &["invoices:read"],
        ));
        Self {
            app,
            storage,
            clock,
            scope,
            service_secret,
        }
    }

    /// An administrator of `acme`, the client `operator`, granted these
    /// capabilities: the first is the one its call is authorized for.
    pub(crate) fn name_operator(&self, capabilities: &[Capability]) -> AdminCaller {
        let token = complete(create_administrator(
            &self.app,
            "acme",
            self.scope,
            "operator",
            capabilities,
        ));
        complete(authorize_admin_call(
            &self.app,
            "acme",
            Some(&token),
            capabilities[0],
        ))
        .expect("an administrator")
    }

    /// Signs `ada` in through `webapp`, granted `scope`.
    pub(crate) fn sign_in(&self, scope: &str) -> SignedInApplication {
        let flow = CodeFlow {
            realm: "acme",
            client_id: "webapp",
            client_secret: None,
            redirect_uri: CALLBACK,
            scope,
            username: "ada",
            password: PASSWORD,
        };
        complete(run_code_flow(&self.app, flow))
    }

    pub(crate) fn copy_service_secret(&self) -> Secret {
        Secret::new(self.service_secret.expose().to_vec())
    }

    /// The secret of `billing` in the Basic scheme, as it registered it.
    pub(crate) fn present_service_secret(&self) -> PresentedProof<'static> {
        PresentedProof {
            secret: Some(PresentedSecret::Basic(self.copy_service_secret())),
            ..PresentedProof::default()
        }
    }

    /// Registers `partner`, a public application that requires the consent
    /// of each person: the only kind of client a grant offline is given to.
    pub(crate) fn register_partner(&self) {
        let partner = Application {
            client_id: "partner",
            redirect_uri: CALLBACK,
            post_logout_redirect_uri: None,
            public: true,
            requires_consent: true,
        };
        complete(register_application(&self.app, self.scope, partner));
    }

    /// Signs `ada` in for the public client `client_id`, which asks her to
    /// consent again (`prompt=consent`), and has her allow it `scope` on the
    /// page. Returns the code the client is sent back with, and her ticket.
    pub(crate) fn allow_on_the_page(
        &self,
        client_id: &str,
        scope: &str,
    ) -> (String, SessionTicket) {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use super::authorize::{
            Authorization, AuthorizationParameters, SignInAnswer, SignInStep, TypedSignIn,
            begin_authorization, finish_sign_in,
        };
        use crate::consent::answer::{ConsentDecision, answer_consent, describe_consent};

        let challenge = URL_SAFE_NO_PAD.encode(self.app.digester.sha256(VERIFIER.as_bytes()));
        let parameters = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(client_id),
            redirect_uri: Some(CALLBACK),
            scope: Some(scope),
            nonce: Some("a-nonce"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            prompt: Some("consent"),
            ..AuthorizationParameters::default()
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(&self.app, "acme", parameters, None))
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
        let step = complete(finish_sign_in(
            &self.app,
            "acme",
            request,
            &browser_secret,
            typed,
        ))
        .expect("a signed-in person");
        let SignInStep::ConsentRequired(signed_in) = step else {
            panic!("asked to consent again, the person answers on the page: {step:?}");
        };
        let shown = complete(describe_consent(
            &self.app,
            "acme",
            request,
            &browser_secret,
            Some(&signed_in.ticket),
        ))
        .expect("the page")
        .shown;
        let location = complete(answer_consent(
            &self.app,
            "acme",
            request,
            &browser_secret,
            Some(&signed_in.ticket),
            ConsentDecision::Allow { shown },
        ))
        .expect("an allowed client");
        let code = location
            .read_parameter("code")
            .expect("a code in the answer")
            .to_owned();
        (code, signed_in.ticket)
    }

    /// Exchanges a code as the public client `client_id`.
    pub(crate) fn exchange_as(&self, client_id: &str, code: &str) -> TokenResponse {
        let exchange = TokenRequest {
            grant_type: Some("authorization_code"),
            client_id: Some(client_id),
            code: Some(code),
            redirect_uri: Some(CALLBACK),
            code_verifier: Some(VERIFIER),
            ..TokenRequest::default()
        };
        complete(grant_token(&self.app, "acme", exchange)).expect("tokens for the code")
    }

    /// As [`Self::allow_on_the_page`], and the code is exchanged.
    pub(crate) fn sign_in_and_consent(&self, client_id: &str, scope: &str) -> SignedInApplication {
        let (code, ticket) = self.allow_on_the_page(client_id, scope);
        SignedInApplication {
            tokens: self.exchange_as(client_id, &code),
            ticket,
            code,
        }
    }

    /// Whether the service `billing` is told that a token stands.
    pub(crate) fn is_token_active(&self, token: &str) -> bool {
        complete(super::introspect::introspect_token(
            &self.app,
            "acme",
            Some("billing"),
            self.present_service_secret(),
            Some(token),
        ))
        .expect("an answer")
        .active
    }

    /// Ends the session of `ticket`, as a sign-out does.
    pub(crate) fn end_session(&self, ticket: &SessionTicket) {
        let mut work = complete(self.app.storage.begin(self.scope)).expect("a unit of work");
        let session = complete(work.read_session(ticket.session))
            .expect("a read")
            .expect("the session")
            .session;
        complete(close_session(&self.app, work.as_mut(), &session)).expect("an ended session");
        complete(work.commit()).expect("a commit");
    }

    /// Presents a refresh token as `client_id`, which is public.
    pub(crate) fn refresh_as(
        &self,
        client_id: &str,
        refresh_token: &str,
        scope: Option<&str>,
    ) -> Result<TokenResponse, OAuthError> {
        let request = TokenRequest {
            grant_type: Some("refresh_token"),
            client_id: Some(client_id),
            refresh_token: Some(refresh_token),
            scope,
            ..TokenRequest::default()
        };
        complete(grant_token(&self.app, "acme", request)).map_err(|failure| failure.error)
    }

    pub(crate) fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, OAuthError> {
        self.refresh_as("webapp", refresh_token, None)
    }

    /// The code the application holding `typed_secret` shows now.
    pub(crate) fn read_code_now(&self, typed_secret: &str) -> String {
        let seconds = u64::try_from(self.app.now().unix_timestamp()).expect("after 1970");
        PredictableCodes::compute_from_text(typed_secret, seconds)
    }

    /// Enrolls an authenticator for whoever holds `ticket`, and returns its
    /// secret as the person's application keeps it. The clock then moves to
    /// the next step: the code that confirmed is spent.
    pub(crate) fn enroll_authenticator(&self, ticket: &SessionTicket) -> String {
        let offered = complete(begin_totp_enrollment(&self.app, "acme", Some(ticket)))
            .expect("a secret to enroll");
        let code = self.read_code_now(&offered.typed_secret);
        complete(confirm_totp_enrollment(
            &self.app,
            "acme",
            Some(ticket),
            Secret::new(PASSWORD.as_bytes().to_vec()),
            &code,
            None,
            &[],
        ))
        .expect("a confirmed authenticator");
        self.clock.advance(std::time::Duration::from_secs(30));
        offered.typed_secret
    }

    /// Signs `ada` in again with her password, then the code of the
    /// application holding `typed_secret`, and returns the new ticket.
    pub(crate) fn sign_in_with_code(&self, typed_secret: &str) -> SessionTicket {
        use crate::login::flow::{FirstStep, finish_sign_in_with_code, sign_in_with_password};

        let step = complete(sign_in_with_password(
            &self.app,
            self.scope,
            "ada",
            Secret::new(PASSWORD.as_bytes().to_vec()),
            None,
            &[],
        ))
        .expect("a right password");
        let FirstStep::SecondFactorRequired(owed) = step else {
            panic!("ada set up an authenticator: she owes a code");
        };
        complete(finish_sign_in_with_code(
            &self.app,
            self.scope,
            owed.person.id,
            &self.read_code_now(typed_secret),
            None,
            &[],
        ))
        .expect("a right code")
        .ticket
    }

    /// Enrolls the security key `credential_id` for whoever holds `ticket`.
    pub(crate) fn enroll_security_key(&self, ticket: &SessionTicket, credential_id: &str) {
        let options = complete(begin_key_enrollment(
            &self.app,
            "acme",
            Some(ticket),
            Secret::new(PASSWORD.as_bytes().to_vec()),
            None,
            &[],
        ))
        .expect("a started enrollment");
        let answer = TrustingKeys::answer_enrollment(&options, credential_id);
        complete(finish_key_enrollment(
            &self.app,
            "acme",
            Some(ticket),
            &answer,
        ))
        .expect("an enrolled key");
    }

    /// Signs `ada` in again with her password, then the key `credential_id`
    /// whose counter is now `counter`, and returns the new ticket.
    pub(crate) fn sign_in_with_key(&self, credential_id: &str, counter: u64) -> SessionTicket {
        use crate::login::flow::{FirstStep, finish_sign_in_with_key, sign_in_with_password};

        let step = complete(sign_in_with_password(
            &self.app,
            self.scope,
            "ada",
            Secret::new(PASSWORD.as_bytes().to_vec()),
            None,
            &[],
        ))
        .expect("a right password");
        let FirstStep::SecondFactorRequired(owed) = step else {
            panic!("ada holds a key: she owes its answer");
        };
        let asked = owed.key.expect("a started proof");
        let answer = TrustingKeys::answer_proof(&asked.options, credential_id, counter);
        complete(finish_sign_in_with_key(
            &self.app,
            self.scope,
            owed.person.id,
            &asked.state,
            &answer,
            None,
            &[],
        ))
        .expect("a right answer")
        .ticket
    }

    /// Signs `ada` in through the public client `client_id`, granted
    /// `scope`, naming `claims`, and exchanges the code.
    pub(crate) fn sign_in_naming(
        &self,
        client_id: &str,
        scope: &str,
        claims: &str,
    ) -> SignedInApplication {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use super::authorize::{
            Authorization, AuthorizationParameters, SignInAnswer, TypedSignIn, begin_authorization,
            finish_sign_in,
        };

        let challenge = URL_SAFE_NO_PAD.encode(self.app.digester.sha256(VERIFIER.as_bytes()));
        let parameters = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(client_id),
            redirect_uri: Some(CALLBACK),
            scope: Some(scope),
            nonce: Some("a-nonce"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            claims: Some(claims),
            ..AuthorizationParameters::default()
        };
        let Ok(Authorization::SignInRequired {
            request,
            browser_secret,
        }) = complete(begin_authorization(&self.app, "acme", parameters, None))
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
        let finished = complete(finish_sign_in(
            &self.app,
            "acme",
            request,
            &browser_secret,
            typed,
        ))
        .expect("a signed-in person")
        .into_finished()
        .expect("a finished request");
        let code = finished
            .response
            .read_parameter("code")
            .expect("a code in the answer")
            .to_owned();
        SignedInApplication {
            tokens: self.exchange_as(client_id, &code),
            ticket: finished.ticket,
            code,
        }
    }

    /// Asks the public client `client_id` for a code, granted `scope` and
    /// naming `claims` when given, in the session of `ticket`, which answers;
    /// and exchanges the code.
    pub(crate) fn grant_in_session(
        &self,
        client_id: &str,
        scope: &str,
        claims: Option<&str>,
        ticket: &SessionTicket,
    ) -> TokenResponse {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use super::authorize::{Authorization, AuthorizationParameters, begin_authorization};

        let challenge = URL_SAFE_NO_PAD.encode(self.app.digester.sha256(VERIFIER.as_bytes()));
        let parameters = AuthorizationParameters {
            response_type: Some("code"),
            client_id: Some(client_id),
            redirect_uri: Some(CALLBACK),
            scope: Some(scope),
            nonce: Some("a-nonce"),
            code_challenge: Some(&challenge),
            code_challenge_method: Some("S256"),
            claims,
            ..AuthorizationParameters::default()
        };
        let begun = complete(begin_authorization(
            &self.app,
            "acme",
            parameters,
            Some(ticket),
        ));
        let Ok(Authorization::Granted { response }) = begun else {
            panic!("the session answers: {begun:?}");
        };
        let code = response.read_parameter("code").expect("a code").to_owned();
        self.exchange_as(client_id, &code)
    }

    /// Registers `lean`, a public application that requires no consent and
    /// may be given `openid` and `profile` alone.
    pub(crate) fn register_lean(&self) {
        use crate::clients::register::NewClient;
        use crate::testkit::fixtures::check_and_register_client;

        let (scopes, callbacks) = (
            ["openid".to_owned(), "profile".to_owned()],
            [CALLBACK.to_owned()],
        );
        let mut work = complete(self.app.storage.begin(self.scope)).expect("a unit of work");
        let wanted = NewClient {
            client_id: "lean",
            name: "lean",
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: None,
            response_types: &[],
            public: true,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: None,
        };
        complete(check_and_register_client(&self.app, work.as_mut(), wanted))
            .expect("an application");
        complete(work.commit()).expect("a commit");
    }

    /// Registers `client_id`, a public application that requires no consent,
    /// sent back to the callback, and loaded at `frontchannel` when a session
    /// it served ends.
    pub(crate) fn register_framed(&self, client_id: &str, frontchannel: Option<&str>) {
        use crate::clients::register::NewClient;
        use crate::testkit::fixtures::check_and_register_client;

        let (scopes, callbacks) = (["openid".to_owned()], [CALLBACK.to_owned()]);
        let mut work = complete(self.app.storage.begin(self.scope)).expect("a unit of work");
        let wanted = NewClient {
            client_id,
            name: client_id,
            scopes: &scopes,
            capabilities: &[],
            redirect_uris: &callbacks,
            post_logout_redirect_uris: &[],
            frontchannel_logout_uri: frontchannel,
            response_types: &[],
            public: true,
            requires_consent: false,
            id_token_signed_response_alg: None,
            auth_method: None,
            jwks: None,
            jwks_uri: None,
            auth_signing_alg: None,
            request_object_signing_alg: None,
            require_signed_request_object: false,
            created_by: None,
        };
        complete(check_and_register_client(&self.app, work.as_mut(), wanted))
            .expect("an application");
        complete(work.commit()).expect("a commit");
    }

    /// The clients the session of `ticket` served, as its ending reads them.
    pub(crate) fn list_served(&self, ticket: &SessionTicket) -> Vec<String> {
        let mut work = complete(self.app.storage.begin(self.scope)).expect("a unit of work");
        complete(work.list_served_clients(ticket.session, 100))
            .expect("a read")
            .first
            .into_iter()
            .map(|served| served.client_id)
            .collect()
    }

    /// Writes the attributes of `ada`, in place of those she had.
    pub(crate) fn write_ada_attributes(&self, attributes: &serde_json::Value) {
        let ada = self.find_ada();
        let mut work = complete(self.app.storage.begin(self.scope)).expect("a unit of work");
        complete(work.lock_person_attributes(ada)).expect("a lock");
        let attributes = attributes.as_object().expect("an object");
        complete(work.write_person_attributes(ada, attributes)).expect("attributes");
        complete(work.commit()).expect("a commit");
    }

    /// Gives `client_id` a mapper that writes the attribute `attribute` of
    /// a person as `claim` for `targets`, under `scope`.
    pub(crate) fn map_attribute(
        &self,
        client_id: &str,
        attribute: &str,
        claim: &str,
        targets: &[crate::claims::ClaimTarget],
        scope: &str,
    ) {
        use crate::claims::{Mapper, MapperKind};

        let mapper = Mapper {
            id: crate::ids::mint_id(&self.app).expect("an identifier"),
            client_id: client_id.to_owned(),
            name: claim.to_owned(),
            kind: MapperKind::Attribute {
                attribute: attribute.to_owned(),
            },
            claim: Some(claim.to_owned()),
            targets: targets.to_vec(),
            scope: Some(scope.to_owned()),
            created_at: self.app.now(),
        };
        let mut work = complete(self.app.storage.begin(self.scope)).expect("a unit of work");
        assert_eq!(complete(work.insert_mapper(&mapper)), Ok(true));
        complete(work.commit()).expect("a commit");
    }

    /// The identifier of `ada`.
    pub(crate) fn find_ada(&self) -> uuid::Uuid {
        complete(async {
            let mut work = self
                .app
                .storage
                .begin(self.scope)
                .await
                .expect("a unit of work");
            work.read_person_by_username("ada")
                .await
                .expect("a read")
                .expect("ada")
                .id
        })
    }

    /// The kinds of the events of the realm, in order.
    pub(crate) fn read_event_kinds(&self) -> Vec<String> {
        self.storage
            .read_audit_envelopes(self.scope.realm())
            .iter()
            .filter_map(|event| event["kind"].as_str().map(str::to_owned))
            .collect()
    }
}
