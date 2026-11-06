//! What the tests of this folder start from: a realm with a person, an
//! application that signs people in, and a service that asks about tokens.

use std::sync::Arc;

use super::errors::OAuthError;
use super::token::{TokenRequest, TokenResponse, grant_token};
use crate::app::App;
use crate::authz::admin::{AdminCaller, authorize_admin_call};
use crate::authz::capability::Capability;
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
