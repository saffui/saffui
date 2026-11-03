//! What the tests of this folder start from: a realm with a person, an
//! application that signs people in, and a service that asks about tokens.

use std::sync::Arc;

use super::errors::OAuthError;
use super::token::{TokenRequest, TokenResponse, grant_token};
use crate::app::App;
use crate::tenancy::RealmScope;
use crate::testkit::clock::FixedClock;
use crate::testkit::drive::complete;
use crate::testkit::fixtures::{
    CodeFlow, SignedInApplication, create_application, create_person, create_realm,
    create_service_client, run_code_flow,
};
use crate::testkit::memory::MemoryStorage;

pub(crate) const CALLBACK: &str = "https://app.example.org/callback";
pub(crate) const PASSWORD: &str = "correct horse battery";

pub(crate) struct Scenario {
    pub(crate) app: App,
    pub(crate) storage: Arc<MemoryStorage>,
    pub(crate) clock: Arc<FixedClock>,
    pub(crate) scope: RealmScope,
}

impl Scenario {
    /// The realm `acme`, the person `ada`, the public application `webapp`
    /// and the service `billing`.
    pub(crate) fn start() -> Self {
        let (app, storage, clock) = MemoryStorage::wire_with_clock();
        let scope = complete(create_realm(&app, "acme"));
        complete(create_person(&app, scope, "ada", PASSWORD));
        complete(create_application(&app, scope, "webapp", CALLBACK, true));
        complete(create_service_client(
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
        }
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

    /// The kinds of the events of the realm, in order.
    pub(crate) fn read_event_kinds(&self) -> Vec<String> {
        self.storage
            .read_audit_envelopes(self.scope.realm())
            .iter()
            .filter_map(|event| event["kind"].as_str().map(str::to_owned))
            .collect()
    }
}
