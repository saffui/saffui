use super::support::{self, Plane};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use config::proxying::{Peer, ProxyHeader, Proxying};
use serde_json::Value;
use server::api::config::{Plane as Mounted, register};
use std::time::Duration;
use store::tenancy::{Tenancy, TenantContext};

/// The header a proxy in front states the scheme in, and a peer it speaks
/// from: a request it vouches for reaches its door without the transport
/// reading the realm first.
const SCHEME: &str = "x-forwarded-proto";
const PROXY: &str = "10.0.0.1:443";

fn mounted(tenancy: Tenancy) -> Mounted {
    Mounted {
        tenancy,
        policy: server::middleware::admin_policy::AdminPolicy {
            audiences: vec![support::AUDIENCE.to_owned()],
            parties: vec![support::PARTY.to_owned()],
            scope: support::SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: Proxying::behind_peers(
            1,
            ProxyHeader::XForwardedFor,
            vec![Peer::parse("10.0.0.0/8").expect("a peer")],
        )
        .saying_the_scheme_in(SCHEME),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
        ceiling: support::ceiling(),
    }
}

fn vouched(request: test::TestRequest) -> test::TestRequest {
    request
        .peer_addr(PROXY.parse().expect("an address"))
        .insert_header((SCHEME, "https"))
}

/// With every connection taken, each surface answers 503 in its own words:
/// the catalogue's slug where the catalogue speaks, OAuth's word where OAuth
/// does. None answers as if the token were missing, which would sign a
/// console out over a busy database.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn a_request_that_finds_no_connection_is_told_to_come_back() {
    let plane = Plane::with_actions(&[]).await;
    let tenancy = plane.build_tenancy_of(1, Duration::from_millis(50));
    let _taken = tenancy
        .begin(&TenantContext::new(support::TENANT, support::REALM))
        .await
        .expect("the one connection");
    let app = test::init_service(App::new().configure(register(&mounted(tenancy)))).await;
    let bearer = format!("Bearer {}", plane.token(&support::claims()));
    let realm = support::REALM;
    let oauth = ("error", "temporarily_unavailable");
    let catalogue = ("error_code", "service_unavailable");

    let asked = [
        (
            "the transport, which reads the realm's rule before the account API",
            test::TestRequest::get()
                .uri(&format!("/realms/{realm}/account-api/v1/me"))
                .insert_header(("authorization", bearer.clone())),
            oauth,
        ),
        (
            "the admin guard",
            test::TestRequest::get()
                .uri(&format!("/admin/realms/{realm}/users"))
                .insert_header(("authorization", bearer.clone())),
            catalogue,
        ),
        (
            "the provisioning door",
            vouched(test::TestRequest::get())
                .uri(&format!("/realms/{realm}/scim/v2/Users"))
                .insert_header(("authorization", bearer.clone())),
            catalogue,
        ),
        (
            "the decision point",
            test::TestRequest::post()
                .uri("/authz/decision")
                .insert_header(("authorization", bearer.clone())),
            catalogue,
        ),
        (
            "the account API",
            vouched(test::TestRequest::get())
                .uri(&format!("/realms/{realm}/account-api/v1/me"))
                .insert_header(("authorization", bearer.clone())),
            catalogue,
        ),
        (
            "the token endpoint",
            vouched(test::TestRequest::post())
                .uri(&format!("/realms/{realm}/protocol/openid-connect/token"))
                .set_form([("grant_type", "client_credentials")]),
            oauth,
        ),
        (
            "the registration endpoint",
            vouched(test::TestRequest::post())
                .uri(&format!("/realms/{realm}/protocol/openid-connect/register"))
                .set_json(serde_json::json!({ "redirect_uris": ["https://app.test/cb"] })),
            oauth,
        ),
        (
            "the key set",
            vouched(test::TestRequest::get())
                .uri(&format!("/realms/{realm}/protocol/openid-connect/certs")),
            oauth,
        ),
        (
            "the discovery document",
            test::TestRequest::get()
                .uri(&format!("/realms/{realm}/.well-known/openid-configuration")),
            oauth,
        ),
    ];
    for (door, request, (member, said)) in asked {
        let response = test::call_service(&app, request.to_request()).await;
        let status = response.status();
        let body: Value =
            serde_json::from_slice(&test::read_body(response).await).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{door}: {body}");
        assert_eq!(body[member], said, "{door}: {body}");
    }

    // A browser signing out is shown a page to come back to, and keeps its
    // cookies: nothing was ended, so nothing may say it was.
    let response = test::call_service(
        &app,
        vouched(test::TestRequest::get())
            .uri(&format!("/realms/{realm}/protocol/openid-connect/logout"))
            .insert_header(("accept", "text/html"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response.headers().get("set-cookie").is_none(),
        "a sign-out that ended nothing let go of the cookies"
    );
}
