#[allow(unused_imports)]
use super::support;
use super::support::{AUDIENCE, PARTY, Plane, REALM, SCOPE, claims};
use actix_web::http::StatusCode;
use actix_web::{App, test};
use models::entities::authz::AdminAction;
use server::api::config::{Plane as Mounted, register};
use server::middleware::admin_policy::AdminPolicy;

fn mounted(plane: &Plane) -> Mounted {
    Mounted {
        pool: plane.pool(),
        tenancy: plane.tenancy(),
        policy: AdminPolicy {
            audiences: vec![AUDIENCE.to_owned()],
            parties: vec![PARTY.to_owned()],
            scope: SCOPE.to_owned(),
        },
        origin: support::origin(),
        login_ui: support::login_ui(),
        hops: config::proxying::Proxying::none(),
        egress: config::serving::Egress::Outward,
        sealing: support::sealing(),
    }
}

/// Every action the catalogue holds, so the walk below is refused for
/// having crossed a realm and never for lacking a capability. A caller that
/// holds nothing would be refused either way, and the test would pass while
/// proving nothing.
fn everything() -> Vec<AdminAction> {
    AdminAction::ALL.to_vec()
}

/// No route lets a token reach a realm other than the one that minted it.
///
/// The route table itself is walked rather than a chosen sample: the
/// invariant is that no route may forget, and a sample only says that the
/// ones somebody thought of did not. A route added tomorrow is covered by
/// this test the moment it joins the table.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn no_route_serves_a_realm_the_token_did_not_come_from() {
    let plane = Plane::with_actions(&everything()).await;
    plane.plant_realm("elsewhere").await;
    let bearer = plane.token(&claims());
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;

    let mut walked = 0;
    let mut reached = Vec::new();
    for route in server::api::routes::routes() {
        // Only the routes that name a realm are about this boundary; the
        // handful that speak for the deployment are the next slice's.
        if !route.pattern.contains("{realm}") {
            continue;
        }
        // Every other placeholder gets a name nothing answers to, so a 404
        // from the handler cannot be mistaken for the guard's refusal: the
        // guard runs first, and its answer is the one under test.
        let path = route
            .pattern
            .replace("{realm}", "elsewhere")
            .split('/')
            .map(|segment| {
                if segment.starts_with('{') {
                    "nothing-answers-to-this"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/");

        let asked = test::TestRequest::default()
            .method(route.method.clone())
            .uri(&path)
            .insert_header(("authorization", format!("Bearer {bearer}")))
            .set_json(serde_json::json!({}))
            .to_request();
        let answered = test::call_service(&app, asked).await.status();
        walked += 1;
        // The guard's own refusal and nothing else. A handler answering
        // "no such thing" would also be a non-success, and a test that
        // accepted it would pass on routes the boundary never reached.
        if answered != StatusCode::FORBIDDEN {
            reached.push(format!("{} {path} -> {answered}", route.method));
        }
    }

    assert!(walked > 200, "the walk covered only {walked} routes");
    assert!(
        reached.is_empty(),
        "{} of {walked} routes did not refuse a foreign realm:\n{}",
        reached.len(),
        reached.join("\n")
    );
}

/// And the caller still reaches its own realm, so the refusal above is a
/// boundary and not an outage.
#[tokio::test]
#[ignore = "needs a database (SAFFUI_TEST_PG)"]
async fn the_caller_still_reaches_its_own_realm() {
    let plane = Plane::with_actions(&[AdminAction::UserRead]).await;
    let bearer = plane.token(&claims());
    let app = test::init_service(App::new().configure(register(&mounted(&plane)))).await;

    let asked = test::TestRequest::get()
        .uri(&format!("/admin/realms/{REALM}/users"))
        .insert_header(("authorization", format!("Bearer {bearer}")))
        .to_request();
    assert_eq!(
        test::call_service(&app, asked).await.status(),
        StatusCode::OK
    );
}
