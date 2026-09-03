use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use serde_json::json;
use store::tenancy::{Tenancy, resolve};

use config::serving::LoginUi;

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::{Denied, uncached};
use crate::api::rest::endpoints::protocol::{binding, caller, i18n, page};

/// How long the login a typed code opens may sit half finished; the cookie
/// lives as long as the row.
const LOGIN_LIFESPAN: i64 = 900;

#[derive(serde::Deserialize)]
pub struct Opening {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    pub scope: Option<String>,
}

/// RFC 8628 §3.1, the door a device knocks on. The client authenticates the
/// way it does at `/token`; what comes back is the long secret it will poll
/// with and the short code its person will type somewhere better.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn open(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Form<Opening>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<config::serving::PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(body) = body.map(web::Form::into_inner) else {
        return Denied::InvalidRequest.answer("the body could not be read as a form");
    };
    let Ok(mut connection) = pool.get().await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return Denied::InvalidClient.answer("the client could not be authenticated");
    };
    let (transaction, client) = match caller::establish(
        &request,
        body.client_id.as_deref(),
        body.client_secret,
        body.client_assertion_type
            .as_deref()
            .zip(body.client_assertion.as_deref())
            .map(|(kind, assertion)| services::client::Signed { kind, assertion }),
        &mut connection,
        &tenancy,
        &sealing,
        &origin,
        **egress,
        &context,
        now,
    )
    .await
    {
        Ok(established) => established,
        Err(response) => return response,
    };

    let opened = match services::device::open(
        &transaction,
        sealing.provider.as_ref(),
        &client,
        body.scope.as_deref(),
        now,
    )
    .await
    {
        Ok(opened) => opened,
        Err(services::device::Unopened::Unauthorized) => {
            return Denied::UnauthorizedClient
                .answer("this client does not sign people in over a device");
        }
        Err(services::device::Unopened::Unreadable) => {
            return Denied::InvalidRequest.answer("the realm could not be read");
        }
    };
    if transaction.commit().await.is_err() {
        return Denied::InvalidRequest.answer("the realm could not be read");
    }

    let at = format!(
        "{}/realms/{}/protocol/openid-connect/device",
        origin.as_str(),
        context.realm_id
    );
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(json!({
        "device_code": opened.device_code,
        "user_code": opened.user_code,
        "verification_uri": at,
        "verification_uri_complete": format!("{at}?user_code={}", opened.user_code),
        "expires_in": opened.expires_in,
        "interval": opened.interval,
    }))
}

/// §3.3, the page a person types the short code into. The code may ride the
/// query off a QR, filling the field; it spends nothing until posted.
pub async fn page(
    request: HttpRequest,
    realm: web::Path<String>,
    pool: web::Data<deadpool_postgres::Pool>,
    tenancy: web::Data<store::tenancy::Tenancy>,
) -> HttpResponse {
    let tongues = super::page::tongues_of_realm(&pool, &tenancy, &realm).await;
    let tongue = tongues.negotiated(
        None,
        request
            .headers()
            .get("accept-language")
            .and_then(|value| value.to_str().ok()),
    );
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Language", tongue))
        .insert_header(("Vary", "Accept-Language"))
        .insert_header((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(i18n::device_page_in(tongue))
}

#[derive(serde::Deserialize)]
pub struct Typed {
    pub user_code: Option<String>,
}

/// §3.3, the typed code. A live one turns into an ordinary login for the
/// device's client, answered on the login page; anything else lands back on
/// the device page saying only that the code does not stand.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn verify(
    _request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Form<Typed>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<config::serving::PublicOrigin>,
    login_ui: web::Data<LoginUi>,
) -> HttpResponse {
    let now = Utc::now();
    let typed = body
        .map(web::Form::into_inner)
        .and_then(|body| body.user_code)
        .unwrap_or_default();
    let back = format!(
        "/realms/{}/protocol/openid-connect/device#no-such-code",
        realm.as_str()
    );
    let Ok(mut connection) = pool.get().await else {
        return sent_back(&back);
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return sent_back(&back);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return sent_back(&back);
    };
    let auth_session_id = match services::device::begin_verification(
        &transaction,
        sealing.provider.as_ref(),
        &context.realm_id,
        &typed,
        now,
    )
    .await
    {
        Ok(opened) => opened,
        Err(_) => return sent_back(&back),
    };
    if transaction.commit().await.is_err() {
        return sent_back(&back);
    }

    let answering = login_ui
        .answering()
        .map(str::to_owned)
        .unwrap_or_else(|| page::location(&origin, &context.realm_id));
    let mut response = HttpResponseBuilder::new(StatusCode::SEE_OTHER);
    binding::set(
        &mut response,
        binding::AUTH_SESSION,
        &auth_session_id,
        &context.realm_id,
        Some(LOGIN_LIFESPAN),
    );
    uncached(&mut response)
        .insert_header(("Location", answering))
        .finish()
}

fn sent_back(location: &str) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(StatusCode::SEE_OTHER))
        .insert_header(("Location", location.to_owned()))
        .finish()
}
