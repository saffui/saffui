use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use models::compliance::subject_request::DsarKind;
use services::privacy::{self, Undoored};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::mail::deliver;
use crate::api::rest::endpoints::protocol::page::escaped;

/// What these pages may do: dress themselves from this server and post the
/// form back to it. No code at all: nothing here needs any.
const POLICY: &str = "default-src 'none'; style-src 'self'; \
                      form-action 'self'; frame-ancestors 'none'; \
                      base-uri 'none'";

#[derive(serde::Deserialize)]
pub struct Asking {
    pub username: Option<String>,
    pub kind: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct Confirming {
    pub token: Option<String>,
    pub user: Option<String>,
    pub kind: Option<String>,
}

fn told(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).finish()
}

fn shown(status: StatusCode, body: String) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status))
        .insert_header(("Content-Type", "text/html; charset=utf-8"))
        .insert_header(("Content-Security-Policy", POLICY))
        .insert_header(("X-Content-Type-Options", "nosniff"))
        .insert_header(("X-Frame-Options", "DENY"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .body(body)
}

/// Ask for a confirmation link.
///
/// Answered the same way whether anybody was found or not, and whether a
/// message went out or not, like the reset door and for the same reason.
pub async fn ask_for_link(
    realm: web::Path<String>,
    asked: Option<web::Either<web::Json<Asking>, web::Form<Asking>>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let asked = match asked {
        Some(web::Either::Left(json)) => json.into_inner(),
        Some(web::Either::Right(form)) => form.into_inner(),
        None => return told(StatusCode::BAD_REQUEST),
    };
    let (Some(named), Some(kind)) = (
        asked.username.filter(|held| !held.is_empty()),
        asked.kind.and_then(|held| held.parse::<DsarKind>().ok()),
    ) else {
        return told(StatusCode::BAD_REQUEST);
    };

    let Ok(mut connection) = pool.get().await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(StatusCode::NOT_FOUND);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(Some(held)) = services::realm::named(&transaction, &context.realm_id).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let ring = store::keyring::load(
        &transaction,
        &sealing.envelope,
        &context.tenant,
        &context.realm_id,
    )
    .await
    .ok();
    let settings = match ring {
        Some(ring) => store::providers::mail::load(&transaction, &ring, &sealing.envelope)
            .await
            .ok()
            .flatten(),
        None => None,
    };

    let outgoing = match privacy::offer_link(
        &transaction,
        sealing.provider.as_ref(),
        &held,
        &origin,
        settings.as_ref().filter(|_| sealing.sender.is_some()),
        &named,
        kind,
        now,
    )
    .await
    {
        Ok(outgoing) => outgoing,
        // About the realm, not about who holds an account in it.
        Err(Undoored::NotOffered) => return told(StatusCode::NOT_FOUND),
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if transaction.commit().await.is_err() {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    }
    if let Some(outgoing) = outgoing {
        deliver(&sealing, &pool, &tenancy, &context, outgoing).await;
    }
    told(StatusCode::ACCEPTED)
}

/// Where the mailed link lands: the request said back in words, and one
/// button. The link is not spent here; a mail scanner follows every GET it
/// sees, and a register fed by scanners records nobody's intent.
pub async fn confirmation_page(
    realm: web::Path<String>,
    asked: web::Query<Confirming>,
) -> HttpResponse {
    let asked = asked.into_inner();
    let (Some(token), Some(user), Some(kind)) = (
        asked.token.filter(|held| !held.is_empty()),
        asked.user.filter(|held| !held.is_empty()),
        asked.kind.and_then(|held| held.parse::<DsarKind>().ok()),
    ) else {
        return told(StatusCode::BAD_REQUEST);
    };
    let body = CONFIRM_PAGE
        .replace(
            "{action}",
            &escaped(&format!(
                "/realms/{realm}/protocol/openid-connect/privacy-confirm"
            )),
        )
        .replace("{token}", &escaped(&token))
        .replace("{user}", &escaped(&user))
        .replace("{kind}", kind.as_str())
        .replace("{asked}", worded(kind));
    shown(StatusCode::OK, body)
}

/// Spend the link and lodge the request in the realm's register, verified:
/// only the mailbox's holder could have posted this form.
pub async fn confirm_request(
    realm: web::Path<String>,
    asked: Option<web::Either<web::Json<Confirming>, web::Form<Confirming>>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let now = Utc::now();
    let asked = match asked {
        Some(web::Either::Left(json)) => json.into_inner(),
        Some(web::Either::Right(form)) => form.into_inner(),
        None => return told(StatusCode::BAD_REQUEST),
    };
    let (Some(token), Some(user), Some(kind)) = (
        asked.token.filter(|held| !held.is_empty()),
        asked.user.filter(|held| !held.is_empty()),
        asked.kind.and_then(|held| held.parse::<DsarKind>().ok()),
    ) else {
        return told(StatusCode::BAD_REQUEST);
    };

    let Ok(mut connection) = pool.get().await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return told(StatusCode::NOT_FOUND);
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(Some(held)) = services::realm::named(&transaction, &context.realm_id).await else {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let lodged = match privacy::lodge_from_link(
        &transaction,
        sealing.provider.as_ref(),
        &held,
        &user,
        kind,
        &token,
        now,
    )
    .await
    {
        Ok(lodged) => lodged,
        Err(Undoored::NotOffered) => return told(StatusCode::NOT_FOUND),
        Err(Undoored::NoSuchLink) => {
            return shown(StatusCode::BAD_REQUEST, DEAD_LINK_PAGE.to_owned());
        }
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR),
    };
    if transaction.commit().await.is_err() {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    }
    shown(
        StatusCode::OK,
        LODGED_PAGE.replace("{reference}", &escaped(&lodged.request_id)),
    )
}

/// The request in a subject's words, for the page that asks them to stand
/// by it.
fn worded(kind: DsarKind) -> &'static str {
    match kind {
        DsarKind::Access => "a copy of the personal data held about you",
        DsarKind::Rectification => "a correction of the personal data held about you",
        DsarKind::Erasure => "the erasure of this account and its personal data",
        DsarKind::Objection => "that a use of your personal data be stopped",
        DsarKind::Portability => "your personal data in a portable form",
    }
}

const CONFIRM_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Confirm your privacy request</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>Confirm your privacy request</h1>
<p>Somebody asked for {asked}. Confirming tells us it was you.</p>
<form method="post" action="{action}">
<input type="hidden" name="token" value="{token}">
<input type="hidden" name="user" value="{user}">
<input type="hidden" name="kind" value="{kind}">
<button type="submit">Confirm the request</button>
</form>
<p>If it was not you, close this page and nothing happens.</p>
</main></body></html>
"#;

const LODGED_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Request received</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>Request received</h1>
<p>Your request is in the register under reference
<strong>{reference}</strong>, and runs on the clock the law gives it.</p>
</main></body></html>
"#;

const DEAD_LINK_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Link expired</title>
<link rel="stylesheet" href="login.css"></head>
<body><main><h1>This link no longer works</h1>
<p>It has been used, or it has expired. Ask for another one.</p>
</main></body></html>
"#;
