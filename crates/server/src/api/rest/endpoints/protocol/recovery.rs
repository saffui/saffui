use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use config::serving::PublicOrigin;
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use services::recovery::{self, Unrecoverable};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;
use crate::api::rest::endpoints::protocol::mail::deliver;

#[derive(serde::Deserialize)]
pub struct Asking {
    pub username: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct Setting {
    pub token: Option<String>,
    pub user: Option<String>,
    pub password: Option<String>,
}

fn told(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).finish()
}

/// Ask for a link.
///
/// Answered the same way whether anybody was found or not, and whether a
/// message went out or not. Anything else is a way to read a realm's list of
/// people off how this server replies.
pub async fn ask_for_link(
    realm: web::Path<String>,
    asked: Option<web::Either<web::Json<Asking>, web::Form<Asking>>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
) -> HttpResponse {
    let now = Utc::now();
    let named = match asked {
        Some(web::Either::Left(json)) => json.into_inner().username,
        Some(web::Either::Right(form)) => form.into_inner().username,
        None => None,
    };
    let Some(named) = named.filter(|held| !held.is_empty()) else {
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

    let outgoing = match recovery::offer_link(
        &transaction,
        sealing.provider.as_ref(),
        &held,
        &origin,
        settings.as_ref().filter(|_| sealing.sender.is_some()),
        &named,
        now,
    )
    .await
    {
        Ok(outgoing) => outgoing,
        // The one answer that is not the same: a realm that does not offer
        // this at all says so, which is about the realm and not about who
        // holds an account in it.
        Err(Unrecoverable::NotOffered) => return told(StatusCode::NOT_FOUND),
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

/// Spend the link and set the password.
pub async fn set_password(
    realm: web::Path<String>,
    asked: Option<web::Either<web::Json<Setting>, web::Form<Setting>>>,
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
    let (Some(token), Some(user), Some(password)) = (
        asked.token.filter(|held| !held.is_empty()),
        asked.user.filter(|held| !held.is_empty()),
        asked.password.filter(|held| !held.is_empty()),
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

    match recovery::set_from_link(
        &transaction,
        sealing.provider.as_ref(),
        &held,
        &user,
        &token,
        &SecretBox::new(Box::new(password)),
        now,
    )
    .await
    {
        Ok(()) => {}
        Err(Unrecoverable::NotOffered) => return told(StatusCode::NOT_FOUND),
        Err(Unrecoverable::NoSuchLink) => {
            return uncached(&mut HttpResponseBuilder::new(StatusCode::BAD_REQUEST))
                .json(serde_json::json!({ "status": "no-such-link" }));
        }
        Err(Unrecoverable::Refused(why)) => {
            return uncached(&mut HttpResponseBuilder::new(StatusCode::BAD_REQUEST))
                .json(serde_json::json!({ "status": "refused", "reason": why }));
        }
        Err(_) => return told(StatusCode::INTERNAL_SERVER_ERROR),
    }
    if transaction.commit().await.is_err() {
        return told(StatusCode::INTERNAL_SERVER_ERROR);
    }
    told(StatusCode::NO_CONTENT)
}
