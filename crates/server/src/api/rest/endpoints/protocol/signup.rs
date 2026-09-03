//! The self-registration door, where the realm opens one.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, HttpResponseBuilder, web};
use deadpool_postgres::Pool;
use secrecy::SecretBox;
use serde::Deserialize;
use services::signup::{self, Unregistrable};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;

#[derive(Debug, Deserialize)]
pub struct Asking {
    pub username: Option<String>,
    pub email: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub password: Option<String>,
}

fn told(status: StatusCode) -> HttpResponse {
    uncached(&mut HttpResponseBuilder::new(status)).finish()
}

/// Create an account from the outside, on the realm's terms.
///
/// Refusals that name their reason are the ones that cannot enumerate:
/// a taken username, a policy the password fails. A held address, where
/// the realm verifies addresses, answers exactly like a fresh one.
pub async fn register(
    realm: web::Path<String>,
    asked: Option<web::Either<web::Json<Asking>, web::Form<Asking>>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let asked = match asked {
        Some(web::Either::Left(json)) => json.into_inner(),
        Some(web::Either::Right(form)) => form.into_inner(),
        None => return told(StatusCode::BAD_REQUEST),
    };
    let (Some(email), Some(password)) = (
        asked.email.clone().filter(|held| !held.is_empty()),
        asked.password.clone().filter(|held| !held.is_empty()),
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

    let outcome = signup::register_person(
        &transaction,
        sealing.provider.as_ref(),
        &held,
        signup::Asked {
            username: asked.username.as_deref(),
            email: &email,
            given_name: asked.given_name.as_deref(),
            family_name: asked.family_name.as_deref(),
            password: &SecretBox::new(Box::new(password)),
        },
    )
    .await;

    match outcome {
        Ok(registered) => {
            if transaction.commit().await.is_err() {
                return told(StatusCode::INTERNAL_SERVER_ERROR);
            }
            uncached(&mut HttpResponseBuilder::new(StatusCode::CREATED))
                .json(serde_json::json!({ "status": "registered", "verify": registered.verify }))
        }
        // The door the realm keeps closed is a page that is not there.
        Err(Unregistrable::NotOffered) => told(StatusCode::NOT_FOUND),
        Err(
            why @ (Unregistrable::NameTaken
            | Unregistrable::AddressHeld
            | Unregistrable::Refused(_)
            | Unregistrable::Invalid(_)),
        ) => uncached(&mut HttpResponseBuilder::new(StatusCode::BAD_REQUEST))
            .json(serde_json::json!({ "status": "refused", "reason": why.to_string() })),
        Err(Unregistrable::Unwritable) => told(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
