//! RFC 7009: a client takes back a token it was issued.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use models::entities::keys::KeyUse;
use serde::Deserialize;
use services::revocation::{self, Unrevokable};
use store::providers::realm_keys;
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::caller;
use crate::api::rest::endpoints::protocol::dto::{Denied, uncached};

#[derive(Debug, Deserialize)]
pub struct Asked {
    pub token: Option<String>,
    /// §2.1: a hint the server may ignore, and this one does.
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn take_back(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let now = Utc::now();
    let Ok(mut connection) = pool.get().await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return Denied::InvalidClient.answer("the client could not be authenticated");
    };
    let Some(asked) = asked else {
        return Denied::InvalidRequest.answer("the body could not be read as a form");
    };
    let (transaction, client) = match caller::establish(
        &request,
        asked.client_id.as_deref(),
        asked.client_secret.clone(),
        &mut connection,
        &tenancy,
        sealing.provider.as_ref(),
        &context,
        now,
    )
    .await
    {
        Ok(established) => established,
        Err(response) => return response,
    };
    let Some(token) = asked.token.as_deref().filter(|token| !token.is_empty()) else {
        return Denied::InvalidRequest.answer("token is required");
    };
    let Ok(keys) = realm_keys::published(&transaction, KeyUse::Sig).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };

    match revocation::revoke(&transaction, &keys, &client, token, now).await {
        Ok(()) => {
            if transaction.commit().await.is_err() {
                return Denied::InvalidRequest.answer("the revocation could not be written");
            }
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).finish()
        }
        Err(Unrevokable::NotTheHolder) => {
            Denied::UnauthorizedClient.answer("the token was not issued to this client")
        }
        Err(Unrevokable::Unwritable) => {
            Denied::InvalidRequest.answer("the revocation could not be written")
        }
    }
}
