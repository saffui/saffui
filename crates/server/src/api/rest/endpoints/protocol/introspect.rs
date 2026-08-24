//! RFC 7662: a client asks what a token says.

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Value, json};
use services::introspection::{self, Told, Untellable};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::caller;
use crate::api::rest::endpoints::protocol::dto::{Denied, uncached};

#[derive(Debug, Deserialize)]
pub struct Asked {
    pub token: Option<String>,
    /// RFC 7521 §4.2, when this is how the client authenticates.
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    /// §2.1: a hint the server may ignore, and this one does.
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl Asked {
    fn signed(&self) -> Option<services::client::Signed<'_>> {
        Some(services::client::Signed {
            kind: self.client_assertion_type.as_deref()?,
            assertion: self.client_assertion.as_deref()?,
        })
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn tell(
    request: HttpRequest,
    realm: web::Path<String>,
    asked: Option<web::Form<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<config::serving::PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
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
        asked.signed(),
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
    let Some(token) = asked.token.as_deref().filter(|token| !token.is_empty()) else {
        return Denied::InvalidRequest.answer("token is required");
    };
    let Ok(keys) = services::realm::published_keys(&transaction).await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };

    match introspection::introspect(&transaction, &keys, &client, token, now).await {
        Ok(Told::Active(claims)) => {
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(Value::Object(claims))
        }
        Ok(Told::Inactive) => {
            uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(json!({ "active": false }))
        }
        Err(Untellable::PublicCaller) => {
            Denied::InvalidClient.answer("a public client may not introspect")
        }
        Err(Untellable::Unreadable) => Denied::InvalidRequest.answer("the realm could not be read"),
    }
}
