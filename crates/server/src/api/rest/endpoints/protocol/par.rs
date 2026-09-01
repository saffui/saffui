use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use chrono::Utc;
use deadpool_postgres::Pool;
use serde_json::{Map, Value, json};
use services::pushed::{self, Unpushable};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::caller;
use crate::api::rest::endpoints::protocol::dto::{Denied, uncached};

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn keep(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Form<Vec<(String, String)>>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<config::serving::PublicOrigin>,
    egress: web::Data<config::serving::Egress>,
) -> HttpResponse {
    let now = Utc::now();
    let Some(body) = body else {
        return Denied::InvalidRequest.answer("the body could not be read as a form");
    };
    let mut parameters = Map::new();
    let (mut client_id, mut client_secret) = (None, None);
    let (mut assertion, mut assertion_type) = (None, None);
    for (named, value) in body.into_inner() {
        match named.as_str() {
            "client_id" => {
                client_id = Some(value.clone());
                parameters.insert(named, Value::String(value));
            }
            "client_secret" => client_secret = Some(value),
            "client_assertion" => assertion = Some(value),
            "client_assertion_type" => assertion_type = Some(value),
            _ => {
                parameters.insert(named, Value::String(value));
            }
        }
    }

    let Ok(mut connection) = pool.get().await else {
        return Denied::InvalidRequest.answer("the realm could not be read");
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return Denied::InvalidClient.answer("the client could not be authenticated");
    };
    let (transaction, client) = match caller::establish(
        &request,
        client_id.as_deref(),
        client_secret,
        assertion_type
            .as_deref()
            .zip(assertion.as_deref())
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

    // RFC 9449 §10.1: a proof pushed here is verified here, and a push that
    // names a key in `dpop_jkt` while proving another has contradicted
    // itself: refused now, when the client still reads a status code.
    if request.headers().get_all("dpop").count() > 1 {
        return Denied::InvalidDpopProof.answer("one proof, exactly");
    }
    if let Some(proof) = request.headers().get("dpop") {
        let Ok(proof) = proof.to_str() else {
            return Denied::InvalidDpopProof.answer("the proof could not be read");
        };
        let proven = services::dpop::proven(
            &transaction,
            sealing.provider.as_ref(),
            proof,
            services::dpop::Bound {
                method: "POST",
                url: &format!(
                    "{}/realms/{}/protocol/openid-connect/par",
                    origin.as_str(),
                    context.realm_id
                ),
                access_token: None,
            },
            now,
        )
        .await;
        match proven {
            Ok(proven) => {
                if parameters
                    .get("dpop_jkt")
                    .and_then(Value::as_str)
                    .is_some_and(|named| named != proven.thumbprint)
                {
                    return Denied::InvalidDpopProof
                        .answer("the push names one key and proves another");
                }
                // §10.1: a proof pushed with the request is the request
                // naming its key, and the code is bound to it as though
                // `dpop_jkt` had spelled it out.
                parameters.insert("dpop_jkt".to_owned(), Value::from(proven.thumbprint));
            }
            Err(why) => {
                tracing::warn!(why = ?why, "dpop proof refused at par");
                return Denied::InvalidDpopProof.answer("the proof does not bind this request");
            }
        }
    }

    match pushed::keep_request(
        &transaction,
        sealing.provider.as_ref(),
        &client,
        &parameters,
        now,
    )
    .await
    {
        Ok((handle, lifespan)) => {
            if transaction.commit().await.is_err() {
                return Denied::InvalidRequest.answer("the request could not be kept");
            }
            uncached(&mut HttpResponseBuilder::new(StatusCode::CREATED))
                .json(json!({ "request_uri": handle, "expires_in": lifespan }))
        }
        Err(
            refusal @ (Unpushable::NotTheClient
            | Unpushable::CarriesAReference
            | Unpushable::AgainstTheProfile(_)),
        ) => Denied::InvalidRequest.answer(&refusal.to_string()),
        Err(Unpushable::Unwritable) => {
            Denied::InvalidRequest.answer("the request could not be kept")
        }
    }
}
