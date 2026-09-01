use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use deadpool_postgres::Pool;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use store::tenancy::{Tenancy, resolve};

use crate::api::config::Sealing;
use crate::api::rest::endpoints::protocol::dto::uncached;

/// What a collector says when it comes by, RFC 8936 §2.4: how much it can
/// take, and which of the last batch it is done with.
#[derive(Debug, Default, Deserialize)]
pub struct Asked {
    #[serde(rename = "maxEvents")]
    pub max_events: Option<i64>,
    pub ack: Option<Vec<String>>,
}

/// Hand a collecting receiver what waits for it, RFC 8936.
///
/// The bearer it presents is the one sealed on its row: the same secret that
/// authenticates a push, presented back as the collector's credential. What
/// it acknowledges is let go before anything is read, so a batch lost on the
/// wire is simply collected again.
pub async fn poll(
    request: HttpRequest,
    realm: web::Path<String>,
    body: Option<web::Json<Asked>>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
) -> HttpResponse {
    let refused = || {
        uncached(&mut HttpResponseBuilder::new(StatusCode::UNAUTHORIZED))
            .json(json!({ "error": "invalid_token" }))
    };
    let Some(presented) = super::basic::bearer(&request) else {
        return refused();
    };
    let asked = body.map(web::Json::into_inner).unwrap_or_default();

    let Ok(mut connection) = pool.get().await else {
        return refused();
    };
    let Ok(context) = resolve::realm_by_name(&connection, &realm).await else {
        return refused();
    };
    let Ok(transaction) = tenancy.transaction(&mut connection, &context).await else {
        return refused();
    };
    let Ok(rows) = store::providers::brokering::list_providers(&transaction).await else {
        return refused();
    };
    // The collector is whichever collecting row's sealed bearer matches what
    // was presented. Nothing about which rows exist leaks on a miss.
    let mut collector = None;
    for row in rows
        .iter()
        .filter(|row| services::caep::is_receiver(row) && row.enabled != Some(false))
    {
        let Ok(receiver) = services::caep::Receiver::parse(row) else {
            continue;
        };
        if receiver.delivery != services::caep::Delivery::Poll {
            continue;
        }
        if crate::federation::opened_bearer(&transaction, &sealing, &context, row)
            .await
            .is_some_and(|held| held == presented)
        {
            collector = Some(row);
            break;
        }
    }
    let Some(row) = collector else {
        return refused();
    };

    if let Some(done) = asked.ack.as_ref().filter(|held| !held.is_empty())
        && store::providers::caep_queue::ack(&transaction, &row.internal_id, done)
            .await
            .is_err()
    {
        return refused();
    }

    let ceiling = asked.max_events.unwrap_or(10).clamp(0, 100);
    let Ok((waiting, more)) =
        store::providers::caep_queue::pending(&transaction, &row.internal_id, ceiling).await
    else {
        return refused();
    };
    if transaction.commit().await.is_err() {
        return refused();
    }

    let sets: Map<String, Value> = waiting
        .into_iter()
        .map(|(jti, set)| (jti, Value::from(set)))
        .collect();
    uncached(&mut HttpResponseBuilder::new(StatusCode::OK)).json(json!({
        "sets": sets,
        "moreAvailable": more,
    }))
}
