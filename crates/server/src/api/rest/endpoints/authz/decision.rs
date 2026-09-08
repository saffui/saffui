use crate::api::rest::endpoints::authz::dto::{Ask, Asked, Told};
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use services::context::Established;
use services::pdp::{Journal, Question, Resource, decide};
use store::tenancy::Tenancy;

/// Ask.
pub async fn ask(
    established: web::ReqData<Established>,
    pool: web::Data<deadpool_postgres::Pool>,
    tenancy: web::Data<Tenancy>,
    journal: web::Data<Journal>,
    asked: web::Json<Ask>,
) -> Result<HttpResponse, ApiError> {
    let asked = asked.into_inner();

    // An application may ask about itself. Otherwise any token holder harvests
    // another application's decisions, and a permissive one answers yes to all.
    if let Asked::Permission { server, .. } = &asked.about
        && !established
            .verified
            .audiences
            .iter()
            .any(|audience| audience == server)
    {
        return Err(ApiError::new(ErrorCode::AccessDenied));
    }

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &established.context.tenant)
        .await
        .map_err(|_| internal())?;

    // The route map is the realm's own statement of what a path means. A
    // caller naming the permission it faces would name the one it can pass,
    // so the resolution happens here and the answer is a refusal when the
    // realm has said nothing: an unmapped path is not an open one.
    let resolved = match &asked.about {
        Asked::Route { method, path } => {
            let routes = store::providers::authz_routes::routes(&transaction)
                .await
                .map_err(|_| internal())?;
            let Some(route) = services::mesh::matched(&routes, method, path) else {
                return Ok(HttpResponse::Ok().json(Told { decision: "deny" }));
            };
            // The same confinement the named question carries: an
            // application asks about its own routes and no one else's.
            if !established.verified.audiences.contains(&route.server_id) {
                return Err(ApiError::new(ErrorCode::AccessDenied));
            }
            Some(route.clone())
        }
        _ => None,
    };

    let resource = match &asked.about {
        Asked::Permission {
            server,
            resource,
            scope,
        } => Resource::Permission {
            server_id: server,
            resource,
            scope,
        },
        Asked::Relationship {
            object_type,
            object_id,
            relation,
        } => Resource::Relationship {
            object_type,
            object_id,
            relation,
        },
        Asked::Route { .. } => {
            let route = resolved.as_ref().expect("a route resolved above");
            Resource::Permission {
                server_id: &route.server_id,
                resource: &route.resource,
                scope: &route.scope,
            }
        }
    };

    let answer = decide(
        &transaction,
        &journal,
        &established.context,
        Question {
            resource,
            action: resolved
                .as_ref()
                .map_or(asked.action.as_str(), |route| route.action.as_str()),
            decision_id: &asked.decision_id,
            trace_id: asked.trace_id.as_deref(),
        },
    )
    .await
    .map_err(|_| internal())?;

    // The record shares the decision's transaction, so a decision returned over
    // one that never committed is a decision nothing wrote down.
    transaction.commit().await.map_err(|_| internal())?;

    Ok(HttpResponse::Ok().json(Told {
        decision: if answer.permitted() { "permit" } else { "deny" },
    }))
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}
