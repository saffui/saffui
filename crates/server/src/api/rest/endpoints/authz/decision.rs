//! Where a protected application asks whether its caller may do something.
//!
//! What is asked about comes from the body. Who is asking never does: the
//! subject is the token's, so an application cannot name somebody else and
//! learn what they may do.

use crate::api::rest::endpoints::authz::dto::{Ask, Asked, Told};
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use services::context::Established;
use services::pdp::{Question, Resource, decide};
use store::tenancy::Tenancy;

/// Ask.
pub async fn ask(
    established: web::ReqData<Established>,
    pool: web::Data<deadpool_postgres::Pool>,
    tenancy: web::Data<Tenancy>,
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
    };

    let answer = decide(
        &transaction,
        &established.context,
        Question {
            resource,
            action: &asked.action,
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
