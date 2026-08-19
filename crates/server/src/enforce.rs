//! Where a protected application asks whether its caller may do something.
//!
//! What is asked about comes from the body. Who is asking never does: the
//! subject is the token's, so an application cannot name somebody else and
//! learn what they may do.

use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use serde::{Deserialize, Serialize};
use services::context::Established;
use services::pdp::{Question, Resource, decide};
use store::tenancy::Tenancy;

/// What is being asked about. Tagged, so a body naming neither arm is refused
/// by the parser rather than falling into whichever is written first.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Asked {
    /// May the caller do this to something an application protects?
    Permission {
        server: String,
        resource: String,
        scope: String,
    },
    /// Does the caller stand in this relation to this object?
    Relationship {
        object_type: String,
        object_id: String,
        relation: String,
    },
}

/// One question.
#[derive(Debug, Deserialize)]
pub struct Ask {
    #[serde(flatten)]
    pub about: Asked,
    /// A stable verb, as the record keeps it.
    pub action: String,
    /// Minted by the caller, since nothing below tells two decisions apart.
    pub decision_id: String,
    pub trace_id: Option<String>,
}

/// The reported answer and nothing else. A caller told which policy refused it
/// would read the realm's rules one refusal at a time.
#[derive(Debug, Serialize)]
pub struct Told {
    pub decision: &'static str,
}

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
