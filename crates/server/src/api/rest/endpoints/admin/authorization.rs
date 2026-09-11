use crate::api::rest::endpoints::within;
use actix_web::{HttpResponse, web};
use commons::error::ErrorCode;
use commons::http::ApiError;
use deadpool_postgres::Pool;
use models::entities::authz::{
    DecisionStrategy, PolicyEnforcementMode, PolicyTerms, ResourceMutationModel, ScopeMutationModel,
};
use serde::Deserialize;
use services::admin::authorization::{self as authz, Unwritable};
use store::tenancy::{Tenancy, TenantContext};

use crate::api::config::Sealing;
use crate::middleware::admin_guard::Admin;

/// The store speaks in whole sentences about what it refused, and the answer
/// carries them out as the detail: restating a cycle or an unusable window
/// here would only say it worse.
fn refused(why: Unwritable, missing: ErrorCode) -> ApiError {
    match why {
        Unwritable::NoSuchClient => ApiError::new(ErrorCode::ClientNotFound),
        Unwritable::AlreadyProtected => ApiError::new(ErrorCode::ResourceServerAlreadyExists),
        Unwritable::NotFound => ApiError::new(missing),
        Unwritable::StillRead(what) => ApiError::with_detail(ErrorCode::StillGranted, what),
        Unwritable::Refused(what) => ApiError::with_detail(ErrorCode::ValidationError, what),
        Unwritable::Backend => ApiError::new(ErrorCode::InternalError),
    }
}

fn internal() -> ApiError {
    ApiError::new(ErrorCode::InternalError)
}

/// What protecting a client asks: how its absencies decide, and how its
/// policies fold.
#[derive(Debug, Deserialize)]
pub struct Protection {
    pub enforcement_mode: PolicyEnforcementMode,
    pub decision_strategy: DecisionStrategy,
    /// Whether resources under this server may be shared by the people they
    /// belong to. Absent is closed: a deployment that has not said does not
    /// get the wider of the two answers.
    #[serde(default)]
    pub user_managed_access: bool,
}

pub async fn protect(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<Protection>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let made = authz::protect(
        &transaction,
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        &client_id,
        asked.enforcement_mode,
        asked.decision_strategy,
        asked.user_managed_access,
    )
    .await
    .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(made))
}

pub async fn server(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = authz::server(&transaction, &client_id)
        .await
        .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn set_mode(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<Protection>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = authz::set_mode(
        &transaction,
        &client_id,
        admin.context.principal.id(),
        asked.enforcement_mode,
        asked.decision_strategy,
    )
    .await
    .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn unprotect(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, client_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    authz::unprotect(&transaction, &client_id)
        .await
        .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// The nested creations share one shape: the server off the path, a mutation
/// off the body, a drawn identity back.
macro_rules! surface {
    ($create:ident, $list:ident, $rework:ident, $delete:ident,
     $mutation:ty, $create_call:ident, $list_call:ident, $rework_call:ident,
     $delete_call:ident, $missing:ident) => {
        pub async fn $create(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            sealing: web::Data<Sealing>,
            path: web::Path<(String, String)>,
            body: web::Json<$mutation>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, server_id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let made = authz::$create_call(
                &transaction,
                sealing.provider.as_ref(),
                &admin.context.tenant.tenant,
                &realm_id,
                admin.context.principal.id(),
                &server_id,
                body.into_inner(),
            )
            .await
            .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::Created().json(made))
        }

        pub async fn $list(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, server_id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let found = authz::$list_call(&transaction, &server_id)
                .await
                .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
            Ok(HttpResponse::Ok().json(found))
        }

        pub async fn $rework(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String, String)>,
            body: web::Json<$mutation>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, server_id, id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            let made = authz::$rework_call(
                &transaction,
                &server_id,
                &id,
                admin.context.principal.id(),
                body.into_inner(),
            )
            .await
            .map_err(|why| refused(why, ErrorCode::$missing))?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::Ok().json(made))
        }

        pub async fn $delete(
            admin: web::ReqData<Admin>,
            pool: web::Data<Pool>,
            tenancy: web::Data<Tenancy>,
            path: web::Path<(String, String, String)>,
        ) -> Result<HttpResponse, ApiError> {
            let (realm_id, server_id, id) = path.into_inner();
            let mut connection = pool.get().await.map_err(|_| internal())?;
            let transaction = tenancy
                .transaction(&mut connection, &within(&admin, &realm_id))
                .await
                .map_err(|_| internal())?;
            authz::$delete_call(&transaction, &server_id, &id)
                .await
                .map_err(|why| refused(why, ErrorCode::$missing))?;
            transaction.commit().await.map_err(|_| internal())?;
            Ok(HttpResponse::NoContent().finish())
        }
    };
}

surface!(
    add_resource,
    resources,
    rework_resource,
    remove_resource,
    ResourceMutationModel,
    add_resource,
    resources,
    rework_resource,
    remove_resource,
    ResourceNotFound
);
surface!(
    add_scope,
    scopes,
    rework_scope,
    remove_scope,
    ScopeMutationModel,
    add_scope,
    scopes,
    rework_scope,
    remove_scope,
    ScopeNotFound
);

/// A policy's terms, and the organization it is confined to.
#[derive(Debug, Deserialize)]
pub struct PolicyBody {
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(flatten)]
    pub terms: PolicyTerms,
}

pub async fn add_policy(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    path: web::Path<(String, String)>,
    body: web::Json<PolicyBody>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, server_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let made = authz::add_policy(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        admin.context.principal.id(),
        &server_id,
        asked.org_id,
        asked.terms,
    )
    .await
    .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Created().json(made))
}

pub async fn policies(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, server_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let found = authz::policies(&transaction, &server_id)
        .await
        .map_err(|why| refused(why, ErrorCode::ResourceServerNotFound))?;
    Ok(HttpResponse::Ok().json(found))
}

pub async fn rework_policy(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
    body: web::Json<PolicyTerms>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, server_id, policy_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = authz::rework_policy(
        &transaction,
        &server_id,
        &policy_id,
        admin.context.principal.id(),
        body.into_inner(),
    )
    .await
    .map_err(|why| refused(why, ErrorCode::PolicyNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(held))
}

pub async fn remove_policy(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, _server, policy_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    authz::remove_policy(&transaction, &policy_id)
        .await
        .map_err(|why| refused(why, ErrorCode::PolicyNotFound))?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

#[derive(Debug, Deserialize)]
pub struct Window {
    #[serde(default = "hundred")]
    pub limit: i64,
}

fn hundred() -> i64 {
    100
}

/// What the engine decided lately, newest first.
pub async fn decisions(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    window: web::Query<Window>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let found = store::providers::authz_policies::recent(&transaction, window.limit.clamp(1, 1000))
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(found))
}

/// Where what was reported disagreed with what was computed: every decision a
/// permissive mode masked.
pub async fn disagreements(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    window: web::Query<Window>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let found =
        store::providers::authz_policies::disagreements(&transaction, window.limit.clamp(1, 1000))
            .await
            .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(found))
}

/// Where the retention cut lands: strictly before this instant.
#[derive(serde::Deserialize)]
pub struct Retention {
    pub before: chrono::DateTime<chrono::Utc>,
}

/// Let go of decisions older than the named instant. Nothing else prunes
/// the log, so how long the realm remembers is the operator's deliberate
/// act, and the bound is required rather than defaulted: forgetting
/// everything must be asked for in so many words.
pub async fn prune_decisions(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
    asked: web::Query<Retention>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let removed = services::admin::authorization::prune_decisions(&transaction, asked.before)
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "removed": removed })))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvaluationQuestion {
    Policy {
        server_id: String,
        policy_id: String,
    },
    Permission {
        server_id: String,
        resource: String,
        scope: String,
    },
    Relationship {
        object_type: String,
        object_id: String,
        relation: String,
    },
}

#[derive(Deserialize)]
pub struct Evaluation {
    /// Who the question is about; the console asks on their behalf.
    pub subject: Option<String>,
    /// The organization the simulated login would act within, by id.
    pub organization: Option<String>,
    pub question: Option<EvaluationQuestion>,
}

/// Ask the decision engine what it would answer, for a named subject.
///
/// The very engine the exchange consults, on a context built for the subject
/// instead of the caller, so the simulator can never drift from the thing it
/// simulates. The decision is recorded in the decision log like any other,
/// under the action `simulated`: an evaluation is an act worth remembering.
pub async fn evaluate(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    journal: web::Data<services::pdp::Journal>,
    sealing: web::Data<Sealing>,
    path: web::Path<String>,
    body: web::Json<Evaluation>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let asked = body.into_inner();
    let (Some(subject), Some(question)) = (asked.subject, asked.question) else {
        return Err(ApiError::with_detail(
            ErrorCode::ValidationError,
            "subject and question are required".to_owned(),
        ));
    };

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(
            &mut connection,
            &TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        )
        .await
        .map_err(|_| internal())?;

    let person = store::providers::users::load(&transaction, &subject)
        .await
        .map_err(|_| internal())?
        .ok_or_else(|| ApiError::new(ErrorCode::UserNotFound))?;
    let acting = match &asked.organization {
        None => services::context::Acting::RealmWide,
        Some(org) => {
            let member = store::providers::organizations::of_member(&transaction, &person.user_id)
                .await
                .map_err(|_| internal())?
                .contains(org);
            if !member {
                return Err(ApiError::with_detail(
                    ErrorCode::ValidationError,
                    "the subject is not a member of that organization".to_owned(),
                ));
            }
            services::context::Acting::In {
                org_id: org.clone(),
            }
        }
    };
    let context = services::context::Context {
        tenant: TenantContext::new(&admin.context.tenant.tenant, &realm_id),
        session_id: String::new(),
        principal: services::context::Principal::of_user(person),
        acting,
        presenter: None,
        now: chrono::Utc::now(),
    };

    let mut drawn = [0_u8; 16];
    sealing
        .provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| internal())?;
    let decision_id = data_encoding::HEXLOWER.encode(&drawn);

    let resource = match &question {
        EvaluationQuestion::Policy {
            server_id,
            policy_id,
        } => services::pdp::Resource::Policy {
            server_id,
            policy_id,
        },
        EvaluationQuestion::Permission {
            server_id,
            resource,
            scope,
        } => services::pdp::Resource::Permission {
            server_id,
            resource,
            scope,
        },
        EvaluationQuestion::Relationship {
            object_type,
            object_id,
            relation,
        } => services::pdp::Resource::Relationship {
            object_type,
            object_id,
            relation,
        },
    };

    let answer = services::pdp::decide(
        &transaction,
        &journal,
        &context,
        services::pdp::Question {
            resource,
            action: "simulated",
            decision_id: &decision_id,
            trace_id: None,
        },
    )
    .await
    .map_err(|_| internal())?;
    // Where a relationship was asked, walk it a second time for the trace.
    // The decision point itself stays untraced: it answers real enforcement
    // points, and a walk that builds strings for a reader nobody has is a cost
    // every request would pay. A simulation has a reader by definition, and
    // this is the only place that pays for one.
    let walked = match &question {
        EvaluationQuestion::Relationship {
            object_type,
            object_id,
            relation,
        } => walk_of(&transaction, object_type, object_id, relation, &context).await,
        _ => None,
    };

    transaction.commit().await.map_err(|_| internal())?;

    let mut told = serde_json::json!({
        "decision_id": decision_id,
        "reported": answer.reported,
        "computed": answer.computed,
        "detail": answer.detail,
    });
    if let Some(walked) = walked {
        told["walk"] = walked;
    }
    Ok(HttpResponse::Ok().json(told))
}

/// The steps a relationship question took, as the reader of a simulation
/// wants them: in order, with the depth to indent by.
async fn walk_of(
    transaction: &deadpool_postgres::Transaction<'_>,
    object_type: &str,
    object_id: &str,
    relation: &str,
    context: &services::context::Context,
) -> Option<serde_json::Value> {
    let schema = services::rebac::schema_of(transaction).await.ok()?;
    let (answered, steps, cut) = services::rebac::explain(
        transaction,
        &schema,
        services::rebac::Object {
            object_type,
            object_id,
        },
        relation,
        services::rebac::Subject {
            subject_type: context.principal.kind(),
            subject_id: context.principal.id(),
        },
        services::rebac::CHECK,
    )
    .await;
    Some(serde_json::json!({
        "reached": answered.as_ref().ok(),
        "stopped": answered.err().map(|why| why.to_string()),
        "steps": steps,
        "cut": cut,
    }))
}

/// The realm's route map: which permission a request path puts at stake.
pub async fn routes(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let realm_id = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let held = store::providers::authz_routes::routes(&transaction)
        .await
        .map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(
        held.iter()
            .map(|route| {
                serde_json::json!({
                    "route_id": route.route_id,
                    "method": route.method,
                    "path": route.path,
                    "server_id": route.server_id,
                    "resource": route.resource,
                    "scope": route.scope,
                    "action": route.action,
                    "priority": route.priority,
                    "enabled": route.enabled,
                })
            })
            .collect::<Vec<_>>(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct AskedRoute {
    /// An exact verb, or `*`.
    pub method: Option<String>,
    /// An exact path, or a prefix ending in `*`.
    pub path: Option<String>,
    pub server_id: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
    pub action: Option<String>,
    #[serde(default = "a_hundred")]
    pub priority: i32,
    pub enabled: Option<bool>,
}

/// Where a route sits when nobody said: after the ones an operator placed
/// deliberately, before nothing.
fn a_hundred() -> i32 {
    100
}

pub async fn put_route(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
    body: web::Json<AskedRoute>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, route_id) = path.into_inner();
    let asked = body.into_inner();
    let refused =
        |detail: &str| ApiError::with_detail(ErrorCode::ValidationError, detail.to_owned());

    let named = |held: Option<String>, what: &str| -> Result<String, ApiError> {
        held.as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| refused(&format!("{what} says what it is")))
    };
    let method = named(asked.method, "method")?.to_uppercase();
    let route_path = named(asked.path, "path")?;
    let server_id = named(asked.server_id, "server_id")?;
    let resource = named(asked.resource, "resource")?;
    let scope = named(asked.scope, "scope")?;
    let action = asked
        .action
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .unwrap_or("invoke")
        .to_owned();

    // A pattern the matcher cannot read would match nothing and say nothing
    // about why, so it is refused here where there is somebody to tell.
    for (pattern, what) in [(&method, "method"), (&route_path, "path")] {
        if !services::mesh::pattern_reads(pattern) {
            return Err(refused(&format!(
                "{what} is an exact value or a prefix ending in *"
            )));
        }
    }

    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    // The resource server has to be one this realm protects: a route naming
    // a server that does not exist is a route whose decisions could only ever
    // be refusals, written as if they were rules.
    if store::providers::authz_surface::load_server(&transaction, &server_id)
        .await
        .map_err(|_| internal())?
        .is_none()
    {
        return Err(refused("no protected application answers to that name"));
    }
    let route = store::providers::authz_routes::AuthzRoute {
        route_id: route_id.clone(),
        method,
        path: route_path,
        server_id,
        resource,
        scope,
        action,
        priority: asked.priority,
        enabled: asked.enabled.unwrap_or(true),
    };
    store::providers::authz_routes::keep(&transaction, &route, admin.context.principal.id())
        .await
        .map_err(|_| internal())?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "route_id": route_id })))
}

pub async fn delete_route(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, route_id) = path.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;
    let removed = store::providers::authz_routes::drop_route(&transaction, &route_id)
        .await
        .map_err(|_| internal())?;
    if !removed {
        return Err(ApiError::new(ErrorCode::ResourceNotFound));
    }
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Who a resource is being shared with, and as what.
#[derive(Debug, Deserialize)]
pub struct ShareBody {
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    /// Sharing with everybody standing in a relation to something, rather
    /// than with one named subject. Empty is one subject.
    #[serde(default)]
    pub subject_relation: String,
}

fn unshareable(why: services::admin::authorization::Unshareable) -> ApiError {
    use services::admin::authorization::Unshareable;
    let told = match why {
        Unshareable::ServerHoldsIt => {
            "this resource server does not let its resources be shared".to_owned()
        }
        Unshareable::ResourceHoldsIt => "this resource is not user managed".to_owned(),
        Unshareable::NoSchema(why) => format!("no relation graph is published: {why}"),
        Unshareable::UnknownType(named) => {
            format!("the relation graph does not describe '{named}'")
        }
        Unshareable::UnknownRelation { relation, on } => {
            format!("the relation graph describes no '{relation}' on '{on}'")
        }
        Unshareable::NotFound => return ApiError::new(ErrorCode::ResourceNotFound),
        Unshareable::Backend => return internal(),
    };
    ApiError::with_detail(ErrorCode::ValidationError, told)
}

/// Share one user-managed resource, as a relation on it.
pub async fn share(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
    body: web::Json<ShareBody>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, server_id, resource_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;

    services::admin::authorization::share_resource(
        &transaction,
        &server_id,
        &resource_id,
        &asked.relation,
        &store::providers::rebac::Subject {
            subject_type: asked.subject_type,
            subject_id: asked.subject_id,
            subject_relation: asked.subject_relation,
        },
        admin.context.principal.id(),
    )
    .await
    .map_err(unshareable)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}

/// Stop sharing one user-managed resource.
pub async fn unshare(
    admin: web::ReqData<Admin>,
    pool: web::Data<Pool>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String, String)>,
    body: web::Json<ShareBody>,
) -> Result<HttpResponse, ApiError> {
    let (realm_id, server_id, resource_id) = path.into_inner();
    let asked = body.into_inner();
    let mut connection = pool.get().await.map_err(|_| internal())?;
    let transaction = tenancy
        .transaction(&mut connection, &within(&admin, &realm_id))
        .await
        .map_err(|_| internal())?;

    services::admin::authorization::unshare_resource(
        &transaction,
        &server_id,
        &resource_id,
        &asked.relation,
        &store::providers::rebac::Subject {
            subject_type: asked.subject_type,
            subject_id: asked.subject_id,
            subject_relation: asked.subject_relation,
        },
    )
    .await
    .map_err(unshareable)?;
    transaction.commit().await.map_err(|_| internal())?;
    Ok(HttpResponse::NoContent().finish())
}
