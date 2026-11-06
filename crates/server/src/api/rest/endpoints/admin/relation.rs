//! The schema of relations of a realm, the relations it keeps, and the
//! clients that guard its types. An object is written `type:id`, a subject
//! `type:id` or `type:id#member`.

use actix_web::dev::JsonBody;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, delete, get, put, web};
use api::{NewRelationSchema, RelationSchemaView, SchemaFaultView};
use saffui_core::app::App as Product;
use saffui_core::authz::capability::Capability;
use saffui_core::authz::relations::schema::SCHEMA_MAX_BYTES;
use saffui_core::authz::relations::{
    self, RelationTuple, SchemaRefusal, read_object, read_subject,
};
use saffui_core::error::{ErrorCode, Failure};
use saffui_core::instant::write_instant;
use serde::Serialize;

use crate::error::render_failure;
use crate::extract::admin::Caller;
use crate::middleware::admin_guard::RequireCapability;

#[derive(Serialize)]
struct FaultsBody {
    code: &'static str,
    error_code: u32,
    message: &'static str,
    faults: Vec<SchemaFaultView>,
}

#[get(
    "/admin/v1/realms/{realm}/relations/schema",
    wrap = "RequireCapability(Capability::PolicyRead)"
)]
pub async fn read_schema(caller: Caller, product: web::Data<Product>) -> HttpResponse {
    match relations::read_relation_schema(&product, caller.scope).await {
        Ok(Some(stored)) => {
            let types = stored
                .open()
                .map(|compiled| compiled.types.into_keys().collect())
                .unwrap_or_default();
            HttpResponse::Ok().json(RelationSchemaView {
                source: stored.source,
                types,
                written_at: write_instant(stored.written_at),
            })
        }
        Ok(None) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

/// The largest body a schema is written in: a source at its bound, each byte
/// of it escaped to six, as `\u0026` is for `&` by an encoder that escapes
/// for HTML, the most an escape of JSON takes for one byte, and room for the
/// object around it.
const SCHEMA_BODY_LIMIT: usize = 6 * SCHEMA_MAX_BYTES + 1024;

/// Read past the limit of the plane, which a source at its bound outgrows
/// once escaped: the guard has let the caller through before the body is read.
#[put(
    "/admin/v1/realms/{realm}/relations/schema",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn write_schema(
    caller: Caller,
    product: web::Data<Product>,
    request: HttpRequest,
    payload: web::Payload,
) -> HttpResponse {
    let mut payload = payload.into_inner();
    let read = JsonBody::<NewRelationSchema>::new(&request, &mut payload, None, true)
        .limit(SCHEMA_BODY_LIMIT)
        .await;
    let Ok(wanted) = read else {
        return render_failure(&ErrorCode::RequestInvalid.into());
    };
    match relations::write_relation_schema(&product, &caller, &wanted.source).await {
        Ok((compiled, removed)) => HttpResponse::Ok().json(serde_json::json!({
            "relations_removed": removed,
            "types": compiled.types.keys().collect::<Vec<_>>(),
        })),
        // The faults are the answer: an administrator reads them to mend the schema.
        Err(SchemaRefusal::Faults(faults)) => {
            let code = ErrorCode::RelationSchemaInvalid;
            HttpResponse::build(StatusCode::BAD_REQUEST).json(FaultsBody {
                code: code.slug(),
                error_code: code.number(),
                message: code.message(),
                faults: faults
                    .into_iter()
                    .map(|fault| SchemaFaultView {
                        line: fault.line,
                        message: fault.message,
                    })
                    .collect(),
            })
        }
        Err(SchemaRefusal::Failed(failure)) => render_failure(&failure),
    }
}

fn read_tuple(object: &str, relation: &str, subject: &str) -> Option<RelationTuple> {
    Some(RelationTuple {
        object: read_object(object)?,
        relation: relation.to_owned(),
        subject: read_subject(subject)?,
    })
}

#[get(
    "/admin/v1/realms/{realm}/relations/{object}/{relation}",
    wrap = "RequireCapability(Capability::PolicyRead)"
)]
pub async fn list_relations(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, object, relation) = path.into_inner();
    let Some(object) = read_object(&object) else {
        return render_failure(&Failure::new(ErrorCode::RelationInvalid));
    };
    match relations::list_relation_subjects(&product, caller.scope, &object, &relation).await {
        Ok((subjects, cut)) => {
            let items: Vec<String> = subjects
                .iter()
                .map(|subject| {
                    let member = subject
                        .member
                        .as_deref()
                        .map_or_else(String::new, |member| format!("#{member}"));
                    format!(
                        "{}:{}{member}",
                        subject.object.object_type, subject.object.object_id
                    )
                })
                .collect();
            // A list cut at its ceiling says so: what is not listed is not absent.
            HttpResponse::Ok().json(serde_json::json!({ "items": items, "cut": cut }))
        }
        Err(failure) => render_failure(&failure),
    }
}

#[put(
    "/admin/v1/realms/{realm}/relations/{object}/{relation}/{subject}",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn write_relation(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String, String)>,
) -> HttpResponse {
    let (_realm, object, relation, subject) = path.into_inner();
    let Some(tuple) = read_tuple(&object, &relation, &subject) else {
        return render_failure(&Failure::new(ErrorCode::RelationInvalid));
    };
    match relations::write_relation(&product, &caller, &tuple).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/relations/{object}/{relation}/{subject}",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn delete_relation(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String, String)>,
) -> HttpResponse {
    let (_realm, object, relation, subject) = path.into_inner();
    let Some(tuple) = read_tuple(&object, &relation, &subject) else {
        return render_failure(&Failure::new(ErrorCode::RelationNotFound));
    };
    match relations::delete_relation(&product, &caller, &tuple).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

#[get(
    "/admin/v1/realms/{realm}/relations/types/{type}/guards",
    wrap = "RequireCapability(Capability::PolicyRead)"
)]
pub async fn list_guards(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (_realm, object_type) = path.into_inner();
    match relations::list_relation_guards(&product, caller.scope, &object_type).await {
        Ok(clients) => HttpResponse::Ok().json(serde_json::json!({ "items": clients })),
        Err(failure) => render_failure(&failure),
    }
}

#[put(
    "/admin/v1/realms/{realm}/relations/types/{type}/guards/{client}",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn write_guard(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, object_type, client_id) = path.into_inner();
    match relations::write_relation_guard(&product, &caller, &object_type, &client_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}

#[delete(
    "/admin/v1/realms/{realm}/relations/types/{type}/guards/{client}",
    wrap = "RequireCapability(Capability::PolicyWrite)"
)]
pub async fn delete_guard(
    caller: Caller,
    product: web::Data<Product>,
    path: web::Path<(String, String, String)>,
) -> HttpResponse {
    let (_realm, object_type, client_id) = path.into_inner();
    match relations::delete_relation_guard(&product, &caller, &object_type, &client_id).await {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(failure) => render_failure(&failure),
    }
}
