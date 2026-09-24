use crate::api::rest::endpoints::within;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use config::serving::PublicOrigin;
use serde_json::Value;
use services::scim::groups::{self, AssertedMembers};
use services::scim::{self, Refusal, list_response};
use store::tenancy::Tenancy;

use super::{answered, base_of, filter_of, internal, refuse_unopened_work, refused, window};
use crate::middleware::admin_guard::Admin;

pub async fn list(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };

    let query = request.query_string();
    let (start_index, page) = window(query);
    let matched = match filter_of(query).map(|filter| scim::folded_filter(&filter, true)) {
        None => None,
        Some(Ok(matched)) => Some(matched),
        Some(Err(refusal)) => return refused(&refusal),
    };
    let found = match groups::groups_matching(&transaction, matched, page).await {
        Ok(found) => found,
        Err(refusal) => return refused(&refusal),
    };

    let total = found.len() as i64;
    let mut resources = Vec::with_capacity(found.len());
    for group in &found {
        match groups::shown_with_members(&transaction, &base, group).await {
            Ok(body) => resources.push(body),
            Err(refusal) => return refused(&refusal),
        }
    }
    answered(StatusCode::OK, list_response(start_index, total, resources))
}

pub async fn get(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (realm_id, group_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let shown = match groups::group(&transaction, &group_id).await {
        Ok(group) => groups::shown_with_members(&transaction, &base, &group).await,
        Err(refusal) => Err(refusal),
    };
    match shown {
        Ok(body) => answered(StatusCode::OK, body),
        Err(refusal) => refused(&refusal),
    }
}

pub async fn create(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
    body: web::Json<Value>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let Some(name) = body["displayName"]
        .as_str()
        .map(str::trim)
        .filter(|it| !it.is_empty())
    else {
        return refused(&Refusal::invalid("displayName is required"));
    };
    // Read as named here and judged in order after the group exists, so a
    // name already taken is still what a provisioner hears first.
    let members: Vec<Option<String>> = body["members"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    entry["value"]
                        .as_str()
                        .filter(|it| !it.is_empty())
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();

    let context = within(&admin, &realm_id);
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let created = groups::create_group(
        &transaction,
        &context.tenant,
        &realm_id,
        admin.context.principal.id(),
        name,
        members,
        chrono::Utc::now(),
    )
    .await;
    let shown = match created {
        Ok(group) => groups::shown_with_members(&transaction, &base, &group).await,
        Err(refusal) => Err(refusal),
    };
    match shown {
        Ok(body) => match transaction.commit().await {
            Ok(()) => answered(StatusCode::CREATED, body),
            Err(_) => internal(),
        },
        Err(refusal) => refused(&refusal),
    }
}

pub async fn patch(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, group_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let folded = match scim::folded_group_patch(&body) {
        Ok(folded) => folded,
        Err(refusal) => return refused(&refusal),
    };

    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let shown = match groups::patch_group(&transaction, &group_id, folded).await {
        Ok(fresh) => groups::shown_with_members(&transaction, &base, &fresh).await,
        Err(refusal) => Err(refusal),
    };
    match shown {
        Ok(body) => match transaction.commit().await {
            Ok(()) => answered(StatusCode::OK, body),
            Err(_) => internal(),
        },
        Err(refusal) => refused(&refusal),
    }
}

pub async fn replace(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, group_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let members = match body.get("members") {
        None => AssertedMembers::Absent,
        Some(members) => match members
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        entry["value"]
                            .as_str()
                            .filter(|it| !it.is_empty())
                            .map(str::to_owned)
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .unwrap_or(None)
        {
            Some(wanted) => AssertedMembers::Listed(wanted),
            None => AssertedMembers::Malformed,
        },
    };

    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let replaced = groups::replace_group(
        &transaction,
        &group_id,
        body["displayName"].as_str().filter(|it| !it.is_empty()),
        members,
    )
    .await;
    let shown = match replaced {
        Ok(fresh) => groups::shown_with_members(&transaction, &base, &fresh).await,
        Err(refusal) => Err(refusal),
    };
    match shown {
        Ok(body) => match transaction.commit().await {
            Ok(()) => answered(StatusCode::OK, body),
            Err(_) => internal(),
        },
        Err(refusal) => refused(&refusal),
    }
}

pub async fn delete(
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    path: web::Path<(String, String)>,
) -> HttpResponse {
    let (realm_id, group_id) = path.into_inner();
    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    match groups::remove_group(&transaction, &group_id).await {
        Ok(()) => match transaction.commit().await {
            Ok(()) => HttpResponse::NoContent().finish(),
            Err(_) => internal(),
        },
        Err(refusal) => refused(&refusal),
    }
}
