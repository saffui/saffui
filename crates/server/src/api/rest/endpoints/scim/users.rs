use crate::api::rest::endpoints::within;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use config::serving::PublicOrigin;
use serde_json::Value;
use services::scim::users::{self as people, Birthplace};
use services::scim::{self, AssertedUser, Refusal, list_response};
use store::tenancy::Tenancy;

use super::{answered, base_of, filter_of, internal, refuse_unopened_work, refused, window};
use crate::api::config::Sealing;
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
    let matched = match filter_of(query).map(|filter| scim::folded_filter(&filter, false)) {
        None => None,
        Some(Ok(matched)) => Some(matched),
        Some(Err(refusal)) => return refused(&refusal),
    };
    let found = match people::people_matching(&transaction, matched, page).await {
        Ok(found) => found,
        Err(refusal) => return refused(&refusal),
    };

    let total = found.len() as i64;
    let mut resources = Vec::with_capacity(found.len());
    for person in &found {
        match people::shown_with_groups(&transaction, &base, person).await {
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
    let (realm_id, user_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let shown = match people::person(&transaction, &user_id).await {
        Ok(person) => people::shown_with_groups(&transaction, &base, &person).await,
        Err(refusal) => Err(refusal),
    };
    match shown {
        Ok(body) => answered(StatusCode::OK, body),
        Err(refusal) => refused(&refusal),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn create(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<String>,
    body: web::Json<Value>,
) -> HttpResponse {
    let realm_id = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let asserted = match AssertedUser::read(&body) {
        Ok(asserted) => asserted,
        Err(refusal) => return refused(&refusal),
    };
    let Some(user_name) = asserted.user_name.clone() else {
        return refused(&Refusal::invalid("userName is required"));
    };

    let context = within(&admin, &realm_id);
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let born = people::provision_person(
        &transaction,
        sealing.provider.as_ref(),
        &Birthplace {
            tenant: &context.tenant,
            realm_id: &realm_id,
            by: admin.context.principal.id(),
            now: chrono::Utc::now(),
        },
        &asserted,
        user_name,
    )
    .await;
    let body = match born {
        Ok(person) => people::shown_with_groups(&transaction, &base, &person).await,
        Err(refusal) => Err(refusal),
    };
    match body {
        Ok(body) => match transaction.commit().await {
            Ok(()) => answered(StatusCode::CREATED, body),
            Err(_) => internal(),
        },
        Err(refusal) => refused(&refusal),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn replace(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, user_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let asserted = match AssertedUser::read(&body) {
        Ok(asserted) => asserted,
        Err(refusal) => return refused(&refusal),
    };

    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let replaced = people::replace_person(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        &user_id,
        &asserted,
    )
    .await;
    let shown = match replaced {
        Ok(fresh) => people::shown_with_groups(&transaction, &base, &fresh).await,
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

#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one request"
)]
pub async fn patch(
    request: HttpRequest,
    admin: web::ReqData<Admin>,
    tenancy: web::Data<Tenancy>,
    sealing: web::Data<Sealing>,
    origin: web::Data<PublicOrigin>,
    path: web::Path<(String, String)>,
    body: web::Json<Value>,
) -> HttpResponse {
    let (realm_id, user_id) = path.into_inner();
    let base = base_of(&request, &origin, &realm_id);
    let folded = match scim::folded_user_patch(&body) {
        Ok(folded) => folded,
        Err(refusal) => return refused(&refusal),
    };

    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let patched = people::patch_person(
        &transaction,
        sealing.provider.as_ref(),
        &admin.context.tenant.tenant,
        &realm_id,
        &user_id,
        folded,
    )
    .await;
    let shown = match patched {
        Ok(fresh) => people::shown_with_groups(&transaction, &base, &fresh).await,
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
    let (realm_id, user_id) = path.into_inner();
    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    match people::remove_person(&transaction, &user_id).await {
        Ok(()) => match transaction.commit().await {
            Ok(()) => HttpResponse::NoContent().finish(),
            Err(_) => internal(),
        },
        Err(refusal) => refused(&refusal),
    }
}
