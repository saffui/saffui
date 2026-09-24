use crate::api::rest::endpoints::within;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use config::serving::PublicOrigin;
use models::entities::authz::GroupModel;
use models::entities::user::UserModel;
use serde_json::Value;
use services::scim::{self, GroupPatch, Refusal, list_response, shown_group};
use store::error::StoreError;
use store::providers::directory::{roles, users};
use store::query::list_query::ListQuery;
use store::tenancy::{Tenancy, UnitOfWork};

use super::{answered, base_of, filter_of, internal, refuse_unopened_work, refused, window};
use crate::middleware::admin_guard::Admin;

async fn members_of(transaction: &UnitOfWork, group: &GroupModel) -> Result<Vec<UserModel>, ()> {
    let (people, _) = roles::group_membership(transaction, &group.group_id)
        .await
        .map_err(|_| ())?;
    let mut held = Vec::new();
    for user_id in people {
        if let Some(person) = users::load(transaction, &user_id).await.map_err(|_| ())? {
            held.push(person);
        }
    }
    Ok(held)
}

async fn shown(transaction: &UnitOfWork, base: &str, group: &GroupModel) -> Result<Value, ()> {
    let members = members_of(transaction, group).await?;
    Ok(shown_group(base, group, &members))
}

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
    let found: Vec<GroupModel> = match filter_of(query) {
        Some(filter) => match scim::folded_filter(&filter, true) {
            Ok(scim::Matched::GroupName(name)) => {
                match roles::load_group_by_name(&transaction, &name).await {
                    Ok(held) => held.into_iter().collect(),
                    Err(_) => return internal(),
                }
            }
            Ok(_) => return refused(&Refusal::invalid_filter("groups filter by displayName")),
            Err(refusal) => return refused(&refusal),
        },
        None => match roles::list_groups(&transaction, &ListQuery::new(page), false).await {
            Ok(held) => held.items,
            Err(_) => return internal(),
        },
    };

    let total = found.len() as i64;
    let mut resources = Vec::with_capacity(found.len());
    for group in &found {
        match shown(&transaction, &base, group).await {
            Ok(body) => resources.push(body),
            Err(()) => return internal(),
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
    match roles::load_group(&transaction, &group_id).await {
        Ok(Some(group)) => match shown(&transaction, &base, &group).await {
            Ok(body) => answered(StatusCode::OK, body),
            Err(()) => internal(),
        },
        Ok(None) => refused(&Refusal::not_found()),
        Err(_) => internal(),
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

    let context = within(&admin, &realm_id);
    let transaction = match tenancy.begin(&context).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let mut metadata = models::auditable::AuditableModel::from_creator(
        context.tenant.clone(),
        admin.context.principal.id().to_owned(),
    );
    metadata.created_at = Some(chrono::Utc::now());
    let group = GroupModel {
        group_id: name.to_owned(),
        realm_id: realm_id.clone(),
        name: name.to_owned(),
        display_name: name.to_owned(),
        description: String::new(),
        is_default: false,
        parent_id: None,
        metadata,
    };
    match roles::create_group(&transaction, &group).await {
        Ok(()) => {}
        Err(StoreError::AlreadyExists) => {
            return refused(&Refusal::uniqueness(format!(
                "a group already answers to {name}"
            )));
        }
        Err(_) => return internal(),
    }
    for member in body["members"].as_array().unwrap_or(&Vec::new()) {
        let Some(user_id) = member["value"].as_str().filter(|it| !it.is_empty()) else {
            return refused(&Refusal::invalid("a member names its value"));
        };
        if roles::add_to_group(&transaction, user_id, &group.group_id)
            .await
            .is_err()
        {
            return internal();
        }
    }

    let body = match shown(&transaction, &base, &group).await {
        Ok(body) => body,
        Err(()) => return internal(),
    };
    if transaction.commit().await.is_err() {
        return internal();
    }
    answered(StatusCode::CREATED, body)
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
    let mut group = match roles::load_group(&transaction, &group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => return refused(&Refusal::not_found()),
        Err(_) => return internal(),
    };
    let seats = folded.iter().any(|change| {
        matches!(
            change,
            GroupPatch::AddMembers(_) | GroupPatch::ReplaceMembers(_)
        )
    });
    let standing_before = if seats {
        if store::providers::governance::sod::hold_realm(&transaction)
            .await
            .is_err()
        {
            return internal();
        }
        match roles::group_membership(&transaction, &group_id).await {
            Ok((standing, _)) => standing,
            Err(_) => return internal(),
        }
    } else {
        Vec::new()
    };
    let mut seated: Vec<String> = Vec::new();

    for change in folded {
        let landed = match change {
            GroupPatch::Rename(name) => {
                group.name = name.clone();
                group.display_name = name;
                roles::update_group(&transaction, &group).await.map(|_| ())
            }
            GroupPatch::AddMembers(people) => {
                seated.extend(people.iter().cloned());
                let mut outcome = Ok(());
                for user_id in people {
                    if let Err(why) = roles::add_to_group(&transaction, &user_id, &group_id).await {
                        outcome = Err(why);
                        break;
                    }
                }
                outcome
            }
            GroupPatch::RemoveMembers(people) => {
                let mut outcome = Ok(());
                for user_id in people {
                    if let Err(why) =
                        roles::remove_from_group(&transaction, &user_id, &group_id).await
                    {
                        outcome = Err(why);
                        break;
                    }
                    // A remove of somebody not in the group is the state
                    // asked for, not an error.
                }
                outcome.map(|_| ())
            }
            GroupPatch::ReplaceMembers(people) => {
                seated.extend(people.iter().cloned());
                let mut outcome = roles::group_membership(&transaction, &group_id)
                    .await
                    .map(|(standing, _)| standing);
                if let Ok(standing) = &outcome {
                    for user_id in standing {
                        if roles::remove_from_group(&transaction, user_id, &group_id)
                            .await
                            .is_err()
                        {
                            outcome = Err(store::error::StoreError::Backend);
                            break;
                        }
                    }
                }
                match outcome {
                    Ok(_) => {
                        let mut landed = Ok(());
                        for user_id in people {
                            if let Err(why) =
                                roles::add_to_group(&transaction, &user_id, &group_id).await
                            {
                                landed = Err(why);
                                break;
                            }
                        }
                        landed
                    }
                    Err(why) => Err(why),
                }
            }
        };
        match landed {
            Ok(()) => {}
            Err(StoreError::AlreadyExists) => {
                return refused(&Refusal::uniqueness(format!(
                    "a group already answers to {}",
                    group.name
                )));
            }
            Err(_) => return internal(),
        }
    }
    if let Err(answer) = weigh_seated(&transaction, &group_id, &standing_before, seated).await {
        return answer;
    }

    let shown = match roles::load_group(&transaction, &group_id).await {
        Ok(Some(fresh)) => match shown(&transaction, &base, &fresh).await {
            Ok(body) => body,
            Err(()) => return internal(),
        },
        _ => return internal(),
    };
    if transaction.commit().await.is_err() {
        return internal();
    }
    answered(StatusCode::OK, shown)
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
    let transaction = match tenancy.begin(&within(&admin, &realm_id)).await {
        Ok(transaction) => transaction,
        Err(why) => return refuse_unopened_work(why),
    };
    let mut group = match roles::load_group(&transaction, &group_id).await {
        Ok(Some(group)) => group,
        Ok(None) => return refused(&Refusal::not_found()),
        Err(_) => return internal(),
    };
    if let Some(name) = body["displayName"].as_str().filter(|it| !it.is_empty()) {
        group.name = name.to_owned();
        group.display_name = name.to_owned();
        match roles::update_group(&transaction, &group).await {
            Ok(_) => {}
            Err(StoreError::AlreadyExists) => {
                return refused(&Refusal::uniqueness(format!(
                    "a group already answers to {name}"
                )));
            }
            Err(_) => return internal(),
        }
    }
    if let Some(members) = body.get("members") {
        let wanted: Vec<String> = match members
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
            Some(wanted) => wanted,
            None => return refused(&Refusal::invalid("members is an array of values")),
        };
        if store::providers::governance::sod::hold_realm(&transaction)
            .await
            .is_err()
        {
            return internal();
        }
        let Ok((standing, _)) = roles::group_membership(&transaction, &group_id).await else {
            return internal();
        };
        for user_id in &standing {
            if roles::remove_from_group(&transaction, user_id, &group_id)
                .await
                .is_err()
            {
                return internal();
            }
        }
        for user_id in &wanted {
            if roles::add_to_group(&transaction, user_id, &group_id)
                .await
                .is_err()
            {
                return internal();
            }
        }
        if let Err(answer) = weigh_seated(&transaction, &group_id, &standing, wanted).await {
            return answer;
        }
    }

    let shown = match roles::load_group(&transaction, &group_id).await {
        Ok(Some(fresh)) => match shown(&transaction, &base, &fresh).await {
            Ok(body) => body,
            Err(()) => return internal(),
        },
        _ => return internal(),
    };
    if transaction.commit().await.is_err() {
        return internal();
    }
    answered(StatusCode::OK, shown)
}

/// Weigh the people a write seats in this group anew: they now hold what the
/// group and those above it carry. SCIM applies a request whole or not at all,
/// so one breach refuses all of it. Members already standing are not weighed,
/// the write handing them nothing they did not hold.
async fn weigh_seated(
    transaction: &UnitOfWork,
    group_id: &str,
    standing_before: &[String],
    seated: Vec<String>,
) -> Result<(), HttpResponse> {
    let mut newcomers: Vec<String> = seated
        .into_iter()
        .filter(|user_id| !standing_before.contains(user_id))
        .collect();
    newcomers.sort_unstable();
    newcomers.dedup();
    if newcomers.is_empty() {
        return Ok(());
    }
    let carried = roles::roles_carried_at_or_above(transaction, group_id)
        .await
        .map_err(|_| internal())?;
    let arriving = roles::roles_reached_from(transaction, &carried)
        .await
        .map_err(|_| internal())?;
    match services::governance::sod::weigh_everyone(transaction, &newcomers, &arriving).await {
        Ok(()) => Ok(()),
        Err(services::governance::sod::Toxic::Refused(said)) => {
            Err(refused(&Refusal::invalid(said)))
        }
        Err(services::governance::sod::Toxic::Backend) => Err(internal()),
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
    match roles::delete_group(&transaction, &group_id).await {
        Ok(true) => {
            if transaction.commit().await.is_err() {
                return internal();
            }
            HttpResponse::NoContent().finish()
        }
        Ok(false) => refused(&Refusal::not_found()),
        Err(_) => internal(),
    }
}
