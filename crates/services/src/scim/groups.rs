//! The groups a provisioner pushes: found, shown with their members, created,
//! patched, replaced and taken away, every newcomer weighed against the
//! separations before a write stands.

use chrono::{DateTime, Utc};
use models::entities::authz::GroupModel;
use models::entities::user::UserModel;
use models::paging::Window;
use serde_json::Value;
use store::error::StoreError;
use store::providers::directory::{roles, users};
use store::query::list_query::ListQuery;
use store::tenancy::UnitOfWork;

use super::{GroupPatch, Matched, Refusal, shown_group};
use crate::governance::sod::{Toxic, weigh_everyone};

/// What a replacement said about the members: nothing, a list that is not one,
/// or the list.
pub enum AssertedMembers {
    Absent,
    Malformed,
    Listed(Vec<String>),
}

/// The groups a filter names, or a page of every group when none does. Groups
/// are filtered by their name and nothing else.
pub async fn groups_matching(
    transaction: &UnitOfWork,
    matched: Option<Matched>,
    page: Window,
) -> Result<Vec<GroupModel>, Refusal> {
    match matched {
        None => roles::list_groups(transaction, &ListQuery::new(page), false)
            .await
            .map(|held| held.items)
            .map_err(|_| Refusal::unreadable()),
        Some(Matched::GroupName(name)) => roles::load_group_by_name(transaction, &name)
            .await
            .map(|held| held.into_iter().collect())
            .map_err(|_| Refusal::unreadable()),
        Some(_) => Err(Refusal::invalid_filter("groups filter by displayName")),
    }
}

pub async fn group(transaction: &UnitOfWork, group_id: &str) -> Result<GroupModel, Refusal> {
    roles::load_group(transaction, group_id)
        .await
        .map_err(|_| Refusal::unreadable())?
        .ok_or_else(Refusal::not_found)
}

/// A Group resource, with the people seated in it.
pub async fn shown_with_members(
    transaction: &UnitOfWork,
    base: &str,
    group: &GroupModel,
) -> Result<Value, Refusal> {
    let (people, _) = roles::group_membership(transaction, &group.group_id)
        .await
        .map_err(|_| Refusal::unreadable())?;
    let mut members: Vec<UserModel> = Vec::new();
    for user_id in people {
        if let Some(person) = users::load(transaction, &user_id)
            .await
            .map_err(|_| Refusal::unreadable())?
        {
            members.push(person);
        }
    }
    Ok(shown_group(base, group, &members))
}

/// A group created under its name, then seated with the members named, in
/// order. An entry that names no member refuses the whole creation.
pub async fn create_group(
    transaction: &UnitOfWork,
    tenant: &str,
    realm_id: &str,
    by: &str,
    name: &str,
    members: Vec<Option<String>>,
    now: DateTime<Utc>,
) -> Result<GroupModel, Refusal> {
    let mut metadata =
        models::auditable::AuditableModel::from_creator(tenant.to_owned(), by.to_owned());
    metadata.created_at = Some(now);
    let group = GroupModel {
        group_id: name.to_owned(),
        realm_id: realm_id.to_owned(),
        name: name.to_owned(),
        display_name: name.to_owned(),
        description: String::new(),
        is_default: false,
        parent_id: None,
        metadata,
    };
    match roles::create_group(transaction, &group).await {
        Ok(()) => {}
        Err(StoreError::AlreadyExists) => {
            return Err(Refusal::uniqueness(format!(
                "a group already answers to {name}"
            )));
        }
        Err(_) => return Err(Refusal::unreadable()),
    }
    for member in members {
        let Some(user_id) = member else {
            return Err(Refusal::invalid("a member names its value"));
        };
        roles::add_to_group(transaction, &user_id, &group.group_id)
            .await
            .map_err(|_| Refusal::unreadable())?;
    }
    Ok(group)
}

/// A group patched by the operations a provisioner folded. The people a write
/// seats anew are weighed once all of it landed. Answers the group as it now
/// reads.
pub async fn patch_group(
    transaction: &UnitOfWork,
    group_id: &str,
    folded: Vec<GroupPatch>,
) -> Result<GroupModel, Refusal> {
    let mut held = group(transaction, group_id).await?;
    let seats = folded.iter().any(|change| {
        matches!(
            change,
            GroupPatch::AddMembers(_) | GroupPatch::ReplaceMembers(_)
        )
    });
    let standing_before = if seats {
        store::providers::governance::sod::hold_realm(transaction)
            .await
            .map_err(|_| Refusal::unreadable())?;
        roles::group_membership(transaction, group_id)
            .await
            .map(|(standing, _)| standing)
            .map_err(|_| Refusal::unreadable())?
    } else {
        Vec::new()
    };
    let mut seated: Vec<String> = Vec::new();

    for change in folded {
        let landed = match change {
            GroupPatch::Rename(name) => {
                held.name = name.clone();
                held.display_name = name;
                roles::update_group(transaction, &held).await.map(|_| ())
            }
            GroupPatch::AddMembers(people) => {
                seated.extend(people.iter().cloned());
                let mut outcome = Ok(());
                for user_id in people {
                    if let Err(why) = roles::add_to_group(transaction, &user_id, group_id).await {
                        outcome = Err(why);
                        break;
                    }
                }
                outcome
            }
            GroupPatch::RemoveMembers(people) => {
                let mut outcome = Ok(());
                for user_id in people {
                    // A remove of somebody not in the group is the state asked
                    // for, not an error.
                    if let Err(why) =
                        roles::remove_from_group(transaction, &user_id, group_id).await
                    {
                        outcome = Err(why);
                        break;
                    }
                }
                outcome.map(|_| ())
            }
            GroupPatch::ReplaceMembers(people) => {
                seated.extend(people.iter().cloned());
                reseat(transaction, group_id, &people).await
            }
        };
        match landed {
            Ok(()) => {}
            Err(StoreError::AlreadyExists) => {
                return Err(Refusal::uniqueness(format!(
                    "a group already answers to {}",
                    held.name
                )));
            }
            Err(_) => return Err(Refusal::unreadable()),
        }
    }
    weigh_seated(transaction, group_id, &standing_before, seated).await?;
    reread(transaction, group_id).await
}

/// A group replaced by the whole document a provisioner asserts: its name when
/// one is given, then its members when they are. Answers the group as it now
/// reads.
pub async fn replace_group(
    transaction: &UnitOfWork,
    group_id: &str,
    display_name: Option<&str>,
    members: AssertedMembers,
) -> Result<GroupModel, Refusal> {
    let mut held = group(transaction, group_id).await?;
    if let Some(name) = display_name {
        held.name = name.to_owned();
        held.display_name = name.to_owned();
        match roles::update_group(transaction, &held).await {
            Ok(_) => {}
            Err(StoreError::AlreadyExists) => {
                return Err(Refusal::uniqueness(format!(
                    "a group already answers to {name}"
                )));
            }
            Err(_) => return Err(Refusal::unreadable()),
        }
    }
    match members {
        AssertedMembers::Absent => {}
        AssertedMembers::Malformed => {
            return Err(Refusal::invalid("members is an array of values"));
        }
        AssertedMembers::Listed(wanted) => {
            store::providers::governance::sod::hold_realm(transaction)
                .await
                .map_err(|_| Refusal::unreadable())?;
            let (standing, _) = roles::group_membership(transaction, group_id)
                .await
                .map_err(|_| Refusal::unreadable())?;
            for user_id in &standing {
                roles::remove_from_group(transaction, user_id, group_id)
                    .await
                    .map_err(|_| Refusal::unreadable())?;
            }
            for user_id in &wanted {
                roles::add_to_group(transaction, user_id, group_id)
                    .await
                    .map_err(|_| Refusal::unreadable())?;
            }
            weigh_seated(transaction, group_id, &standing, wanted).await?;
        }
    }
    reread(transaction, group_id).await
}

pub async fn remove_group(transaction: &UnitOfWork, group_id: &str) -> Result<(), Refusal> {
    roles::delete_group(transaction, group_id)
        .await
        .map_err(|_| Refusal::unreadable())?
        .then_some(())
        .ok_or_else(Refusal::not_found)
}

/// Everybody standing in the group taken out, then the people asked for seated.
async fn reseat(
    transaction: &UnitOfWork,
    group_id: &str,
    people: &[String],
) -> Result<(), StoreError> {
    let (standing, _) = roles::group_membership(transaction, group_id).await?;
    for user_id in &standing {
        roles::remove_from_group(transaction, user_id, group_id)
            .await
            .map_err(|_| StoreError::Backend)?;
    }
    for user_id in people {
        roles::add_to_group(transaction, user_id, group_id).await?;
    }
    Ok(())
}

/// The group as the write left it. Gone by now is the realm failing, not a
/// resource nobody asked about.
async fn reread(transaction: &UnitOfWork, group_id: &str) -> Result<GroupModel, Refusal> {
    roles::load_group(transaction, group_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(Refusal::unreadable)
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
) -> Result<(), Refusal> {
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
        .map_err(|_| Refusal::unreadable())?;
    let arriving = roles::roles_reached_from(transaction, &carried)
        .await
        .map_err(|_| Refusal::unreadable())?;
    match weigh_everyone(transaction, &newcomers, &arriving).await {
        Ok(()) => Ok(()),
        Err(Toxic::Refused(said)) => Err(Refusal::invalid(said)),
        Err(Toxic::Backend) => Err(Refusal::unreadable()),
    }
}
