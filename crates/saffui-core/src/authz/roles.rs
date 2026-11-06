//! Roles, and the groups that carry them. A role is a name an application
//! reads in a token: a role of the realm is said to every client, a role of
//! a client to that client alone.

use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::admin::AdminCaller;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::clients::store::ListWindow;
use crate::clients::{is_unshowable, read_named_client};
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::tenancy::RealmScope;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub id: Uuid,
    /// The client the role is said to. A role of the realm has none.
    pub client_id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: OffsetDateTime,
}

/// Whether a text may name a role or a group: 1 to 64 letters, digits,
/// dots, colons, hyphens or underscores. A role goes into tokens as it is
/// written, and is compared byte for byte.
#[must_use]
pub fn is_role_name(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".:_-".contains(&byte))
}

/// Reads a description or a reason: trimmed, and absent when nothing is left.
///
/// # Errors
///
/// Returns [`ErrorCode::RoleTextInvalid`] past 255 characters, or for a
/// character that cannot be shown: a control or a format character.
pub fn read_role_text(text: Option<&str>) -> Result<Option<String>, Failure> {
    let Some(text) = text.map(str::trim).filter(|text| !text.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > 255 || text.chars().any(is_unshowable) {
        return Err(Failure::new(ErrorCode::RoleTextInvalid));
    }
    Ok(Some(text.to_owned()))
}

/// Who asked, as the chain says it.
pub(crate) fn describe_actor(caller: &AdminCaller) -> Value {
    json!({ "client_id": caller.client.client_id })
}

pub struct NewRole<'a> {
    pub name: &'a str,
    /// The client whose role it is. Absent, it is a role of the realm.
    pub client_id: Option<&'a str>,
    pub description: Option<&'a str>,
}

/// Creates a role of the realm, or of one of its clients.
///
/// # Errors
///
/// Returns [`ErrorCode::RoleNameInvalid`], [`ErrorCode::RoleTextInvalid`],
/// [`ErrorCode::ClientNotFound`] for a client the realm does not have,
/// [`ErrorCode::RoleNameTaken`], or the storage failure.
pub async fn create_role(
    app: &App,
    caller: &AdminCaller,
    wanted: NewRole<'_>,
) -> Result<Role, Failure> {
    if !is_role_name(wanted.name) {
        return Err(Failure::new(ErrorCode::RoleNameInvalid));
    }
    let description = read_role_text(wanted.description)?;
    let mut work = app.storage.begin(caller.scope).await?;
    if let Some(client_id) = wanted.client_id
        && read_named_client(work.as_mut(), client_id).await?.is_none()
    {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    let role = Role {
        id: mint_id(app)?,
        client_id: wanted.client_id.map(str::to_owned),
        name: wanted.name.to_owned(),
        description,
        created_at: app.now(),
    };
    if !work.insert_role(&role).await? {
        return Err(Failure::new(ErrorCode::RoleNameTaken));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "client_id": role.client_id,
        "name": role.name,
        "role_id": role.id.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::RoleCreated, told).await?;
    work.commit().await?;
    Ok(role)
}

/// Lists the roles of a realm and of its clients, and counts them when asked.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_roles(
    app: &App,
    scope: RealmScope,
    window: ListWindow,
    counted: bool,
) -> Result<(Vec<Role>, Option<u64>), Failure> {
    let mut work = app.storage.begin(scope).await?;
    let roles = work.list_roles(window).await?;
    let total = if counted {
        Some(work.count_roles().await?)
    } else {
        None
    };
    Ok((roles, total))
}

/// Removes a role.
///
/// # Errors
///
/// Returns [`ErrorCode::NamedByPolicy`], [`ErrorCode::RoleNotFound`], or the
/// storage failure.
pub async fn delete_role(app: &App, caller: &AdminCaller, role: Uuid) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    // A policy that names it would stop applying in silence, a refusal too:
    // looked for under the lock a policy is written under.
    work.lock_definitions().await?;
    if work.is_named_by_policy("role", role).await? {
        return Err(Failure::new(ErrorCode::NamedByPolicy));
    }
    if !work.delete_role(role).await? {
        return Err(Failure::new(ErrorCode::RoleNotFound));
    }
    let told = json!({ "actor": describe_actor(caller), "role_id": role.to_string() });
    record_event(app, work.as_mut(), EventKind::RoleDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

pub struct NewGroup<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
}

/// Creates a group of the realm.
///
/// # Errors
///
/// Returns [`ErrorCode::GroupNameInvalid`], [`ErrorCode::RoleTextInvalid`],
/// [`ErrorCode::GroupNameTaken`], or the storage failure.
pub async fn create_group(
    app: &App,
    caller: &AdminCaller,
    wanted: NewGroup<'_>,
) -> Result<Group, Failure> {
    if !is_role_name(wanted.name) {
        return Err(Failure::new(ErrorCode::GroupNameInvalid));
    }
    let group = Group {
        id: mint_id(app)?,
        name: wanted.name.to_owned(),
        description: read_role_text(wanted.description)?,
        created_at: app.now(),
    };
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.insert_group(&group).await? {
        return Err(Failure::new(ErrorCode::GroupNameTaken));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "group_id": group.id.to_string(),
        "name": group.name,
    });
    record_event(app, work.as_mut(), EventKind::GroupCreated, told).await?;
    work.commit().await?;
    Ok(group)
}

/// Lists the groups of a realm, and counts them when asked.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_groups(
    app: &App,
    scope: RealmScope,
    window: ListWindow,
    counted: bool,
) -> Result<(Vec<Group>, Option<u64>), Failure> {
    let mut work = app.storage.begin(scope).await?;
    let groups = work.list_groups(window).await?;
    let total = if counted {
        Some(work.count_groups().await?)
    } else {
        None
    };
    Ok((groups, total))
}

/// Removes a group.
///
/// # Errors
///
/// Returns [`ErrorCode::NamedByPolicy`], [`ErrorCode::GroupNotFound`], or the
/// storage failure.
pub async fn delete_group(app: &App, caller: &AdminCaller, group: Uuid) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    work.lock_definitions().await?;
    if work.is_named_by_policy("group", group).await? {
        return Err(Failure::new(ErrorCode::NamedByPolicy));
    }
    if !work.delete_group(group).await? {
        return Err(Failure::new(ErrorCode::GroupNotFound));
    }
    let told = json!({ "actor": describe_actor(caller), "group_id": group.to_string() });
    record_event(app, work.as_mut(), EventKind::GroupDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{
        NewGroup, NewRole, create_group, create_role, delete_group, delete_role, is_role_name,
        list_groups, list_roles, read_role_text,
    };
    use crate::authz::admin::AdminCaller;
    use crate::authz::capability::Capability;
    use crate::clients::store::ListWindow;
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    fn start() -> (Scenario, AdminCaller) {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::RoleWrite]);
        (scenario, caller)
    }

    fn make_role(
        scenario: &Scenario,
        caller: &AdminCaller,
        name: &str,
        client_id: Option<&str>,
    ) -> Result<Uuid, ErrorCode> {
        let wanted = NewRole {
            name,
            client_id,
            description: None,
        };
        complete(create_role(&scenario.app, caller, wanted))
            .map(|role| role.id)
            .map_err(|failure| failure.code)
    }

    #[test]
    fn a_name_is_what_a_token_can_carry_as_it_is_and_nothing_else() {
        for name in [
            "admin",
            "billing:approver",
            "Team.Lead",
            "a",
            &"r".repeat(64),
        ] {
            assert!(is_role_name(name), "{name:?}");
        }
        for name in [
            "",
            "two words",
            "caf\u{e9}",
            "a/b",
            "quote\"",
            &"r".repeat(65),
        ] {
            assert!(!is_role_name(name), "{name:?}");
        }
        assert_eq!(read_role_text(Some("  ")), Ok(None));
        assert_eq!(
            read_role_text(Some(" audit, Q3 ")),
            Ok(Some("audit, Q3".to_owned()))
        );
        for unshowable in ["line\nbreak", "turned \u{202e}around", "cut\u{2028}here"] {
            assert_eq!(
                read_role_text(Some(unshowable)).map_err(|failure| failure.code),
                Err(ErrorCode::RoleTextInvalid),
                "{unshowable:?}"
            );
        }
    }

    #[test]
    fn a_role_of_the_realm_and_a_role_of_a_client_may_share_a_name_and_each_is_made_once() {
        let (scenario, caller) = start();

        assert!(make_role(&scenario, &caller, "admin", None).is_ok());
        assert!(make_role(&scenario, &caller, "admin", Some("webapp")).is_ok());
        assert!(make_role(&scenario, &caller, "admin", Some("billing")).is_ok());

        assert_eq!(
            make_role(&scenario, &caller, "admin", None),
            Err(ErrorCode::RoleNameTaken)
        );
        assert_eq!(
            make_role(&scenario, &caller, "admin", Some("webapp")),
            Err(ErrorCode::RoleNameTaken)
        );
        assert_eq!(
            make_role(&scenario, &caller, "admin", Some("nobody")),
            Err(ErrorCode::ClientNotFound)
        );
        assert_eq!(
            make_role(&scenario, &caller, "two words", None),
            Err(ErrorCode::RoleNameInvalid)
        );
        let made = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .filter(|event| event["kind"] == "role.created")
            .count();
        assert_eq!(made, 3);
    }

    #[test]
    fn roles_are_listed_by_name_and_counted_when_asked() {
        let (scenario, caller) = start();
        for name in ["writer", "reader", "auditor"] {
            make_role(&scenario, &caller, name, None).expect("a role");
        }
        let window = ListWindow { first: 1, max: 1 };

        let (page, total) =
            complete(list_roles(&scenario.app, scenario.scope, window, true)).expect("a page");
        let (_, uncounted) =
            complete(list_roles(&scenario.app, scenario.scope, window, false)).expect("a page");

        let names: Vec<&str> = page.iter().map(|role| role.name.as_str()).collect();
        assert_eq!(names, ["reader"]);
        assert_eq!((total, uncounted), (Some(3), None));
    }

    #[test]
    fn a_role_is_deleted_once_and_says_so_in_the_chain() {
        let (scenario, caller) = start();
        let role = make_role(&scenario, &caller, "admin", None).expect("a role");
        let delete =
            || complete(delete_role(&scenario.app, &caller, role)).map_err(|failure| failure.code);

        assert_eq!(delete(), Ok(()));
        assert_eq!(delete(), Err(ErrorCode::RoleNotFound));
        let deleted = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .pop()
            .expect("an event");
        assert_eq!(deleted["kind"], "role.deleted");
        assert_eq!(deleted["payload"]["actor"]["client_id"], "operator");
    }

    #[test]
    fn a_group_is_named_once_listed_by_name_and_deleted_once() {
        let (scenario, caller) = start();
        let make = |name: &str| {
            let wanted = NewGroup {
                name,
                description: Some("people of the night shift"),
            };
            complete(create_group(&scenario.app, &caller, wanted)).map_err(|failure| failure.code)
        };

        let night = make("night-shift").expect("a group");
        make("day-shift").expect("a group");
        assert_eq!(
            make("night-shift").map(|group| group.id),
            Err(ErrorCode::GroupNameTaken)
        );
        assert_eq!(
            make("night shift").map(|group| group.id),
            Err(ErrorCode::GroupNameInvalid)
        );

        let window = ListWindow { first: 0, max: 10 };
        let (groups, total) =
            complete(list_groups(&scenario.app, scenario.scope, window, true)).expect("a page");
        let names: Vec<&str> = groups.iter().map(|group| group.name.as_str()).collect();
        assert_eq!(names, ["day-shift", "night-shift"]);
        assert_eq!(total, Some(2));
        assert_eq!(
            night.description.as_deref(),
            Some("people of the night shift")
        );
        let delete = || {
            complete(delete_group(&scenario.app, &caller, night.id)).map_err(|failure| failure.code)
        };
        assert_eq!(delete(), Ok(()));
        assert_eq!(delete(), Err(ErrorCode::GroupNotFound));
    }
}
