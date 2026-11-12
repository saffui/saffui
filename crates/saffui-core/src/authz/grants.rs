//! Who holds a role: a person it was granted to, or a member of a group it
//! was granted to. A grant and a membership stand for a while, on the word
//! of a client of the administration plane, for a reason. What stands is
//! read at the instant of the question, and nothing else counts.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::admin::AdminCaller;
use super::roles::{describe_actor, read_role_text};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::error::{ErrorCode, Failure};
use crate::instant::write_instant;
use crate::ports::storage::UnitOfWork;
use crate::tenancy::RealmScope;

/// The scope that asks for the roles of a person in an access token.
pub const ROLES_SCOPE: &str = "roles";

/// How long a grant stands, on whose word, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub valid_from: OffsetDateTime,
    /// Absent, it stands until it is taken away.
    pub valid_until: Option<OffsetDateTime>,
    /// The client of the administration plane that gave it.
    pub granted_by: String,
    pub reason: Option<String>,
    pub granted_at: OffsetDateTime,
}

impl Grant {
    #[must_use]
    pub fn stands_at(&self, now: OffsetDateTime) -> bool {
        self.valid_from <= now && self.valid_until.is_none_or(|until| now < until)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoleHolder {
    Person(Uuid),
    Group(Uuid),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleGrant {
    pub role: Uuid,
    pub holder: RoleHolder,
    pub grant: Grant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub group: Uuid,
    pub person: Uuid,
    pub grant: Grant,
}

/// A role a person holds at an instant, by one way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldRole {
    pub role: Uuid,
    pub client_id: Option<String>,
    pub name: String,
    /// The group it comes through. Absent, it was granted to the person.
    pub through: Option<Uuid>,
    /// When this way ends: the first end of a grant on it.
    pub until: Option<OffsetDateTime>,
}

/// What an administrator asks of a grant. Every part may be left out.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrantTerms<'a> {
    pub valid_from: Option<OffsetDateTime>,
    pub valid_until: Option<OffsetDateTime>,
    pub reason: Option<&'a str>,
}

/// Settles the terms of a grant made at `now`. A start in the past is the
/// instant of the grant: nobody held anything before it was given. An end
/// comes after the start, and so after now.
fn settle_grant(
    caller: &AdminCaller,
    terms: GrantTerms<'_>,
    now: OffsetDateTime,
) -> Result<Grant, Failure> {
    let valid_from = terms.valid_from.map_or(now, |from| from.max(now));
    if terms.valid_until.is_some_and(|until| until <= valid_from) {
        return Err(Failure::new(ErrorCode::GrantPeriodInvalid));
    }
    Ok(Grant {
        valid_from,
        valid_until: terms.valid_until,
        granted_by: caller.client.client_id.clone(),
        reason: read_role_text(terms.reason)?,
        granted_at: now,
    })
}

fn describe_holder(holder: RoleHolder) -> Value {
    match holder {
        RoleHolder::Person(person) => json!({ "person_id": person.to_string() }),
        RoleHolder::Group(group) => json!({ "group_id": group.to_string() }),
    }
}

fn describe_grant(grant: &Grant) -> Value {
    json!({
        "reason": grant.reason,
        "valid_from": write_instant(grant.valid_from),
        "valid_until": grant.valid_until.map(write_instant),
    })
}

async fn require_person(work: &mut dyn UnitOfWork, person: Uuid) -> Result<(), Failure> {
    match work.read_person(person).await? {
        Some(_) => Ok(()),
        None => Err(Failure::new(ErrorCode::PersonNotFound)),
    }
}

async fn require_group(work: &mut dyn UnitOfWork, group: Uuid) -> Result<(), Failure> {
    match work.read_group(group).await? {
        Some(_) => Ok(()),
        None => Err(Failure::new(ErrorCode::GroupNotFound)),
    }
}

/// Grants a role to a person or to a group, in place of the grant they
/// had of it. Returns the grant as it was settled.
///
/// # Errors
///
/// Returns [`ErrorCode::GrantPeriodInvalid`], [`ErrorCode::RoleTextInvalid`],
/// [`ErrorCode::RoleNotFound`], [`ErrorCode::PersonNotFound`] or
/// [`ErrorCode::GroupNotFound`], or the storage failure.
pub async fn grant_role(
    app: &App,
    caller: &AdminCaller,
    role: Uuid,
    holder: RoleHolder,
    terms: GrantTerms<'_>,
) -> Result<Grant, Failure> {
    let grant = settle_grant(caller, terms, app.now())?;
    let mut work = app.storage.begin(caller.scope).await?;
    if work.read_role(role).await?.is_none() {
        return Err(Failure::new(ErrorCode::RoleNotFound));
    }
    match holder {
        RoleHolder::Person(person) => require_person(work.as_mut(), person).await?,
        RoleHolder::Group(group) => require_group(work.as_mut(), group).await?,
    }
    let given = RoleGrant {
        role,
        holder,
        grant,
    };
    work.write_role_grant(&given).await?;
    let told = json!({
        "actor": describe_actor(caller),
        "grant": describe_grant(&given.grant),
        "holder": describe_holder(holder),
        "role_id": role.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::RoleGranted, told).await?;
    work.commit().await?;
    Ok(given.grant)
}

/// Takes a role away from a person or a group.
///
/// # Errors
///
/// Returns [`ErrorCode::RoleGrantNotFound`], or the storage failure.
pub async fn revoke_role(
    app: &App,
    caller: &AdminCaller,
    role: Uuid,
    holder: RoleHolder,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_role_grant(role, holder).await? {
        return Err(Failure::new(ErrorCode::RoleGrantNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "holder": describe_holder(holder),
        "role_id": role.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::RoleRevoked, told).await?;
    work.commit().await?;
    Ok(())
}

/// Makes a person a member of a group, in place of the membership they had.
/// Returns the membership as it was settled.
///
/// # Errors
///
/// Returns [`ErrorCode::GrantPeriodInvalid`], [`ErrorCode::RoleTextInvalid`],
/// [`ErrorCode::GroupNotFound`] or [`ErrorCode::PersonNotFound`], or the
/// storage failure.
pub async fn add_member(
    app: &App,
    caller: &AdminCaller,
    group: Uuid,
    person: Uuid,
    terms: GrantTerms<'_>,
) -> Result<Grant, Failure> {
    let grant = settle_grant(caller, terms, app.now())?;
    let mut work = app.storage.begin(caller.scope).await?;
    require_group(work.as_mut(), group).await?;
    require_person(work.as_mut(), person).await?;
    let membership = Membership {
        group,
        person,
        grant,
    };
    work.write_membership(&membership).await?;
    let told = json!({
        "actor": describe_actor(caller),
        "grant": describe_grant(&membership.grant),
        "group_id": group.to_string(),
        "person_id": person.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::MemberAdded, told).await?;
    work.commit().await?;
    Ok(membership.grant)
}

/// Takes a person out of a group.
///
/// # Errors
///
/// Returns [`ErrorCode::MembershipNotFound`], or the storage failure.
pub async fn remove_member(
    app: &App,
    caller: &AdminCaller,
    group: Uuid,
    person: Uuid,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_membership(group, person).await? {
        return Err(Failure::new(ErrorCode::MembershipNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "group_id": group.to_string(),
        "person_id": person.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::MemberRemoved, told).await?;
    work.commit().await?;
    Ok(())
}

/// How many ways of holding a role, and how many groups, a person may have:
/// what a token, an introspection or a decision reads of them is bounded.
pub const MAX_HELD: u32 = 1000;

/// Reads the roles a person holds at `now`, once per way.
///
/// # Errors
///
/// Returns [`ErrorCode::HeldTooMany`] past [`MAX_HELD`] ways, or the storage
/// failure.
pub(crate) async fn read_held_roles(
    work: &mut dyn UnitOfWork,
    person: Uuid,
    now: OffsetDateTime,
) -> Result<Vec<HeldRole>, Failure> {
    let held = work
        .list_held_roles(person, now, MAX_HELD.saturating_add(1))
        .await?;
    if held.len() > MAX_HELD as usize {
        return Err(Failure::new(ErrorCode::HeldTooMany));
    }
    Ok(held)
}

/// Names, in the detail of a refusal for too many roles or groups, the
/// client they were read for: the journal tells whose tokens or questions
/// meet the bound.
pub(crate) fn name_client_held_for(failure: Failure, client_id: &str) -> Failure {
    if failure.code == ErrorCode::HeldTooMany {
        Failure::with_detail(
            ErrorCode::HeldTooMany,
            format!("read for the client {client_id}"),
        )
    } else {
        failure
    }
}

/// Reads the groups a person is a member of at `now`.
///
/// # Errors
///
/// Returns [`ErrorCode::HeldTooMany`] past [`MAX_HELD`] groups, or the
/// storage failure.
pub(crate) async fn read_member_groups(
    work: &mut dyn UnitOfWork,
    person: Uuid,
    now: OffsetDateTime,
) -> Result<Vec<Uuid>, Failure> {
    let groups = work
        .list_member_groups(person, now, MAX_HELD.saturating_add(1))
        .await?;
    if groups.len() > MAX_HELD as usize {
        return Err(Failure::new(ErrorCode::HeldTooMany));
    }
    Ok(groups)
}

/// Lists the roles a person holds now, once per way.
///
/// # Errors
///
/// Returns [`ErrorCode::PersonNotFound`], [`ErrorCode::HeldTooMany`], or the
/// storage failure.
pub async fn list_held_roles(
    app: &App,
    scope: RealmScope,
    person: Uuid,
) -> Result<Vec<HeldRole>, Failure> {
    let mut work = app.storage.begin(scope).await?;
    require_person(work.as_mut(), person).await?;
    read_held_roles(work.as_mut(), person, app.now()).await
}

/// What a token for one client says of the roles of a person.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RoleClaims {
    /// The roles of the realm, by name.
    pub realm: Vec<String>,
    /// The roles of the client the token is for, by name.
    pub client: Vec<String>,
    /// When the first of these roles ends: a token that says them lives no
    /// longer.
    pub until: Option<OffsetDateTime>,
}

impl RoleClaims {
    /// Gathers what a token for `client_id` says of the roles held. The
    /// roles of another client are not said. A role held two ways lasts as
    /// long as the longer one.
    #[must_use]
    pub fn gather<'a>(held: impl IntoIterator<Item = &'a HeldRole>, client_id: &str) -> Self {
        let mut lasting: BTreeMap<Uuid, (&HeldRole, Option<OffsetDateTime>)> = BTreeMap::new();
        let said = held.into_iter().filter(|way| {
            way.client_id
                .as_deref()
                .is_none_or(|owner| owner == client_id)
        });
        for way in said {
            lasting
                .entry(way.role)
                .and_modify(|(_, until)| {
                    *until = match (*until, way.until) {
                        (Some(one), Some(other)) => Some(one.max(other)),
                        _ => None,
                    };
                })
                .or_insert((way, way.until));
        }
        let mut claims = Self::default();
        for (role, until) in lasting.into_values() {
            let names = if role.client_id.is_some() {
                &mut claims.client
            } else {
                &mut claims.realm
            };
            names.push(role.name.clone());
            if let Some(until) = until {
                claims.until = Some(claims.until.map_or(until, |first| first.min(until)));
            }
        }
        claims.realm.sort();
        claims.client.sort();
        claims
    }

    #[must_use]
    pub fn write_realm_access(&self) -> Value {
        json!({ "roles": self.realm })
    }

    #[must_use]
    pub fn write_resource_access(&self, client_id: &str) -> Value {
        let mut access = Map::new();
        access.insert(client_id.to_owned(), json!({ "roles": self.client }));
        Value::Object(access)
    }
}

/// Reads what a token for `client_id` says of the roles `person` holds at `now`.
pub(crate) async fn read_role_claims(
    work: &mut dyn UnitOfWork,
    person: Uuid,
    client_id: &str,
    now: OffsetDateTime,
) -> Result<RoleClaims, Failure> {
    let held = read_held_roles(work, person, now).await?;
    Ok(RoleClaims::gather(&held, client_id))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        GrantTerms, HeldRole, RoleClaims, RoleHolder, add_member, grant_role, list_held_roles,
        remove_member, revoke_role,
    };
    use crate::authz::admin::AdminCaller;
    use crate::authz::capability::Capability;
    use crate::authz::roles::{NewGroup, NewRole, create_group, create_role, delete_group};
    use crate::error::ErrorCode;
    use crate::oidc::introspect::introspect_token;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    struct Started {
        scenario: Scenario,
        caller: AdminCaller,
        ada: Uuid,
    }

    fn start() -> Started {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::RoleWrite]);
        let ada = scenario.find_ada();
        Started {
            scenario,
            caller,
            ada,
        }
    }

    impl Started {
        fn make_role(&self, name: &str, client_id: Option<&str>) -> Uuid {
            let wanted = NewRole {
                name,
                client_id,
                description: None,
            };
            complete(create_role(&self.scenario.app, &self.caller, wanted))
                .expect("a role")
                .id
        }

        fn make_group(&self, name: &str) -> Uuid {
            let wanted = NewGroup {
                name,
                description: None,
            };
            complete(create_group(&self.scenario.app, &self.caller, wanted))
                .expect("a group")
                .id
        }

        fn grant(
            &self,
            role: Uuid,
            holder: RoleHolder,
            terms: GrantTerms<'_>,
        ) -> Result<(), ErrorCode> {
            complete(grant_role(
                &self.scenario.app,
                &self.caller,
                role,
                holder,
                terms,
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        }

        fn add(&self, group: Uuid, terms: GrantTerms<'_>) -> Result<(), ErrorCode> {
            complete(add_member(
                &self.scenario.app,
                &self.caller,
                group,
                self.ada,
                terms,
            ))
            .map(|_| ())
            .map_err(|failure| failure.code)
        }

        fn now(&self) -> OffsetDateTime {
            self.scenario.app.now()
        }

        fn hold(&self) -> Vec<HeldRole> {
            complete(list_held_roles(
                &self.scenario.app,
                self.scenario.scope,
                self.ada,
            ))
            .expect("the roles of ada")
        }

        fn name_held(&self) -> Vec<String> {
            self.hold().into_iter().map(|held| held.name).collect()
        }
    }

    fn until(when: OffsetDateTime) -> GrantTerms<'static> {
        GrantTerms {
            valid_until: Some(when),
            ..GrantTerms::default()
        }
    }

    fn read_claims(token: &str) -> Value {
        let payload = token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    #[test]
    fn a_role_granted_for_later_is_held_from_its_start_to_its_end_and_at_no_other_time() {
        let started = start();
        let role = started.make_role("on-call", None);
        let now = started.now();
        let terms = GrantTerms {
            valid_from: Some(now + time::Duration::hours(1)),
            valid_until: Some(now + time::Duration::hours(2)),
            reason: Some("the night of the release"),
        };

        assert_eq!(
            started.grant(role, RoleHolder::Person(started.ada), terms),
            Ok(())
        );

        assert!(started.hold().is_empty(), "not before it starts");
        started.scenario.clock.advance(Duration::from_hours(1));
        assert_eq!(started.name_held(), ["on-call"]);
        started.scenario.clock.advance(Duration::from_hours(1));
        assert!(started.hold().is_empty(), "not once it ended");
    }

    #[test]
    fn a_role_granted_to_a_group_is_held_by_its_members_until_the_first_of_the_two_ends() {
        let started = start();
        let role = started.make_role("approver", None);
        let group = started.make_group("finance");
        let now = started.now();
        started
            .grant(
                role,
                RoleHolder::Group(group),
                until(now + time::Duration::hours(3)),
            )
            .expect("a grant to the group");
        assert!(started.hold().is_empty(), "nobody is a member yet");

        started
            .add(group, until(now + time::Duration::hours(1)))
            .expect("a membership");

        let held = started.hold();
        assert_eq!(held.len(), 1);
        assert_eq!(
            (held[0].through, held[0].until),
            (Some(group), Some(now + time::Duration::hours(1)))
        );
        started.scenario.clock.advance(Duration::from_hours(1));
        assert!(started.hold().is_empty(), "the membership ended first");
    }

    #[test]
    fn terms_that_end_before_they_start_are_refused_and_a_start_in_the_past_is_now() {
        let started = start();
        let role = started.make_role("approver", None);
        let now = started.now();
        let person = RoleHolder::Person(started.ada);

        let backwards = GrantTerms {
            valid_from: Some(now + time::Duration::hours(2)),
            valid_until: Some(now + time::Duration::hours(1)),
            reason: None,
        };
        assert_eq!(
            started.grant(role, person, backwards),
            Err(ErrorCode::GrantPeriodInvalid)
        );
        assert_eq!(
            started.grant(role, person, until(now - time::Duration::minutes(1))),
            Err(ErrorCode::GrantPeriodInvalid),
            "a grant that ended already grants nothing"
        );
        let wordy = GrantTerms {
            reason: Some(&"r".repeat(256)),
            ..GrantTerms::default()
        };
        assert_eq!(
            started.grant(role, person, wordy),
            Err(ErrorCode::RoleTextInvalid)
        );

        let backdated = GrantTerms {
            valid_from: Some(now - time::Duration::days(30)),
            ..GrantTerms::default()
        };
        let grant = complete(grant_role(
            &started.scenario.app,
            &started.caller,
            role,
            person,
            backdated,
        ))
        .expect("a grant");
        assert_eq!(grant.valid_from, now);
        assert_eq!(grant.granted_by, "operator");
    }

    #[test]
    fn a_grant_given_again_replaces_the_first_and_a_revoked_one_is_gone() {
        let started = start();
        let role = started.make_role("approver", None);
        let now = started.now();
        let person = RoleHolder::Person(started.ada);
        started
            .grant(role, person, until(now + time::Duration::hours(1)))
            .expect("a grant");

        started
            .grant(role, person, GrantTerms::default())
            .expect("the same grant, without an end");

        let held = started.hold();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].until, None);
        let revoke = || {
            complete(revoke_role(
                &started.scenario.app,
                &started.caller,
                role,
                person,
            ))
            .map_err(|failure| failure.code)
        };
        assert_eq!(revoke(), Ok(()));
        assert_eq!(revoke(), Err(ErrorCode::RoleGrantNotFound));
        assert!(started.hold().is_empty());
    }

    #[test]
    fn a_grant_names_a_role_and_a_holder_the_realm_has() {
        let started = start();
        let role = started.make_role("approver", None);
        let group = started.make_group("finance");
        let nobody = Uuid::from_u128(7);

        assert_eq!(
            started.grant(
                nobody,
                RoleHolder::Person(started.ada),
                GrantTerms::default()
            ),
            Err(ErrorCode::RoleNotFound)
        );
        assert_eq!(
            started.grant(role, RoleHolder::Person(nobody), GrantTerms::default()),
            Err(ErrorCode::PersonNotFound)
        );
        assert_eq!(
            started.grant(role, RoleHolder::Group(nobody), GrantTerms::default()),
            Err(ErrorCode::GroupNotFound)
        );
        let joined = complete(add_member(
            &started.scenario.app,
            &started.caller,
            group,
            nobody,
            GrantTerms::default(),
        ));
        assert_eq!(
            joined.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::PersonNotFound)
        );
        let left = complete(remove_member(
            &started.scenario.app,
            &started.caller,
            group,
            started.ada,
        ));
        assert_eq!(
            left.map_err(|failure| failure.code),
            Err(ErrorCode::MembershipNotFound)
        );
        let unknown = complete(list_held_roles(
            &started.scenario.app,
            started.scenario.scope,
            nobody,
        ));
        assert_eq!(
            unknown.map(|_| ()).map_err(|failure| failure.code),
            Err(ErrorCode::PersonNotFound)
        );
    }

    #[test]
    fn a_group_deleted_takes_what_it_carried_from_its_members() {
        let started = start();
        let role = started.make_role("approver", None);
        let group = started.make_group("finance");
        started
            .grant(role, RoleHolder::Group(group), GrantTerms::default())
            .expect("a grant");
        started
            .add(group, GrantTerms::default())
            .expect("a membership");
        assert_eq!(started.name_held(), ["approver"]);

        complete(delete_group(&started.scenario.app, &started.caller, group)).expect("a deletion");

        assert!(started.hold().is_empty());
    }

    #[test]
    fn the_chain_says_who_granted_what_to_whom_for_how_long_and_why() {
        let started = start();
        let role = started.make_role("approver", None);
        let now = started.now();
        let terms = GrantTerms {
            valid_until: Some(now + time::Duration::days(7)),
            reason: Some("cover for the holidays"),
            ..GrantTerms::default()
        };

        started
            .grant(role, RoleHolder::Person(started.ada), terms)
            .expect("a grant");

        let granted = started
            .scenario
            .storage
            .read_audit_envelopes(started.scenario.scope.realm())
            .pop()
            .expect("an event");
        assert_eq!(granted["kind"], "role.granted");
        let payload = &granted["payload"];
        assert_eq!(payload["actor"]["client_id"], "operator");
        assert_eq!(payload["role_id"], role.to_string());
        assert_eq!(payload["holder"]["person_id"], started.ada.to_string());
        assert_eq!(payload["grant"]["reason"], "cover for the holidays");
        assert!(payload["grant"]["valid_until"].is_string());
    }

    fn held(name: &str, client_id: Option<&str>, role: u128, until: Option<i64>) -> HeldRole {
        HeldRole {
            role: Uuid::from_u128(role),
            client_id: client_id.map(str::to_owned),
            name: name.to_owned(),
            through: None,
            until: until.map(|hours| OffsetDateTime::UNIX_EPOCH + time::Duration::hours(hours)),
        }
    }

    #[test]
    fn a_token_says_the_roles_of_the_realm_and_of_its_own_client_and_lasts_as_the_first_to_end() {
        let ways = [
            held("admin", None, 1, Some(5)),
            // The same role, another way, longer.
            held("admin", None, 1, Some(9)),
            held("reader", None, 2, None),
            held("editor", Some("webapp"), 3, Some(7)),
            held("auditor", Some("billing"), 4, Some(1)),
        ];

        let claims = RoleClaims::gather(&ways, "webapp");

        assert_eq!(claims.realm, ["admin", "reader"]);
        assert_eq!(claims.client, ["editor"]);
        assert_eq!(
            claims.until,
            Some(OffsetDateTime::UNIX_EPOCH + time::Duration::hours(7)),
            "the role of another client ends first, and is not said"
        );
        assert_eq!(
            claims.write_realm_access(),
            json!({ "roles": ["admin", "reader"] })
        );
        assert_eq!(
            claims.write_resource_access("webapp"),
            json!({ "webapp": { "roles": ["editor"] } })
        );
        let forever = RoleClaims::gather(
            &[
                held("admin", None, 1, Some(5)),
                held("admin", None, 1, None),
            ],
            "webapp",
        );
        assert_eq!(forever.until, None, "one way without an end is enough");
    }

    #[test]
    fn an_access_token_asked_with_roles_says_them_and_lives_no_longer_than_the_first_to_end() {
        let started = start();
        let admin = started.make_role("admin", None);
        let editor = started.make_role("editor", Some("webapp"));
        let audit = started.make_role("auditor", Some("billing"));
        let now = started.now();
        for role in [admin, editor, audit] {
            started
                .grant(
                    role,
                    RoleHolder::Person(started.ada),
                    until(now + time::Duration::minutes(2)),
                )
                .expect("a grant");
        }
        started
            .grant(
                admin,
                RoleHolder::Person(started.ada),
                GrantTerms::default(),
            )
            .expect("admin, for good");

        let signed_in = started.scenario.sign_in("openid roles");

        let claims = read_claims(&signed_in.tokens.access_token);
        assert_eq!(claims["realm_access"], json!({ "roles": ["admin"] }));
        assert_eq!(
            claims["resource_access"],
            json!({ "webapp": { "roles": ["editor"] } })
        );
        assert_eq!(
            claims["exp"],
            (now + time::Duration::minutes(2)).unix_timestamp(),
            "the role of the client ends in two minutes"
        );
        assert_eq!(signed_in.tokens.expires_in, 120);
        let without = read_claims(&started.scenario.sign_in("openid").tokens.access_token);
        assert!(without.get("realm_access").is_none() && without.get("resource_access").is_none());
        let identity = read_claims(
            signed_in
                .tokens
                .id_token
                .as_deref()
                .expect("an identity token"),
        );
        assert!(
            identity.get("realm_access").is_none(),
            "the roles are said to the client's API, not in its identity token"
        );
    }

    #[test]
    fn a_refresh_reads_the_roles_again_and_introspection_says_them_as_they_are_now() {
        let started = start();
        let admin = started.make_role("admin", None);
        let person = RoleHolder::Person(started.ada);
        started
            .grant(admin, person, GrantTerms::default())
            .expect("a grant");
        let signed_in = started.scenario.sign_in("openid roles");
        let token = signed_in.tokens.access_token.clone();
        let introspect = || {
            complete(introspect_token(
                &started.scenario.app,
                "acme",
                Some("billing"),
                Some(started.scenario.copy_service_secret()),
                Some(&token),
            ))
            .expect("an answer")
        };
        let told = introspect();
        assert_eq!(told.realm_access, Some(json!({ "roles": ["admin"] })));
        assert_eq!(
            told.resource_access, None,
            "the roles of webapp are told to webapp alone"
        );
        let soon = started.now() + time::Duration::minutes(1);
        started
            .grant(admin, person, until(soon))
            .expect("the grant again, for a minute");
        assert_eq!(
            introspect().exp,
            Some(soon.unix_timestamp()),
            "the answer stands no longer than the role it says"
        );

        complete(revoke_role(
            &started.scenario.app,
            &started.caller,
            admin,
            person,
        ))
        .expect("a revocation");

        let told = introspect();
        assert!(told.active);
        assert_eq!(
            told.realm_access,
            Some(json!({ "roles": [] })),
            "the token still says admin; the realm no longer does"
        );
        let refreshed = started
            .scenario
            .refresh(
                signed_in
                    .tokens
                    .refresh_token
                    .as_deref()
                    .expect("a refresh token"),
            )
            .expect("a new token");
        assert_eq!(
            read_claims(&refreshed.access_token)["realm_access"],
            json!({ "roles": [] })
        );
    }

    #[test]
    fn past_the_ceiling_of_ways_the_roles_of_a_person_are_refused_by_name() {
        use super::MAX_HELD;
        use crate::authz::grants::{Grant, RoleGrant};
        use crate::authz::roles::Role;
        use crate::ids::mint_id;

        let started = start();
        let now = started.now();
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            for index in 0..=MAX_HELD {
                let role = Role {
                    id: mint_id(&started.scenario.app).expect("an identifier"),
                    client_id: None,
                    name: format!("role-{index}"),
                    description: None,
                    created_at: now,
                };
                assert_eq!(work.insert_role(&role).await, Ok(true));
                let given = RoleGrant {
                    role: role.id,
                    holder: RoleHolder::Person(started.ada),
                    grant: Grant {
                        valid_from: now,
                        valid_until: None,
                        granted_by: "operator".to_owned(),
                        reason: None,
                        granted_at: now,
                    },
                };
                work.write_role_grant(&given).await.expect("a grant");
            }
            work.commit().await.expect("a commit");
        });

        let held = complete(list_held_roles(
            &started.scenario.app,
            started.scenario.scope,
            started.ada,
        ));
        assert_eq!(
            held.map(|held| held.len()).map_err(|failure| failure.code),
            Err(ErrorCode::HeldTooMany)
        );
    }
}
