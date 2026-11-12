//! The mappers of a client, as an administrator writes them. A mapper is
//! never changed: it is taken away and written again.

use serde_json::json;
use uuid::Uuid;

use super::rules::{check_mapper, check_mapper_beside, check_mapper_capabilities};
use super::{Mapper, MapperKind, NewMapper};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::capability::check_capabilities_held;
use crate::authz::roles::describe_actor;
use crate::clients::{check_client_identifier, read_named_client};
use crate::error::{ErrorCode, Failure};
use crate::ids::mint_id;
use crate::tenancy::RealmScope;

/// Gives a client one more mapper. Its caller may read what it says, holds
/// every capability of the client, and names a scope the client may be given.
///
/// # Errors
///
/// Returns [`ErrorCode::MapperInvalid`], [`ErrorCode::CapabilityMissing`],
/// [`ErrorCode::ClientNotFound`] for the client or for the client whose
/// roles it would say, [`ErrorCode::MapperLimitReached`],
/// [`ErrorCode::MapperOverlaps`], [`ErrorCode::MapperNameTaken`], or the
/// storage failure.
pub async fn create_mapper(
    app: &App,
    caller: &AdminCaller,
    client_id: &str,
    wanted: NewMapper<'_>,
) -> Result<Mapper, Failure> {
    check_mapper(&wanted)?;
    check_mapper_capabilities(&wanted.kind, &caller.client.capabilities)?;
    let mut work = app.storage.begin(caller.scope).await?;
    // Taken before its mappers are read: a writer that comes meanwhile
    // waits, then reads what this one kept.
    let locked = if check_client_identifier(client_id).is_ok() {
        work.lock_client(client_id).await?
    } else {
        None
    };
    let Some(locked) = locked else {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    };
    // Nobody hands out more than they have: a mapper makes the tokens of the
    // client say what it carries.
    check_capabilities_held(&caller.client.capabilities, &locked.capabilities)?;
    if wanted
        .scope
        .is_some_and(|asked| !locked.scopes.iter().any(|scope| scope == asked))
    {
        return Err(Failure::with_detail(ErrorCode::MapperInvalid, "scope"));
    }
    if let MapperKind::ClientRoles { client_id: said } = &wanted.kind
        && read_named_client(work.as_mut(), said).await?.is_none()
    {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    let kept = work.list_mappers(client_id).await?;
    check_mapper_beside(&kept, &wanted)?;
    let mut targets = wanted.targets.to_vec();
    targets.sort();
    let mapper = Mapper {
        id: mint_id(app)?,
        client_id: client_id.to_owned(),
        name: wanted.name.to_owned(),
        kind: wanted.kind,
        claim: wanted.claim.map(str::to_owned),
        targets,
        scope: wanted.scope.map(str::to_owned),
        created_at: app.now(),
    };
    if !work.insert_mapper(&mapper).await? {
        return Err(Failure::new(ErrorCode::MapperNameTaken));
    }
    let targets: Vec<&str> = mapper.targets.iter().map(|target| target.name()).collect();
    // A mapper is never changed: this event is what it was.
    let told = json!({
        "actor": describe_actor(caller),
        "claim": mapper.claim,
        "client_id": mapper.client_id,
        "definition": serde_json::to_value(&mapper.kind)
            .map_err(|_| Failure::new(ErrorCode::Internal))?,
        "mapper_id": mapper.id.to_string(),
        "name": mapper.name,
        "scope": mapper.scope,
        "targets": targets,
    });
    record_event(app, work.as_mut(), EventKind::MapperCreated, told).await?;
    work.commit().await?;
    Ok(mapper)
}

/// Lists the mappers of a client, in the order of their names.
///
/// # Errors
///
/// Returns [`ErrorCode::ClientNotFound`] or the storage failure.
pub async fn list_mappers(
    app: &App,
    scope: RealmScope,
    client_id: &str,
) -> Result<Vec<Mapper>, Failure> {
    let mut work = app.storage.begin(scope).await?;
    if read_named_client(work.as_mut(), client_id).await?.is_none() {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    Ok(work.list_mappers(client_id).await?)
}

/// Takes a mapper from a client its caller holds every capability of.
///
/// # Errors
///
/// Returns [`ErrorCode::MapperNotFound`], [`ErrorCode::CapabilityMissing`],
/// or the storage failure.
pub async fn delete_mapper(
    app: &App,
    caller: &AdminCaller,
    client_id: &str,
    id: Uuid,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    let Some(client) = read_named_client(work.as_mut(), client_id).await? else {
        return Err(Failure::new(ErrorCode::MapperNotFound));
    };
    check_capabilities_held(&caller.client.capabilities, &client.capabilities)?;
    if !work.delete_mapper(client_id, id).await? {
        return Err(Failure::new(ErrorCode::MapperNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "client_id": client_id,
        "mapper_id": id.to_string(),
    });
    record_event(app, work.as_mut(), EventKind::MapperDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};

    use super::{create_mapper, delete_mapper, list_mappers};
    use crate::authz::admin::AdminCaller;
    use crate::authz::capability::Capability;
    use crate::authz::grants::{GrantTerms, RoleHolder, grant_role};
    use crate::authz::roles::{NewRole, create_role};
    use crate::claims::attributes::write_attributes;
    use crate::claims::{ClaimTarget, MapperKind, NewMapper};
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::oidc::userinfo::read_user_info;
    use crate::testkit::drive::complete;

    const ISSUER: &str = "https://id.example.test/realms/acme";

    fn read_claims(token: &str) -> Value {
        let payload = token.split('.').nth(1).expect("a compact token");
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("base64url"))
            .expect("claims")
    }

    fn attribute(name: &str) -> MapperKind {
        MapperKind::Attribute {
            attribute: name.to_owned(),
        }
    }

    /// A mapper of the `profile` scope that writes `claim` in the identity
    /// token and the userinfo answer.
    fn make_mapper(
        name: &'static str,
        kind: MapperKind,
        claim: &'static str,
    ) -> NewMapper<'static> {
        NewMapper {
            name,
            kind,
            claim: Some(claim),
            targets: &[ClaimTarget::IdToken, ClaimTarget::Userinfo],
            scope: Some("profile"),
        }
    }

    /// The mapper `department`: the attribute of that name, as `dept`.
    fn department() -> NewMapper<'static> {
        make_mapper("department", attribute("department"), "dept")
    }

    fn create(
        scenario: &Scenario,
        caller: &AdminCaller,
        wanted: NewMapper<'_>,
    ) -> Result<(), ErrorCode> {
        complete(create_mapper(&scenario.app, caller, "webapp", wanted))
            .map(|_| ())
            .map_err(|failure| failure.code)
    }

    #[test]
    fn a_mapper_and_an_attribute_reach_the_tokens_and_a_change_reaches_the_next_one() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[
            Capability::ClientWrite,
            Capability::UserWrite,
            Capability::UserRead,
        ]);
        let ada = scenario.find_ada();
        create(&scenario, &operator, department()).expect("a mapper");
        let audience = NewMapper {
            name: "api",
            kind: MapperKind::Audience {
                audience: "https://api.example.org".to_owned(),
            },
            claim: None,
            targets: &[ClaimTarget::AccessToken],
            scope: None,
        };
        create(&scenario, &operator, audience).expect("a mapper");
        let attributes = json!({ "department": "research", "given_name": "Ada" });
        complete(write_attributes(
            &scenario.app,
            &operator,
            ada,
            attributes.as_object().expect("an object"),
        ))
        .expect("attributes");

        let tokens = scenario.sign_in("openid profile").tokens;

        let identity = read_claims(tokens.id_token.as_deref().expect("an identity token"));
        assert_eq!(identity["dept"], "research");
        assert_eq!(
            identity["given_name"], "Ada",
            "the profile says what it knows"
        );
        let access = read_claims(&tokens.access_token);
        assert_eq!(
            access["aud"],
            json!([ISSUER, "https://api.example.org"]),
            "the realm first, then the audience of the mapper"
        );
        assert!(access.get("dept").is_none(), "not a target of the mapper");
        let told =
            complete(read_user_info(&scenario.app, "acme", &tokens.access_token)).expect("claims");
        assert_eq!(told["dept"], "research");
        assert_eq!(told["given_name"], "Ada");

        let changed = json!({ "department": "engineering" });
        complete(write_attributes(
            &scenario.app,
            &operator,
            ada,
            changed.as_object().expect("an object"),
        ))
        .expect("attributes");
        let refreshed = scenario
            .refresh(tokens.refresh_token.as_deref().expect("a refresh token"))
            .expect("new tokens");
        let identity = read_claims(refreshed.id_token.as_deref().expect("an identity token"));
        assert_eq!(identity["dept"], "engineering", "read again at each token");
        assert!(identity.get("given_name").is_none());
        let kinds = scenario.read_event_kinds();
        for kind in ["client.mapper_created", "person.attributes_written"] {
            assert!(kinds.iter().any(|known| known == kind), "{kind}");
        }
    }

    #[test]
    fn an_identity_token_that_says_a_role_lives_no_longer_than_the_role() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[
            Capability::ClientWrite,
            Capability::RoleWrite,
            Capability::RoleRead,
        ]);
        let ada = scenario.find_ada();
        let reviewer = complete(create_role(
            &scenario.app,
            &operator,
            NewRole {
                name: "reviewer",
                client_id: None,
                description: None,
            },
        ))
        .expect("a role")
        .id;
        let ends = scenario.app.now() + time::Duration::seconds(120);
        let terms = GrantTerms {
            valid_until: Some(ends),
            ..GrantTerms::default()
        };
        complete(grant_role(
            &scenario.app,
            &operator,
            reviewer,
            RoleHolder::Person(ada),
            terms,
        ))
        .expect("a grant");
        let roles = NewMapper {
            targets: &[ClaimTarget::IdToken],
            ..make_mapper("roles", MapperKind::RealmRoles, "roles")
        };
        create(&scenario, &operator, roles).expect("a mapper");

        let tokens = scenario.sign_in("openid profile").tokens;

        let identity = read_claims(tokens.id_token.as_deref().expect("an identity token"));
        assert_eq!(identity["roles"], json!(["reviewer"]));
        assert_eq!(
            identity["exp"],
            ends.unix_timestamp(),
            "the identity token ends with the role it says"
        );
        let access = read_claims(&tokens.access_token);
        assert_eq!(
            access["exp"].as_i64(),
            access["iat"].as_i64().map(|issued| issued + 300),
            "the access token says no role: it lives its whole time"
        );
    }

    #[test]
    fn a_mapper_is_refused_for_a_client_that_does_not_exist_twice_beside_another_or_past_fifty() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite, Capability::UserRead]);
        let create_for = |client_id: &str, wanted| {
            complete(create_mapper(&scenario.app, &operator, client_id, wanted))
                .map(|mapper| mapper.id)
                .map_err(|failure| failure.code)
        };

        assert_eq!(
            create_for("nobody", department()).map(|_| ()),
            Err(ErrorCode::ClientNotFound)
        );
        assert_eq!(
            create_for("not an identifier", department()).map(|_| ()),
            Err(ErrorCode::ClientNotFound)
        );
        let roles_of_nobody = make_mapper(
            "roles",
            MapperKind::ClientRoles {
                client_id: "nobody".to_owned(),
            },
            "roles",
        );
        let mut with_roles = operator.clone();
        with_roles.client.capabilities.push(Capability::RoleRead);
        assert_eq!(
            create(&scenario, &with_roles, roles_of_nobody),
            Err(ErrorCode::ClientNotFound)
        );
        let first = create_for("webapp", department()).expect("a mapper");
        assert_eq!(
            create_for("webapp", department()).map(|_| ()),
            Err(ErrorCode::MapperNameTaken)
        );
        assert_eq!(
            create(
                &scenario,
                &operator,
                make_mapper("team", attribute("team"), "dept")
            ),
            Err(ErrorCode::MapperOverlaps),
            "two mappers write one claim"
        );
        for index in 0..49 {
            let (name, source, claim) = (
                format!("m{index:02}"),
                format!("a{index:02}"),
                format!("c{index:02}"),
            );
            let wanted = NewMapper {
                name: &name,
                kind: attribute(&source),
                claim: Some(&claim),
                ..department()
            };
            create(&scenario, &operator, wanted).expect("a mapper");
        }
        assert_eq!(
            create(
                &scenario,
                &operator,
                make_mapper("m99", attribute("a99"), "c99")
            ),
            Err(ErrorCode::MapperLimitReached)
        );

        assert_eq!(
            complete(delete_mapper(&scenario.app, &operator, "billing", first))
                .map_err(|failure| failure.code),
            Err(ErrorCode::MapperNotFound),
            "a mapper is taken from its own client only"
        );
        complete(delete_mapper(&scenario.app, &operator, "webapp", first)).expect("deleted");
        let left = complete(list_mappers(&scenario.app, scenario.scope, "webapp")).expect("a list");
        assert_eq!(left.len(), 49);
        assert_eq!(
            complete(delete_mapper(&scenario.app, &operator, "webapp", first))
                .map_err(|failure| failure.code),
            Err(ErrorCode::MapperNotFound)
        );
        let deleted = scenario
            .read_event_kinds()
            .iter()
            .filter(|kind| *kind == "client.mapper_deleted")
            .count();
        assert_eq!(deleted, 1);
    }

    #[test]
    fn a_mapper_of_the_people_is_written_by_a_caller_that_may_read_them() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite]);
        let mut reader = operator.clone();
        reader.client.capabilities.push(Capability::UserRead);

        assert_eq!(
            create(&scenario, &operator, department()),
            Err(ErrorCode::CapabilityMissing)
        );
        assert_eq!(create(&scenario, &reader, department()), Ok(()));
    }

    #[test]
    fn a_mapper_of_roles_is_written_by_a_caller_that_may_read_them() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite, Capability::UserRead]);
        let mut reader = operator.clone();
        reader.client.capabilities.push(Capability::RoleRead);
        let roles = || make_mapper("roles", MapperKind::RealmRoles, "roles");

        assert_eq!(
            create(&scenario, &operator, roles()),
            Err(ErrorCode::CapabilityMissing)
        );
        assert_eq!(create(&scenario, &reader, roles()), Ok(()));
    }

    #[test]
    fn a_mapper_of_an_attribute_policies_read_is_written_by_a_caller_that_may_read_policies() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite, Capability::UserRead]);
        let mut reader = operator.clone();
        reader.client.capabilities.push(Capability::PolicyRead);
        let team = || make_mapper("team", attribute("policy.team"), "team");

        assert_eq!(
            create(&scenario, &operator, team()),
            Err(ErrorCode::CapabilityMissing)
        );
        assert_eq!(create(&scenario, &reader, team()), Ok(()));
    }

    #[test]
    fn a_caller_gives_or_takes_no_mapper_of_a_client_that_holds_more_than_it() {
        use crate::authz::admin::authorize_admin_call;
        use crate::testkit::fixtures::create_administrator;

        let scenario = Scenario::start();
        let operator = scenario.name_operator(&Capability::ALL);
        let token = complete(create_administrator(
            &scenario.app,
            "acme",
            scenario.scope,
            "clerk",
            &[Capability::ClientWrite],
        ));
        let clerk = complete(authorize_admin_call(
            &scenario.app,
            "acme",
            Some(&token),
            Capability::ClientWrite,
        ))
        .expect("a clerk");
        let audience = || NewMapper {
            name: "api",
            kind: MapperKind::Audience {
                audience: "https://api.example.org".to_owned(),
            },
            claim: None,
            targets: &[ClaimTarget::AccessToken],
            scope: None,
        };
        let create_on = |caller, client_id| {
            complete(create_mapper(&scenario.app, caller, client_id, audience()))
                .map(|mapper| mapper.id)
                .map_err(|failure| failure.code)
        };

        assert_eq!(
            create_on(&clerk, "operator"),
            Err(ErrorCode::CapabilityMissing),
            "the clerk holds less than the operator"
        );
        assert!(create_on(&clerk, "clerk").is_ok(), "its own client");
        let kept = create_on(&operator, "operator").expect("a mapper");
        assert_eq!(
            complete(delete_mapper(&scenario.app, &clerk, "operator", kept))
                .map_err(|failure| failure.code),
            Err(ErrorCode::CapabilityMissing)
        );
        assert_eq!(
            complete(delete_mapper(&scenario.app, &operator, "operator", kept)),
            Ok(())
        );
    }

    #[test]
    fn a_mapper_of_the_roles_of_a_client_puts_them_in_the_token() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[
            Capability::ClientWrite,
            Capability::RoleWrite,
            Capability::RoleRead,
        ]);
        let approver = complete(create_role(
            &scenario.app,
            &operator,
            NewRole {
                name: "approver",
                client_id: Some("billing"),
                description: None,
            },
        ))
        .expect("a role")
        .id;
        complete(grant_role(
            &scenario.app,
            &operator,
            approver,
            RoleHolder::Person(scenario.find_ada()),
            GrantTerms::default(),
        ))
        .expect("a grant");
        let of_billing = NewMapper {
            targets: &[ClaimTarget::AccessToken],
            ..make_mapper(
                "billing",
                MapperKind::ClientRoles {
                    client_id: "billing".to_owned(),
                },
                "billing_roles",
            )
        };
        create(&scenario, &operator, of_billing).expect("a mapper");

        let tokens = scenario.sign_in("openid profile").tokens;

        let access = read_claims(&tokens.access_token);
        assert_eq!(access["billing_roles"], json!(["approver"]));
    }

    #[test]
    fn a_person_who_holds_too_many_roles_is_refused_by_name_of_the_client() {
        use crate::authz::grants::MAX_HELD;
        use crate::oidc::introspect::introspect_token;
        use crate::oidc::token::{TokenRequest, grant_token};
        use crate::testkit::fixtures::grant_many_roles;

        let scenario = Scenario::start();
        let tokens = scenario.sign_in("openid roles").tokens;
        complete(grant_many_roles(
            &scenario.app,
            scenario.scope,
            scenario.find_ada(),
            MAX_HELD + 1,
        ));
        let named = |detail: Option<String>| detail.is_some_and(|detail| detail.contains("webapp"));

        let refreshed = complete(grant_token(
            &scenario.app,
            "acme",
            TokenRequest {
                grant_type: Some("refresh_token"),
                client_id: Some("webapp"),
                refresh_token: tokens.refresh_token.as_deref(),
                ..TokenRequest::default()
            },
        ))
        .expect_err("too many roles to say");
        assert_eq!(refreshed.cause.code, ErrorCode::HeldTooMany);
        assert!(named(refreshed.cause.detail), "the client of the grant");
        let told = complete(introspect_token(
            &scenario.app,
            "acme",
            Some("billing"),
            Some(scenario.copy_service_secret()),
            Some(&tokens.access_token),
        ))
        .expect_err("too many roles to tell");
        assert_eq!(told.cause.code, ErrorCode::HeldTooMany);
        assert!(named(told.cause.detail), "the client of the token");
    }

    #[test]
    fn a_mapper_names_a_scope_its_client_may_be_given() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[Capability::ClientWrite, Capability::UserRead]);
        let under = |scope| NewMapper {
            scope: Some(scope),
            ..department()
        };

        assert_eq!(
            create(&scenario, &operator, under("invoices:read")),
            Err(ErrorCode::MapperInvalid),
            "a scope of another client"
        );
        assert_eq!(create(&scenario, &operator, under("email")), Ok(()));
    }

    #[test]
    fn a_person_who_allowed_openid_alone_is_said_nothing_by_the_mappers_of_the_client() {
        let scenario = Scenario::start();
        scenario.register_partner();
        let operator = scenario.name_operator(&[
            Capability::ClientWrite,
            Capability::UserRead,
            Capability::UserWrite,
        ]);
        let wanted = NewMapper {
            targets: &ClaimTarget::ALL,
            ..department()
        };
        complete(create_mapper(&scenario.app, &operator, "partner", wanted)).expect("a mapper");
        let written = json!({ "department": "research" });
        complete(write_attributes(
            &scenario.app,
            &operator,
            scenario.find_ada(),
            written.as_object().expect("an object"),
        ))
        .expect("attributes");
        let says_department = |tokens: &crate::oidc::token::TokenResponse| {
            let identity = read_claims(tokens.id_token.as_deref().expect("an identity token"));
            let access = read_claims(&tokens.access_token);
            let told = complete(read_user_info(&scenario.app, "acme", &tokens.access_token))
                .expect("claims");
            [identity, access, told].map(|said| said.get("dept").is_some())
        };

        let allowed_openid = scenario.sign_in_and_consent("partner", "openid").tokens;
        assert_eq!(says_department(&allowed_openid), [false; 3]);

        let allowed_profile = scenario
            .sign_in_and_consent("partner", "openid profile")
            .tokens;
        assert_eq!(says_department(&allowed_profile), [true; 3]);
    }

    #[test]
    fn without_openid_nothing_is_read_for_an_identity_token_that_is_not_made() {
        let scenario = Scenario::start();
        let operator = scenario.name_operator(&[
            Capability::ClientWrite,
            Capability::UserRead,
            Capability::RoleRead,
        ]);
        let for_identity = |name, kind, claim| NewMapper {
            targets: &[ClaimTarget::IdToken],
            ..make_mapper(name, kind, claim)
        };
        create(
            &scenario,
            &operator,
            for_identity("roles", MapperKind::RealmRoles, "roles"),
        )
        .expect("a mapper");
        create(
            &scenario,
            &operator,
            for_identity("dept", attribute("department"), "dept"),
        )
        .expect("a mapper");
        let (attributes, roles) = (
            scenario.storage.count_attribute_reads(),
            scenario.storage.count_held_role_reads(),
        );

        let tokens = scenario.sign_in("profile").tokens;

        assert!(tokens.id_token.is_none());
        assert_eq!(scenario.storage.count_attribute_reads(), attributes);
        assert_eq!(scenario.storage.count_held_role_reads(), roles);
        scenario.sign_in("openid profile");
        assert!(
            scenario.storage.count_attribute_reads() > attributes
                && scenario.storage.count_held_role_reads() > roles,
            "read for the identity token once it is made"
        );
    }
}
