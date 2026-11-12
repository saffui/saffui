//! The attributes of a person: what an administrator writes of them beyond
//! their name and address. Mappers say them in tokens. Policies read only
//! those whose name starts with `policy.`, and a caller that may not write
//! policies may not write those: holding `user:write` grants no decision.

use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::rules::{AttributeReach, check_attributes, merge_attributes};
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::authz::admin::AdminCaller;
use crate::authz::roles::describe_actor;
use crate::error::{ErrorCode, Failure};

/// Replaces the attributes of a person the caller both reads and writes, and
/// writes those it names. Those it may not read or write stay as they were,
/// and count toward the bound.
///
/// # Errors
///
/// Returns [`ErrorCode::AttributesInvalid`], [`ErrorCode::CapabilityMissing`]
/// for an attribute policies read written without `policy:write`,
/// [`ErrorCode::PersonNotFound`], or the storage failure.
pub async fn write_attributes(
    app: &App,
    caller: &AdminCaller,
    person: Uuid,
    written: &Map<String, Value>,
) -> Result<(), Failure> {
    check_attributes(written)?;
    let capabilities = &caller.client.capabilities;
    if !written
        .keys()
        .all(|name| AttributeReach::written_by(capabilities).covers(name))
    {
        return Err(Failure::new(ErrorCode::CapabilityMissing));
    }
    let reach = AttributeReach::replaced_by(capabilities);
    let mut work = app.storage.begin(caller.scope).await?;
    // Read under the lock of the person: a writer that comes meanwhile waits,
    // then counts what this one leaves.
    let Some(kept) = work.lock_person_attributes(person).await? else {
        return Err(Failure::new(ErrorCode::PersonNotFound));
    };
    let mut removed: Vec<&str> = kept
        .keys()
        .filter(|name| reach.covers(name) && !written.contains_key(*name))
        .map(String::as_str)
        .collect();
    removed.sort_unstable();
    let mut names: Vec<&str> = written.keys().map(String::as_str).collect();
    names.sort_unstable();
    // The names only: the values are about a person, and the chain is kept for years.
    let told = json!({
        "actor": describe_actor(caller),
        "attributes": names,
        "person_id": person.to_string(),
        "removed": removed,
    });
    let merged = merge_attributes(kept, written, reach);
    check_attributes(&merged)?;
    work.write_person_attributes(person, &merged).await?;
    record_event(app, work.as_mut(), EventKind::PersonAttributesWritten, told).await?;
    work.commit().await?;
    Ok(())
}

/// Reads the attributes of a person the caller reaches: those policies read
/// are told to a caller that may read policies alone.
///
/// # Errors
///
/// Returns [`ErrorCode::PersonNotFound`] or the storage failure.
pub async fn read_attributes(
    app: &App,
    caller: &AdminCaller,
    person: Uuid,
) -> Result<Map<String, Value>, Failure> {
    let reach = AttributeReach::read_by(&caller.client.capabilities);
    let mut work = app.storage.begin(caller.scope).await?;
    let mut kept = work
        .read_person_attributes(person)
        .await?
        .ok_or(Failure::new(ErrorCode::PersonNotFound))?;
    kept.retain(|name, _| reach.covers(name));
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::{read_attributes, write_attributes};
    use crate::authz::capability::Capability;
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    #[test]
    fn a_caller_without_policy_write_writes_no_attribute_a_policy_reads_and_leaves_them_as_kept() {
        let scenario = Scenario::start();
        let ada = scenario.find_ada();
        let clerk = scenario.name_operator(&[Capability::UserWrite, Capability::UserRead]);
        let write_attributes_as = |caller, attributes: Value| {
            complete(write_attributes(
                &scenario.app,
                caller,
                ada,
                attributes.as_object().expect("an object"),
            ))
            .map_err(|failure| failure.code)
        };
        let mut reader = clerk.clone();
        reader.client.capabilities.push(Capability::PolicyRead);
        let read_back = || complete(read_attributes(&scenario.app, &reader, ada));

        assert_eq!(
            write_attributes_as(&clerk, json!({ "policy.clearance": "secret" })),
            Err(ErrorCode::CapabilityMissing)
        );
        assert_eq!(read_back(), Ok(Map::new()), "nothing was kept");

        let mut both = clerk.clone();
        both.client.capabilities.push(Capability::PolicyWrite);
        let given = json!({ "department": "audit", "policy.clearance": "secret" });
        assert_eq!(write_attributes_as(&both, given.clone()), Ok(()));
        assert_eq!(read_back().map(Value::Object), Ok(given));

        assert_eq!(
            write_attributes_as(&clerk, json!({ "locale": "fr" })),
            Ok(())
        );
        assert_eq!(
            read_back().map(Value::Object),
            Ok(json!({ "locale": "fr", "policy.clearance": "secret" })),
            "the clerk replaced what it may write, and left the rest"
        );
    }

    #[test]
    fn the_attributes_policies_read_are_told_to_a_caller_that_may_read_policies_alone() {
        let scenario = Scenario::start();
        let ada = scenario.find_ada();
        let operator = scenario.name_operator(&[
            Capability::UserRead,
            Capability::UserWrite,
            Capability::PolicyWrite,
        ]);
        let written = json!({ "department": "audit", "policy.team": "audit" });
        complete(write_attributes(
            &scenario.app,
            &operator,
            ada,
            written.as_object().expect("an object"),
        ))
        .expect("attributes");
        let mut of_people = operator.clone();
        of_people.client.capabilities = vec![Capability::UserRead];
        let mut of_policies = of_people.clone();
        of_policies.client.capabilities.push(Capability::PolicyRead);
        let read_as =
            |caller| complete(read_attributes(&scenario.app, caller, ada)).map(Value::Object);

        assert_eq!(read_as(&of_people), Ok(json!({ "department": "audit" })));
        assert_eq!(read_as(&of_policies), Ok(written));
    }

    #[test]
    fn a_writer_that_cannot_read_the_policy_space_takes_nothing_of_it_away() {
        let scenario = Scenario::start();
        let ada = scenario.find_ada();
        let operator = scenario.name_operator(&[
            Capability::UserRead,
            Capability::UserWrite,
            Capability::PolicyRead,
            Capability::PolicyWrite,
        ]);
        let mut blind = operator.clone();
        blind.client.capabilities = vec![
            Capability::UserRead,
            Capability::UserWrite,
            Capability::PolicyWrite,
        ];
        let write_attributes_as = |caller, attributes: &Map<String, Value>| {
            complete(write_attributes(&scenario.app, caller, ada, attributes))
        };
        let read_as = |caller| complete(read_attributes(&scenario.app, caller, ada));
        let given = json!({ "department": "audit", "policy.team": "audit" });
        write_attributes_as(&operator, given.as_object().expect("an object")).expect("attributes");

        let mut seen = read_as(&blind).expect("attributes");
        assert_eq!(
            Value::Object(seen.clone()),
            json!({ "department": "audit" })
        );
        seen.insert("department".to_owned(), json!("research"));
        write_attributes_as(&blind, &seen).expect("what it read, changed");

        assert_eq!(
            read_as(&operator).map(Value::Object),
            Ok(json!({ "department": "research", "policy.team": "audit" })),
            "what the writer could not see is still there"
        );
        let removed = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "person.attributes_written")
            .expect("the event")["payload"]["removed"]
            .clone();
        assert_eq!(removed, json!([]));
        let named = json!({ "department": "research", "policy.team": "finance" });
        write_attributes_as(&blind, named.as_object().expect("an object"))
            .expect("a name of the space written on purpose");
        assert_eq!(read_as(&operator).map(Value::Object), Ok(named));
    }

    #[test]
    fn what_a_write_leaves_is_bounded_with_what_the_writer_could_not_reach() {
        let scenario = Scenario::start();
        let ada = scenario.find_ada();
        let clerk = scenario.name_operator(&[Capability::UserWrite]);
        let mut both = clerk.clone();
        both.client.capabilities.push(Capability::PolicyWrite);
        let named = |prefix: &str, count: usize| -> Map<String, Value> {
            (0..count)
                .map(|index| (format!("{prefix}{index:02}"), json!("x")))
                .collect()
        };
        complete(write_attributes(
            &scenario.app,
            &both,
            ada,
            &named("policy.p", 32),
        ))
        .expect("the attributes of the policies");

        let past = complete(write_attributes(
            &scenario.app,
            &clerk,
            ada,
            &named("a", 33),
        ));
        let at = complete(write_attributes(
            &scenario.app,
            &clerk,
            ada,
            &named("a", 32),
        ));

        assert_eq!(
            past.map_err(|failure| failure.code),
            Err(ErrorCode::AttributesInvalid)
        );
        assert_eq!(at, Ok(()));
    }

    #[test]
    fn the_chain_names_the_attributes_written_and_never_their_values() {
        let scenario = Scenario::start();
        let ada = scenario.find_ada();
        let clerk = scenario.name_operator(&[Capability::UserWrite]);
        let written = json!({ "department": "a-research-team", "badge": ["b-7731"] });

        complete(write_attributes(
            &scenario.app,
            &clerk,
            ada,
            written.as_object().expect("an object"),
        ))
        .expect("attributes");

        let event = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "person.attributes_written")
            .expect("the event");
        assert_eq!(
            event["payload"]["attributes"],
            json!(["badge", "department"])
        );
        assert_eq!(event["payload"]["person_id"], ada.to_string());
        assert_eq!(event["payload"]["removed"], json!([]));
        let told = event.to_string();
        for value in ["a-research-team", "b-7731"] {
            assert!(!told.contains(value), "{value} in {told}");
        }
    }

    #[test]
    fn the_chain_names_the_attributes_a_write_took_away_that_its_caller_could_reach() {
        let scenario = Scenario::start();
        let ada = scenario.find_ada();
        let clerk = scenario.name_operator(&[Capability::UserWrite]);
        let mut both = clerk.clone();
        both.client
            .capabilities
            .extend([Capability::PolicyRead, Capability::PolicyWrite]);
        let write_attributes_as = |caller, attributes: Value| {
            complete(write_attributes(
                &scenario.app,
                caller,
                ada,
                attributes.as_object().expect("an object"),
            ))
            .expect("attributes");
        };
        let last_removed = || {
            scenario
                .storage
                .read_audit_envelopes(scenario.scope.realm())
                .into_iter()
                .rfind(|event| event["kind"] == "person.attributes_written")
                .expect("the event")["payload"]["removed"]
                .clone()
        };
        write_attributes_as(
            &both,
            json!({ "policy.x": "secret-x", "team": "audit", "zone": "north" }),
        );

        write_attributes_as(&clerk, json!({ "team": "audit" }));
        assert_eq!(
            last_removed(),
            json!(["zone"]),
            "what the clerk cannot reach it does not take away"
        );
        write_attributes_as(&both, json!({}));
        assert_eq!(last_removed(), json!(["policy.x", "team"]));
        assert!(!last_removed().to_string().contains("secret-x"));
    }
}
