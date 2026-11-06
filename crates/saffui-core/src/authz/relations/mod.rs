//! Relations between objects and subjects, and the permissions computed
//! from them: a schema per realm, the relations kept, and a bounded walk.

pub mod check;
pub mod schema;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize as _;
use serde_json::json;
use time::OffsetDateTime;

use self::schema::{
    AllowedSubject, COMPILED_VERSION, CompiledSchema, MemberKind, SchemaFault, compile_schema,
};
use super::admin::AdminCaller;
use super::roles::describe_actor;
use crate::app::App;
use crate::audit::EventKind;
use crate::audit::append::record_event;
use crate::error::{ErrorCode, Failure};

/// An object: its type, and its identifier within the type.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectRef {
    pub object_type: String,
    pub object_id: String,
}

/// What a relation names: an object, or the members of a member of an
/// object (`team:core#member`).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectRef {
    pub object: ObjectRef,
    pub member: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelationTuple {
    pub object: ObjectRef,
    pub relation: String,
    pub subject: SubjectRef,
}

/// What a schema admits of a relation: a type of object, one of its
/// relations, and a subject the relation names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedRelation {
    pub object_type: String,
    pub relation: String,
    pub subject: AllowedSubject,
}

/// Every relation a schema admits, type by type.
#[must_use]
pub fn list_admitted_relations(schema: &CompiledSchema) -> Vec<AdmittedRelation> {
    schema
        .types
        .iter()
        .flat_map(|(object_type, found)| {
            found.relations.iter().flat_map(move |(relation, allowed)| {
                allowed.iter().map(move |subject| AdmittedRelation {
                    object_type: object_type.clone(),
                    relation: relation.clone(),
                    subject: subject.clone(),
                })
            })
        })
        .collect()
}

fn is_admitted_by(one: &AdmittedRelation, schema: &CompiledSchema) -> bool {
    schema
        .types
        .get(&one.object_type)
        .and_then(|found| found.relations.get(&one.relation))
        .is_some_and(|allowed| allowed.contains(&one.subject))
}

/// What changes when a schema replaces another: every relation one of them
/// admits and the other does not. A relation of a kind the later one admits
/// anew was not kept by the product, which refused it until now.
#[must_use]
pub fn list_changed_relations(
    before: &CompiledSchema,
    after: &CompiledSchema,
) -> Vec<AdmittedRelation> {
    let withdrawn = list_admitted_relations(before)
        .into_iter()
        .filter(|one| !is_admitted_by(one, after));
    let admitted_anew = list_admitted_relations(after)
        .into_iter()
        .filter(|one| !is_admitted_by(one, before));
    withdrawn.chain(admitted_anew).collect()
}

/// A schema as a realm keeps it: what was written, and what it compiled to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSchema {
    pub source: String,
    pub compiled: serde_json::Value,
    pub written_at: OffsetDateTime,
}

impl StoredSchema {
    /// The compiled form. A form another version wrote is compiled again
    /// from its source, never read as it is.
    #[must_use]
    pub fn open(&self) -> Option<CompiledSchema> {
        read_compiled_schema(&self.compiled).or_else(|| compile_schema(&self.source).ok())
    }
}

/// Reads a compiled form as this version writes it. A form of another
/// version, or one that does not read, is none.
#[must_use]
pub fn read_compiled_schema(compiled: &serde_json::Value) -> Option<CompiledSchema> {
    CompiledSchema::deserialize(compiled)
        .ok()
        .filter(|schema| schema.version == COMPILED_VERSION)
}

/// What a question reads of the schema of a realm: the compiled form, and
/// whether the client that asks guards the type asked of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardedSchema {
    pub compiled: serde_json::Value,
    pub guarded: bool,
}

/// Whether a text may identify an object: 1 to 128 letters, digits, dots,
/// colons, at signs, hyphens or underscores.
#[must_use]
pub fn is_object_id(text: &str) -> bool {
    (1..=128).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".:@_-".contains(&byte))
}

/// Reads an object written `type:id`.
#[must_use]
pub fn read_object(text: &str) -> Option<ObjectRef> {
    let (object_type, object_id) = text.split_once(':')?;
    (schema::is_schema_name(object_type) && is_object_id(object_id)).then(|| ObjectRef {
        object_type: object_type.to_owned(),
        object_id: object_id.to_owned(),
    })
}

/// Reads a subject written `type:id`, or `type:id#member` for the members
/// of a member of an object.
#[must_use]
pub fn read_subject(text: &str) -> Option<SubjectRef> {
    let (object, member) = match text.rsplit_once('#') {
        Some((object, member)) if schema::is_schema_name(member) => {
            (object, Some(member.to_owned()))
        }
        Some(_) => return None,
        None => (text, None),
    };
    Some(SubjectRef {
        object: read_object(object)?,
        member,
    })
}

/// Lists the subjects a relation of an object names, at most as many as a
/// walk reads, and says whether there were more.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_relation_subjects(
    app: &App,
    scope: crate::tenancy::RealmScope,
    object: &ObjectRef,
    relation: &str,
) -> Result<(Vec<SubjectRef>, bool), Failure> {
    let mut work = app.storage.begin(scope).await?;
    let ceiling = u32::try_from(check::MAX_FANOUT).unwrap_or(u32::MAX);
    let mut subjects = work
        .list_relation_subjects(object, relation, ceiling.saturating_add(1))
        .await?;
    let cut = subjects.len() > check::MAX_FANOUT;
    subjects.truncate(check::MAX_FANOUT);
    Ok((subjects, cut))
}

/// Why a schema was not written.
#[derive(Debug, PartialEq, Eq)]
pub enum SchemaRefusal {
    /// Its faults, each at its line.
    Faults(Vec<SchemaFault>),
    Failed(Failure),
}

impl From<Failure> for SchemaRefusal {
    fn from(failure: Failure) -> Self {
        Self::Failed(failure)
    }
}

impl From<crate::ports::storage::StorageError> for SchemaRefusal {
    fn from(error: crate::ports::storage::StorageError) -> Self {
        Self::Failed(error.into())
    }
}

/// Writes the schema of relations of a realm, in place of the one before.
/// The relations it no longer admits go with the schema that admitted them:
/// a later schema that admits them again finds none of them. So do those of
/// a kind it admits anew, kept behind the product's back. Returns the schema
/// and how many relations went.
///
/// # Errors
///
/// Returns the faults of the schema, or the storage failure.
pub async fn write_relation_schema(
    app: &App,
    caller: &AdminCaller,
    source: &str,
) -> Result<(CompiledSchema, u64), SchemaRefusal> {
    let compiled = compile_schema(source).map_err(SchemaRefusal::Faults)?;
    let stored = StoredSchema {
        source: source.to_owned(),
        compiled: serde_json::to_value(&compiled).map_err(|_| Failure::new(ErrorCode::Internal))?,
        written_at: app.now(),
    };
    let mut work = app.storage.begin(caller.scope).await?;
    // Checked and written under the lock of the definitions, as a policy is.
    work.lock_definitions().await?;
    // A type a policy guards is decided by policies: the schema does not take it.
    let types: Vec<String> = compiled.types.keys().cloned().collect();
    if work.has_policy_for_types(&types).await? {
        return Err(SchemaRefusal::Failed(Failure::new(
            ErrorCode::ResourceTypeTaken,
        )));
    }
    // Read under the lock: what it admitted stands until this one replaces it.
    let before = work.read_relation_schema().await?;
    work.write_relation_schema(&stored).await?;
    let removed = match before.as_ref().map(StoredSchema::open) {
        Some(Some(before)) => {
            let changed = list_changed_relations(&before, &compiled);
            if changed.is_empty() {
                0
            } else {
                work.delete_relations_of_kinds(&changed).await?
            }
        }
        // What the schema before admitted is not known: whatever this one
        // does not admit goes.
        Some(None) => {
            work.delete_relations_not_admitted(&list_admitted_relations(&compiled))
                .await?
        }
        // No schema stood, and the product kept no relation: every kind this
        // one admits is new, and whatever it does not admit goes too.
        None => work.delete_relations_not_admitted(&[]).await?,
    };
    // The schema is replaced in place: the chain keeps what each said.
    let told = json!({
        "actor": describe_actor(caller),
        "relations_removed": removed,
        "source": source,
        "source_sha256": URL_SAFE_NO_PAD.encode(app.digester.sha256(source.as_bytes())),
        "types": compiled.types.keys().collect::<Vec<_>>(),
    });
    record_event(app, work.as_mut(), EventKind::RelationSchemaWritten, told)
        .await
        .map_err(SchemaRefusal::Failed)?;
    work.commit().await?;
    Ok((compiled, removed))
}

/// Reads the schema of relations of a realm, as it was written.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn read_relation_schema(
    app: &App,
    scope: crate::tenancy::RealmScope,
) -> Result<Option<StoredSchema>, Failure> {
    let mut work = app.storage.begin(scope).await?;
    Ok(work.read_relation_schema().await?)
}

/// Refuses a relation the schema of the realm does not admit: an object of
/// a type it does not have, a member that is not a relation, a subject the
/// relation does not name.
fn check_relation(schema: &CompiledSchema, tuple: &RelationTuple) -> Result<(), Failure> {
    let invalid = || Failure::new(ErrorCode::RelationInvalid);
    let ids_read =
        is_object_id(&tuple.object.object_id) && is_object_id(&tuple.subject.object.object_id);
    let Some(MemberKind::Relation(allowed)) =
        schema.find_member(&tuple.object.object_type, &tuple.relation)
    else {
        return Err(invalid());
    };
    let admitted = allowed.iter().any(|subject| {
        subject.object_type == tuple.subject.object.object_type
            && subject.member == tuple.subject.member
    });
    if ids_read && admitted {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn describe_relation(tuple: &RelationTuple) -> serde_json::Value {
    json!({
        "object": format!("{}:{}", tuple.object.object_type, tuple.object.object_id),
        "relation": tuple.relation,
        "subject": format!(
            "{}:{}{}",
            tuple.subject.object.object_type,
            tuple.subject.object.object_id,
            tuple.subject.member.as_deref().map_or_else(String::new, |member| format!("#{member}")),
        ),
    })
}

/// Keeps a relation the schema of the realm admits. Kept twice, it is kept
/// once, and the chain says so once.
///
/// # Errors
///
/// Returns [`ErrorCode::RelationInvalid`], also when the realm has no
/// schema, or the storage failure.
pub async fn write_relation(
    app: &App,
    caller: &AdminCaller,
    tuple: &RelationTuple,
) -> Result<(), Failure> {
    let invalid = || Failure::new(ErrorCode::RelationInvalid);
    let mut work = app.storage.begin(caller.scope).await?;
    // Checked and kept while no writer of the schema can replace it: one that
    // comes after finds this relation, and removes it if it no longer admits it.
    let compiled = work
        .lock_definitions_and_read_schema()
        .await?
        .ok_or_else(invalid)?;
    let schema = match read_compiled_schema(&compiled) {
        Some(schema) => schema,
        // A form another version wrote: its source is read and compiled again.
        None => work
            .read_relation_schema()
            .await?
            .and_then(|stored| stored.open())
            .ok_or_else(invalid)?,
    };
    check_relation(&schema, tuple)?;
    if work.insert_relation(tuple, app.now()).await? {
        let told = json!({ "actor": describe_actor(caller), "relation": describe_relation(tuple) });
        record_event(app, work.as_mut(), EventKind::RelationWritten, told).await?;
        work.commit().await?;
    }
    Ok(())
}

/// How many clients guard one type at most, as an administrator lists them.
pub const MAX_GUARDS_LISTED: u32 = 100;

/// Makes a client of the realm a guard of a type of the schema: the point of
/// decision answers it, and it alone with the others that guard the type,
/// by the relations of the type. Made twice, it is made once.
///
/// # Errors
///
/// Returns [`ErrorCode::RelationInvalid`] for a name no type may have,
/// [`ErrorCode::ClientNotFound`], or the storage failure.
pub async fn write_relation_guard(
    app: &App,
    caller: &AdminCaller,
    object_type: &str,
    client_id: &str,
) -> Result<(), Failure> {
    if !schema::is_schema_name(object_type) {
        return Err(Failure::new(ErrorCode::RelationInvalid));
    }
    let mut work = app.storage.begin(caller.scope).await?;
    if crate::clients::read_named_client(work.as_mut(), client_id)
        .await?
        .is_none()
    {
        return Err(Failure::new(ErrorCode::ClientNotFound));
    }
    if work
        .insert_relation_guard(object_type, client_id, app.now())
        .await?
    {
        let told = json!({
            "actor": describe_actor(caller),
            "client_id": client_id,
            "object_type": object_type,
        });
        record_event(app, work.as_mut(), EventKind::RelationGuardWritten, told).await?;
        work.commit().await?;
    }
    Ok(())
}

/// Takes a guard of a type away.
///
/// # Errors
///
/// Returns [`ErrorCode::RelationNotFound`], or the storage failure.
pub async fn delete_relation_guard(
    app: &App,
    caller: &AdminCaller,
    object_type: &str,
    client_id: &str,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_relation_guard(object_type, client_id).await? {
        return Err(Failure::new(ErrorCode::RelationNotFound));
    }
    let told = json!({
        "actor": describe_actor(caller),
        "client_id": client_id,
        "object_type": object_type,
    });
    record_event(app, work.as_mut(), EventKind::RelationGuardDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

/// Lists the clients that guard a type.
///
/// # Errors
///
/// Returns the storage failure.
pub async fn list_relation_guards(
    app: &App,
    scope: crate::tenancy::RealmScope,
    object_type: &str,
) -> Result<Vec<String>, Failure> {
    let mut work = app.storage.begin(scope).await?;
    Ok(work
        .list_relation_guards(object_type, MAX_GUARDS_LISTED)
        .await?)
}

/// Removes a relation.
///
/// # Errors
///
/// Returns [`ErrorCode::RelationNotFound`], or the storage failure.
pub async fn delete_relation(
    app: &App,
    caller: &AdminCaller,
    tuple: &RelationTuple,
) -> Result<(), Failure> {
    let mut work = app.storage.begin(caller.scope).await?;
    if !work.delete_relation(tuple).await? {
        return Err(Failure::new(ErrorCode::RelationNotFound));
    }
    let told = json!({ "actor": describe_actor(caller), "relation": describe_relation(tuple) });
    record_event(app, work.as_mut(), EventKind::RelationDeleted, told).await?;
    work.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{read_object, read_subject, write_relation_schema};
    use crate::authz::capability::Capability;
    use crate::oidc::scenario::Scenario;
    use crate::testkit::drive::complete;

    #[test]
    fn a_schema_that_no_longer_admits_a_subject_takes_its_relations_and_a_later_one_wakes_none() {
        use super::{ObjectRef, RelationTuple, SubjectRef, list_relation_subjects, write_relation};

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let wide = "definition user {}\ndefinition team {\n  relation member: user\n}\ndefinition document {\n  relation reader: user | team#member\n}";
        let narrow = "definition user {}\ndefinition team {\n  relation member: user\n}\ndefinition document {\n  relation reader: user\n}";
        let object = |object_type: &str, object_id: &str| ObjectRef {
            object_type: object_type.to_owned(),
            object_id: object_id.to_owned(),
        };
        let reader = |subject: ObjectRef, member: Option<&str>| RelationTuple {
            object: object("document", "q3"),
            relation: "reader".to_owned(),
            subject: SubjectRef {
                object: subject,
                member: member.map(str::to_owned),
            },
        };
        complete(write_relation_schema(&scenario.app, &caller, wide)).expect("a schema");
        for tuple in [
            reader(object("team", "core"), Some("member")),
            reader(object("user", "ada"), None),
        ] {
            complete(write_relation(&scenario.app, &caller, &tuple)).expect("a relation");
        }
        let readers = || {
            complete(list_relation_subjects(
                &scenario.app,
                scenario.scope,
                &object("document", "q3"),
                "reader",
            ))
            .expect("a list")
            .0
            .len()
        };

        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, narrow)).expect("a schema");
        assert_eq!(removed, 1, "the members of a team are no longer readers");
        assert_eq!(readers(), 1);
        let written = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "relation.schema_written")
            .expect("the event");
        assert_eq!(written["payload"]["relations_removed"], 1);

        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, wide)).expect("a schema");
        assert_eq!(removed, 0);
        assert_eq!(
            readers(),
            1,
            "the schema that admits them again wakes none of them"
        );
    }

    #[test]
    fn a_schema_removes_only_the_kinds_it_withdraws_and_one_that_withdraws_none_removes_nothing() {
        use super::{ObjectRef, RelationTuple, SubjectRef, list_relation_subjects, write_relation};

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let wide = "definition user {}\ndefinition team {\n  relation member: user\n}\ndefinition document {\n  relation owner: user\n  relation reader: user | team#member\n}";
        let narrow = "definition user {}\ndefinition team {\n  relation member: user\n}\ndefinition document {\n  relation reader: user\n}";
        let object = |text: &str| {
            let (object_type, object_id) = text.split_once(':').expect("type:id");
            ObjectRef {
                object_type: object_type.to_owned(),
                object_id: object_id.to_owned(),
            }
        };
        let relate = |object_text: &str, relation: &str, subject_text: &str| {
            let (subject, member) = match subject_text.split_once('#') {
                Some((subject, member)) => (subject, Some(member.to_owned())),
                None => (subject_text, None),
            };
            RelationTuple {
                object: object(object_text),
                relation: relation.to_owned(),
                subject: SubjectRef {
                    object: object(subject),
                    member,
                },
            }
        };
        let count = |object_text: &str, relation: &str| {
            complete(list_relation_subjects(
                &scenario.app,
                scenario.scope,
                &object(object_text),
                relation,
            ))
            .expect("a list")
            .0
            .len()
        };
        complete(write_relation_schema(&scenario.app, &caller, wide)).expect("a schema");
        for (object_text, relation, subject_text) in [
            ("document:q3", "owner", "user:bob"),
            ("document:q3", "reader", "user:ada"),
            ("document:q3", "reader", "team:core#member"),
            ("document:q4", "reader", "team:core#member"),
            ("document:q4", "reader", "user:eve"),
            ("team:core", "member", "user:ada"),
        ] {
            let tuple = relate(object_text, relation, subject_text);
            complete(write_relation(&scenario.app, &caller, &tuple)).expect("a relation");
        }

        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, narrow)).expect("a schema");
        assert_eq!(removed, 3, "the owners, and the teams that read");
        assert_eq!(
            (
                count("document:q3", "owner"),
                count("document:q3", "reader"),
                count("document:q4", "reader"),
                count("team:core", "member"),
            ),
            (0, 1, 1, 1)
        );

        // A relation no schema admits, kept behind the product's back: a
        // schema that withdraws nothing does not look for it.
        complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            work.insert_relation(
                &relate("document:q3", "owner", "user:mallory"),
                scenario.app.now(),
            )
            .await
            .expect("a relation kept by hand");
            work.commit().await.expect("a commit");
        });
        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, narrow)).expect("a schema");
        assert_eq!(removed, 0);
        assert_eq!(count("document:q3", "owner"), 1, "nothing was swept");

        // A schema that admits its kind again takes it with the schema it
        // writes: no question ever reads it as an owner.
        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, wide)).expect("a schema");
        assert_eq!(removed, 1, "the relation kept by hand, and nothing else");
        assert_eq!(count("document:q3", "owner"), 0);
        assert_eq!(count("document:q3", "reader"), 1);
    }

    #[test]
    fn a_first_schema_takes_every_relation_and_one_after_an_unreadable_schema_what_it_does_not_admit()
     {
        use super::{ObjectRef, RelationTuple, StoredSchema, SubjectRef, list_relation_subjects};

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let schema = "definition user {}\ndefinition document {\n  relation owner: user\n}";
        let relate = |object_id: &str, relation: &str, subject_id: &str| RelationTuple {
            object: ObjectRef {
                object_type: "document".to_owned(),
                object_id: object_id.to_owned(),
            },
            relation: relation.to_owned(),
            subject: SubjectRef {
                object: ObjectRef {
                    object_type: "user".to_owned(),
                    object_id: subject_id.to_owned(),
                },
                member: None,
            },
        };
        let keep_by_hand = |tuples: &[RelationTuple]| {
            complete(async {
                let mut work = scenario
                    .app
                    .storage
                    .begin(scenario.scope)
                    .await
                    .expect("a unit of work");
                for tuple in tuples {
                    work.insert_relation(tuple, scenario.app.now())
                        .await
                        .expect("a relation kept by hand");
                }
                work.commit().await.expect("a commit");
            });
        };
        let count = |object_id: &str, relation: &str| {
            let object = ObjectRef {
                object_type: "document".to_owned(),
                object_id: object_id.to_owned(),
            };
            complete(list_relation_subjects(
                &scenario.app,
                scenario.scope,
                &object,
                relation,
            ))
            .expect("a list")
            .0
            .len()
        };
        keep_by_hand(&[
            relate("q1", "owner", "mallory"),
            relate("q1", "editor", "mallory"),
        ]);

        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, schema)).expect("a schema");
        assert_eq!(removed, 2, "what it admits, and what it does not");
        assert_eq!((count("q1", "owner"), count("q1", "editor")), (0, 0));

        // A schema no version reads: what it admitted is not known.
        complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            let unreadable = StoredSchema {
                source: "definition".to_owned(),
                compiled: serde_json::json!({ "version": 0 }),
                written_at: scenario.app.now(),
            };
            work.write_relation_schema(&unreadable)
                .await
                .expect("a schema written by hand");
            work.commit().await.expect("a commit");
        });
        keep_by_hand(&[relate("q2", "owner", "ada"), relate("q2", "editor", "eve")]);
        let (_, removed) =
            complete(write_relation_schema(&scenario.app, &caller, schema)).expect("a schema");
        assert_eq!(removed, 1, "what it does not admit");
        assert_eq!((count("q2", "owner"), count("q2", "editor")), (1, 0));
    }

    #[test]
    fn a_client_of_the_realm_guards_a_type_and_the_chain_says_who_made_it_one() {
        use super::{delete_relation_guard, list_relation_guards, write_relation_guard};
        use crate::error::ErrorCode;

        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let guard = |object_type: &str, client_id: &str| {
            complete(write_relation_guard(
                &scenario.app,
                &caller,
                object_type,
                client_id,
            ))
            .map_err(|failure| failure.code)
        };

        assert_eq!(guard("document", "billing"), Ok(()));
        assert_eq!(
            guard("document", "billing"),
            Ok(()),
            "made twice, it is made once"
        );
        assert_eq!(guard("document", "nobody"), Err(ErrorCode::ClientNotFound));
        assert_eq!(
            guard("Document", "billing"),
            Err(ErrorCode::RelationInvalid)
        );
        assert_eq!(
            complete(list_relation_guards(
                &scenario.app,
                scenario.scope,
                "document"
            )),
            Ok(vec!["billing".to_owned()])
        );
        let made = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .filter(|event| event["kind"] == "relation.guard_written")
            .count();
        assert_eq!(made, 1);
        let delete = || {
            complete(delete_relation_guard(
                &scenario.app,
                &caller,
                "document",
                "billing",
            ))
            .map_err(|failure| failure.code)
        };
        assert_eq!(delete(), Ok(()));
        assert_eq!(delete(), Err(ErrorCode::RelationNotFound));
    }

    #[test]
    fn a_list_past_its_ceiling_says_it_was_cut() {
        use super::check::MAX_FANOUT;
        use super::{ObjectRef, RelationTuple, SubjectRef, list_relation_subjects};

        let scenario = Scenario::start();
        let object = |object_type: &str, object_id: &str| ObjectRef {
            object_type: object_type.to_owned(),
            object_id: object_id.to_owned(),
        };
        complete(async {
            let mut work = scenario
                .app
                .storage
                .begin(scenario.scope)
                .await
                .expect("a unit of work");
            for index in 0..=MAX_FANOUT {
                let tuple = RelationTuple {
                    object: object("document", "q3"),
                    relation: "reader".to_owned(),
                    subject: SubjectRef {
                        object: object("user", &format!("person-{index}")),
                        member: None,
                    },
                };
                work.insert_relation(&tuple, scenario.app.now())
                    .await
                    .expect("a relation");
            }
            work.commit().await.expect("a commit");
        });

        let (subjects, cut) = complete(list_relation_subjects(
            &scenario.app,
            scenario.scope,
            &object("document", "q3"),
            "reader",
        ))
        .expect("a list");
        assert!(cut);
        assert_eq!(subjects.len(), MAX_FANOUT);
    }

    #[test]
    fn the_chain_keeps_what_each_schema_said() {
        let scenario = Scenario::start();
        let caller = scenario.name_operator(&[Capability::PolicyWrite]);
        let source = "definition user {}\ndefinition team {\n  relation member: user\n}";

        complete(write_relation_schema(&scenario.app, &caller, source)).expect("a schema");

        let written = scenario
            .storage
            .read_audit_envelopes(scenario.scope.realm())
            .into_iter()
            .rfind(|event| event["kind"] == "relation.schema_written")
            .expect("the event");
        assert_eq!(written["payload"]["source"], source);
        assert_eq!(
            written["payload"]["types"],
            serde_json::json!(["team", "user"])
        );
        assert!(written["payload"]["source_sha256"].is_string());
    }

    #[test]
    fn an_object_and_a_subject_are_read_as_they_are_written_and_nothing_else_is() {
        let object = read_object("document:q3-2026").expect("an object");
        assert_eq!(
            (object.object_type.as_str(), object.object_id.as_str()),
            ("document", "q3-2026")
        );
        let members = read_subject("team:core#member").expect("a subject");
        assert_eq!(members.member.as_deref(), Some("member"));
        assert_eq!(
            read_subject("user:ada").and_then(|subject| subject.member),
            None
        );
        for text in [
            "document",
            "Document:q3",
            "document:",
            "document:a b",
            "doc:x/y",
        ] {
            assert!(read_object(text).is_none(), "{text:?}");
        }
        for text in ["team:core#", "team:core#Member", "team#member"] {
            assert!(read_subject(text).is_none(), "{text:?}");
        }
    }
}
