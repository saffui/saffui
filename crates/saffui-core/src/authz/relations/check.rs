//! Whether a subject stands in a member of an object: a walk over the
//! relations kept, bounded in depth, in reads of the storage, in subjects
//! read at once and in time. A walk that reaches a bound answers that it
//! could not tell, never that the subject does not stand. A storage that
//! fails is not a bound: the walk stops on its error.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

use time::{Duration, OffsetDateTime};

use super::schema::{CompiledSchema, MemberKind, Rule};
use super::{ObjectRef, SubjectRef};
use crate::app::App;
use crate::authz::shares::DecisionShare;
use crate::ports::storage::{StorageError, UnitOfWork};

/// How deep a walk goes before it gives up.
pub const MAX_DEPTH: usize = 64;
/// How many times a walk reads the storage.
pub const MAX_READS: usize = 1000;
/// How many subjects one relation of one object may name to be walked.
pub const MAX_FANOUT: usize = 1000;
/// How long a walk takes before it gives up.
pub const MAX_DURATION: Duration = Duration::milliseconds(100);
/// How many members a walk enters before it gives up, whether it reads or
/// not: a schema of a few lines can double the work at each level.
pub const MAX_STEPS: usize = 10_000;

/// What a walk found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    Found,
    NotFound,
    /// It could not tell. A decision refuses, and says why.
    Undecided(WalkLimit),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkLimit {
    Depth,
    Reads,
    Fanout,
    Duration,
    /// The walk came back to where it was: the relations kept form a loop.
    Cycle,
    Steps,
}

impl WalkLimit {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Depth => "depth",
            Self::Reads => "reads",
            Self::Fanout => "fanout",
            Self::Duration => "duration",
            Self::Cycle => "cycle",
            Self::Steps => "steps",
        }
    }
}

type Step<'w> = Pin<Box<dyn Future<Output = Result<Walk, StorageError>> + Send + 'w>>;

/// What one read of a walk found.
enum Subjects {
    Read(Vec<SubjectRef>),
    /// A bound was reached before or around the read.
    Bound(WalkLimit),
}

/// Folds the walks of a sum: one found is enough.
fn fold_union(walks: impl IntoIterator<Item = Walk>) -> Walk {
    let mut undecided = None;
    for walk in walks {
        match walk {
            Walk::Found => return Walk::Found,
            Walk::Undecided(limit) => undecided = Some(limit),
            Walk::NotFound => {}
        }
    }
    undecided.map_or(Walk::NotFound, Walk::Undecided)
}

/// What a walk may spend: the instant it gives up, and the share of the
/// node it holds for as long as it walks.
pub(crate) struct WalkBudget<'a> {
    pub(crate) deadline: OffsetDateTime,
    /// Held, never read: a walk cannot start without a share it keeps.
    pub(crate) _share: &'a DecisionShare,
}

struct Walker<'w> {
    app: &'w App,
    work: &'w mut dyn UnitOfWork,
    schema: &'w CompiledSchema,
    subject: &'w ObjectRef,
    deadline: OffsetDateTime,
    reads: usize,
    steps: usize,
    /// What this walk found of each member, an undecided answer too: no
    /// member is walked twice, so the work grows with the members, never
    /// with the ways to reach them. Refusing sooner never permits wrongly.
    known: HashMap<(ObjectRef, String), Walk>,
    /// What is being walked now.
    walking: HashSet<(ObjectRef, String)>,
}

impl Walker<'_> {
    fn check_time(&self) -> Option<WalkLimit> {
        (self.app.now() > self.deadline).then_some(WalkLimit::Duration)
    }

    /// Reads the subjects a relation of an object names, within the bounds.
    async fn read_subjects(
        &mut self,
        object: &ObjectRef,
        relation: &str,
    ) -> Result<Subjects, StorageError> {
        self.reads += 1;
        if self.reads > MAX_READS {
            return Ok(Subjects::Bound(WalkLimit::Reads));
        }
        if let Some(limit) = self.check_time() {
            return Ok(Subjects::Bound(limit));
        }
        let ceiling = u32::try_from(MAX_FANOUT + 1).unwrap_or(u32::MAX);
        let subjects = self
            .work
            .list_relation_subjects(object, relation, ceiling)
            .await?;
        if subjects.len() > MAX_FANOUT {
            return Ok(Subjects::Bound(WalkLimit::Fanout));
        }
        // Around the read too: a slow storage is a slow walk.
        if let Some(limit) = self.check_time() {
            return Ok(Subjects::Bound(limit));
        }
        Ok(Subjects::Read(subjects))
    }

    fn walk_member(&mut self, object: ObjectRef, member: String, depth: usize) -> Step<'_> {
        Box::pin(async move {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Ok(Walk::Undecided(WalkLimit::Steps));
            }
            // At each member, not only around a read: a walk that never reads
            // still meets its deadline.
            if let Some(limit) = self.check_time() {
                return Ok(Walk::Undecided(limit));
            }
            if depth > MAX_DEPTH {
                return Ok(Walk::Undecided(WalkLimit::Depth));
            }
            let key = (object, member);
            if let Some(known) = self.known.get(&key) {
                return Ok(*known);
            }
            if !self.walking.insert(key.clone()) {
                return Ok(Walk::Undecided(WalkLimit::Cycle));
            }
            let (object, member) = &key;
            let schema = self.schema;
            let walk = match schema.find_member(&object.object_type, member) {
                None => Walk::NotFound,
                Some(MemberKind::Relation(_)) => {
                    self.walk_relation(object.clone(), member.clone(), depth)
                        .await?
                }
                Some(MemberKind::Permission(rule)) => {
                    self.walk_rule(object.clone(), rule.clone(), depth).await?
                }
            };
            self.walking.remove(&key);
            self.known.insert(key, walk);
            Ok(walk)
        })
    }

    /// Whether the subject is named by a relation of the object, itself or
    /// as a member of what it names. A subject the schema does not admit
    /// there is not walked.
    fn walk_relation(&mut self, object: ObjectRef, relation: String, depth: usize) -> Step<'_> {
        Box::pin(async move {
            let schema = self.schema;
            let Some(MemberKind::Relation(allowed)) =
                schema.find_member(&object.object_type, &relation)
            else {
                return Ok(Walk::NotFound);
            };
            let subjects = match self.read_subjects(&object, &relation).await? {
                Subjects::Read(subjects) => subjects,
                Subjects::Bound(limit) => return Ok(Walk::Undecided(limit)),
            };
            let admitted: Vec<SubjectRef> = subjects
                .into_iter()
                .filter(|named| {
                    allowed.iter().any(|subject| {
                        subject.object_type == named.object.object_type
                            && subject.member == named.member
                    })
                })
                .collect();
            if admitted
                .iter()
                .any(|named| named.member.is_none() && named.object == *self.subject)
            {
                return Ok(Walk::Found);
            }
            let mut walks = Vec::new();
            for named in admitted {
                if let Some(member) = named.member {
                    let walk = self.walk_member(named.object, member, depth + 1).await?;
                    if walk == Walk::Found {
                        return Ok(Walk::Found);
                    }
                    walks.push(walk);
                }
            }
            Ok(fold_union(walks))
        })
    }

    fn walk_rule(&mut self, object: ObjectRef, rule: Rule, depth: usize) -> Step<'_> {
        Box::pin(async move {
            match rule {
                Rule::Computed { member } => self.walk_member(object, member, depth + 1).await,
                Rule::Arrow { relation, member } => {
                    let schema = self.schema;
                    let Some(MemberKind::Relation(allowed)) =
                        schema.find_member(&object.object_type, &relation)
                    else {
                        return Ok(Walk::NotFound);
                    };
                    let objects: Vec<ObjectRef> =
                        match self.read_subjects(&object, &relation).await? {
                            Subjects::Read(subjects) => subjects
                                .into_iter()
                                .filter(|named| {
                                    named.member.is_none()
                                        && allowed.iter().any(|subject| {
                                            subject.member.is_none()
                                                && subject.object_type == named.object.object_type
                                        })
                                })
                                .map(|named| named.object)
                                .collect(),
                            Subjects::Bound(limit) => return Ok(Walk::Undecided(limit)),
                        };
                    let mut walks = Vec::new();
                    for next in objects {
                        let walk = self.walk_member(next, member.clone(), depth + 1).await?;
                        if walk == Walk::Found {
                            return Ok(Walk::Found);
                        }
                        walks.push(walk);
                    }
                    Ok(fold_union(walks))
                }
                Rule::Union { rules } => {
                    let mut walks = Vec::new();
                    for inner in rules {
                        let walk = self.walk_rule(object.clone(), inner, depth + 1).await?;
                        if walk == Walk::Found {
                            return Ok(Walk::Found);
                        }
                        walks.push(walk);
                    }
                    Ok(fold_union(walks))
                }
                // An intersection of nothing finds nothing: the parser never
                // writes one, and a stored form is not trusted to be its work.
                Rule::Intersection { rules } if rules.is_empty() => Ok(Walk::NotFound),
                Rule::Intersection { rules } => {
                    let mut undecided = None;
                    for inner in rules {
                        match self.walk_rule(object.clone(), inner, depth + 1).await? {
                            Walk::NotFound => return Ok(Walk::NotFound),
                            Walk::Undecided(limit) => undecided = Some(limit),
                            Walk::Found => {}
                        }
                    }
                    Ok(undecided.map_or(Walk::Found, Walk::Undecided))
                }
            }
        })
    }
}

/// Tells whether `subject` stands in `member` of `object`.
///
/// # Errors
///
/// Returns the storage failure: a read that fails is never taken for an answer.
pub(crate) async fn walk_relations(
    app: &App,
    work: &mut dyn UnitOfWork,
    schema: &CompiledSchema,
    object: &ObjectRef,
    member: &str,
    subject: &ObjectRef,
    budget: WalkBudget<'_>,
) -> Result<Walk, StorageError> {
    let mut walker = Walker {
        app,
        work,
        schema,
        subject,
        deadline: budget.deadline,
        reads: 0,
        steps: 0,
        known: HashMap::new(),
        walking: HashSet::new(),
    };
    walker
        .walk_member(object.clone(), member.to_owned(), 0)
        .await
}

#[cfg(test)]
mod tests {
    use super::super::schema::compile_schema;
    use super::super::{
        ObjectRef, RelationTuple, SubjectRef, write_relation, write_relation_schema,
    };
    use std::sync::Arc;

    use super::{MAX_DURATION, MAX_FANOUT, MAX_READS, Walk, WalkBudget, WalkLimit, walk_relations};
    use crate::app::App;
    use crate::authz::admin::AdminCaller;
    use crate::authz::capability::Capability;
    use crate::authz::shares::{DecisionShare, DecisionShares};
    use crate::error::ErrorCode;
    use crate::oidc::scenario::Scenario;
    use crate::tenancy::TenantId;
    use crate::testkit::drive::complete;

    const SCHEMA: &str = "
        definition user {}
        definition team {
            relation member: user | team#member
        }
        definition folder {
            relation parent: folder
            relation viewer: user | team#member
            permission view = viewer + view from parent
        }
        definition document {
            relation folder: folder
            relation owner: user
            relation editor: user | team#member
            relation blocked: user
            permission edit = owner + editor
            permission view = edit + view from folder
            permission approve = edit & owner
        }
    ";

    fn take_share() -> DecisionShare {
        Arc::new(DecisionShares::default())
            .take(TenantId::from_uuid(uuid::Uuid::nil()))
            .expect("a share")
    }

    fn budget<'a>(app: &App, share: &'a DecisionShare) -> WalkBudget<'a> {
        WalkBudget {
            deadline: app.now() + MAX_DURATION,
            _share: share,
        }
    }

    fn object(text: &str) -> ObjectRef {
        let (object_type, object_id) = text.split_once(':').expect("type:id");
        ObjectRef {
            object_type: object_type.to_owned(),
            object_id: object_id.to_owned(),
        }
    }

    fn relate(object_text: &str, relation: &str, subject_text: &str) -> RelationTuple {
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
    }

    struct Started {
        scenario: Scenario,
        caller: AdminCaller,
    }

    impl Started {
        fn open(schema: &str) -> Self {
            let scenario = Scenario::start();
            let caller = scenario.name_operator(&[Capability::PolicyWrite]);
            complete(write_relation_schema(&scenario.app, &caller, schema)).expect("a schema");
            Self { scenario, caller }
        }

        fn keep(&self, object_text: &str, relation: &str, subject_text: &str) {
            complete(write_relation(
                &self.scenario.app,
                &self.caller,
                &relate(object_text, relation, subject_text),
            ))
            .expect("a relation");
        }

        fn ask(&self, object_text: &str, member: &str, subject_text: &str) -> Walk {
            let schema = compile_schema(SCHEMA).expect("a schema");
            complete(async {
                let share = take_share();
                let mut work = self
                    .scenario
                    .app
                    .storage
                    .begin(self.scenario.scope)
                    .await
                    .expect("a unit of work");
                walk_relations(
                    &self.scenario.app,
                    work.as_mut(),
                    &schema,
                    &object(object_text),
                    member,
                    &object(subject_text),
                    budget(&self.scenario.app, &share),
                )
                .await
                .expect("the storage answers")
            })
        }
    }

    #[test]
    fn a_subject_stands_through_a_relation_a_team_and_a_parent_folder() {
        let started = Started::open(SCHEMA);
        started.keep("team:core", "member", "user:ada");
        started.keep("team:all", "member", "team:core#member");
        started.keep("folder:root", "viewer", "team:all#member");
        started.keep("folder:reports", "parent", "folder:root");
        started.keep("document:q3", "folder", "folder:reports");
        started.keep("document:q3", "owner", "user:bob");

        assert_eq!(started.ask("document:q3", "view", "user:ada"), Walk::Found);
        assert_eq!(
            started.ask("document:q3", "edit", "user:ada"),
            Walk::NotFound
        );
        assert_eq!(started.ask("document:q3", "edit", "user:bob"), Walk::Found);
        assert_eq!(
            started.ask("document:q3", "view", "user:eve"),
            Walk::NotFound
        );
        assert_eq!(
            started.ask("folder:root", "view", "team:core"),
            Walk::NotFound,
            "a team is not its members"
        );
    }

    #[test]
    fn an_intersection_needs_every_part_and_an_empty_one_cannot_be_written() {
        let started = Started::open(SCHEMA);
        started.keep("document:q3", "editor", "user:ada");
        started.keep("document:q3", "owner", "user:bob");

        assert_eq!(
            started.ask("document:q3", "approve", "user:ada"),
            Walk::NotFound
        );
        assert_eq!(
            started.ask("document:q3", "approve", "user:bob"),
            Walk::Found
        );
        assert!(
            compile_schema(
                "definition doc {
 permission p = ()
}"
            )
            .is_err()
        );
    }

    #[test]
    fn a_relation_the_schema_does_not_admit_is_refused_when_written() {
        let started = Started::open(SCHEMA);
        let refuse = |object_text: &str, relation: &str, subject_text: &str| {
            complete(write_relation(
                &started.scenario.app,
                &started.caller,
                &relate(object_text, relation, subject_text),
            ))
            .map_err(|failure| failure.code)
        };

        for (object_text, relation, subject_text) in [
            ("document:q3", "view", "user:ada"),
            ("document:q3", "owner", "team:core"),
            ("document:q3", "owner", "team:core#member"),
            ("printer:p1", "owner", "user:ada"),
            ("document:q3", "folder", "folder:a b"),
        ] {
            assert_eq!(
                refuse(object_text, relation, subject_text),
                Err(ErrorCode::RelationInvalid),
                "{object_text} {relation} {subject_text}"
            );
        }
        assert_eq!(refuse("document:q3", "owner", "user:ada"), Ok(()));
        assert_eq!(
            refuse("document:q3", "owner", "user:ada"),
            Ok(()),
            "kept once"
        );
        let written = started
            .scenario
            .read_event_kinds()
            .iter()
            .filter(|kind| *kind == "relation.written")
            .count();
        assert_eq!(written, 1);
    }

    #[test]
    fn a_loop_in_the_relations_kept_is_told_as_a_loop_and_never_as_a_refusal() {
        let started = Started::open(SCHEMA);
        started.keep("folder:a", "parent", "folder:b");
        started.keep("folder:b", "parent", "folder:a");

        assert_eq!(
            started.ask("folder:a", "view", "user:ada"),
            Walk::Undecided(WalkLimit::Cycle)
        );
        started.keep("folder:b", "viewer", "user:ada");
        assert_eq!(
            started.ask("folder:a", "view", "user:ada"),
            Walk::Found,
            "a loop does not hide a way that exists"
        );
    }

    #[test]
    fn a_chain_deeper_than_the_bound_cannot_be_told() {
        let started = Started::open(SCHEMA);
        for level in 0..40 {
            started.keep(
                &format!("folder:f{level}"),
                "parent",
                &format!("folder:f{}", level + 1),
            );
        }
        started.keep("folder:f40", "viewer", "user:ada");

        assert_eq!(
            started.ask("folder:f0", "view", "user:ada"),
            Walk::Undecided(WalkLimit::Depth),
            "forty folders deep is past the bound of sixty-four steps"
        );
        assert_eq!(started.ask("folder:f30", "view", "user:ada"), Walk::Found);
    }

    #[test]
    fn a_relation_that_names_too_many_subjects_cannot_be_told() {
        let started = Started::open(SCHEMA);
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            for index in 0..=MAX_FANOUT {
                work.insert_relation(
                    &relate("folder:crowded", "viewer", &format!("user:u{index}")),
                    started.scenario.app.now(),
                )
                .await
                .expect("a relation");
            }
            work.commit().await.expect("a commit");
        });

        assert_eq!(
            started.ask("folder:crowded", "view", "user:ada"),
            Walk::Undecided(WalkLimit::Fanout)
        );
    }

    #[test]
    fn a_kept_relation_the_schema_no_longer_admits_is_walked_by_nobody() {
        let started = Started::open(SCHEMA);
        started.keep("document:q3", "editor", "user:ada");
        let narrower = SCHEMA.replace(
            "relation editor: user | team#member",
            "relation editor: team#member",
        );
        complete(write_relation_schema(
            &started.scenario.app,
            &started.caller,
            &narrower,
        ))
        .expect("a narrower schema");

        let walked = complete(async {
            let share = take_share();
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            // A relation kept before the schema narrowed, as a storage that
            // was written behind the product's back would hold it.
            work.insert_relation(
                &relate("document:q3", "editor", "user:ada"),
                started.scenario.app.now(),
            )
            .await
            .expect("a relation kept by hand");
            // The schema as the realm keeps it, not one compiled here.
            let schema = work
                .read_relation_schema()
                .await
                .expect("a read")
                .and_then(|stored| stored.open())
                .expect("the narrower schema");
            walk_relations(
                &started.scenario.app,
                work.as_mut(),
                &schema,
                &object("document:q3"),
                "edit",
                &object("user:ada"),
                budget(&started.scenario.app, &share),
            )
            .await
        });
        assert_eq!(walked, Ok(Walk::NotFound));
    }

    #[test]
    fn an_intersection_of_nothing_finds_nothing() {
        use std::collections::BTreeMap;

        use super::super::schema::{COMPILED_VERSION, CompiledSchema, ObjectType, Rule};

        let started = Started::open(SCHEMA);
        let mut permissions = BTreeMap::new();
        permissions.insert("read".to_owned(), Rule::Intersection { rules: Vec::new() });
        let mut types = BTreeMap::new();
        types.insert("user".to_owned(), ObjectType::default());
        types.insert(
            "document".to_owned(),
            ObjectType {
                relations: BTreeMap::new(),
                permissions,
            },
        );
        let forged = CompiledSchema {
            version: COMPILED_VERSION,
            types,
        };
        let walked = complete(async {
            let share = take_share();
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            walk_relations(
                &started.scenario.app,
                work.as_mut(),
                &forged,
                &object("document:q3"),
                "read",
                &object("user:ada"),
                budget(&started.scenario.app, &share),
            )
            .await
        });
        assert_eq!(walked, Ok(Walk::NotFound));
    }

    #[test]
    fn a_walk_past_its_deadline_cannot_be_told() {
        let started = Started::open(SCHEMA);
        started.keep("document:q3", "owner", "user:ada");
        let schema = compile_schema(SCHEMA).expect("a schema");
        let walked = complete(async {
            let share = take_share();
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            walk_relations(
                &started.scenario.app,
                work.as_mut(),
                &schema,
                &object("document:q3"),
                "edit",
                &object("user:ada"),
                WalkBudget {
                    deadline: started.scenario.app.now() - time::Duration::milliseconds(1),
                    _share: &share,
                },
            )
            .await
        });
        assert_eq!(walked, Ok(Walk::Undecided(WalkLimit::Duration)));
    }

    #[test]
    fn a_schema_that_doubles_at_each_level_is_walked_once_per_member() {
        use std::fmt::Write as _;

        let mut source =
            "definition user {}\ndefinition doc {\n  relation r: user\n  permission p34 = r\n"
                .to_owned();
        // Two ways to each level, each two steps deep: `r` lies past the
        // depth, by 2^33 ways that read nothing.
        for level in (1..34).rev() {
            writeln!(
                source,
                "  permission p{level} = p{next} + p{next}",
                next = level + 1
            )
            .expect("a line");
        }
        source.push('}');
        let schema = compile_schema(&source).expect("a schema");
        let started = Started::open(SCHEMA);
        let begun = std::time::Instant::now();
        let walked = complete(async {
            let share = take_share();
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            walk_relations(
                &started.scenario.app,
                work.as_mut(),
                &schema,
                &object("doc:x"),
                "p1",
                &object("user:ada"),
                budget(&started.scenario.app, &share),
            )
            .await
        });
        assert_eq!(walked, Ok(Walk::Undecided(WalkLimit::Depth)));
        assert!(
            begun.elapsed() < std::time::Duration::from_secs(1),
            "each member once, not each way to it: {:?}",
            begun.elapsed()
        );
    }

    #[test]
    fn a_walk_that_enters_too_many_members_cannot_be_told() {
        use std::collections::BTreeMap;

        use super::super::schema::{COMPILED_VERSION, CompiledSchema, ObjectType, Rule};

        // A sum of more members than a walk enters, none of which reads.
        let mut permissions = BTreeMap::new();
        let members: Vec<Rule> = (0..super::MAX_STEPS)
            .map(|index| Rule::Computed {
                member: format!("m{index}"),
            })
            .collect();
        for index in 0..super::MAX_STEPS {
            permissions.insert(format!("m{index}"), Rule::Union { rules: Vec::new() });
        }
        permissions.insert("read".to_owned(), Rule::Union { rules: members });
        let mut types = BTreeMap::new();
        types.insert("user".to_owned(), ObjectType::default());
        types.insert(
            "document".to_owned(),
            ObjectType {
                relations: BTreeMap::new(),
                permissions,
            },
        );
        let wide = CompiledSchema {
            version: COMPILED_VERSION,
            types,
        };
        let started = Started::open(SCHEMA);
        let walked = complete(async {
            let share = take_share();
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            walk_relations(
                &started.scenario.app,
                work.as_mut(),
                &wide,
                &object("document:q3"),
                "read",
                &object("user:ada"),
                budget(&started.scenario.app, &share),
            )
            .await
        });
        assert_eq!(walked, Ok(Walk::Undecided(WalkLimit::Steps)));
    }

    #[test]
    fn a_walk_that_reads_more_than_its_bound_cannot_be_told() {
        let started = Started::open(SCHEMA);
        complete(async {
            let mut work = started
                .scenario
                .app
                .storage
                .begin(started.scenario.scope)
                .await
                .expect("a unit of work");
            // As many teams as a walk reads, each its own read, under one folder.
            for index in 0..MAX_READS {
                work.insert_relation(
                    &relate("folder:root", "viewer", &format!("team:t{index}#member")),
                    started.scenario.app.now(),
                )
                .await
                .expect("a relation");
            }
            work.commit().await.expect("a commit");
        });
        assert_eq!(
            started.ask("folder:root", "view", "user:ada"),
            Walk::Undecided(WalkLimit::Reads)
        );
    }
}
