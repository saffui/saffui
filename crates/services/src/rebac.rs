//! Following edges from an object back to a subject, under bounds it cannot
//! exceed.
//!
//! The other engine. A policy decides from facts about a subject; this decides
//! by walking, and walking is the part that has to be made to stop. Four things
//! bound it, and every one of them is an error rather than a refusal: a walk
//! that ran out of budget did not find that the subject is unrelated, and
//! answering no would be answering a question nobody managed to ask.
//!
//! It takes the transaction it was asked in. The engine this replaces gives its
//! store a connection of its own per call, so a check reads only committed
//! state and nothing can write edges and then verify them.

use std::collections::{BTreeMap, BTreeSet};

use authz::rebac::{CompiledSchema, Rule};
use deadpool_postgres::Transaction;
use store::providers::rebac;

/// How far a check may go.
///
/// No default, for the reason every other budget here has none: bounds a caller
/// did not choose are bounds nobody owns. The depth counts hops between
/// members, the queries count round trips to the store, and the fanout is how
/// many edges one relation may contribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub max_depth: u32,
    pub max_queries: u32,
    pub max_fanout: i64,
}

/// What a check is walked under.
///
/// The queries budget stands where the reference puts a wall clock deadline.
/// A deadline makes the same question answer differently on a slow afternoon,
/// and the record of a decision is supposed to be replayable; counting round
/// trips bounds the same thing the deadline was there to bound, and counts it
/// the same way twice.
pub const CHECK: Budget = Budget {
    max_depth: 64,
    max_queries: 1000,
    max_fanout: 1000,
};

/// What is being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object<'a> {
    pub object_type: &'a str,
    pub object_id: &'a str,
}

/// Who is being asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subject<'a> {
    pub subject_type: &'a str,
    pub subject_id: &'a str,
}

/// Why a check reached no answer.
///
/// Every one of these is an error and not a refusal. A walk that hit a ceiling
/// has not established that the subject is unrelated, and a decision point that
/// read it as one would turn every crafted graph into an answer of its choosing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unwalkable {
    #[error("the realm has no relationship schema")]
    NoSchema,
    #[error("the schema does not describe a '{object_type}'")]
    UnknownType { object_type: String },
    #[error("the chain of members ran past {max_depth}")]
    TooDeep { max_depth: u32 },
    #[error("the walk asked the store more than {max_queries} times")]
    TooManyQueries { max_queries: u32 },
    /// One relation contributed more edges than the walk may look at. Refused
    /// rather than truncated, since the subject may be in the part not read.
    #[error("'{relation}' on {object_type}:{object_id} has more than {max_fanout} edges")]
    TooWide {
        object_type: String,
        object_id: String,
        relation: String,
        max_fanout: i64,
    },
    /// A member reached itself. The compiler refuses this, so meeting one here
    /// means a schema was installed by something that did not compile it.
    #[error("'{member}' on {object_type}:{object_id} reaches itself")]
    Ring {
        object_type: String,
        object_id: String,
        member: String,
    },
    /// An edge names a subject type the relation never declared. The compiled
    /// schema carries what may stand where, so this is an edge that should not
    /// have been written.
    #[error("'{relation}' does not accept a {subject_type}")]
    Undeclared {
        relation: String,
        subject_type: String,
    },
    #[error("the store could not be read")]
    Unreadable,
    /// The stored schema is in a shape this build does not know. Refused rather
    /// than read as one it does, which is what the number beside it is for.
    #[error("the stored schema is in format {found}, and this build reads {known}")]
    UnknownFormat { found: i32, known: u32 },
}

impl Unwalkable {
    /// A stable name for the journal, so a record can be counted and searched
    /// rather than matched on prose.
    pub fn slug(&self) -> &'static str {
        match self {
            Self::NoSchema => "no-schema",
            Self::UnknownType { .. } => "unknown-type",
            Self::TooDeep { .. } => "too-deep",
            Self::TooManyQueries { .. } => "too-many-queries",
            Self::TooWide { .. } => "too-wide",
            Self::Ring { .. } => "ring",
            Self::Undeclared { .. } => "undeclared-subject",
            Self::Unreadable => "unreadable",
            Self::UnknownFormat { .. } => "unknown-format",
        }
    }
}

/// This realm's schema, compiled, or why there is none to walk by.
///
/// The shape is checked against what this build reads. A document in a form it
/// does not know is refused rather than deserialised into the nearest thing it
/// has, which would be deciding by a schema nobody wrote.
pub async fn schema_of(transaction: &Transaction<'_>) -> Result<CompiledSchema, Unwalkable> {
    let stored = rebac::load_schema(transaction)
        .await
        .map_err(|_| Unwalkable::Unreadable)?
        .ok_or(Unwalkable::NoSchema)?;

    if stored.format != authz::rebac::FORMAT as i32 {
        return Err(Unwalkable::UnknownFormat {
            found: stored.format,
            known: authz::rebac::FORMAT,
        });
    }

    serde_json::from_value(stored.compiled).map_err(|_| Unwalkable::Unreadable)
}

/// Whether this subject stands in this member of this object.
pub async fn check(
    transaction: &Transaction<'_>,
    schema: &CompiledSchema,
    object: Object<'_>,
    member: &str,
    subject: Subject<'_>,
    budget: Budget,
) -> Result<bool, Unwalkable> {
    if !schema.has_type(object.object_type) {
        return Err(Unwalkable::UnknownType {
            object_type: object.object_type.to_owned(),
        });
    }

    Walk {
        transaction,
        schema,
        subject,
        budget,
        queries: 0,
        on_path: BTreeSet::new(),
        seen: BTreeMap::new(),
    }
    .member(object, member, 0)
    .await
}

/// One question's walk: what it has answered, and what it is in the middle of.
struct Walk<'a> {
    transaction: &'a Transaction<'a>,
    schema: &'a CompiledSchema,
    subject: Subject<'a>,
    budget: Budget,
    queries: u32,
    /// The members between the question and here. Re-entering one is a ring.
    on_path: BTreeSet<(String, String, String)>,
    /// What has already been answered, so a node reachable by two paths is
    /// walked once. Without it a diamond is exponential in its paths, and the
    /// only thing standing between a schema and that is a budget, which turns
    /// the blowup into a refusal the author cannot explain.
    seen: BTreeMap<(String, String, String), bool>,
}

impl Walk<'_> {
    async fn member(
        &mut self,
        object: Object<'_>,
        member: &str,
        depth: u32,
    ) -> Result<bool, Unwalkable> {
        if depth > self.budget.max_depth {
            return Err(Unwalkable::TooDeep {
                max_depth: self.budget.max_depth,
            });
        }

        let here = (
            object.object_type.to_owned(),
            object.object_id.to_owned(),
            member.to_owned(),
        );
        if let Some(answered) = self.seen.get(&here) {
            return Ok(*answered);
        }
        if !self.on_path.insert(here.clone()) {
            return Err(Unwalkable::Ring {
                object_type: here.0,
                object_id: here.1,
                member: here.2,
            });
        }

        // A member the schema does not describe contributes nothing. An arrow
        // may reach objects of several types, and a member absent on one of
        // them is the ordinary case rather than a fault.
        let answer = match self.schema.lookup(object.object_type, member) {
            None => Ok(false),
            Some(rule) => self.rule(object, member, rule.clone(), depth).await,
        };

        // Off the path whatever happened, so a partial failure does not leave a
        // member looking like it is still being walked.
        self.on_path.remove(&here);
        let answer = answer?;
        self.seen.insert(here, answer);
        Ok(answer)
    }

    async fn rule(
        &mut self,
        object: Object<'_>,
        member: &str,
        rule: Rule,
        depth: u32,
    ) -> Result<bool, Unwalkable> {
        match rule {
            Rule::Direct { subjects } => self.direct(object, member, &subjects, depth).await,
            Rule::Computed { name } => Box::pin(self.member(object, &name, depth + 1)).await,
            Rule::Arrow { tupleset, computed } => {
                self.arrow(object, &tupleset, &computed, depth).await
            }
            Rule::Any { parts } => {
                for part in parts.as_slice() {
                    if Box::pin(self.rule(object, member, part.clone(), depth)).await? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Rule::All { parts } => {
                for part in parts.as_slice() {
                    if !Box::pin(self.rule(object, member, part.clone(), depth)).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
        }
    }

    /// The edges stored against one relation.
    ///
    /// The relation is the member the rule was found under, which holds because
    /// a compiled union or intersection never contains a direct rule: only a
    /// relation compiles to one, and a relation is always a member's whole body.
    async fn direct(
        &mut self,
        object: Object<'_>,
        relation: &str,
        declared: &[authz::rebac::SubjectType],
        depth: u32,
    ) -> Result<bool, Unwalkable> {
        let edges = self.edges(object, relation).await?;

        for edge in &edges {
            // What may stand here is in the compiled schema, so an edge naming
            // something else is one that should never have been written. The
            // reference drops the declaration at compile time and expands
            // whatever the store returns.
            if !accepts(declared, edge) {
                return Err(Unwalkable::Undeclared {
                    relation: relation.to_owned(),
                    subject_type: edge.subject_type.clone(),
                });
            }

            if edge.subject_relation.is_empty() {
                if edge.subject_type == self.subject.subject_type
                    && edge.subject_id == self.subject.subject_id
                {
                    return Ok(true);
                }
                continue;
            }

            // A set of subjects: everything standing in that relation to that
            // object stands here too.
            let reached = Box::pin(self.member(
                Object {
                    object_type: &edge.subject_type,
                    object_id: &edge.subject_id,
                },
                &edge.subject_relation,
                depth + 1,
            ))
            .await?;
            if reached {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Follow a relation to other objects, and ask each of them.
    async fn arrow(
        &mut self,
        object: Object<'_>,
        tupleset: &str,
        computed: &str,
        depth: u32,
    ) -> Result<bool, Unwalkable> {
        for edge in self.edges(object, tupleset).await? {
            // Only objects are followed. A userset on the tupleset relation
            // names holders of a relation rather than one object, and there is
            // nothing to ask a set of subjects for.
            if !edge.subject_relation.is_empty() {
                continue;
            }
            let reached = Box::pin(self.member(
                Object {
                    object_type: &edge.subject_type,
                    object_id: &edge.subject_id,
                },
                computed,
                depth + 1,
            ))
            .await?;
            if reached {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// One question to the store, counted and bounded.
    async fn edges(
        &mut self,
        object: Object<'_>,
        relation: &str,
    ) -> Result<Vec<rebac::Subject>, Unwalkable> {
        self.queries += 1;
        if self.queries > self.budget.max_queries {
            return Err(Unwalkable::TooManyQueries {
                max_queries: self.budget.max_queries,
            });
        }

        let edges = rebac::subjects(
            self.transaction,
            object.object_type,
            object.object_id,
            relation,
            self.budget.max_fanout,
        )
        .await
        .map_err(|_| Unwalkable::Unreadable)?;

        // One more than the ceiling was read, so this is a relation wider than
        // the walk may look at rather than one that exactly fills it. Refused
        // rather than truncated: the subject may be in the part not read, and
        // answering no would be answering from half the edges.
        if edges.len() as i64 > self.budget.max_fanout {
            return Err(Unwalkable::TooWide {
                object_type: object.object_type.to_owned(),
                object_id: object.object_id.to_owned(),
                relation: relation.to_owned(),
                max_fanout: self.budget.max_fanout,
            });
        }

        Ok(edges)
    }
}

/// Whether a relation accepts what this edge names.
fn accepts(declared: &[authz::rebac::SubjectType], edge: &rebac::Subject) -> bool {
    declared.iter().any(|allowed| {
        allowed.type_name == edge.subject_type
            && allowed.relation.as_deref().unwrap_or("") == edge.subject_relation
    })
}
