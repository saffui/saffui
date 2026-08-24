use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};

use super::ast::{At, Expr, Member, Schema};

/// The shape the compiled form is in.
///
/// Stored beside it. A build meeting a number it does not know refuses rather
/// than reading the document as a shape it is not.
pub const FORMAT: u32 = 1;

/// What may stand in a relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectType {
    pub type_name: String,
    /// Present for a userset: the holders of this relation on that type.
    pub relation: Option<String>,
}

/// Two or more rules.
///
/// A newtype because the count is the guarantee. An empty intersection answers
/// yes to everything, and the compiled form is reloaded from a column, so a
/// hand edited row would otherwise be able to say it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Parts(Vec<Rule>);

impl Parts {
    pub fn as_slice(&self) -> &[Rule] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Parts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let parts = Vec::<Rule>::deserialize(deserializer)?;
        if parts.len() < 2 {
            return Err(serde::de::Error::custom(
                "a union or intersection joins two or more rules",
            ));
        }
        Ok(Parts(parts))
    }
}

/// What one member of one type answers by.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Rule {
    /// Edges stored against this relation, and what may stand in it.
    ///
    /// The subject types travel. The reference validates them and throws them
    /// away, so its walk expands whatever the store returns for a relation and
    /// the declaration is documentation rather than a rule.
    Direct {
        subjects: Vec<SubjectType>,
    },
    /// Another member of the same object.
    Computed {
        name: String,
    },
    /// Follow `tupleset` to other objects and ask each for `computed`.
    Arrow {
        tupleset: String,
        computed: String,
    },
    Any {
        parts: Parts,
    },
    All {
        parts: Parts,
    },
}

/// A schema, as a walk reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledSchema {
    pub format: u32,
    types: BTreeMap<String, BTreeMap<String, Rule>>,
}

impl CompiledSchema {
    pub fn lookup(&self, type_name: &str, member: &str) -> Option<&Rule> {
        self.types.get(type_name)?.get(member)
    }

    pub fn has_type(&self, type_name: &str) -> bool {
        self.types.contains_key(type_name)
    }

    /// Every type, and every member of it. An administrative surface needs to
    /// show a schema without a round trip through its own serialisation.
    pub fn types(&self) -> impl Iterator<Item = (&str, &BTreeMap<String, Rule>)> {
        self.types
            .iter()
            .map(|(name, members)| (name.as_str(), members))
    }
}

/// One thing wrong with a schema, and where it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub at: At,
    pub says: String,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.at.line, self.at.column, self.says
        )
    }
}

/// Everything wrong with a schema.
///
/// All of them, because compiling is not a request an author makes ten times to
/// be told about ten mistakes one at a time.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", .0.iter().map(Fault::to_string).collect::<Vec<_>>().join("; "))]
pub struct Faults(pub Vec<Fault>);

/// Compile a schema, or say everything that is wrong with it.
pub fn compile(schema: &Schema) -> Result<CompiledSchema, Faults> {
    let mut faults = Vec::new();

    // What exists, before anything is checked against it.
    let mut relations: BTreeSet<(String, String)> = BTreeSet::new();
    let mut members: BTreeSet<(String, String)> = BTreeSet::new();
    let mut types: BTreeSet<String> = BTreeSet::new();

    for definition in &schema.definitions {
        if !types.insert(definition.name.text.clone()) {
            faults.push(Fault {
                at: definition.name.at,
                says: format!("'{}' is declared twice", definition.name.text),
            });
        }
        for member in &definition.members {
            let name = member.name();
            let key = (definition.name.text.clone(), name.text.clone());
            if !members.insert(key.clone()) {
                faults.push(Fault {
                    at: name.at,
                    says: format!(
                        "'{}' already names a relation or permission on '{}'",
                        name.text, definition.name.text
                    ),
                });
            }
            if matches!(member, Member::Relation(_)) {
                relations.insert(key);
            }
        }
    }

    for definition in &schema.definitions {
        for member in &definition.members {
            match member {
                Member::Relation(relation) => {
                    for subject in &relation.subjects {
                        if !types.contains(&subject.type_name.text) {
                            faults.push(Fault {
                                at: subject.type_name.at,
                                says: format!("no type named '{}'", subject.type_name.text),
                            });
                            continue;
                        }
                        if let Some(userset) = &subject.relation {
                            let key = (subject.type_name.text.clone(), userset.text.clone());
                            if !members.contains(&key) {
                                faults.push(Fault {
                                    at: userset.at,
                                    says: format!(
                                        "'{}' has no member named '{}'",
                                        subject.type_name.text, userset.text
                                    ),
                                });
                            }
                        }
                    }
                }
                Member::Permission(permission) => {
                    check(
                        &permission.body,
                        &definition.name.text,
                        &members,
                        &relations,
                        &mut faults,
                    );
                }
            }
        }
    }

    // Only once the names resolve, since a ring through a name that does not
    // exist is a missing name and not a ring.
    if faults.is_empty() {
        rings(schema, &mut faults);
    }

    if !faults.is_empty() {
        faults.sort_by_key(|fault| (fault.at.line, fault.at.column));
        return Err(Faults(faults));
    }

    let mut compiled: BTreeMap<String, BTreeMap<String, Rule>> = BTreeMap::new();
    for definition in &schema.definitions {
        let entry = compiled.entry(definition.name.text.clone()).or_default();
        for member in &definition.members {
            let rule = match member {
                Member::Relation(relation) => Rule::Direct {
                    subjects: relation
                        .subjects
                        .iter()
                        .map(|subject| SubjectType {
                            type_name: subject.type_name.text.clone(),
                            relation: subject.relation.as_ref().map(|name| name.text.clone()),
                        })
                        .collect(),
                },
                Member::Permission(permission) => rule_of(&permission.body),
            };
            entry.insert(member.name().text.clone(), rule);
        }
    }

    Ok(CompiledSchema {
        format: FORMAT,
        types: compiled,
    })
}

/// Every name a permission reads has to be one that exists.
fn check(
    expr: &Expr,
    definition: &str,
    members: &BTreeSet<(String, String)>,
    relations: &BTreeSet<(String, String)>,
    faults: &mut Vec<Fault>,
) {
    match expr {
        Expr::Member(name) => {
            if !members.contains(&(definition.to_owned(), name.text.clone())) {
                faults.push(Fault {
                    at: name.at,
                    says: format!("'{definition}' has no member named '{}'", name.text),
                });
            }
        }
        Expr::Arrow {
            tupleset, computed, ..
        } => {
            // The tupleset has to be a relation, since a permission stores no
            // edges to follow. What is asked of the objects at the far end is
            // deliberately not checked: the tupleset may reach several types
            // and a member absent on one of them contributes nothing.
            if !relations.contains(&(definition.to_owned(), tupleset.text.clone())) {
                faults.push(Fault {
                    at: tupleset.at,
                    says: format!(
                        "'{}' is not a relation on '{definition}', so there is nothing to follow",
                        tupleset.text
                    ),
                });
            }
            let _ = computed;
        }
        Expr::Any { parts, .. } | Expr::All { parts, .. } => {
            for part in parts {
                check(part, definition, members, relations, faults);
            }
        }
    }
}

/// A permission that computes from itself, directly or round a ring.
///
/// Decidable here, and the reference leaves it to the walk, where it becomes a
/// cost paid on every request and a denial nothing explains.
fn rings(schema: &Schema, faults: &mut Vec<Fault>) {
    let mut computes: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut written: BTreeMap<(String, String), At> = BTreeMap::new();

    for definition in &schema.definitions {
        for member in &definition.members {
            if let Member::Permission(permission) = member {
                let key = (definition.name.text.clone(), permission.name.text.clone());
                written.insert(key.clone(), permission.name.at);
                let mut reached = Vec::new();
                computed_names(&permission.body, &mut reached);
                computes.insert(key, reached);
            }
        }
    }

    for (key, at) in &written {
        let successors = |node: &str| {
            computes
                .get(&(key.0.clone(), node.to_owned()))
                .cloned()
                .unwrap_or_default()
        };
        // Bounded like everything else that follows edges, and an unanswerable
        // walk is refused: a schema too tangled to check is not one to install.
        match commons::walk::reaches(
            &key.1,
            &key.1,
            successors,
            commons::walk::POLICY_AGGREGATION,
        ) {
            Ok(false) => {}
            Ok(true) => faults.push(Fault {
                at: *at,
                says: format!("'{}' computes from itself", key.1),
            }),
            Err(_) => faults.push(Fault {
                at: *at,
                says: format!("'{}' is too tangled to check for a ring", key.1),
            }),
        }
    }
}

/// The members one expression computes from, on the same object.
///
/// An arrow is not one: it leaves this object, so it cannot close a ring on it.
fn computed_names(expr: &Expr, into: &mut Vec<String>) {
    match expr {
        Expr::Member(name) => into.push(name.text.clone()),
        Expr::Arrow { .. } => {}
        Expr::Any { parts, .. } | Expr::All { parts, .. } => {
            for part in parts {
                computed_names(part, into);
            }
        }
    }
}

fn rule_of(expr: &Expr) -> Rule {
    match expr {
        Expr::Member(name) => Rule::Computed {
            name: name.text.clone(),
        },
        Expr::Arrow {
            tupleset, computed, ..
        } => Rule::Arrow {
            tupleset: tupleset.text.clone(),
            computed: computed.text.clone(),
        },
        Expr::Any { parts, .. } => Rule::Any {
            parts: Parts(parts.iter().map(rule_of).collect()),
        },
        Expr::All { parts, .. } => Rule::All {
            parts: Parts(parts.iter().map(rule_of).collect()),
        },
    }
}
