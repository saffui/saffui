//! What a credential says, read the way its proof signs it: the types it
//! declares, expanded, and whether a claim a verifier names by a path of member
//! names from the credential's root, as OpenID4VP names one, holds a value the
//! proof tells apart from every other.
//!
//! A proof signs a dataset, not the JSON it was read from. Two members of one
//! node object that name the same property are one property to it, and their
//! values can trade places under the same signature; so can the values two
//! node objects give one property of the node they both name. The keys of an
//! index map are in no dataset at all, and a member whose value reads as
//! nothing adds nothing a proof signs. A claim resting on any of them is
//! refused.

use serde_json::{Map, Value};

use crate::Unreadable;
use crate::context::{ActiveContext, Contexts};
use crate::expand::Expander;
use crate::iri::is_keyword;

/// Why a claim is not one a verifier may take from a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unclaimed {
    #[error("the credential holds no such claim")]
    Absent,
    #[error(
        "another member names the same property of the same node, and the proof does not tell their values apart"
    )]
    Shared,
    #[error("the claim is or stands under an index map, whose keys no proof signs")]
    Indexed,
    #[error("the claim is not reached through node objects alone")]
    NotAProperty,
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
}

/// A credential read for its types and its claims.
pub struct ReadCredential<'d> {
    document: &'d Map<String, Value>,
    contexts: &'d dyn Contexts,
    /// The credential expanded: what its proof signs of it.
    expanded: Map<String, Value>,
}

/// Read a credential, without its proof, every context it names taken from
/// `contexts`.
pub fn read_credential<'d>(
    document: &'d Value,
    contexts: &'d dyn Contexts,
) -> Result<ReadCredential<'d>, Unreadable> {
    let not_a_node = Unreadable::Unsupported("a credential that is not one node object");
    let Value::Object(members) = document else {
        return Err(not_a_node);
    };
    let Value::Object(expanded) =
        Expander { contexts }.expand(&ActiveContext::default(), None, document, false)?
    else {
        return Err(not_a_node);
    };
    Ok(ReadCredential {
        document: members,
        contexts,
        expanded,
    })
}

impl ReadCredential<'_> {
    /// The credential's types, expanded to IRIs.
    pub fn types(&self) -> Vec<&str> {
        self.expanded
            .get("@type")
            .and_then(Value::as_array)
            .map(|types| types.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// Whether the claim `path` names holds a value the proof tells apart from
    /// every other, reached from the credential's root through node objects
    /// alone.
    pub fn check_claim(&self, path: &[String]) -> Result<(), Unclaimed> {
        let expander = Expander {
            contexts: self.contexts,
        };
        let mut parent = ActiveContext::default();
        let mut property_scoped: Option<Value> = None;
        let mut node = self.document;
        // The same node, expanded: what the proof signs of it.
        let mut expanded = &self.expanded;
        for (at, member) in path.iter().enumerate() {
            let last = at + 1 == path.len();
            let active = expander
                .read_node_contexts(&parent, node, false, property_scoped.as_ref())?
                .active;
            let Some(value) = node.get(member) else {
                return Err(Unclaimed::Absent);
            };
            let property = active
                .expand_iri(member, true)
                .ok_or_else(|| Unreadable::Undefined(member.clone()))?;
            if is_keyword(&property) {
                // A node's identifier and types name the node itself: they end
                // a path, and no other keyword is a claim.
                if !last || !matches!(property.as_str(), "@id" | "@type") {
                    return Err(Unclaimed::NotAProperty);
                }
                return holds_something(expanded.get(&property))
                    .then_some(())
                    .ok_or(Unclaimed::Absent);
            }
            let named_again = node.keys().any(|key| {
                key != member && active.expand_iri(key, true).as_deref() == Some(property.as_str())
            });
            let identifier = expanded.get("@id").and_then(Value::as_str);
            if named_again
                || identifier.is_some_and(|identifier| {
                    count_nodes_holding(&self.expanded, identifier, &property) > 1
                })
            {
                return Err(Unclaimed::Shared);
            }
            let term = active.term(member);
            let container = term.map(|term| term.container).unwrap_or_default();
            if container.index {
                return Err(Unclaimed::Indexed);
            }
            let held = expanded.get(&property);
            if !holds_something(held) {
                return Err(Unclaimed::Absent);
            }
            if last {
                return Ok(());
            }
            // The path goes on through the one node object the member holds:
            // a value, a list or a graph is none.
            match (value, held.and_then(Value::as_array).map(Vec::as_slice)) {
                (Value::Object(child), Some([Value::Object(expanded_child)]))
                    if !["@value", "@list", "@graph"]
                        .iter()
                        .any(|keyword| expanded_child.contains_key(*keyword)) =>
                {
                    property_scoped = term.and_then(|term| term.context.clone());
                    parent = active;
                    node = child;
                    expanded = expanded_child;
                }
                _ => return Err(Unclaimed::NotAProperty),
            }
        }
        Err(Unclaimed::Absent)
    }
}

/// Whether an expanded entry holds a value: an identifier, or a non-empty list
/// of values.
fn holds_something(entry: Option<&Value>) -> bool {
    match entry {
        Some(Value::String(_)) => true,
        Some(Value::Array(values)) => !values.is_empty(),
        _ => false,
    }
}

/// How many node objects, `object` and those within it, name the node
/// `identifier` names and hold `property`.
fn count_nodes_holding(object: &Map<String, Value>, identifier: &str, property: &str) -> usize {
    // A value object is no node, and the JSON literal it may hold names none.
    if object.contains_key("@value") {
        return 0;
    }
    let here = object.get("@id").and_then(Value::as_str) == Some(identifier)
        && object.contains_key(property);
    usize::from(here)
        + object
            .values()
            .map(|held| count_nodes_holding_in(held, identifier, property))
            .sum::<usize>()
}

fn count_nodes_holding_in(value: &Value, identifier: &str, property: &str) -> usize {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|item| count_nodes_holding_in(item, identifier, property))
            .sum(),
        Value::Object(object) => count_nodes_holding(object, identifier, property),
        _ => 0,
    }
}
