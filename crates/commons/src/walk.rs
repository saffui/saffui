//! Following edges through a graph that may not be one.
//!
//! Written once, because every caller needs the same three things and each one
//! is a way to hang: a visited set, so a cycle is walked once rather than
//! forever; a depth ceiling, so a long chain cannot exhaust the stack; and a
//! node ceiling, so a wide one cannot exhaust the heap.
//!
//! What matters as much as the bounds is what happens at them. Running out of
//! budget is not an answer, and a walk that returned "no path" on exhaustion
//! would be indistinguishable from one that searched the whole graph. Every
//! ceiling here is [`Exhausted`], and the caller decides what an unanswered
//! question means: at a write it is a refusal, at a decision it is a policy
//! that could not be evaluated.

use std::collections::{BTreeSet, VecDeque};

/// How far a walk may go before it gives up.
///
/// No default. A caller that did not choose its bounds would inherit whatever
/// suited whoever wrote them, and the two ceilings answer different questions:
/// the depth is how long a chain may be, the node count is how much of the
/// graph may be touched to find that out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// The longest path followed, counted in edges from the start.
    pub max_depth: usize,
    /// The most nodes visited.
    pub max_nodes: usize,
}

/// The ceiling one policy aggregation graph is followed under, wherever it is
/// followed.
///
/// Named here rather than in either caller because the write path that refuses
/// a cycle and the decision that folds the graph have to agree. Two copies of
/// the number would let a policy set be one a write accepts and a decision
/// cannot answer, which is a realm that saves a rule and then decides nothing.
pub const POLICY_AGGREGATION: Budget = Budget {
    max_depth: 16,
    max_nodes: 1024,
};

/// The walk ran out of budget with edges left to follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the walk did not finish within its budget")]
pub struct Exhausted;

/// Whether any path of one edge or more leads from `start` to `target`.
///
/// `start` reaching itself means an edge comes back to it, not that a node is
/// trivially its own neighbour: the question this is asked is whether adding an
/// edge closes a cycle, and a walk that answered yes for every node would
/// refuse every write.
pub fn reaches<S>(
    start: &str,
    target: &str,
    successors: S,
    budget: Budget,
) -> Result<bool, Exhausted>
where
    S: Fn(&str) -> Vec<String>,
{
    let mut visited: BTreeSet<String> = BTreeSet::new();
    visited.insert(start.to_owned());

    let mut pending: VecDeque<(String, usize)> = step(start, 1, &successors, &budget)?.into();

    // Breadth first, and that is not a preference. A node is reached here at
    // its shortest distance from the start, so the depth ceiling means "no node
    // further than this many edges is expanded". Followed depth first, a node
    // would be expanded at whatever depth the traversal order happened to reach
    // it first, and the same graph would be inside the ceiling or outside it
    // depending on the order its edges came back in.
    while let Some((node, depth)) = pending.pop_front() {
        if node == target {
            return Ok(true);
        }
        // A node already walked has already had its successors queued, and the
        // second visit adds nothing but a way round a cycle again.
        if !visited.insert(node.clone()) {
            continue;
        }
        if visited.len() > budget.max_nodes {
            return Err(Exhausted);
        }
        pending.extend(step(&node, depth + 1, &successors, &budget)?);
    }

    Ok(false)
}

/// The successors of one node, at the depth they sit at.
///
/// Refused rather than truncated when that depth is past the ceiling. Dropping
/// them would turn a chain too long to follow into a chain with nothing at the
/// end of it.
fn step<S>(
    node: &str,
    depth: usize,
    successors: &S,
    budget: &Budget,
) -> Result<Vec<(String, usize)>, Exhausted>
where
    S: Fn(&str) -> Vec<String>,
{
    let next = successors(node);
    if next.is_empty() {
        return Ok(Vec::new());
    }
    if depth > budget.max_depth {
        return Err(Exhausted);
    }
    Ok(next.into_iter().map(|node| (node, depth)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn graph(edges: &[(&str, &str)]) -> impl Fn(&str) -> Vec<String> + use<> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (from, to) in edges {
            map.entry((*from).to_owned())
                .or_default()
                .push((*to).to_owned());
        }
        move |node: &str| map.get(node).cloned().unwrap_or_default()
    }

    fn generous() -> Budget {
        Budget {
            max_depth: 16,
            max_nodes: 64,
        }
    }

    #[test]
    fn a_path_that_exists_is_found() {
        let edges = graph(&[("a", "b"), ("b", "c"), ("c", "d")]);
        assert_eq!(reaches("a", "d", &edges, generous()), Ok(true));
    }

    #[test]
    fn a_path_that_does_not_exist_is_not() {
        let edges = graph(&[("a", "b"), ("c", "d")]);
        assert_eq!(reaches("a", "d", &edges, generous()), Ok(false));
    }

    /// The whole point of the visited set: without it this call does not return.
    #[test]
    fn a_cycle_is_walked_once() {
        let edges = graph(&[("a", "b"), ("b", "c"), ("c", "a")]);
        assert_eq!(reaches("a", "a", &edges, generous()), Ok(true));
        assert_eq!(reaches("a", "elsewhere", &edges, generous()), Ok(false));
    }

    /// A node is not its own neighbour, but an edge back to it is a path.
    #[test]
    fn a_node_reaches_itself_only_through_an_edge() {
        let none = graph(&[]);
        assert_eq!(reaches("a", "a", &none, generous()), Ok(false));

        let loops = graph(&[("a", "a")]);
        assert_eq!(reaches("a", "a", &loops, generous()), Ok(true));
    }

    /// A node is reached at its shortest distance whatever order its edges came
    /// back in, so the depth ceiling decides the same way twice. Followed depth
    /// first, `a` would reach `d` by the long arm first and this graph would be
    /// refused at a ceiling that its shortest path fits inside.
    #[test]
    fn the_depth_ceiling_counts_the_shortest_path() {
        let edges = graph(&[("a", "d"), ("a", "b"), ("b", "c"), ("c", "d"), ("d", "e")]);
        let shallow = Budget {
            max_depth: 1,
            max_nodes: 64,
        };
        assert_eq!(
            reaches("a", "d", &edges, shallow),
            Ok(true),
            "the one edge to the target was not counted as one edge"
        );
    }

    /// Past the depth ceiling the answer is that there is no answer. Reporting
    /// no path would be reporting the absence of what was never looked for.
    #[test]
    fn a_chain_longer_than_the_ceiling_is_unanswered() {
        let edges = graph(&[("a", "b"), ("b", "c"), ("c", "d")]);
        let shallow = Budget {
            max_depth: 2,
            max_nodes: 64,
        };
        assert_eq!(reaches("a", "d", &edges, shallow), Err(Exhausted));

        // And the same graph answers once the ceiling is where the chain ends.
        let enough = Budget {
            max_depth: 3,
            max_nodes: 64,
        };
        assert_eq!(reaches("a", "d", &edges, enough), Ok(true));
    }

    #[test]
    fn a_graph_wider_than_the_ceiling_is_unanswered() {
        let fan_out = |node: &str| {
            if node == "a" {
                (0..32).map(|n| format!("n{n}")).collect()
            } else {
                Vec::new()
            }
        };
        let narrow = Budget {
            max_depth: 16,
            max_nodes: 4,
        };
        assert_eq!(reaches("a", "absent", fan_out, narrow), Err(Exhausted));
    }
}
