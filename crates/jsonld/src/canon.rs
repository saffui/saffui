//! RDF Dataset Canonicalization, RDFC-1.0 (W3C Recommendation, 2024-05-21):
//! canonical identifiers for the blank nodes of a dataset, then its canonical
//! N-Quads form. The step numbers below are the specification's.

use std::collections::{BTreeMap, HashMap, HashSet};

use crypto::provider::{CryptoProvider, HashAlg};
use data_encoding::HEXLOWER;

use crate::nquads::write_quad;
use crate::rdf::{Position, Quad};

/// The work a canonicalization may do before it is refused. Each call of the
/// N-degree hash and each permutation it tries costs one. RDFC-1.0 §4.4.3
/// requires a bound: a dataset built to exhaust it is refused, not waited on.
///
/// The W3C suite's three poisoned graphs that it calls computable need 3,348
/// each and every other test at most 54; its ten-node clique needs more than a
/// million. A caller whose datasets are small passes less.
pub const DEFAULT_WORK: u64 = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the dataset needs more work to canonicalize than it is allowed")]
    TooComplex,
    #[error("the dataset could not be hashed")]
    Unhashable,
}

/// A dataset in canonical form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonicalized {
    /// The canonical N-Quads document.
    pub nquads: String,
    /// Each blank node identifier of the input with its canonical one, in the
    /// order they were issued.
    pub issued: Vec<(String, String)>,
}

/// Canonicalize `quads` under `hash`, doing at most `work` units of work.
/// Identical quads count once: a dataset is a set.
pub fn canonicalize(
    provider: &dyn CryptoProvider,
    hash: HashAlg,
    quads: &[Quad],
    work: u64,
) -> Result<Canonicalized, Refused> {
    let mut seen = HashSet::with_capacity(quads.len());
    let quads: Vec<&Quad> = quads.iter().filter(|quad| seen.insert(*quad)).collect();
    let (mut state, blank_nodes) = State::new(provider, hash, &quads, work);
    let mut blank_nodes_by_hash = state.hash_first_degrees(&blank_nodes)?;

    // 4: a unique first degree hash is enough, in code point order of hashes.
    blank_nodes_by_hash.retain(|_, listed| match listed.as_slice() {
        [identifier] => {
            state.canonical.issue(identifier);
            false
        }
        _ => true,
    });

    // 5
    for listed in blank_nodes_by_hash.values() {
        let mut paths = Vec::new();
        for identifier in listed {
            if state.canonical.get(identifier).is_some() {
                continue;
            }
            let mut temporary = Issuer::new("b");
            temporary.issue(identifier);
            paths.push(state.hash_n_degree(identifier, temporary)?);
        }
        paths.sort_by(|left, right| left.0.cmp(&right.0));
        for (_, issuer) in paths {
            for (existing, _) in issuer.issued {
                state.canonical.issue(&existing);
            }
        }
    }

    // 7
    let canonical = &state.canonical;
    let mut lines = Vec::with_capacity(quads.len());
    for quad in &quads {
        let mut line = String::new();
        write_quad(&mut line, quad, &|identifier, out| {
            out.push_str(canonical.get(identifier).unwrap_or(identifier));
        });
        lines.push(line);
    }
    lines.sort_unstable();
    Ok(Canonicalized {
        nquads: lines.concat(),
        issued: state.canonical.issued,
    })
}

struct State<'q> {
    provider: &'q dyn CryptoProvider,
    hash: HashAlg,
    quads: &'q [&'q Quad],
    mentions: HashMap<&'q str, Vec<usize>>,
    first_degree: HashMap<&'q str, String>,
    canonical: Issuer,
    work_left: u64,
}

impl<'q> State<'q> {
    /// 1 and 2: the quads each blank node is a component of, each quad once,
    /// with the blank nodes in the order they are first mentioned.
    fn new(
        provider: &'q dyn CryptoProvider,
        hash: HashAlg,
        quads: &'q [&'q Quad],
        work: u64,
    ) -> (Self, Vec<&'q str>) {
        let mut mentions: HashMap<&'q str, Vec<usize>> = HashMap::new();
        let mut blank_nodes = Vec::new();
        for (index, quad) in quads.iter().enumerate() {
            for (identifier, _) in quad.blank_nodes() {
                let listed = mentions.entry(identifier).or_insert_with(|| {
                    blank_nodes.push(identifier);
                    Vec::new()
                });
                if listed.last() != Some(&index) {
                    listed.push(index);
                }
            }
        }
        let state = Self {
            provider,
            hash,
            quads,
            mentions,
            first_degree: HashMap::new(),
            canonical: Issuer::new("c14n"),
            work_left: work,
        };
        (state, blank_nodes)
    }

    /// 3: the blank nodes grouped by first degree hash.
    fn hash_first_degrees(
        &mut self,
        blank_nodes: &[&'q str],
    ) -> Result<BTreeMap<String, Vec<&'q str>>, Refused> {
        let mut blank_nodes_by_hash: BTreeMap<String, Vec<&'q str>> = BTreeMap::new();
        for &identifier in blank_nodes {
            let first_degree = self.hash_first_degree(identifier)?;
            blank_nodes_by_hash
                .entry(first_degree.clone())
                .or_default()
                .push(identifier);
            self.first_degree.insert(identifier, first_degree);
        }
        Ok(blank_nodes_by_hash)
    }

    fn spend(&mut self) -> Result<(), Refused> {
        self.work_left = self.work_left.checked_sub(1).ok_or(Refused::TooComplex)?;
        Ok(())
    }

    fn hash_of(&self, input: &str) -> Result<String, Refused> {
        let digest = self
            .provider
            .digest()
            .hash(self.hash, input.as_bytes())
            .map_err(|_| Refused::Unhashable)?;
        Ok(HEXLOWER.encode(&digest))
    }

    fn mentions_of<'s>(&'s self, identifier: &str) -> impl Iterator<Item = &'q Quad> + use<'q, 's> {
        let quads = self.quads;
        self.mentions
            .get(identifier)
            .into_iter()
            .flatten()
            .map(move |&index| quads[index])
    }

    /// §4.6: the mention set with this node written `a` and every other blank
    /// node `z`, sorted and hashed.
    fn hash_first_degree(&self, reference: &str) -> Result<String, Refused> {
        let mut lines: Vec<String> = self
            .mentions_of(reference)
            .map(|quad| {
                let mut line = String::new();
                write_quad(&mut line, quad, &|identifier, out| {
                    out.push_str(if identifier == reference { "a" } else { "z" });
                });
                line
            })
            .collect();
        lines.sort_unstable();
        self.hash_of(&lines.concat())
    }

    /// §4.7
    fn hash_related(
        &self,
        related: &str,
        quad: &Quad,
        issuer: &Issuer,
        position: Position,
    ) -> Result<String, Refused> {
        let mut input = String::new();
        input.push(position.letter());
        if position != Position::Graph {
            input.push('<');
            input.push_str(&quad.predicate);
            input.push('>');
        }
        match self.canonical.get(related).or_else(|| issuer.get(related)) {
            Some(identifier) => {
                input.push_str("_:");
                input.push_str(identifier);
            }
            None => input.push_str(
                self.first_degree
                    .get(related)
                    .map(String::as_str)
                    .unwrap_or_default(),
            ),
        }
        self.hash_of(&input)
    }

    /// §4.8
    fn hash_n_degree(
        &mut self,
        identifier: &str,
        mut issuer: Issuer,
    ) -> Result<(String, Issuer), Refused> {
        self.spend()?;
        // 1 to 3
        let mut related_by_hash: BTreeMap<String, Vec<&'q str>> = BTreeMap::new();
        let mentioned: Vec<&'q Quad> = self.mentions_of(identifier).collect();
        for quad in mentioned {
            for (related, position) in quad.blank_nodes() {
                if related != identifier {
                    let related_hash = self.hash_related(related, quad, &issuer, position)?;
                    related_by_hash
                        .entry(related_hash)
                        .or_default()
                        .push(related);
                }
            }
        }

        // 4, 5
        let mut data_to_hash = String::new();
        for (related_hash, listed) in related_by_hash {
            data_to_hash.push_str(&related_hash);
            let mut chosen: Option<(String, Issuer)> = None;
            let mut permutations = Permutations::of(listed);
            // 5.4.4.3 and 5.4.5.5 skip a path once it is at least as long as the
            // chosen one and after it. Every permutation of a list recurses on
            // the same nodes and ends as long as the chosen path, so that point
            // comes only at its last step, with nothing left to skip.
            while let Some(permutation) = permutations.next_permutation() {
                self.spend()?;
                let mut issuer_copy = issuer.clone();
                let mut path = String::new();
                let mut recursion = Vec::new();
                for related in permutation {
                    match self.canonical.get(related) {
                        Some(canonical) => {
                            path.push_str("_:");
                            path.push_str(canonical);
                        }
                        None => {
                            if issuer_copy.get(related).is_none() {
                                recursion.push(related);
                            }
                            path.push_str("_:");
                            path.push_str(issuer_copy.issue(related));
                        }
                    }
                }
                for related in recursion {
                    let (result_hash, result_issuer) = self.hash_n_degree(related, issuer_copy)?;
                    issuer_copy = result_issuer;
                    path.push_str("_:");
                    path.push_str(issuer_copy.issue(related));
                    path.push('<');
                    path.push_str(&result_hash);
                    path.push('>');
                }
                if chosen
                    .as_ref()
                    .is_none_or(|(chosen_path, _)| path < *chosen_path)
                {
                    chosen = Some((path, issuer_copy));
                }
            }
            if let Some((chosen_path, chosen_issuer)) = chosen {
                data_to_hash.push_str(&chosen_path);
                issuer = chosen_issuer;
            }
        }

        // 6
        Ok((self.hash_of(&data_to_hash)?, issuer))
    }
}

/// An identifier issuer, §4.3 and §4.5.
#[derive(Debug, Clone)]
struct Issuer {
    prefix: &'static str,
    /// Existing identifier and issued identifier, in the order issued.
    issued: Vec<(String, String)>,
    index: HashMap<String, usize>,
}

impl Issuer {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            issued: Vec::new(),
            index: HashMap::new(),
        }
    }

    fn get(&self, existing: &str) -> Option<&str> {
        self.index
            .get(existing)
            .map(|&at| self.issued[at].1.as_str())
    }

    fn issue(&mut self, existing: &str) -> &str {
        let at = match self.index.get(existing) {
            Some(&at) => at,
            None => {
                let at = self.issued.len();
                self.issued
                    .push((existing.to_owned(), format!("{}{at}", self.prefix)));
                self.index.insert(existing.to_owned(), at);
                at
            }
        };
        &self.issued[at].1
    }
}

/// The permutations of a list, in the Steinhaus-Johnson-Trotter order over the
/// sorted list, each value keeping one direction however often it repeats: the
/// order the reference implementation walks, which decides ties between paths
/// and so the identifiers it issues.
struct Permutations<'q> {
    current: Vec<&'q str>,
    left: HashMap<&'q str, bool>,
    done: bool,
}

impl<'q> Permutations<'q> {
    fn of(mut listed: Vec<&'q str>) -> Self {
        listed.sort_unstable();
        let left = listed.iter().map(|&element| (element, true)).collect();
        Self {
            current: listed,
            left,
            done: false,
        }
    }

    fn next_permutation(&mut self) -> Option<Vec<&'q str>> {
        if self.done {
            return None;
        }
        let permutation = self.current.clone();
        // The largest mobile element: one greater than the neighbour it looks at.
        let mut largest: Option<(&'q str, usize)> = None;
        for (at, &element) in self.current.iter().enumerate() {
            let looks_left = self.left.get(element).copied().unwrap_or(true);
            let mobile = if looks_left {
                at > 0 && element > self.current[at - 1]
            } else {
                at + 1 < self.current.len() && element > self.current[at + 1]
            };
            if mobile && largest.is_none_or(|(held, _)| element > held) {
                largest = Some((element, at));
            }
        }
        match largest {
            None => self.done = true,
            Some((element, at)) => {
                let looks_left = self.left.get(element).copied().unwrap_or(true);
                let swap = if looks_left { at - 1 } else { at + 1 };
                self.current.swap(at, swap);
                for other in &self.current {
                    if *other > element
                        && let Some(direction) = self.left.get_mut(other)
                    {
                        *direction = !*direction;
                    }
                }
            }
        }
        Some(permutation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdf::{Node, Object};
    use crypto::provider::CryptoConfig;
    use crypto::provider::openssl::OpenSslProvider;

    fn provider() -> OpenSslProvider {
        OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
    }

    /// A term of the specification's examples: `_:x` a blank node, `:x` an IRI
    /// under the prefix its logs expand.
    fn node(term: &str) -> Node {
        match term.strip_prefix("_:") {
            Some(label) => Node::Blank(label.to_owned()),
            None => Node::Iri(format!("http://example.com/#{}", &term[1..])),
        }
    }

    fn quads(statements: &[[&str; 3]]) -> Vec<Quad> {
        statements
            .iter()
            .map(|[subject, predicate, object]| Quad {
                subject: node(subject),
                predicate: format!("http://example.com/#{}", &predicate[1..]),
                object: Object::Node(node(object)),
                graph: None,
            })
            .collect()
    }

    fn sha256(input: &str) -> String {
        let digest = provider()
            .digest()
            .hash(HashAlg::Sha256, input.as_bytes())
            .expect("a digest");
        HEXLOWER.encode(&digest)
    }

    /// Example 3 of the specification, the one its later examples reuse.
    fn shared_hashes() -> Vec<Quad> {
        quads(&[
            [":p", ":q", "_:e0"],
            [":p", ":q", "_:e1"],
            ["_:e0", ":p", "_:e2"],
            ["_:e1", ":p", "_:e3"],
            ["_:e2", ":r", "_:e3"],
        ])
    }

    #[test]
    fn the_first_degree_hashes_are_the_specifications() {
        let provider = provider();
        let unique = quads(&[
            [":p", ":q", "_:e0"],
            [":p", ":r", "_:e1"],
            ["_:e0", ":s", ":u"],
            ["_:e1", ":t", ":u"],
        ]);
        let unique: Vec<&Quad> = unique.iter().collect();
        let (state, _) = State::new(&provider, HashAlg::Sha256, &unique, DEFAULT_WORK);
        // Example 4.
        assert_eq!(
            state.hash_first_degree("e0"),
            Ok("21d1dd5ba21f3dee9d76c0c00c260fa6f5d5d65315099e553026f4828d0dc77a".into())
        );
        assert_eq!(
            state.hash_first_degree("e1"),
            Ok("6fa0b9bdb376852b5743ff39ca4cbf7ea14d34966b2828478fbf222e7c764473".into())
        );

        let shared = shared_hashes();
        let shared: Vec<&Quad> = shared.iter().collect();
        let (state, _) = State::new(&provider, HashAlg::Sha256, &shared, DEFAULT_WORK);
        // Example 5.
        for (identifier, hash) in [
            (
                "e0",
                "3b26142829b8887d011d779079a243bd61ab53c3990d550320a17b59ade6ba36",
            ),
            (
                "e1",
                "3b26142829b8887d011d779079a243bd61ab53c3990d550320a17b59ade6ba36",
            ),
            (
                "e2",
                "15973d39de079913dac841ac4fa8c4781c0febfba5e83e5c6e250869587f8659",
            ),
            (
                "e3",
                "7e790a99273eed1dc57e43205d37ce232252c85b26ca4a6ff74ff3b5aea7bccd",
            ),
        ] {
            assert_eq!(
                state.hash_first_degree(identifier),
                Ok(hash.into()),
                "{identifier}"
            );
        }
    }

    /// A quad naming the same blank node twice is one quad in its mention set.
    #[test]
    fn a_quad_counts_once_for_a_node_it_mentions_twice() {
        let provider = provider();
        let looped = quads(&[["_:e0", ":p", "_:e0"]]);
        let looped: Vec<&Quad> = looped.iter().collect();
        let (state, _) = State::new(&provider, HashAlg::Sha256, &looped, DEFAULT_WORK);
        assert_eq!(
            state.hash_first_degree("e0"),
            Ok(sha256("_:a <http://example.com/#p> _:a .\n"))
        );
    }

    #[test]
    fn a_related_node_is_hashed_as_the_specification_writes_it() {
        let provider = provider();
        let shared = shared_hashes();
        let named = Quad {
            graph: Some(Node::Blank("e2".into())),
            ..shared[2].clone()
        };
        let quads: Vec<&Quad> = shared.iter().collect();
        let (mut state, _) = State::new(&provider, HashAlg::Sha256, &quads, DEFAULT_WORK);
        state.canonical.issue("e2");
        let issuer = Issuer::new("b");
        // Example 6.
        assert_eq!(
            state.hash_related("e2", quads[2], &issuer, Position::Object),
            Ok("29cf7e22790bc2ed395b81b3933e5329fc7b25390486085cac31ce7252ca60fa".into())
        );
        // A graph name is hashed without the predicate (§4.7.3, step 2).
        assert_eq!(
            state.hash_related("e2", &named, &issuer, Position::Graph),
            Ok(sha256("g_:c14n0"))
        );
    }

    /// Example 7: the N-degree hashes of the two nodes whose first degree
    /// hashes are shared, once the other two hold canonical identifiers.
    #[test]
    fn the_n_degree_hashes_are_the_specifications() {
        let provider = provider();
        let shared = shared_hashes();
        let quads: Vec<&Quad> = shared.iter().collect();
        let (mut state, blank_nodes) = State::new(&provider, HashAlg::Sha256, &quads, DEFAULT_WORK);
        state
            .hash_first_degrees(&blank_nodes)
            .expect("first degree hashes");
        state.canonical.issue("e2");
        state.canonical.issue("e3");
        for (identifier, hash) in [
            (
                "e0",
                "fbc300de5afafd97a4b9ee1e72b57754dcdcb7ebb724789ac6a94a5b82a48d30",
            ),
            (
                "e1",
                "2c0b377baf86f6c18fed4b0df6741290066e73c932861749b172d1e5560f5045",
            ),
        ] {
            let mut temporary = Issuer::new("b");
            temporary.issue(identifier);
            let (result, _) = state
                .hash_n_degree(identifier, temporary)
                .expect("an N-degree hash");
            assert_eq!(result, hash, "{identifier}");
        }
    }

    #[test]
    fn every_permutation_of_distinct_values_comes_once() {
        let mut permutations = Permutations::of(vec!["c", "a", "b"]);
        let mut seen = Vec::new();
        while let Some(permutation) = permutations.next_permutation() {
            seen.push(permutation.concat());
        }
        assert_eq!(seen, ["abc", "acb", "cab", "cba", "bca", "bac"]);
    }

    #[test]
    fn a_repeated_value_is_not_permuted_with_itself() {
        let mut permutations = Permutations::of(vec!["e1", "e1"]);
        assert_eq!(permutations.next_permutation(), Some(vec!["e1", "e1"]));
        assert_eq!(permutations.next_permutation(), None);
    }

    #[test]
    fn an_issuer_issues_once_per_identifier_in_order() {
        let mut issuer = Issuer::new("b");
        assert_eq!(issuer.issue("e7"), "b0");
        assert_eq!(issuer.issue("e3"), "b1");
        assert_eq!(issuer.issue("e7"), "b0");
        assert_eq!(issuer.get("e3"), Some("b1"));
        assert_eq!(issuer.get("e9"), None);
    }
}
