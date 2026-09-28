//! The W3C RDF Dataset Canonicalization test suite, `tests/rdfc10/`, taken from
//! github.com/w3c/rdf-canon at 15619df2 (see THIRD-PARTY.md): every evaluation
//! test, every identifier map test, and the one negative test.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crypto::provider::openssl::OpenSslProvider;
use crypto::provider::{CryptoConfig, HashAlg};
use jsonld::canon::{DEFAULT_WORK, Refused, canonicalize};
use jsonld::rdf::{Literal, Node, Object, Quad, RDF_LANG_STRING, XSD_STRING};

fn suite() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/rdfc10")
}

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
}

/// One row of the suite's manifest.
struct Case {
    test: String,
    hash: HashAlg,
    evaluation: String,
    map: bool,
}

fn cases() -> Vec<Case> {
    let manifest = std::fs::read_to_string(suite().join("manifest.csv")).expect("the manifest");
    let mut rows = manifest.lines().map(csv_fields);
    let header = rows.next().expect("a header");
    let column = |name: &str| {
        header
            .iter()
            .position(|held| held == name)
            .unwrap_or_else(|| panic!("no {name} column"))
    };
    let (test, hash, evaluation, map) = (
        column("test"),
        column("hashAlgorithm"),
        column("rdfc10"),
        column("rdfc10map"),
    );
    rows.filter(|row| row.len() > map)
        .map(|row| Case {
            test: row[test].clone(),
            hash: match row[hash].as_str() {
                "" | "SHA256" => HashAlg::Sha256,
                "SHA384" => HashAlg::Sha384,
                other => panic!("an unknown hash {other}"),
            },
            evaluation: row[evaluation].clone(),
            map: row[map] == "TRUE",
        })
        .collect()
}

/// The fields of a CSV line, quoted ones read with their doubled quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = line.chars().peekable();
    while let Some(character) = characters.next() {
        match (character, quoted) {
            ('"', true) if characters.peek() == Some(&'"') => {
                characters.next();
                field.push('"');
            }
            ('"', _) => quoted = !quoted,
            (',', false) => fields.push(std::mem::take(&mut field)),
            (other, _) => field.push(other),
        }
    }
    fields.push(field);
    fields
}

fn input_of(test: &str) -> Vec<Quad> {
    let text = std::fs::read_to_string(suite().join(format!("{test}-in.nq"))).expect("an input");
    text.lines()
        .filter_map(|line| NQuads::new(line).statement())
        .collect()
}

/// A reader of the N-Quads the suite writes, one statement per line.
struct NQuads<'t> {
    rest: &'t str,
}

impl<'t> NQuads<'t> {
    fn new(line: &'t str) -> Self {
        Self { rest: line }
    }

    fn skip_space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t']);
    }

    fn statement(&mut self) -> Option<Quad> {
        self.skip_space();
        if self.rest.is_empty() || self.rest.starts_with('#') {
            return None;
        }
        let subject = self.node();
        let predicate = self.iri();
        let object = self.object();
        self.skip_space();
        let graph = (!self.rest.starts_with('.')).then(|| self.node());
        self.skip_space();
        assert!(self.rest.starts_with('.'), "a statement ends with a dot");
        Some(Quad {
            subject,
            predicate,
            object,
            graph,
        })
    }

    fn node(&mut self) -> Node {
        self.skip_space();
        if self.rest.starts_with("_:") {
            let end = self.rest.find([' ', '\t']).unwrap_or(self.rest.len());
            let label = self.rest[2..end].trim_end_matches('.').to_owned();
            self.rest = &self.rest[2 + label.len()..];
            Node::Blank(label)
        } else {
            Node::Iri(self.iri())
        }
    }

    fn iri(&mut self) -> String {
        self.skip_space();
        let body = self.rest.strip_prefix('<').expect("an IRI");
        let end = body.find('>').expect("an IRI's end");
        self.rest = &body[end + 1..];
        unescape(&body[..end])
    }

    fn object(&mut self) -> Object {
        self.skip_space();
        let Some(body) = self.rest.strip_prefix('"') else {
            return Object::Node(self.node());
        };
        let mut end = 0;
        let mut escaped = false;
        for (at, character) in body.char_indices() {
            match character {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => {
                    end = at;
                    break;
                }
                _ => escaped = false,
            }
        }
        let lexical = unescape(&body[..end]);
        self.rest = &body[end + 1..];
        if let Some(tagged) = self.rest.strip_prefix('@') {
            let tag_end = tagged.find([' ', '\t']).unwrap_or(tagged.len());
            let language = tagged[..tag_end].to_owned();
            self.rest = &tagged[tag_end..];
            return Object::Literal(Literal {
                lexical,
                datatype: RDF_LANG_STRING.to_owned(),
                language: Some(language),
            });
        }
        let datatype = match self.rest.strip_prefix("^^") {
            Some(typed) => {
                self.rest = typed;
                self.iri()
            }
            None => XSD_STRING.to_owned(),
        };
        Object::Literal(Literal {
            lexical,
            datatype,
            language: None,
        })
    }
}

/// ECHAR and UCHAR read back into the characters they stand for.
fn unescape(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut characters = escaped.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        let code = |length: usize, characters: &mut std::str::Chars<'_>| {
            let hex: String = characters.take(length).collect();
            char::from_u32(u32::from_str_radix(&hex, 16).expect("hexadecimal"))
                .expect("a character")
        };
        match characters.next().expect("an escape") {
            't' => out.push('\t'),
            'b' => out.push('\u{8}'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            'f' => out.push('\u{c}'),
            'u' => out.push(code(4, &mut characters)),
            'U' => out.push(code(8, &mut characters)),
            other => out.push(other),
        }
    }
    out
}

#[test]
fn every_evaluation_test_gives_the_canonical_form() {
    let provider = provider();
    let mut ran = 0;
    for case in cases().iter().filter(|case| case.evaluation == "TRUE") {
        let expected = std::fs::read_to_string(suite().join(format!("{}-rdfc10.nq", case.test)))
            .expect("an expected result");
        let canonical = canonicalize(&provider, case.hash, &input_of(&case.test), DEFAULT_WORK)
            .unwrap_or_else(|refused| panic!("{}: {refused}", case.test));
        assert_eq!(canonical.nquads, expected, "{}", case.test);
        ran += 1;
    }
    assert_eq!(ran, 64);
}

#[test]
fn every_map_test_issues_the_expected_identifiers() {
    let provider = provider();
    let mut ran = 0;
    for case in cases().iter().filter(|case| case.map) {
        let expected: BTreeMap<String, String> = serde_json::from_str(
            &std::fs::read_to_string(suite().join(format!("{}-rdfc10map.json", case.test)))
                .expect("an expected map"),
        )
        .expect("a JSON map");
        let canonical = canonicalize(&provider, case.hash, &input_of(&case.test), DEFAULT_WORK)
            .unwrap_or_else(|refused| panic!("{}: {refused}", case.test));
        let issued: BTreeMap<String, String> = canonical.issued.into_iter().collect();
        assert_eq!(issued, expected, "{}", case.test);
        ran += 1;
    }
    assert_eq!(ran, 21);
}

/// A clique of ten blank nodes, each related to every other: the work it asks
/// for grows with the permutations of nine, and it is refused rather than
/// waited on.
#[test]
fn a_poisoned_dataset_is_refused() {
    let provider = provider();
    let negative: Vec<Case> = cases()
        .into_iter()
        .filter(|case| case.evaluation == "RDFC10NegativeEvalTest")
        .collect();
    assert_eq!(negative.len(), 1);
    for case in negative {
        let refused = canonicalize(&provider, case.hash, &input_of(&case.test), DEFAULT_WORK);
        assert_eq!(refused, Err(Refused::TooComplex), "{}", case.test);
    }
}

/// The work the suite's poisoned graphs that it calls computable need, to the
/// unit: what `DEFAULT_WORK` is measured against, and what an accounting that
/// stopped counting permutations, or stopped cutting paths short, would move.
#[test]
fn the_computable_poisoned_graphs_need_the_measured_work() {
    let provider = provider();
    for test in ["test044", "test045", "test046"] {
        let quads = input_of(test);
        assert!(
            canonicalize(&provider, HashAlg::Sha256, &quads, 3_348).is_ok(),
            "{test}"
        );
        assert_eq!(
            canonicalize(&provider, HashAlg::Sha256, &quads, 3_347),
            Err(Refused::TooComplex),
            "{test}"
        );
    }
}
