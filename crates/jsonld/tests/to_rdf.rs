//! The toRdf tests of the W3C JSON-LD 1.1 suite, `tests/jsonld-api/`, taken
//! from github.com/w3c/json-ld-api at ffdb3261 (see THIRD-PARTY.md).
//!
//! This processor reads a strict part of JSON-LD, so the rule is not that every
//! test passes: a positive test gives exactly the expected dataset or is
//! refused in words, a negative test is refused, and nothing is ever read into
//! a dataset other than the one expected.

mod support;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crypto::provider::HashAlg;
use jsonld::canon::{DEFAULT_WORK, canonicalize};
use jsonld::json::parse_strict;
use jsonld::rdf::Quad;
use jsonld::to_rdf;
use serde_json::Value;
use support::{provider, quads_of};

const BASE: &str = "https://w3c.github.io/json-ld-api/tests/";

fn suite() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/jsonld-api")
}

/// Every JSON document of the suite, by the URL its tests name it with.
fn documents() -> HashMap<String, Value> {
    let mut documents = HashMap::new();
    let mut pending = vec![suite().join("toRdf")];
    while let Some(folder) = pending.pop() {
        for entry in std::fs::read_dir(&folder).expect("a folder") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "jsonld")
                && let Ok(document) = parse_strict(&std::fs::read(&path).expect("a file"))
            {
                documents.insert(url_of(&path), document);
            }
        }
    }
    documents
}

fn url_of(path: &Path) -> String {
    let relative = path.strip_prefix(suite()).expect("inside the suite");
    format!("{BASE}{}", relative.to_string_lossy())
}

/// What a test came to.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Passed,
    Refused(String),
    Wrong(String),
}

/// A dataset in the form two isomorphic datasets share.
fn canonical(quads: &[Quad]) -> String {
    canonicalize(&provider(), HashAlg::Sha256, quads, DEFAULT_WORK)
        .expect("a dataset the suite expects canonicalizes")
        .nquads
}

fn run(test: &Value, documents: &HashMap<String, Value>) -> Outcome {
    let types: Vec<&str> = test["@type"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let input = test["input"].as_str().expect("an input");
    let text = std::fs::read(suite().join(input)).expect("the test's input");
    let read = parse_strict(&text).and_then(|document| to_rdf(&document, documents, 100_000));
    if types.contains(&"jld:NegativeEvaluationTest") {
        return match read {
            Err(refused) => Outcome::Refused(refused.to_string()),
            Ok(_) => Outcome::Wrong("an invalid document was read".to_owned()),
        };
    }
    let quads = match read {
        Ok(quads) => quads,
        Err(refused) => return Outcome::Refused(refused.to_string()),
    };
    if types.contains(&"jld:PositiveSyntaxTest") {
        return Outcome::Passed;
    }
    let expected =
        std::fs::read_to_string(suite().join(test["expect"].as_str().expect("an expected result")))
            .expect("an expected result");
    let (read, expected) = (canonical(&quads), canonical(&quads_of(&expected)));
    if read == expected {
        Outcome::Passed
    } else {
        Outcome::Wrong(format!("read:\n{read}expected:\n{expected}"))
    }
}

/// Whether a test is about a processor this one is not: JSON-LD 1.0, or an
/// option saffui never sets. One negative test, er56, reads its input from
/// upstream's expand folder, which is not taken.
fn applies(test: &Value) -> bool {
    let option = &test["option"];
    option["specVersion"] != "json-ld-1.0"
        && option["processingMode"] != "json-ld-1.0"
        && option.get("expandContext").is_none()
        && test["input"]
            .as_str()
            .is_some_and(|input| input.starts_with("toRdf/"))
}

#[test]
fn every_test_is_read_exactly_or_refused() {
    let manifest =
        parse_strict(&std::fs::read(suite().join("toRdf-manifest.jsonld")).expect("the manifest"))
            .expect("a manifest");
    let documents = documents();
    let mut passed = Vec::new();
    let mut refused = Vec::new();
    let mut wrong = Vec::new();
    for test in manifest["sequence"].as_array().expect("tests") {
        if !applies(test) {
            continue;
        }
        let id = test["@id"].as_str().unwrap_or_default().to_owned();
        match run(test, &documents) {
            Outcome::Passed => passed.push(id),
            Outcome::Refused(why) => refused.push(format!("{id}: {why}")),
            Outcome::Wrong(what) => wrong.push(format!("{id}: {what}")),
        }
    }
    assert!(
        wrong.is_empty(),
        "{} read wrong:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    // The part of JSON-LD this processor reads, as measured: a change here is a
    // change in what it reads, to be made on purpose.
    assert_eq!(
        (passed.len(), refused.len()),
        (135, 311),
        "refused:\n{}",
        refused.join("\n")
    );
}
