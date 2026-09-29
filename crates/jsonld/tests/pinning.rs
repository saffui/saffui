//! Which contexts a realm may pin: read the way a document naming them would
//! read them, under the contexts built in and those already pinned.

use std::collections::HashMap;
use std::path::PathBuf;

use jsonld::built_in::{CREDENTIALS_V1, HeldContexts, built_in_contexts};
use jsonld::json::parse_strict;
use jsonld::{Contexts, Unreadable, check_context_document};
use serde_json::{Value, json};

fn check(document: &Value, pinned: &HashMap<String, Value>) -> Result<(), Unreadable> {
    check_context_document(document, &HeldContexts::new(pinned))
}

#[test]
fn every_built_in_context_is_read() {
    let built_in = built_in_contexts();
    assert_eq!(built_in.len(), 3);
    for (url, document) in built_in {
        assert_eq!(check(document, &HashMap::new()), Ok(()), "{url}");
    }
}

#[test]
fn an_issuers_context_reads_under_the_built_in_ones() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/proofs/holashchand/insurance-context.json");
    let insurance = parse_strict(&std::fs::read(path).expect("a fixture")).expect("JSON");
    assert_eq!(check(&insurance, &HashMap::new()), Ok(()));
}

#[test]
fn a_context_that_would_give_meaning_to_undefined_keys_is_refused() {
    let vocabulary = json!({ "@context": { "@vocab": "https://example.com/terms#" } });
    assert_eq!(
        check(&vocabulary, &HashMap::new()),
        Err(Unreadable::Unsupported("a vocabulary mapping"))
    );
}

#[test]
fn a_context_naming_one_not_held_waits_for_it() {
    let naming = json!({
        "@context": ["https://example.com/terms", { "a": "https://example.com/a" }]
    });
    assert_eq!(
        check(&naming, &HashMap::new()),
        Err(Unreadable::UnknownContext(
            "https://example.com/terms".to_owned()
        ))
    );
    let pinned = HashMap::from([(
        "https://example.com/terms".to_owned(),
        json!({ "@context": { "b": "https://example.com/b" } }),
    )]);
    assert_eq!(check(&naming, &pinned), Ok(()));
}

#[test]
fn a_document_that_is_no_context_is_refused() {
    for document in [
        json!({ "a": "https://example.com/a" }),
        json!([]),
        json!("x"),
    ] {
        assert_eq!(
            check(&document, &HashMap::new()),
            Err(Unreadable::Invalid("invalid remote context")),
            "{document}"
        );
    }
}

#[test]
fn a_pinned_context_never_stands_for_a_built_in_one() {
    let pinned = HashMap::from([(CREDENTIALS_V1.to_owned(), json!({ "@context": {} }))]);
    assert_eq!(
        HeldContexts::new(&pinned).document(CREDENTIALS_V1),
        built_in_contexts().get(CREDENTIALS_V1)
    );
}
