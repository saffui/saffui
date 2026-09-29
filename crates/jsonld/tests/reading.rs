//! What the processor reads and what it refuses, where the W3C suite's own
//! tests are refused for another reason first.

use std::collections::HashMap;

use jsonld::rdf::Quad;
use jsonld::{Unreadable, to_rdf};
use serde_json::{Value, json};

fn read_document(document: Value) -> Result<Vec<Quad>, Unreadable> {
    read_document_with(document, &HashMap::new())
}

fn read_document_with(
    document: Value,
    contexts: &HashMap<String, Value>,
) -> Result<Vec<Quad>, Unreadable> {
    to_rdf(&document, contexts, 1_000)
}

/// A context a type brings reaches the node of that type, and no node under
/// it: in a credential, the terms `VerifiableCredential` defines stop at the
/// credential and do not reach its subject.
#[test]
fn a_type_scoped_context_stays_on_its_node() {
    let context = json!({
        "Thing": {
            "@id": "https://example.com/Thing",
            "@context": { "inner": "https://example.com/inner" }
        },
        "child": "https://example.com/child"
    });
    let own = json!({ "@context": context, "@type": "Thing", "inner": "x" });
    assert_eq!(read_document(own).map(|quads| quads.len()), Ok(2));
    let under = json!({ "@context": context, "@type": "Thing", "child": { "inner": "x" } });
    assert_eq!(
        read_document(under),
        Err(Unreadable::Undefined("inner".to_owned()))
    );
}

/// A remote context that names itself is followed until the chain is too long,
/// then refused.
#[test]
fn a_context_that_includes_itself_is_refused() {
    let contexts = HashMap::from([(
        "https://example.com/loop".to_owned(),
        json!({ "@context": ["https://example.com/loop", { "a": "https://example.com/a" }] }),
    )]);
    let document = json!({ "@context": "https://example.com/loop", "a": "x" });
    assert_eq!(
        read_document_with(document, &contexts),
        Err(Unreadable::Invalid("context overflow"))
    );
}

/// A context is refused whole for a term it defines wrongly, even one the
/// document does not use.
#[test]
fn a_context_with_a_bad_definition_is_refused_even_unused() {
    for (definition, error) in [
        (
            json!({ "@id": "https://example.com/t", "@type": "not an IRI" }),
            "invalid type mapping",
        ),
        (
            json!({ "@id": "https://example.com/t", "@container": ["@list", "@set"] }),
            "invalid container mapping",
        ),
    ] {
        let document = json!({
            "@context": { "t": definition, "a": "https://example.com/a" },
            "a": "x"
        });
        assert_eq!(read_document(document), Err(Unreadable::Invalid(error)));
    }
}

/// One node under two keys of an index map carries two indexes.
#[test]
fn one_node_under_two_indexes_is_refused() {
    let document = json!({
        "@context": { "items": { "@id": "https://example.com/items", "@container": "@index" } },
        "@id": "https://example.com/s",
        "items": {
            "first": { "@id": "https://example.com/x" },
            "second": { "@id": "https://example.com/x", "https://example.com/p": "v" }
        }
    });
    assert_eq!(
        read_document(document),
        Err(Unreadable::Invalid("conflicting indexes"))
    );
}

/// The keys of an index map are not in the dataset, so no proof signs them:
/// what is read through one is the value alone.
#[test]
fn the_keys_of_an_index_map_are_not_in_the_dataset() {
    let document = json!({
        "@context": { "claim": { "@id": "https://example.com/claim", "@container": "@index" } },
        "@id": "https://example.com/s",
        "claim": { "identityQRCode": "value" }
    });
    let quads = read_document(document).expect("a dataset");
    assert_eq!(quads.len(), 1);
    assert!(!format!("{quads:?}").contains("identityQRCode"));
}
