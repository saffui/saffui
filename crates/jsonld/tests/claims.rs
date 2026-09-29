//! What a verifier reads from a credential: its types, expanded, and the claims
//! a query names by paths of member names, each refused where the proof would
//! not tell its value apart from another.

use std::collections::HashMap;
use std::path::PathBuf;

use jsonld::Unreadable;
use jsonld::built_in::{CREDENTIALS_V1, HeldContexts};
use jsonld::claims::{Unclaimed, read_credential};
use jsonld::json::parse_strict;
use serde_json::{Value, json};

const TEST_CONTEXT: &str = "https://issuer.example/contexts/test-v1.jsonld";

fn fixture(path: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/proofs")
        .join(path);
    parse_strict(&std::fs::read(&path).expect("a fixture")).expect("JSON")
}

/// The contexts a realm would pin for the credentials below.
fn pinned() -> HashMap<String, Value> {
    HashMap::from([
        (
            "https://holashchand.github.io/test_project/insurance-context.json".to_owned(),
            fixture("holashchand/insurance-context.json"),
        ),
        (
            TEST_CONTEXT.to_owned(),
            json!({ "@context": {
                "@version": 1.1,
                "ex": "https://issuer.example/vocab#",
                "TestCredential": "ex:TestCredential",
                "Person": { "@id": "ex:Person", "@context": { "nick": "ex:name" } },
                "name": "ex:name",
                "nick": "ex:nickname",
                "friend": "ex:friend",
                "witness": "ex:witness",
                "claims169": { "@id": "ex:claims169", "@container": "@index" },
                "label": { "@id": "ex:label", "@container": "@language" },
                "address": { "@id": "ex:address", "@context": { "locality": "ex:town" } },
                "locality": "ex:locality",
                "town": "ex:town",
                "hobbies": { "@id": "ex:hobbies", "@container": "@set" },
                "motto": "ex:motto",
                "height": "ex:height",
                "extra": { "@id": "ex:extra", "@type": "@json" },
                "steps": { "@id": "ex:steps", "@container": "@list" },
                "evidence": { "@id": "ex:evidence", "@container": "@graph" }
            } }),
        ),
    ])
}

/// The insurance credential a MOSIP issuer signed, without its proof.
fn insurance_credential() -> Value {
    let mut credential = fixture("vc-verifier/Ed25519Signature2020SignedSunbirdVC.json");
    credential
        .as_object_mut()
        .expect("an object")
        .remove("proof");
    credential
}

/// A credential under the test context, its subject given by `subject`.
fn test_credential(subject: Value) -> Value {
    json!({
        "@context": [CREDENTIALS_V1, TEST_CONTEXT],
        "id": "urn:uuid:5f3c6a8e-0d6b-4c1e-9a55-3f1f4b0b6e2a",
        "type": ["VerifiableCredential", "TestCredential"],
        "issuer": "did:web:issuer.example",
        "issuanceDate": "2026-09-01T00:00:00Z",
        "credentialSubject": subject,
    })
}

fn path(members: &[&str]) -> Vec<String> {
    members.iter().map(|member| (*member).to_owned()).collect()
}

fn claim(credential: &Value, members: &[&str]) -> Result<(), Unclaimed> {
    let pinned = pinned();
    let contexts = HeldContexts::new(&pinned);
    read_credential(credential, &contexts)
        .expect("a readable credential")
        .check_claim(&path(members))
}

#[test]
fn a_credential_s_types_are_read_expanded() {
    let pinned = pinned();
    let contexts = HeldContexts::new(&pinned);
    let insurance = insurance_credential();
    assert_eq!(
        read_credential(&insurance, &contexts)
            .expect("a readable credential")
            .types(),
        [
            "https://www.w3.org/2018/credentials#VerifiableCredential",
            "https://holashchand.github.io/test_project/insurance-context.json#InsuranceCredential",
        ]
    );
    let test = test_credential(json!({ "id": "did:example:holder", "name": "Ama" }));
    assert_eq!(
        read_credential(&test, &contexts)
            .expect("a readable credential")
            .types(),
        [
            "https://www.w3.org/2018/credentials#VerifiableCredential",
            "https://issuer.example/vocab#TestCredential",
        ]
    );
    assert_eq!(
        read_credential(&json!([test]), &contexts).err(),
        Some(Unreadable::Unsupported(
            "a credential that is not one node object"
        ))
    );
}

/// The insurance context maps `policyName` and `policyNumber` to one IRI: the
/// proof would not see them trade values, so neither is a claim.
#[test]
fn a_claim_two_members_name_is_refused() {
    let insurance = insurance_credential();
    for members in [
        &["credentialSubject", "fullName"][..],
        &["credentialSubject", "benefits"],
        &["credentialSubject", "id"],
        &["type"],
        &["issuer"],
        &["issuanceDate"],
    ] {
        assert_eq!(claim(&insurance, members), Ok(()), "{members:?}");
    }
    for members in [
        &["credentialSubject", "policyName"][..],
        &["credentialSubject", "policyNumber"],
    ] {
        assert_eq!(
            claim(&insurance, members),
            Err(Unclaimed::Shared),
            "{members:?}"
        );
    }
}

#[test]
fn a_claim_the_credential_does_not_hold_is_absent() {
    let insurance = insurance_credential();
    for members in [&["credentialSubject", "policyHolder"][..], &["holder"], &[]] {
        assert_eq!(
            claim(&insurance, members),
            Err(Unclaimed::Absent),
            "{members:?}"
        );
    }
    // A member whose value reads as nothing adds nothing the proof signs, and
    // could be added to a signed credential unseen.
    let empty = test_credential(json!({
        "id": "did:example:holder",
        "type": [],
        "hobbies": [],
        "motto": null,
        "label": {},
    }));
    for member in ["type", "hobbies", "motto", "label"] {
        assert_eq!(
            claim(&empty, &["credentialSubject", member]),
            Err(Unclaimed::Absent),
            "{member}"
        );
    }
    // An empty list is signed: it is the list's end.
    let steps = test_credential(json!({ "id": "did:example:holder", "steps": [] }));
    assert_eq!(claim(&steps, &["credentialSubject", "steps"]), Ok(()));
}

#[test]
fn a_claim_is_reached_through_node_objects_alone() {
    let insurance = insurance_credential();
    for members in [
        &["credentialSubject", "fullName", "first"][..],
        &["credentialSubject", "benefits", "first"],
        &["credentialSubject", "id", "first"],
        &["@context"],
        &["type", "first"],
    ] {
        assert_eq!(
            claim(&insurance, members),
            Err(Unclaimed::NotAProperty),
            "{members:?}"
        );
    }
    let subject = test_credential(json!({
        "id": "did:example:holder",
        "label": { "en": "Driver" },
        "height": { "@value": "1.8" },
        "extra": { "unit": "m" },
        "steps": { "name": "first" },
        "evidence": { "name": "Ama" },
        "address": { "locality": "Lomé" },
    }));
    for member in ["label", "height", "extra", "steps", "evidence", "address"] {
        assert_eq!(
            claim(&subject, &["credentialSubject", member]),
            Ok(()),
            "{member}"
        );
    }
    for members in [
        &["credentialSubject", "label", "en"][..],
        &["credentialSubject", "height", "unit"],
        &["credentialSubject", "extra", "unit"],
        &["credentialSubject", "steps", "name"],
        &["credentialSubject", "evidence", "name"],
    ] {
        assert_eq!(
            claim(&subject, members),
            Err(Unclaimed::NotAProperty),
            "{members:?}"
        );
    }
    assert_eq!(
        claim(&subject, &["credentialSubject", "address", "locality"]),
        Ok(())
    );
}

/// An index map's keys are in no dataset: whatever stands under them may be
/// renamed under the same proof.
#[test]
fn a_claim_under_an_index_map_is_refused() {
    let indexed = test_credential(json!({
        "id": "did:example:holder",
        "claims169": { "1": "Ama", "2": "Mensah" },
    }));
    assert_eq!(
        claim(&indexed, &["credentialSubject", "claims169"]),
        Err(Unclaimed::Indexed)
    );
    assert_eq!(
        claim(&indexed, &["credentialSubject", "claims169", "1"]),
        Err(Unclaimed::Indexed)
    );
}

/// Each member is read under the context of the node that holds it: a
/// property's own context reaches into its node, and a type's does not reach
/// past the node that names the type.
#[test]
fn a_member_is_read_under_its_own_node_s_context() {
    let scoped = test_credential(json!({
        "id": "did:example:holder",
        "locality": "Golfe",
        "town": "Lomé",
        "address": { "locality": "Lomé", "town": "Lomé-Sud" },
    }));
    assert_eq!(claim(&scoped, &["credentialSubject", "locality"]), Ok(()));
    assert_eq!(claim(&scoped, &["credentialSubject", "town"]), Ok(()));
    assert_eq!(
        claim(&scoped, &["credentialSubject", "address", "locality"]),
        Err(Unclaimed::Shared)
    );

    let typed = test_credential(json!({
        "id": "did:example:holder",
        "type": "Person",
        "nick": "Ama",
        "name": "Ama Mensah",
        "friend": { "nick": "Kofi", "name": "Kofi Owusu" },
    }));
    assert_eq!(
        claim(&typed, &["credentialSubject", "nick"]),
        Err(Unclaimed::Shared)
    );
    assert_eq!(
        claim(&typed, &["credentialSubject", "friend", "nick"]),
        Ok(())
    );
    assert_eq!(
        claim(&typed, &["credentialSubject", "friend", "name"]),
        Ok(())
    );
}

/// Two node objects naming one node give it one set of properties: a value
/// may move from one to the other under the same proof.
#[test]
fn a_property_two_node_objects_give_one_node_is_refused() {
    let mut twice = test_credential(json!({ "id": "did:example:holder", "name": "Ama" }));
    twice["witness"] = json!({ "id": "did:example:holder", "name": "Kofi" });
    assert_eq!(
        claim(&twice, &["credentialSubject", "name"]),
        Err(Unclaimed::Shared)
    );
    assert_eq!(claim(&twice, &["witness", "name"]), Err(Unclaimed::Shared));
    assert_eq!(claim(&twice, &["credentialSubject", "id"]), Ok(()));

    let apart = {
        let mut apart = twice.clone();
        apart["witness"]["id"] = json!("did:example:witness");
        apart
    };
    assert_eq!(claim(&apart, &["credentialSubject", "name"]), Ok(()));
    assert_eq!(claim(&apart, &["witness", "name"]), Ok(()));

    // The same node, named again without the property, lends it no value; a
    // JSON literal names no node at all.
    let mut named_again = twice.clone();
    named_again["witness"] = json!({ "id": "did:example:holder", "nick": "Kofi" });
    named_again["credentialSubject"]["extra"] =
        json!({ "@id": "did:example:holder", "https://issuer.example/vocab#name": "Kofi" });
    assert_eq!(claim(&named_again, &["credentialSubject", "name"]), Ok(()));
}
