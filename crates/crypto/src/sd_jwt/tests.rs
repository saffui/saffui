use data_encoding::BASE64URL_NOPAD;
use serde_json::json;

use super::*;
use crate::jose::jwk::{Jwk, KeyPair};
use crate::jose::jws::alg::ecdsa::{EcdsaJwsSigner, EcdsaJwsVerifier};
use crate::jose::jws::{self, ES256, JwsHeader};
use crate::jose::{Map, Value};
use crate::provider::CryptoConfig;
use crate::provider::openssl::OpenSslProvider;

// The RFC's own examples, extracted from its text (Section 5, Appendix A),
// with the issuer key of Appendix A.5 that signed them.
const SECTION_5_1_ISSUED: &str = include_str!("../../data/rfc9901/section-5-1-issued.txt");
const SECTION_5_2_PRESENTED: &str = include_str!("../../data/rfc9901/section-5-2-presented.txt");
const SECTION_5_2_PROCESSED: &str = include_str!("../../data/rfc9901/section-5-2-processed.json");
const A_1_PRESENTED: &str = include_str!("../../data/rfc9901/appendix-a-1-presented.txt");
const A_1_PROCESSED: &str = include_str!("../../data/rfc9901/appendix-a-1-processed.json");
const A_2_PRESENTED: &str = include_str!("../../data/rfc9901/appendix-a-2-presented.txt");
const A_2_PROCESSED: &str = include_str!("../../data/rfc9901/appendix-a-2-processed.json");
const A_3_ISSUED: &str = include_str!("../../data/rfc9901/appendix-a-3-issued.txt");
const A_3_PRESENTED: &str = include_str!("../../data/rfc9901/appendix-a-3-presented.txt");
const A_3_PROCESSED: &str = include_str!("../../data/rfc9901/appendix-a-3-processed.json");
const A_4_PRESENTED: &str = include_str!("../../data/rfc9901/appendix-a-4-presented.txt");
const A_4_PROCESSED: &str = include_str!("../../data/rfc9901/appendix-a-4-processed.json");
const A_5_ISSUER_KEY: &str = include_str!("../../data/rfc9901/appendix-a-5-issuer-key.json");

/// When the RFC's holder signed its key binding tokens, and what for.
const RFC_BOUND_AT: i64 = 1_748_537_244;
const RFC_AUDIENCE: &str = "https://verifier.example.org";
const RFC_NONCE: &str = "1234567890";

fn provider() -> OpenSslProvider {
    OpenSslProvider::new(&CryptoConfig::default()).expect("a provider")
}

fn rfc_issuer() -> EcdsaJwsVerifier {
    let key = Jwk::from_bytes(A_5_ISSUER_KEY.as_bytes()).expect("the RFC's issuer key");
    ES256.verifier_from_jwk(&key).expect("an ES256 verifier")
}

fn processed(expected: &str) -> Map<String, Value> {
    serde_json::from_str(expected).expect("the RFC's processed payload")
}

fn bound_policy<'a>(token_type: &'a str) -> VerifyingPolicy<'a> {
    VerifyingPolicy {
        token_type,
        required_claims: &[],
        key_binding: Some(KeyBinding {
            audience: RFC_AUDIENCE,
            nonce: RFC_NONCE,
            max_age: 300,
        }),
        now: RFC_BOUND_AT,
        leeway: 60,
    }
}

fn unbound_policy<'a>(token_type: &'a str) -> VerifyingPolicy<'a> {
    VerifyingPolicy {
        key_binding: None,
        ..bound_policy(token_type)
    }
}

fn verify_rfc(presented: &str, policy: &VerifyingPolicy<'_>) -> Result<Verified, Refused> {
    verify_presentation(&provider(), presented.trim(), &rfc_issuer(), policy)
}

/// An issuer of this test's own: a fresh P-256 key, its signer and verifier.
struct Issuer {
    signer: EcdsaJwsSigner,
    verifier: EcdsaJwsVerifier,
}

impl Issuer {
    fn drawn() -> Self {
        let pair = ES256.generate_key_pair().expect("a key pair");
        Self {
            signer: ES256
                .signer_from_jwk(&pair.to_jwk_key_pair())
                .expect("a signer"),
            verifier: ES256
                .verifier_from_jwk(&pair.to_jwk_public_key())
                .expect("a verifier"),
        }
    }

    fn sign(&self, token_type: &str, payload: &Value) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type(token_type);
        jws::serialize_compact(payload.to_string().as_bytes(), &header, &self.signer)
            .expect("a signed payload")
    }
}

/// A holder key pair, and the `cnf` claim that names its public half.
struct Holder {
    signer: EcdsaJwsSigner,
    confirmation: Value,
}

impl Holder {
    fn drawn() -> Self {
        let pair = ES256.generate_key_pair().expect("a key pair");
        let public = serde_json::to_value(pair.to_jwk_public_key().as_ref()).expect("a jwk");
        Self {
            signer: ES256
                .signer_from_jwk(&pair.to_jwk_key_pair())
                .expect("a signer"),
            confirmation: json!({ "jwk": public }),
        }
    }
}

/// A disclosure and its SHA-256 digest, built by hand so that shapes the
/// issuer side refuses to make can still be presented.
fn hand_disclosure(members: Value) -> (String, String) {
    let encoded = BASE64URL_NOPAD.encode(members.to_string().as_bytes());
    let digest =
        digest_of(&provider(), crate::provider::HashAlg::Sha256, &encoded).expect("a digest");
    (encoded, digest)
}

fn own_policy<'a>() -> VerifyingPolicy<'a> {
    VerifyingPolicy {
        token_type: "dc+sd-jwt",
        required_claims: &[],
        key_binding: None,
        now: 1_800_000_000,
        leeway: 60,
    }
}

/// A presentation of `payload` signed by `issuer`, carrying `disclosures`.
fn presented(issuer: &Issuer, payload: Value, disclosures: &[&str]) -> String {
    let mut presentation = format!("{}~", issuer.sign("dc+sd-jwt", &payload));
    for disclosure in disclosures {
        presentation.push_str(disclosure);
        presentation.push('~');
    }
    presentation
}

/// The digest RFC 9901 §4.2.3 works out by hand is the one computed here.
#[test]
fn the_rfc_digest_is_reproduced() {
    let digest = digest_of(
        &provider(),
        crate::provider::HashAlg::Sha256,
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
    )
    .expect("a digest");
    assert_eq!(digest, "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0");
}

/// Every presentation the RFC shows verifies under its issuer key and yields
/// the processed payload the RFC prints, key binding checked where it is sent.
#[test]
fn each_rfc_presentation_verifies_to_its_processed_payload() {
    for (name, presented, typ, bound, expected) in [
        (
            "5.2",
            SECTION_5_2_PRESENTED,
            "example+sd-jwt",
            true,
            SECTION_5_2_PROCESSED,
        ),
        ("A.1", A_1_PRESENTED, "example+sd-jwt", false, A_1_PROCESSED),
        ("A.2", A_2_PRESENTED, "example+sd-jwt", false, A_2_PROCESSED),
        ("A.3", A_3_PRESENTED, "dc+sd-jwt", true, A_3_PROCESSED),
        ("A.4", A_4_PRESENTED, "example+sd-jwt", true, A_4_PROCESSED),
    ] {
        let policy = if bound {
            bound_policy(typ)
        } else {
            unbound_policy(typ)
        };
        let verified = verify_rfc(presented, &policy).unwrap_or_else(|why| panic!("{name}: {why}"));
        assert_eq!(verified.claims, processed(expected), "{name}");
        assert_eq!(verified.holder_key.is_some(), bound, "{name}");
    }
}

/// An issued SD-JWT carries every disclosure, and every one of them lands.
#[test]
fn an_issued_sd_jwt_opens_every_claim() {
    let verified =
        verify_rfc(SECTION_5_1_ISSUED, &unbound_policy("example+sd-jwt")).expect("verified");
    for name in [
        "given_name",
        "family_name",
        "email",
        "phone_number",
        "phone_number_verified",
        "address",
        "birthdate",
        "updated_at",
    ] {
        assert!(verified.claims.contains_key(name), "{name} did not land");
    }
    assert_eq!(verified.claims["nationalities"], json!(["US", "DE"]));
    assert!(!verified.claims.contains_key("_sd"));
    assert!(!verified.claims.contains_key("_sd_alg"));

    let verified = verify_rfc(A_3_ISSUED, &unbound_policy("dc+sd-jwt")).expect("verified");
    assert_eq!(verified.claims["age_equal_or_over"]["65"], json!(false));
    assert_eq!(
        verified.claims["place_of_birth"]["locality"],
        json!("Berlin")
    );
}

/// Whether key binding is required is the verifier's, never the presenter's:
/// a token stripped of it is refused, and one carrying it unasked is too.
#[test]
fn key_binding_is_decided_by_the_verifier() {
    assert_eq!(
        verify_rfc(SECTION_5_1_ISSUED, &bound_policy("example+sd-jwt")).unwrap_err(),
        Refused::KeyBindingMissing
    );
    assert_eq!(
        verify_rfc(SECTION_5_2_PRESENTED, &unbound_policy("example+sd-jwt")).unwrap_err(),
        Refused::KeyBindingUnexpected
    );
}

/// A key binding token answers one verifier, one request, one moment.
#[test]
fn a_key_binding_token_answers_one_request() {
    let mut policy = bound_policy("example+sd-jwt");
    policy.key_binding = Some(KeyBinding {
        audience: "https://another-verifier.example.org",
        nonce: RFC_NONCE,
        max_age: 300,
    });
    assert_eq!(
        verify_rfc(SECTION_5_2_PRESENTED, &policy).unwrap_err(),
        Refused::KeyBindingAudience
    );

    policy.key_binding = Some(KeyBinding {
        audience: RFC_AUDIENCE,
        nonce: "another request",
        max_age: 300,
    });
    assert_eq!(
        verify_rfc(SECTION_5_2_PRESENTED, &policy).unwrap_err(),
        Refused::KeyBindingNonce
    );

    let mut late = bound_policy("example+sd-jwt");
    late.now = RFC_BOUND_AT + 301;
    assert_eq!(
        verify_rfc(SECTION_5_2_PRESENTED, &late).unwrap_err(),
        Refused::KeyBindingStale
    );
    let mut early = bound_policy("example+sd-jwt");
    early.now = RFC_BOUND_AT - 61;
    assert_eq!(
        verify_rfc(SECTION_5_2_PRESENTED, &early).unwrap_err(),
        Refused::KeyBindingStale
    );
}

/// The key binding token covers the disclosures presented: dropping one,
/// adding one, or repeating one is caught.
#[test]
fn the_key_binding_token_covers_exactly_what_was_presented() {
    let presented = SECTION_5_2_PRESENTED.trim();
    let (head, token) = presented.rsplit_once('~').expect("a key binding token");
    let mut components: Vec<&str> = head.split('~').collect();

    let dropped = format!("{}~{}", components[..components.len() - 1].join("~"), token);
    assert_eq!(
        verify_rfc(&dropped, &bound_policy("example+sd-jwt")).unwrap_err(),
        Refused::KeyBindingHash
    );

    let issued_extra = SECTION_5_1_ISSUED
        .trim()
        .split('~')
        .nth(3)
        .expect("an email disclosure");
    components.push(issued_extra);
    let added = format!("{}~{}", components.join("~"), token);
    assert_eq!(
        verify_rfc(&added, &bound_policy("example+sd-jwt")).unwrap_err(),
        Refused::KeyBindingHash
    );

    let first = head.split('~').nth(1).expect("a disclosure");
    let repeated = format!("{head}~{first}~{token}");
    assert_eq!(
        verify_rfc(&repeated, &bound_policy("example+sd-jwt")).unwrap_err(),
        Refused::RepeatedDisclosure
    );
}

/// A disclosure whose value was changed answers no digest the issuer signed.
#[test]
fn an_altered_disclosure_answers_nothing() {
    let (altered, _) = hand_disclosure(json!(["eluV5Og3gSNII8EYnsxA_A", "family_name", "Roe"]));
    let presented = SECTION_5_1_ISSUED.trim().replacen(
        "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
        &altered,
        1,
    );
    assert_ne!(presented, SECTION_5_1_ISSUED.trim());
    assert_eq!(
        verify_rfc(&presented, &unbound_policy("example+sd-jwt")).unwrap_err(),
        Refused::UnreferencedDisclosure
    );
}

/// The type, the issuer key and the clock are all the verifier's to check.
#[test]
fn the_issuer_token_is_held_to_its_type_key_and_window() {
    assert_eq!(
        verify_rfc(A_1_PRESENTED, &unbound_policy("dc+sd-jwt")).unwrap_err(),
        Refused::WrongType
    );
    assert!(verify_rfc(A_1_PRESENTED, &unbound_policy("EXAMPLE+SD-JWT")).is_ok());

    let stranger = Issuer::drawn();
    assert_eq!(
        verify_presentation(
            &provider(),
            A_1_PRESENTED.trim(),
            &stranger.verifier,
            &unbound_policy("example+sd-jwt")
        )
        .unwrap_err(),
        Refused::IssuerSignature
    );

    let mut expired = unbound_policy("example+sd-jwt");
    expired.now = 1_883_000_000 + 60;
    assert_eq!(
        verify_rfc(A_1_PRESENTED, &expired).unwrap_err(),
        Refused::Expired
    );

    let mut required = unbound_policy("example+sd-jwt");
    required.required_claims = &["iss", "sub"];
    assert_eq!(
        verify_rfc(A_1_PRESENTED, &required).unwrap_err(),
        Refused::MissingClaim("sub".to_owned())
    );
}

/// What this build conceals, a holder presents in part and binds, and the
/// verifier opens exactly the part presented: flat, structured, recursive and
/// array-element disclosures, decoys among them.
#[test]
fn concealed_claims_open_exactly_as_presented() {
    let provider = provider();
    let issuer = Issuer::drawn();
    let holder = Holder::drawn();
    let claims = json!({
        "iss": "https://issuer.example",
        "vct": "urn:example:badge",
        "exp": 1_900_000_000,
        "cnf": holder.confirmation,
        "given_name": "Ama",
        "address": { "locality": "Lomé", "country": "TG" },
        "nationalities": ["TG", "GH"],
        "place_of_birth": { "locality": "Kpalimé", "country": "TG" },
    });
    let Value::Object(claims) = claims else {
        unreachable!()
    };
    let concealment = conceal_claims(
        &provider,
        claims,
        &[
            Concealed::Property(&["given_name"]),
            Concealed::Property(&["address", "locality"]),
            Concealed::Element(&["nationalities"], 1),
            Concealed::Property(&["place_of_birth", "locality"]),
            Concealed::Property(&["place_of_birth"]),
        ],
        2,
    )
    .expect("concealed");
    assert_eq!(concealment.disclosures.len(), 5);
    assert_eq!(concealment.payload["_sd_alg"], json!("sha-256"));
    let top = concealment.payload["_sd"].as_array().expect("top digests");
    assert_eq!(
        top.len(),
        2 + 2,
        "given_name, place_of_birth and two decoys"
    );
    assert!(
        top.windows(2)
            .all(|pair| pair[0].as_str() <= pair[1].as_str())
    );
    assert!(!concealment.payload.contains_key("given_name"));
    assert_eq!(concealment.payload["address"]["country"], json!("TG"));

    let issued =
        concealment.issued(&issuer.sign("dc+sd-jwt", &Value::Object(concealment.payload.clone())));
    let everything = verify_presentation(&provider, &issued, &issuer.verifier, &own_policy())
        .expect("the issued SD-JWT verifies");
    assert_eq!(everything.claims["given_name"], json!("Ama"));
    assert_eq!(everything.claims["address"]["locality"], json!("Lomé"));
    assert_eq!(everything.claims["nationalities"], json!(["TG", "GH"]));
    assert_eq!(
        everything.claims["place_of_birth"]["locality"],
        json!("Kpalimé")
    );

    let keep_address = select_disclosures(&issued, |disclosure| {
        disclosure.name.as_deref() == Some("locality") && disclosure.value == json!("Lomé")
    })
    .expect("a presentation");
    let bound = bind_presentation(
        &provider,
        &keep_address,
        &holder.signer,
        "https://verifier.example",
        "n-0S6",
        1_800_000_000,
    )
    .expect("bound");
    let mut policy = own_policy();
    policy.key_binding = Some(KeyBinding {
        audience: "https://verifier.example",
        nonce: "n-0S6",
        max_age: 300,
    });
    let opened =
        verify_presentation(&provider, &bound, &issuer.verifier, &policy).expect("verified");
    assert_eq!(
        opened.claims["address"],
        json!({ "country": "TG", "locality": "Lomé" })
    );
    assert_eq!(
        opened.claims["nationalities"],
        json!(["TG"]),
        "the withheld element left"
    );
    assert!(!opened.claims.contains_key("given_name"));
    assert!(!opened.claims.contains_key("place_of_birth"));

    let other = Holder::drawn();
    let impostor = bind_presentation(
        &provider,
        &keep_address,
        &other.signer,
        "https://verifier.example",
        "n-0S6",
        1_800_000_000,
    )
    .expect("bound by another key");
    assert_eq!(
        verify_presentation(&provider, &impostor, &issuer.verifier, &policy).unwrap_err(),
        Refused::KeyBindingSignature
    );
}

/// A key binding token must be typed, signed by a key the issuer named, and
/// carry every claim the RFC makes it carry.
#[test]
fn a_key_binding_token_is_held_to_its_shape() {
    let provider = provider();
    let issuer = Issuer::drawn();
    let holder = Holder::drawn();
    let mut policy = own_policy();
    policy.key_binding = Some(KeyBinding {
        audience: "https://verifier.example",
        nonce: "n",
        max_age: 300,
    });

    let unnamed = presented(&issuer, json!({ "iss": "https://issuer.example" }), &[]);
    let bound = bind_presentation(
        &provider,
        &unnamed,
        &holder.signer,
        "https://verifier.example",
        "n",
        1_800_000_000,
    )
    .expect("bound");
    assert_eq!(
        verify_presentation(&provider, &bound, &issuer.verifier, &policy).unwrap_err(),
        Refused::NoHolderKey
    );

    let named = presented(
        &issuer,
        json!({ "iss": "https://issuer.example", "cnf": holder.confirmation }),
        &[],
    );
    let sign_binding = |typ: &str, claims: Value| {
        let mut header = JwsHeader::new();
        header.set_token_type(typ);
        let token = jws::serialize_compact(claims.to_string().as_bytes(), &header, &holder.signer)
            .expect("signed");
        format!("{named}{token}")
    };
    let sd_hash = digest_of(&provider, crate::provider::HashAlg::Sha256, &named).expect("a digest");
    let whole = json!({ "iat": 1_800_000_000, "aud": "https://verifier.example", "nonce": "n", "sd_hash": sd_hash });
    assert!(
        verify_presentation(
            &provider,
            &sign_binding("kb+jwt", whole.clone()),
            &issuer.verifier,
            &policy
        )
        .is_ok()
    );
    assert_eq!(
        verify_presentation(
            &provider,
            &sign_binding("JWT", whole.clone()),
            &issuer.verifier,
            &policy
        )
        .unwrap_err(),
        Refused::KeyBindingType
    );
    for missing in ["iat", "aud", "nonce", "sd_hash"] {
        let mut partial = whole.clone();
        partial.as_object_mut().expect("an object").remove(missing);
        assert_eq!(
            verify_presentation(
                &provider,
                &sign_binding("kb+jwt", partial),
                &issuer.verifier,
                &policy
            )
            .unwrap_err(),
            Refused::KeyBindingUnreadable,
            "{missing}"
        );
    }
    let mut listed = whole.clone();
    listed["aud"] = json!(["https://verifier.example"]);
    assert_eq!(
        verify_presentation(
            &provider,
            &sign_binding("kb+jwt", listed),
            &issuer.verifier,
            &policy
        )
        .unwrap_err(),
        Refused::KeyBindingUnreadable,
        "an audience list is not the single string the RFC asks for"
    );
    let mut lapsed = whole.clone();
    lapsed["exp"] = json!(1_799_999_000);
    assert_eq!(
        verify_presentation(
            &provider,
            &sign_binding("kb+jwt", lapsed),
            &issuer.verifier,
            &policy
        )
        .unwrap_err(),
        Refused::KeyBindingStale
    );

    let mut contradicted = holder.confirmation.clone();
    contradicted["jwk"]["alg"] = json!("ES384");
    let misnamed = presented(
        &issuer,
        json!({ "iss": "https://issuer.example", "cnf": contradicted }),
        &[],
    );
    let bound = bind_presentation(
        &provider,
        &misnamed,
        &holder.signer,
        "https://verifier.example",
        "n",
        1_800_000_000,
    )
    .expect("bound");
    assert_eq!(
        verify_presentation(&provider, &bound, &issuer.verifier, &policy).unwrap_err(),
        Refused::NoHolderKey,
        "a key whose stated algorithm contradicts its curve names no algorithm"
    );
}

/// Every shape RFC 9901 §7.1 tells a verifier to reject is rejected.
#[test]
fn the_shapes_the_rfc_rejects_are_rejected() {
    let provider = provider();
    let issuer = Issuer::drawn();
    let refused = |payload: Value, disclosures: &[&str]| {
        verify_presentation(
            &provider,
            &presented(&issuer, payload, disclosures),
            &issuer.verifier,
            &own_policy(),
        )
        .unwrap_err()
    };

    let (named, named_digest) = hand_disclosure(json!(["salt-1", "given_name", "Ama"]));
    let (element, element_digest) = hand_disclosure(json!(["salt-2", "TG"]));

    assert_eq!(
        refused(json!({ "_sd": [named_digest, named_digest] }), &[&named]),
        Refused::RepeatedDigest
    );
    assert_eq!(
        refused(
            json!({ "_sd": [named_digest], "inner": { "_sd": [named_digest] } }),
            &[&named]
        ),
        Refused::RepeatedDigest
    );
    assert_eq!(
        refused(
            json!({ "given_name": "Kofi", "_sd": [named_digest] }),
            &[&named]
        ),
        Refused::ClaimCollision("given_name".to_owned())
    );
    assert_eq!(
        refused(json!({ "_sd": [element_digest] }), &[&element]),
        Refused::MalformedDisclosure
    );
    assert_eq!(
        refused(json!({ "list": [{ "...": named_digest }] }), &[&named]),
        Refused::MalformedDisclosure
    );
    for reserved in ["_sd", "...", "_sd_alg"] {
        let (disclosure, digest) = hand_disclosure(json!(["salt-3", reserved, 1]));
        assert_eq!(
            refused(json!({ "_sd": [digest] }), &[&disclosure]),
            Refused::ForbiddenClaimName(reserved.to_owned())
        );
    }
    assert_eq!(
        refused(json!({ "claim": { "...": element_digest } }), &[]),
        Refused::MalformedDigestCarrier
    );
    assert_eq!(
        refused(
            json!({ "list": [{ "...": element_digest, "more": 1 }] }),
            &[]
        ),
        Refused::MalformedDigestCarrier
    );
    assert_eq!(
        refused(json!({ "list": [{ "...": 7 }] }), &[]),
        Refused::MalformedDigestCarrier
    );
    assert_eq!(
        refused(json!({ "_sd": "a digest" }), &[]),
        Refused::MalformedDigestCarrier
    );
    assert_eq!(
        refused(json!({ "_sd": [7] }), &[]),
        Refused::MalformedDigestCarrier
    );
    assert_eq!(
        refused(json!({ "inner": { "_sd_alg": "sha-256" } }), &[]),
        Refused::MisplacedHashAlgorithm
    );
    assert_eq!(
        refused(json!({ "_sd_alg": "md5" }), &[]),
        Refused::UnknownHash("md5".to_owned())
    );
    assert_eq!(
        refused(json!({ "_sd": [] }), &[&named]),
        Refused::UnreferencedDisclosure
    );
    assert_eq!(
        refused(json!({ "nbf": 1_900_000_000 }), &[]),
        Refused::NotYetValid
    );
    assert_eq!(
        refused(json!({ "exp": "tomorrow" }), &[]),
        Refused::UnreadablePayload
    );
    assert_eq!(
        refused(json!(["not", "an", "object"]), &[]),
        Refused::UnreadablePayload
    );
    for broken in [
        "bm90IGpzb24",
        "WyJvbmx5LW9uZSJd",
        "WzEsICJuYW1lIiwgMl0",
        "WyJzYWx0IiwgMSwgMl0",
        "==",
    ] {
        assert_eq!(
            refused(json!({}), &[broken]),
            Refused::MalformedDisclosure,
            "{broken}"
        );
    }

    let issued = presented(&issuer, json!({}), &[]);
    for torn in [
        "",
        "~",
        "no-tilde-at-all",
        &format!("{issued}~"),
        &format!("~{issued}"),
    ] {
        assert_eq!(
            verify_presentation(&provider, torn, &issuer.verifier, &own_policy()).unwrap_err(),
            Refused::NotAnSdJwt,
            "{torn:?}"
        );
    }
}

/// Digests made with a stronger SHA-2 open like SHA-256 ones, and the
/// verifier reads the hash from `_sd_alg`, never assumes it.
#[test]
fn the_hash_is_read_from_the_payload() {
    let provider = provider();
    let issuer = Issuer::drawn();
    let encoded = BASE64URL_NOPAD.encode(
        json!(["salt-4", "given_name", "Ama"])
            .to_string()
            .as_bytes(),
    );
    let digest =
        digest_of(&provider, crate::provider::HashAlg::Sha512, &encoded).expect("a digest");
    let verified = verify_presentation(
        &provider,
        &presented(
            &issuer,
            json!({ "_sd_alg": "sha-512", "_sd": [digest] }),
            &[&encoded],
        ),
        &issuer.verifier,
        &own_policy(),
    )
    .expect("verified");
    assert_eq!(verified.claims["given_name"], json!("Ama"));

    assert_eq!(
        verify_presentation(
            &provider,
            &presented(&issuer, json!({ "_sd": [digest] }), &[&encoded]),
            &issuer.verifier,
            &own_policy(),
        )
        .unwrap_err(),
        Refused::UnreferencedDisclosure,
        "a SHA-512 digest read as SHA-256 opens nothing"
    );
}

/// The issuer side refuses what would make a token a verifier cannot trust.
#[test]
fn the_issuer_refuses_what_a_verifier_could_not_trust() {
    let provider = provider();
    let Value::Object(claims) = json!({
        "iss": "https://issuer.example",
        "exp": 1_900_000_000,
        "nationalities": ["TG"],
    }) else {
        unreachable!()
    };
    for validity in ["iss", "exp"] {
        assert_eq!(
            conceal_claims(
                &provider,
                claims.clone(),
                &[Concealed::Property(&[validity])],
                0
            )
            .unwrap_err(),
            Unconcealable::ValidityClaim(validity.to_owned())
        );
    }
    assert_eq!(
        conceal_claims(
            &provider,
            claims.clone(),
            &[Concealed::Property(&["absent"])],
            0
        )
        .unwrap_err(),
        Unconcealable::NotFound
    );
    assert_eq!(
        conceal_claims(
            &provider,
            claims.clone(),
            &[Concealed::Element(&["nationalities"], 3)],
            0
        )
        .unwrap_err(),
        Unconcealable::NotFound
    );
    assert_eq!(
        conceal_claims(
            &provider,
            claims.clone(),
            &[
                Concealed::Element(&["nationalities"], 0),
                Concealed::Element(&["nationalities"], 0)
            ],
            0
        )
        .unwrap_err(),
        Unconcealable::AlreadyConcealed
    );
    let Value::Object(planted) = json!({ "profile": { "_sd": ["a digest nobody made"] } }) else {
        unreachable!()
    };
    assert_eq!(
        conceal_claims(&provider, planted, &[], 0).unwrap_err(),
        Unconcealable::ReservedName("_sd".to_owned())
    );
}

/// The header is read before anything is verified, for the key to verify with.
#[test]
fn the_issuer_header_is_readable_before_verification() {
    let header = read_issuer_header(A_3_PRESENTED.trim()).expect("a header");
    assert_eq!(header["typ"], json!("dc+sd-jwt"));
    assert_eq!(header["alg"], json!("ES256"));
}
