//! A W3C credential in JSON-LD, presented the way Inji's wallets present one:
//! a presentation its holder signs with the `did:jwk` key the credential binds,
//! carrying one credential its issuer signed under a key the realm read from
//! that issuer. Both proofs are Data Integrity proofs over the canonical form
//! of what they sign, read under the contexts built in and those the realm
//! pins, never fetched while a person presents.

use chrono::{DateTime, Duration, Utc};
use crypto::provider::{CryptoProvider, PublicKey};
use crypto::public_jwk::public_key_from_jwk;
use data_encoding::BASE64URL_NOPAD;
use jsonld::built_in::CREDENTIALS_V2;
use jsonld::claims::{ReadCredential, Unclaimed, read_credential};
use jsonld::json::parse_strict;
use jsonld::proof::{Bounds, Unproven, read_proof, verify_proof};
use jsonld::{Contexts, Unreadable, to_rdf};
use models::entities::credential_issuers::CredentialIssuer;
use serde_json::{Map, Value};
use store::providers::realms::credential_issuers;
use store::tenancy::UnitOfWork;

use super::presentation::{LEEWAY_SECONDS, Unanswerable, claim_path, read_text_claim};
use super::status::{Citation, read_bitstring_citations};

/// What reading one proof may cost: a credential and the presentation holding
/// it run to a few dozen statements.
pub(super) const BOUNDS: Bounds = Bounds {
    most_quads: 1_000,
    work: 500,
};

/// The longest `did:jwk` read: the JWK of a P-256 key runs to a few hundred
/// characters once encoded.
const MOST_DID_JWK_CHARS: usize = 1_024;

/// The members only a private key has.
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];

/// The members of a credential that say when it holds.
const VALIDITY_MEMBERS: [&str; 4] = ["issuanceDate", "validFrom", "expirationDate", "validUntil"];

/// What a request holds a presentation to.
pub(super) struct Binding<'a> {
    pub client_id: &'a str,
    pub nonce: &'a str,
}

/// What a verified presentation says, without the value of any claim but the
/// identifier a login asked for.
pub(super) struct Verified {
    pub issuer_id: String,
    pub issuer: String,
    /// The credential's types, expanded.
    pub types: Vec<String>,
    /// The claims asked for, each a path joined with dots.
    pub claims: Vec<String>,
    /// The text at the path a login identifies by, when one asked.
    pub identifier: Option<String>,
    /// The statuses the credential cites.
    pub citations: Vec<Citation>,
}

/// One presentation, verified: the holder's proof over it, for this request;
/// the issuer's proof over the credential it carries, under a key of the issuer
/// the realm names; the credential bound to the holder's key, valid now, of a
/// type the query accepts, and holding each claim asked for in a member its
/// proof tells apart. The outer result is whether the store could be read; the
/// inner one is the verdict, in the realm's words.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one presentation"
)]
pub(super) async fn verify_ldp_presentation(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    contexts: &dyn Contexts,
    binding: &Binding<'_>,
    asked: &Value,
    presented: &Value,
    identifying: Option<&[String]>,
    now: DateTime<Utc>,
) -> Result<Result<Verified, &'static str>, Unanswerable> {
    let held = match verify_holder_proof(provider, contexts, binding, presented) {
        Ok(held) => held,
        Err(why) => return Ok(Err(why)),
    };
    let Some(named) = credential_issuers::by_issuer(transaction, &held.issuer)
        .await
        .map_err(|_| Unanswerable::Unwritable)?
    else {
        return Ok(Err("a credential's issuer is not one this realm names"));
    };
    Ok(verify_issued_credential(
        provider,
        contexts,
        asked,
        &held,
        &named,
        identifying,
        now,
    ))
}

/// A presentation whose holder's proof holds, and the credential it carries.
struct Presented<'p> {
    credential: &'p Value,
    issuer: String,
    holder: PublicKey,
}

/// The presentation's own proof: signed for this request by the `did:jwk` key
/// its method names, over a presentation of one credential.
fn verify_holder_proof<'p>(
    provider: &dyn CryptoProvider,
    contexts: &dyn Contexts,
    binding: &Binding<'_>,
    presented: &'p Value,
) -> Result<Presented<'p>, &'static str> {
    let Value::Object(presentation) = presented else {
        return Err("a credential is not presented in the form its format takes");
    };
    let proof =
        read_proof(presented).map_err(|_| "a presentation's proof is missing or malformed")?;
    if proof
        .proof_purpose
        .as_deref()
        .is_some_and(|purpose| purpose != "authentication")
    {
        return Err("a presentation's proof is not for authentication");
    }
    if proof.challenge.as_deref() != Some(binding.nonce)
        || proof.domain.as_deref() != Some(binding.client_id)
    {
        return Err("a presentation is not bound to this request");
    }
    // A `did:jwk` has one method, `#0`.
    let method = proof.verification_method.as_str();
    let holder = method
        .strip_suffix("#0")
        .and_then(read_did_jwk)
        .ok_or("a presentation is not signed by a did:jwk key")?;
    if presentation.get("holder").is_some_and(|named| {
        named.as_str() != Some(method) && named.as_str() != method.strip_suffix("#0")
    }) {
        return Err("a presentation names another holder than its signer");
    }
    verify_proof(
        provider,
        presented,
        contexts,
        std::slice::from_ref(&holder),
        BOUNDS,
    )
    .map_err(|why| refused_proof(&why, "a presentation's signature is not its holder's"))?;

    let credential = match presentation.get("verifiableCredential") {
        Some(Value::Array(listed)) => match listed.as_slice() {
            [credential @ Value::Object(_)] => credential,
            _ => return Err("a presentation carries one credential"),
        },
        Some(credential @ Value::Object(_)) => credential,
        _ => return Err("a presentation carries one credential"),
    };
    let issuer = match credential.get("issuer") {
        Some(Value::String(issuer)) => Some(issuer.as_str()),
        Some(Value::Object(issuer)) => issuer.get("id").and_then(Value::as_str),
        _ => None,
    }
    .ok_or("a credential names no issuer")?;
    Ok(Presented {
        credential,
        issuer: issuer.to_owned(),
        holder,
    })
}

/// The credential's own proof, by the issuer the realm names, what the query
/// asks of it, and the statuses it cites.
fn verify_issued_credential(
    provider: &dyn CryptoProvider,
    contexts: &dyn Contexts,
    asked: &Value,
    presented: &Presented<'_>,
    named: &CredentialIssuer,
    identifying: Option<&[String]>,
    now: DateTime<Utc>,
) -> Result<Verified, &'static str> {
    let proof = read_proof(presented.credential)
        .map_err(|_| "a credential's proof is missing or malformed")?;
    if proof.proof_purpose.as_deref() != Some("assertionMethod") {
        return Err("a credential's proof is not an assertion");
    }
    let keys = asserting_keys(&named.keys, &proof.verification_method);
    if keys.is_empty() {
        return Err("a credential is signed by a key this verifier does not read");
    }
    verify_proof(provider, presented.credential, contexts, &keys, BOUNDS)
        .map_err(|why| refused_proof(&why, "a credential's signature is not its issuer's"))?;

    let mut unsigned = presented.credential.clone();
    if let Some(members) = unsigned.as_object_mut() {
        members.remove("proof");
    }
    let read = read_credential(&unsigned, contexts)
        .map_err(|_| "a presentation holds what its proofs would not sign")?;
    // Read off the dataset the proof signs, where no member can name a status
    // apart from what was signed.
    let quads = to_rdf(&unsigned, contexts, BOUNDS.most_quads)
        .map_err(|_| "a presentation holds what its proofs would not sign")?;
    check_holder_binding(&read, presented)?;
    check_validity(&read, presented.credential, now)?;

    let types = read.types();
    let accepted = asked
        .pointer("/meta/type_values")
        .and_then(Value::as_array)
        .is_some_and(|alternatives| {
            alternatives
                .iter()
                .filter_map(Value::as_array)
                .any(|alternative| {
                    alternative.iter().all(|wanted| {
                        wanted
                            .as_str()
                            .is_some_and(|wanted| types.contains(&wanted))
                    })
                })
        });
    if !accepted {
        return Err("a credential is of a type the query did not accept");
    }
    let paths: Vec<Vec<String>> = asked
        .get("claims")
        .and_then(Value::as_array)
        .map(|claims| claims.iter().filter_map(claim_path).collect())
        .unwrap_or_default();
    for path in &paths {
        read.check_claim(path).map_err(refused_claim)?;
    }
    // Read off the document only once its proof tells the member apart, the
    // way the holder's key is.
    let identifier = match identifying {
        Some(path) => {
            read.check_claim(path).map_err(refused_claim)?;
            read_text_claim(presented.credential, path)
        }
        None => None,
    };
    Ok(Verified {
        issuer_id: named.issuer_id.clone(),
        issuer: named.issuer.clone(),
        types: types.into_iter().map(str::to_owned).collect(),
        claims: paths.iter().map(|path| path.join(".")).collect(),
        identifier,
        citations: read_bitstring_citations(&quads)?,
    })
}

/// The keys of an issuer a proof's method may name: only a key the issuer
/// asserts with, as the realm read it from that issuer, makes a proof the
/// issuer's. The one the method names when the issuer holds it under that very
/// identifier; otherwise each of them, the identifier being only a hint:
/// MOSIP's issuers name their key under another DID that publishes it too.
pub(super) fn asserting_keys(keys: &[Value], verification_method: &str) -> Vec<PublicKey> {
    let asserted: Vec<&Map<String, Value>> = keys.iter().filter_map(Value::as_object).collect();
    let named_key = asserted
        .iter()
        .find(|jwk| jwk.get("kid").and_then(Value::as_str) == Some(verification_method));
    match named_key {
        Some(jwk) => public_key_from_jwk(jwk).into_iter().collect(),
        None => asserted
            .iter()
            .filter_map(|jwk| public_key_from_jwk(jwk))
            .collect(),
    }
}

/// The credential names the key that signed the presentation as its subject's,
/// and names its issuer and its subject in members its proof tells apart.
fn check_holder_binding(
    read: &ReadCredential<'_>,
    presented: &Presented<'_>,
) -> Result<(), &'static str> {
    for path in [&["issuer"][..], &["credentialSubject", "id"]] {
        read.check_claim(&owned_path(path)).map_err(
            |_| "a credential's issuer or holder rests on a member its proof does not tell apart",
        )?;
    }
    let bound = presented
        .credential
        .pointer("/credentialSubject/id")
        .and_then(Value::as_str)
        .and_then(read_did_jwk)
        .ok_or("a credential binds no did:jwk key")?;
    if bound.der() != presented.holder.der() {
        return Err("a credential is not bound to the key that presents it");
    }
    Ok(())
}

/// Whether the credential holds now, by the dates VCDM 1.1 and 2.0 write:
/// issued and valid from no later than now, expiring and valid until no
/// sooner. Each an RFC 3339 date-time, in a member its proof tells apart. VCDM
/// 1.1 requires the date of issue; 2.0, whose context names the credential
/// first, has none and requires no date.
fn check_validity(
    read: &ReadCredential<'_>,
    credential: &Value,
    now: DateTime<Utc>,
) -> Result<(), &'static str> {
    let leeway = Duration::seconds(LEEWAY_SECONDS);
    let unreadable = "a credential's dates are not RFC 3339 date-times its proof tells apart";
    let mut dates = [None; 4];
    for (member, date) in VALIDITY_MEMBERS.iter().zip(dates.iter_mut()) {
        let Some(written) = credential.get(*member) else {
            continue;
        };
        read.check_claim(&owned_path(&[member]))
            .map_err(|_| unreadable)?;
        let at = written
            .as_str()
            .and_then(|written| DateTime::parse_from_rfc3339(written).ok())
            .ok_or(unreadable)?;
        *date = Some(at.with_timezone(&Utc));
    }
    let [issued, from, expires, until] = dates;
    let version_two = match credential.get("@context") {
        Some(Value::Array(contexts)) => contexts.first(),
        named => named,
    }
    .and_then(Value::as_str)
        == Some(CREDENTIALS_V2);
    if issued.is_none() && !version_two {
        return Err("a credential does not say when it was issued");
    }
    if issued.into_iter().chain(from).any(|at| at > now + leeway) {
        return Err("a credential is not yet valid");
    }
    if expires
        .into_iter()
        .chain(until)
        .any(|at| at <= now - leeway)
    {
        return Err("a credential has expired");
    }
    Ok(())
}

fn owned_path(members: &[&str]) -> Vec<String> {
    members.iter().map(|member| (*member).to_owned()).collect()
}

/// The key a `did:jwk` names: a JWK written in base64url, which MOSIP's
/// issuers pad and Inji's wallets do not. Nothing for a DID of another method,
/// for a private key, or for a kind of key a presentation is not signed with.
fn read_did_jwk(did: &str) -> Option<PublicKey> {
    let encoded = did
        .strip_prefix("did:jwk:")
        .filter(|encoded| encoded.len() <= MOST_DID_JWK_CHARS)?;
    let decoded = BASE64URL_NOPAD
        .decode(encoded.trim_end_matches('=').as_bytes())
        .ok()?;
    let Ok(Value::Object(jwk)) = parse_strict(&decoded) else {
        return None;
    };
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| jwk.contains_key(*member))
    {
        return None;
    }
    public_key_from_jwk(&jwk)
}

/// A proof that does not hold, in the realm's words: `signature` when the
/// signature is the one thing wrong.
fn refused_proof(why: &Unproven, signature: &'static str) -> &'static str {
    match why {
        Unproven::Signature => signature,
        Unproven::Unreadable(Unreadable::UnknownContext(_)) => {
            "a presentation names a JSON-LD context this realm does not pin"
        }
        Unproven::Unreadable(Unreadable::TooLarge) | Unproven::TooComplex => {
            "a presentation is too large or too complex to verify"
        }
        Unproven::Unreadable(_) => "a presentation holds what its proofs would not sign",
        _ => "a presentation's proofs are malformed",
    }
}

/// A claim the query asked for that the credential does not hold as asked.
fn refused_claim(why: Unclaimed) -> &'static str {
    match why {
        Unclaimed::Absent => "a credential lacks a claim the query asked for",
        Unclaimed::Shared => {
            "a claim the query asked for shares its property with another member, so the proof does not tell them apart"
        }
        Unclaimed::Indexed => {
            "a claim the query asked for stands under an index map, whose keys the proof does not sign"
        }
        Unclaimed::NotAProperty => "a claim the query asked for is not a property of a node",
        Unclaimed::Unreadable(_) => "a presentation holds what its proofs would not sign",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use chrono::SecondsFormat;
    use crypto::jose::jwk::{Ed25519, KeyPair};
    use crypto::jose::jws::{ES256, EdDSA};
    use jsonld::built_in::{CREDENTIALS_V1, HeldContexts};
    use serde_json::json;

    use super::*;

    const UNREADABLE_DATES: &str =
        "a credential's dates are not RFC 3339 date-times its proof tells apart";

    /// Whether a credential written with `dates` holds at `now`.
    fn check_dates(dates: Value, now: DateTime<Utc>) -> Result<(), &'static str> {
        check_dates_under(CREDENTIALS_V1, dates, now)
    }

    /// The same, for a credential naming `context` first.
    fn check_dates_under(
        context: &str,
        dates: Value,
        now: DateTime<Utc>,
    ) -> Result<(), &'static str> {
        let mut credential = json!({
            "@context": [context],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "credentialSubject": { "id": "did:example:holder" },
        });
        for (member, date) in dates.as_object().expect("dates") {
            credential[member] = date.clone();
        }
        let pinned = HashMap::new();
        let contexts = HeldContexts::new(&pinned);
        let read = read_credential(&credential, &contexts).expect("a readable credential");
        check_validity(&read, &credential, now)
    }

    /// A credential holds from when it was issued, and from when it is valid,
    /// until it expires, and until it is valid, each within the leeway two
    /// clocks may disagree by.
    #[test]
    fn a_credential_holds_between_its_dates_within_the_leeway() {
        let now = DateTime::from_timestamp(1_790_000_000, 0).expect("a time");
        let at = |seconds: i64| {
            json!((now + Duration::seconds(seconds)).to_rfc3339_opts(SecondsFormat::Secs, true))
        };
        let issued = at(-3_600);
        for dates in [
            json!({ "issuanceDate": at(LEEWAY_SECONDS) }),
            json!({ "issuanceDate": issued, "validFrom": at(LEEWAY_SECONDS) }),
            json!({ "issuanceDate": issued, "expirationDate": at(1 - LEEWAY_SECONDS) }),
            json!({ "issuanceDate": issued, "validUntil": at(1 - LEEWAY_SECONDS) }),
        ] {
            assert_eq!(check_dates(dates.clone(), now), Ok(()), "{dates}");
        }
        for (dates, refused) in [
            (
                json!({ "issuanceDate": at(LEEWAY_SECONDS + 1) }),
                "a credential is not yet valid",
            ),
            (
                json!({ "issuanceDate": issued, "validFrom": at(LEEWAY_SECONDS + 1) }),
                "a credential is not yet valid",
            ),
            (
                json!({ "issuanceDate": issued, "expirationDate": at(-LEEWAY_SECONDS) }),
                "a credential has expired",
            ),
            (
                json!({ "issuanceDate": issued, "validUntil": at(-LEEWAY_SECONDS) }),
                "a credential has expired",
            ),
            (
                json!({ "expirationDate": at(3_600) }),
                "a credential does not say when it was issued",
            ),
            (json!({ "issuanceDate": "2026-09-29" }), UNREADABLE_DATES),
            (
                json!({ "issuanceDate": issued, "validUntil": "2026-09-29T12:00:00" }),
                UNREADABLE_DATES,
            ),
        ] {
            assert_eq!(check_dates(dates.clone(), now), Err(refused), "{dates}");
        }
    }

    /// VCDM 2.0 writes no date of issue and requires no date at all; the
    /// dates it writes hold as 1.1's do.
    #[test]
    fn a_vcdm_two_credential_needs_no_date_of_issue() {
        let now = DateTime::from_timestamp(1_790_000_000, 0).expect("a time");
        let at = |seconds: i64| {
            json!((now + Duration::seconds(seconds)).to_rfc3339_opts(SecondsFormat::Secs, true))
        };
        assert_eq!(check_dates_under(CREDENTIALS_V2, json!({}), now), Ok(()));
        assert_eq!(
            check_dates_under(
                CREDENTIALS_V2,
                json!({ "validFrom": at(-3_600), "validUntil": at(3_600) }),
                now
            ),
            Ok(())
        );
        assert_eq!(
            check_dates_under(
                CREDENTIALS_V2,
                json!({ "validUntil": at(-LEEWAY_SECONDS) }),
                now
            ),
            Err("a credential has expired")
        );
        assert_eq!(
            check_dates_under(
                CREDENTIALS_V2,
                json!({ "validFrom": at(LEEWAY_SECONDS + 1) }),
                now
            ),
            Err("a credential is not yet valid")
        );
        assert_eq!(
            check_dates(json!({ "validFrom": at(-3_600) }), now),
            Err("a credential does not say when it was issued")
        );
    }

    fn did_jwk(jwk: &Value) -> String {
        format!(
            "did:jwk:{}",
            BASE64URL_NOPAD.encode(jwk.to_string().as_bytes())
        )
    }

    #[test]
    fn a_did_jwk_names_its_key_padded_or_not() {
        for pair in [
            Box::new(EdDSA.generate_key_pair(Ed25519).expect("a key pair")) as Box<dyn KeyPair>,
            Box::new(ES256.generate_key_pair().expect("a key pair")),
        ] {
            let jwk = Value::Object(pair.to_jwk_public_key().as_ref().clone());
            let did = did_jwk(&jwk);
            let expected = Some(pair.to_der_public_key());
            assert_eq!(read_did_jwk(&did).map(|key| key.der().to_vec()), expected);
            let padding = "=".repeat((4 - (did.len() - "did:jwk:".len()) % 4) % 4);
            assert_eq!(
                read_did_jwk(&format!("{did}{padding}")).map(|key| key.der().to_vec()),
                expected
            );
        }
    }

    #[test]
    fn a_did_jwk_of_a_private_key_or_another_method_names_no_key() {
        let pair = EdDSA.generate_key_pair(Ed25519).expect("a key pair");
        let public = Value::Object(pair.to_jwk_public_key().as_ref().clone());
        // The whole pair: its public half would read, were the private one
        // not beside it.
        let pair_written = Value::Object(pair.to_jwk_key_pair().as_ref().clone());
        assert!(pair_written.get("x").is_some() && pair_written.get("d").is_some());
        assert!(read_did_jwk(&did_jwk(&public)).is_some());
        assert!(read_did_jwk(&did_jwk(&pair_written)).is_none());
        let encoded = &did_jwk(&public)["did:jwk:".len()..];
        assert!(read_did_jwk(&format!("did:key:{encoded}")).is_none());
        assert!(read_did_jwk(&format!("did:jwk:{encoded}#0")).is_none());
        assert!(read_did_jwk("did:jwk:eyJrdHkiOiJPS1AifQ").is_none());
        let long =
            json!({ "kty": "OKP", "crv": "Ed25519", "x": public["x"], "pad": "a".repeat(800) });
        assert!(read_did_jwk(&did_jwk(&long)).is_none());
    }
}
