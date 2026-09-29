//! A realm asking a wallet for a presentation, OpenID4VP 1.0, and what it
//! makes of the answer.
//!
//! The request is signed under the realm's `did:web` with its Ed25519 key and
//! fetched by the wallet at its `request_uri`. The answer comes back to one
//! address per realm, encrypted to a key drawn for that request alone; the
//! encrypted answer names that key, which is how it finds its request. A
//! request is answered once, and nothing a person disclosed is kept: the
//! outcome names issuers, types and claims, never their values.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use crypto::jose::jwe::{self, ECDH_ES};
use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crypto::jose::jwk::{Jwk, KeyPair};
use crypto::jose::jws::{
    ES256, ES384, ES512, EdDSA, JwsVerifier, PS256, PS384, PS512, RS256, RS384, RS512,
};
use crypto::provider::{CryptoProvider, SignAlg};
use crypto::sd_jwt::{self, KeyBinding, VerifyingPolicy};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use jsonld::built_in::HeldContexts;
use models::entities::credential_issuers::CredentialIssuer;
use models::entities::keys::KeyUse;
use serde_json::{Map, Value, json};
use store::keyring::Signing;
use store::providers::protocol::presentations::{self, Answering, KeptRequest, Standing};
use store::providers::realms::{credential_issuers, realm_keys};
use store::tenancy::UnitOfWork;

use super::did::realm_did;
use super::linked_data::{Binding, verify_ldp_presentation};

/// How long a request waits for its answer, in seconds.
pub const LIFETIME_SECONDS: i64 = 300;

/// The encryptions an answer may come back under. HAIP names both.
pub const RESPONSE_ENCRYPTIONS: [&str; 2] = ["A256GCM", "A128GCM"];

/// The credential formats this verifier reads: SD-JWT VC, and W3C
/// credentials in JSON-LD secured by Data Integrity proofs.
pub const SD_JWT_VC: &str = "dc+sd-jwt";
pub const LDP_VC: &str = "ldp_vc";

/// The Data Integrity proofs a JSON-LD credential or presentation may carry:
/// MOSIP's issuers sign under the first, Inji's wallets under the second.
const LDP_PROOF_TYPES: [&str; 2] = ["Ed25519Signature2020", "JsonWebSignature2020"];

/// The `typ` an SD-JWT VC issuer writes: the one the specification settled
/// on, and the one it replaced, which issuers in service still write.
const SD_JWT_VC_TYPES: [&str; 2] = ["dc+sd-jwt", "vc+sd-jwt"];

/// The algorithms an issuer may sign under, and a holder bind a key under.
const ISSUER_ALGORITHMS: [&str; 10] = [
    "EdDSA", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
];
const HOLDER_ALGORITHMS: [&str; 4] = ["EdDSA", "ES256", "ES384", "ES512"];

const SEALING_PURPOSE: &str = "presentation-response-key";
const MOST_CREDENTIALS: usize = 5;
const MOST_CLAIMS: usize = 32;
/// How far two clocks may disagree when a presentation's times are read.
pub(super) const LEEWAY_SECONDS: i64 = 60;
/// How long a refusal's words are kept.
const MOST_ERROR_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unaskable {
    #[error("{0}")]
    NotAQuery(&'static str),
    #[error("the realm holds no Ed25519 key to sign a request with: mint one under its keys")]
    NoSigningKey,
    #[error("the realm's issuer is not an address a DID is read from")]
    NoDid,
    #[error("the request could not be kept")]
    Unwritable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unanswerable {
    /// No pending request answers to what was sent: an unknown key or state, a
    /// request already answered, or one that ran out. One answer for all of
    /// them, so the door says nothing about which requests exist.
    #[error("no request is waiting for this answer")]
    Unknown,
    #[error("the answer could not be read")]
    Unreadable,
    #[error("the answer could not be kept")]
    Unwritable,
}

/// The identifier the realm presents itself under, as a verifier.
pub fn realm_client_id(did: &str) -> String {
    format!("decentralized_identifier:{did}")
}

/// Where a wallet fetches one request.
pub fn request_uri(issuer: &str, request_id: &str) -> String {
    format!("{issuer}/vp/request/{request_id}")
}

/// Where every answer to the realm's requests is sent. One address, so the
/// realm's DID document can declare it as a service.
pub fn response_uri(issuer: &str) -> String {
    format!("{issuer}/vp/response")
}

/// Whether a DCQL query asks only for what this verifier can check: SD-JWT VC
/// or JSON-LD credentials, each naming the types it accepts, with claims named
/// by paths of member names.
pub fn check_query(query: &Value) -> Result<(), Unaskable> {
    let refused = Unaskable::NotAQuery;
    let asked = query
        .as_object()
        .ok_or(refused("the query is a JSON object"))?;
    if asked.keys().any(|member| member != "credentials") {
        return Err(refused(
            "the query holds credentials and nothing else: credential sets are not read yet",
        ));
    }
    let credentials = asked
        .get("credentials")
        .and_then(Value::as_array)
        .filter(|listed| !listed.is_empty() && listed.len() <= MOST_CREDENTIALS)
        .ok_or(refused("the query asks for one to five credentials"))?;
    let mut ids = HashSet::new();
    for credential in credentials {
        let id = credential
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_query_id(id))
            .ok_or(refused(
                "each credential has an id of letters, digits, `_` and `-`",
            ))?;
        if !ids.insert(id) {
            return Err(refused("each credential has an id of its own"));
        }
        match credential.get("format").and_then(Value::as_str) {
            Some(SD_JWT_VC) => {
                credential
                    .pointer("/meta/vct_values")
                    .and_then(Value::as_array)
                    .filter(|types| !types.is_empty() && types.iter().all(Value::is_string))
                    .ok_or(refused(
                        "each dc+sd-jwt credential names the types it accepts in meta.vct_values",
                    ))?;
            }
            Some(LDP_VC) => {
                credential
                    .pointer("/meta/type_values")
                    .and_then(Value::as_array)
                    .filter(|alternatives| {
                        !alternatives.is_empty() && alternatives.iter().all(is_expanded_type_set)
                    })
                    .ok_or(refused(
                        "each ldp_vc credential names the types it accepts in meta.type_values, lists of absolute IRIs",
                    ))?;
            }
            _ => {
                return Err(refused(
                    "each credential is asked for as dc+sd-jwt or ldp_vc",
                ));
            }
        }
        if credential
            .get("multiple")
            .is_some_and(|many| many != &json!(false))
        {
            return Err(refused("each credential is asked for once"));
        }
        if let Some(claims) = credential.get("claims") {
            let claims = claims
                .as_array()
                .filter(|listed| !listed.is_empty() && listed.len() <= MOST_CLAIMS)
                .ok_or(refused("claims, when given, are one to thirty-two paths"))?;
            for claim in claims {
                claim_path(claim)
                    .ok_or(refused("each claim is named by a path of member names"))?;
            }
        }
    }
    Ok(())
}

/// A request the realm asked, with where a wallet reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub request_id: String,
    /// The `openid4vp://` link a wallet opens, or a QR code carries.
    pub uri: String,
    pub expires_at: DateTime<Utc>,
}

/// Ask for a presentation: draw the request's nonce and its answer's key,
/// sign the request, and keep it until it is answered or runs out.
pub async fn ask(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    issuer: &str,
    query: &Value,
    by: &str,
    now: DateTime<Utc>,
) -> Result<Asked, Unaskable> {
    check_query(query)?;
    let did = realm_did(issuer).ok_or(Unaskable::NoDid)?;
    let key = realm_keys::active(
        transaction,
        signing.ring,
        signing.envelope,
        KeyUse::Sig,
        Some(SignAlg::EdDsa),
    )
    .await
    .map_err(|_| Unaskable::Unwritable)?
    .ok_or(Unaskable::NoSigningKey)?;

    let request_id = HEXLOWER.encode(&draw::<16>(signing.provider)?);
    let nonce = BASE64URL_NOPAD.encode(&draw::<32>(signing.provider)?);
    let response_kid = BASE64URL_NOPAD.encode(&draw::<16>(signing.provider)?);
    let pair = EcKeyPair::generate(EcCurve::P256).map_err(|_| Unaskable::Unwritable)?;
    let mut answer_key = pair.to_jwk_public_key();
    answer_key.set_key_id(response_kid.clone());
    answer_key.set_key_use("enc");
    answer_key.set_algorithm("ECDH-ES");
    let sealed = signing
        .ring
        .seal(
            signing.envelope,
            SEALING_PURPOSE,
            &request_id,
            &pair.to_pem_private_key(),
        )
        .await
        .map_err(|_| Unaskable::Unwritable)?;

    let expires_at = now + Duration::seconds(LIFETIME_SECONDS);
    let client_id = realm_client_id(&did);
    let claims = request_claims(&RequestParts {
        client_id: &client_id,
        issuer,
        request_id: &request_id,
        nonce: &nonce,
        answer_key: Value::Object(answer_key.as_ref().clone()),
        query,
        now,
        expires_at,
    });
    let request_object = crate::token::issuance::sign_claims_as(
        &key,
        &claims,
        "oauth-authz-req+jwt",
        &format!("{did}#{}", key.kid),
    )
    .map_err(|_| Unaskable::Unwritable)?;

    presentations::keep(
        transaction,
        &KeptRequest {
            request_id: &request_id,
            nonce: &nonce,
            response_kid: &response_kid,
            response_key: &sealed,
            query,
            request_object: &request_object,
            expires_at,
            created_by: by,
        },
    )
    .await
    .map_err(|_| Unaskable::Unwritable)?;

    let uri = format!(
        "openid4vp://?client_id={}&request_uri={}",
        encoded(&client_id),
        encoded(&request_uri(issuer, &request_id)),
    );
    Ok(Asked {
        request_id,
        uri,
        expires_at,
    })
}

/// The signed request a wallet fetches, while it is pending.
pub async fn read_request_object(
    transaction: &UnitOfWork,
    request_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<String>, Unanswerable> {
    presentations::pending_request_object(transaction, request_id, &now)
        .await
        .map_err(|_| Unanswerable::Unwritable)
}

/// Where a request stands, for whoever asked for it.
pub async fn read_standing(
    transaction: &UnitOfWork,
    request_id: &str,
) -> Result<Option<Standing>, Unanswerable> {
    presentations::standing(transaction, request_id)
        .await
        .map_err(|_| Unanswerable::Unwritable)
}

/// What a wallet posted to the realm's response address.
pub enum Answer<'a> {
    /// A `direct_post.jwt` answer: the encrypted response.
    Encrypted(&'a str),
    /// A refusal, which a wallet sends in the clear, naming the request by
    /// its state.
    Refused { error: &'a str, state: &'a str },
}

/// What an answer settled its request as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    Verified,
    Refused,
    Failed(&'static str),
}

/// Settle the request an answer is for, once.
pub async fn settle_answer(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    issuer: &str,
    answer: Answer<'_>,
    now: DateTime<Utc>,
) -> Result<Settled, Unanswerable> {
    let (held, settled, outcome) = match answer {
        Answer::Refused { error, state } => {
            let held = presentations::claim_by_request_id(transaction, state, &now)
                .await
                .map_err(|_| Unanswerable::Unwritable)?
                .ok_or(Unanswerable::Unknown)?;
            let said: String = error
                .chars()
                .filter(char::is_ascii_graphic)
                .take(MOST_ERROR_CHARS)
                .collect();
            (held, Settled::Refused, json!({ "error": said }))
        }
        Answer::Encrypted(response) => {
            let kid = answer_key_id(response)?;
            let held = presentations::claim_by_response_kid(transaction, &kid, &now)
                .await
                .map_err(|_| Unanswerable::Unwritable)?
                .ok_or(Unanswerable::Unknown)?;
            let did = realm_did(issuer).ok_or(Unanswerable::Unwritable)?;
            match verify_answer(
                transaction,
                signing,
                &realm_client_id(&did),
                &held,
                response,
                now,
            )
            .await?
            {
                Ok(credentials) => (
                    held,
                    Settled::Verified,
                    json!({ "credentials": credentials }),
                ),
                Err(why) => (held, Settled::Failed(why), json!({ "reason": why })),
            }
        }
    };
    let status = match settled {
        Settled::Verified => "verified",
        Settled::Refused => "refused",
        Settled::Failed(_) => "failed",
    };
    presentations::settle(transaction, &held.request_id, status, &outcome, &now)
        .await
        .map_err(|_| Unanswerable::Unwritable)?
        .then_some(settled)
        .ok_or(Unanswerable::Unknown)
}

/// The key an encrypted answer names, read before anything is decrypted:
/// ECDH-ES to that key, under an encryption the request offered, and no
/// compression, which no wallet uses and which is inflated at the realm's cost.
fn answer_key_id(response: &str) -> Result<String, Unanswerable> {
    let header = response.split('.').next().ok_or(Unanswerable::Unreadable)?;
    let header = BASE64URL_NOPAD
        .decode(header.as_bytes())
        .map_err(|_| Unanswerable::Unreadable)?;
    let Ok(Value::Object(header)) = serde_json::from_slice::<Value>(&header) else {
        return Err(Unanswerable::Unreadable);
    };
    let said = |name: &str| header.get(name).and_then(Value::as_str);
    if said("alg") != Some("ECDH-ES")
        || !said("enc").is_some_and(|enc| RESPONSE_ENCRYPTIONS.contains(&enc))
        || header.contains_key("zip")
    {
        return Err(Unanswerable::Unreadable);
    }
    said("kid")
        .map(str::to_owned)
        .ok_or(Unanswerable::Unreadable)
}

/// Decrypt an answer and verify every credential the query asked for.
///
/// The outer result is whether the store could be read; the inner one is the
/// verdict, a refusal in the realm's words when any check fails.
async fn verify_answer(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    client_id: &str,
    held: &Answering,
    response: &str,
    now: DateTime<Utc>,
) -> Result<Result<Vec<Value>, &'static str>, Unanswerable> {
    let key = signing
        .ring
        .open(
            signing.envelope,
            SEALING_PURPOSE,
            &held.request_id,
            &held.response_key,
        )
        .await
        .map_err(|_| Unanswerable::Unwritable)?;
    let Ok(decrypter) = ECDH_ES.decrypter_from_pem(secrecy::ExposeSecret::expose_secret(&key))
    else {
        return Ok(Err("the answer's key could not be read"));
    };
    let Ok((payload, _)) = jwe::deserialize_compact(response, &decrypter) else {
        return Ok(Err("the answer could not be decrypted"));
    };
    let Ok(Value::Object(payload)) = serde_json::from_slice::<Value>(&payload) else {
        return Ok(Err("the answer is not a JSON object"));
    };
    if payload
        .get("state")
        .is_some_and(|state| state.as_str() != Some(held.request_id.as_str()))
    {
        return Ok(Err("the answer names another request"));
    }
    let Some(tokens) = payload.get("vp_token").and_then(Value::as_object) else {
        return Ok(Err("the answer carries no vp_token object"));
    };
    let asked = held
        .query
        .get("credentials")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if tokens.keys().any(|id| {
        !asked
            .iter()
            .any(|credential| credential.get("id").and_then(Value::as_str) == Some(id))
    }) {
        return Ok(Err(
            "the answer carries a credential the query did not ask for",
        ));
    }

    // The contexts a JSON-LD credential is read under, read once per answer.
    let pinned = if asked
        .iter()
        .any(|credential| credential.get("format").and_then(Value::as_str) == Some(LDP_VC))
    {
        crate::admin::jsonld_contexts::pinned_documents(transaction)
            .await
            .map_err(|_| Unanswerable::Unwritable)?
    } else {
        HashMap::new()
    };
    let contexts = HeldContexts::new(&pinned);

    let mut verified = Vec::with_capacity(asked.len());
    for credential in &asked {
        let id = credential
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let presented = match tokens.get(id).and_then(Value::as_array).map(Vec::as_slice) {
            Some([presented]) => presented,
            _ => return Ok(Err("each credential asked for is presented once")),
        };
        let outcome = match (credential.get("format").and_then(Value::as_str), presented) {
            (Some(SD_JWT_VC), Value::String(presented)) => match verify_credential(
                transaction,
                signing.provider,
                client_id,
                &held.nonce,
                credential,
                presented,
                now,
            )
            .await?
            {
                Ok((issuer, vct, claims)) => {
                    json!({ "id": id, "issuer": issuer, "vct": vct, "claims": claims })
                }
                Err(why) => return Ok(Err(why)),
            },
            (Some(LDP_VC), _) => match verify_ldp_presentation(
                transaction,
                signing.provider,
                &contexts,
                &Binding {
                    client_id,
                    nonce: &held.nonce,
                },
                credential,
                presented,
                now,
            )
            .await?
            {
                Ok(outcome) => json!({
                    "id": id,
                    "issuer": outcome.issuer,
                    "types": outcome.types,
                    "claims": outcome.claims,
                }),
                Err(why) => return Ok(Err(why)),
            },
            _ => {
                return Ok(Err(
                    "a credential is not presented in the form its format takes",
                ));
            }
        };
        verified.push(outcome);
    }
    Ok(Ok(verified))
}

/// One SD-JWT VC presentation, verified against the issuer the realm names by
/// its `iss`: the issuer's signature, the disclosures, the holder's key
/// binding to this request, the type and the claims asked for. What comes
/// back is the issuer, the type and the names of the claims asked for, never
/// their values.
async fn verify_credential(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    client_id: &str,
    nonce: &str,
    asked: &Value,
    presented: &str,
    now: DateTime<Utc>,
) -> Result<Result<(String, String, Vec<String>), &'static str>, Unanswerable> {
    let Ok(header) = sd_jwt::read_issuer_header(presented) else {
        return Ok(Err("a credential is not an SD-JWT"));
    };
    let Some(token_type) = header.get("typ").and_then(Value::as_str).and_then(|typ| {
        SD_JWT_VC_TYPES
            .iter()
            .find(|known| known.eq_ignore_ascii_case(typ))
            .copied()
    }) else {
        return Ok(Err("a credential is not an SD-JWT VC"));
    };
    let Some(iss) = unverified_issuer(presented) else {
        return Ok(Err("a credential names no issuer"));
    };
    let Some(named) = credential_issuers::by_issuer(transaction, &iss)
        .await
        .map_err(|_| Unanswerable::Unwritable)?
    else {
        return Ok(Err("a credential's issuer is not one this realm names"));
    };
    let Some(algorithm) = header.get("alg").and_then(Value::as_str) else {
        return Ok(Err("a credential names no algorithm"));
    };
    let kid = header.get("kid").and_then(Value::as_str);

    let paths: Vec<Vec<String>> = asked
        .get("claims")
        .and_then(Value::as_array)
        .map(|claims| claims.iter().filter_map(claim_path).collect())
        .unwrap_or_default();
    // The claims asked for are looked for below, path by path, where the
    // refusal can say which check failed.
    let policy = VerifyingPolicy {
        token_type,
        required_claims: &[],
        key_binding: Some(KeyBinding {
            audience: client_id,
            nonce,
            max_age: LIFETIME_SECONDS,
        }),
        now: now.timestamp(),
        leeway: LEEWAY_SECONDS,
    };

    // The key the header names, or every key of the issuer when it names none.
    let candidates = candidate_keys(&named, kid);
    let mut outcome = Err("a credential's signature is not its issuer's");
    for jwk in candidates {
        let Some(verifier) = verifier_for(algorithm, &jwk) else {
            continue;
        };
        match sd_jwt::verify_presentation(provider, presented, verifier.as_ref(), &policy) {
            Ok(verified) => {
                outcome = Ok(verified);
                break;
            }
            Err(sd_jwt::Refused::IssuerSignature) => continue,
            Err(_) => {
                outcome = Err("a credential's disclosures, key binding or time claims do not hold");
                break;
            }
        }
    }
    let verified = match outcome {
        Ok(verified) => verified,
        Err(why) => return Ok(Err(why)),
    };

    let vct = verified
        .claims
        .get("vct")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let accepted = asked
        .pointer("/meta/vct_values")
        .and_then(Value::as_array)
        .is_some_and(|types| types.iter().any(|held| held.as_str() == Some(vct)));
    if !accepted {
        return Ok(Err("a credential is of a type the query did not accept"));
    }
    for path in &paths {
        let mut at = verified.claims.get(&path[0]);
        for member in &path[1..] {
            at = at.and_then(|held| held.get(member));
        }
        if at.is_none() {
            return Ok(Err("a credential lacks a claim the query asked for"));
        }
    }
    Ok(Ok((
        named.issuer,
        vct.to_owned(),
        paths.iter().map(|path| path.join(".")).collect(),
    )))
}

/// The `iss` of an SD-JWT's issuer token, read before its signature is: only
/// to find the issuer whose keys will then decide.
fn unverified_issuer(presented: &str) -> Option<String> {
    let token = presented.split('~').next()?;
    let payload = token.split('.').nth(1)?;
    let payload = BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
    let payload: Value = serde_json::from_slice(&payload).ok()?;
    payload.get("iss")?.as_str().map(str::to_owned)
}

fn candidate_keys(named: &CredentialIssuer, kid: Option<&str>) -> Vec<Map<String, Value>> {
    named
        .keys
        .iter()
        .filter_map(Value::as_object)
        .filter(|jwk| kid.is_none() || jwk.get("kid").and_then(Value::as_str) == kid)
        .cloned()
        .collect()
}

/// A verifier for the algorithm the issuer's header names, over a key of the
/// family that algorithm signs with. Any other pairing is no verifier.
fn verifier_for(algorithm: &str, jwk: &Map<String, Value>) -> Option<Box<dyn JwsVerifier>> {
    let key = Jwk::from_map(jwk.clone()).ok()?;
    let verifier: Box<dyn JwsVerifier> = match algorithm {
        "EdDSA" => Box::new(EdDSA.verifier_from_jwk(&key).ok()?),
        "ES256" => Box::new(ES256.verifier_from_jwk(&key).ok()?),
        "ES384" => Box::new(ES384.verifier_from_jwk(&key).ok()?),
        "ES512" => Box::new(ES512.verifier_from_jwk(&key).ok()?),
        "RS256" => Box::new(RS256.verifier_from_jwk(&key).ok()?),
        "RS384" => Box::new(RS384.verifier_from_jwk(&key).ok()?),
        "RS512" => Box::new(RS512.verifier_from_jwk(&key).ok()?),
        "PS256" => Box::new(PS256.verifier_from_jwk(&key).ok()?),
        "PS384" => Box::new(PS384.verifier_from_jwk(&key).ok()?),
        "PS512" => Box::new(PS512.verifier_from_jwk(&key).ok()?),
        _ => return None,
    };
    Some(verifier)
}

struct RequestParts<'a> {
    client_id: &'a str,
    issuer: &'a str,
    request_id: &'a str,
    nonce: &'a str,
    answer_key: Value,
    query: &'a Value,
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// The request's claims, OpenID4VP 1.0.
fn request_claims(parts: &RequestParts<'_>) -> Map<String, Value> {
    let formats = json!({
        SD_JWT_VC: {
            "sd-jwt_alg_values": ISSUER_ALGORITHMS,
            "kb-jwt_alg_values": HOLDER_ALGORITHMS,
        },
        LDP_VC: { "proof_type_values": LDP_PROOF_TYPES },
    });
    let claims = json!({
        "iss": parts.client_id,
        "aud": "https://self-issued.me/v2",
        "client_id": parts.client_id,
        "response_type": "vp_token",
        "response_mode": "direct_post.jwt",
        "response_uri": response_uri(parts.issuer),
        "nonce": parts.nonce,
        "state": parts.request_id,
        "dcql_query": parts.query,
        "client_metadata": {
            "jwks": { "keys": [parts.answer_key] },
            "encrypted_response_enc_values_supported": RESPONSE_ENCRYPTIONS,
            "vp_formats_supported": formats,
            // The same, under the names of the draft this version replaced.
            // A wallet library still reading those finds what it looks for,
            // and one reading this version ignores them.
            "vp_formats": formats,
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": RESPONSE_ENCRYPTIONS[0],
        },
        "iat": parts.now.timestamp(),
        "exp": parts.expires_at.timestamp(),
    });
    match claims {
        Value::Object(claims) => claims,
        _ => Map::new(),
    }
}

/// A claim's path as member names, or `None` for a path holding anything else.
pub(super) fn claim_path(claim: &Value) -> Option<Vec<String>> {
    let path = claim.get("path")?.as_array()?;
    if path.is_empty() || path.len() > 8 {
        return None;
    }
    path.iter()
        .map(|member| {
            member
                .as_str()
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

/// One alternative of `meta.type_values`: types a credential must all hold, as
/// its contexts expand them. A type left unexpanded names nothing a credential
/// read here can hold.
fn is_expanded_type_set(alternative: &Value) -> bool {
    alternative.as_array().is_some_and(|types| {
        !types.is_empty()
            && types
                .iter()
                .all(|held| held.as_str().is_some_and(jsonld::is_absolute_iri))
    })
}

fn is_query_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn draw<const N: usize>(provider: &dyn CryptoProvider) -> Result<[u8; N], Unaskable> {
    let mut drawn = [0u8; N];
    provider
        .rand()
        .fill(&mut drawn)
        .map_err(|_| Unaskable::Unwritable)?;
    Ok(drawn)
}

fn encoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid_query() -> Value {
        json!({
            "credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": { "vct_values": ["urn:eudi:pid:1"] },
                "claims": [{ "path": ["given_name"] }, { "path": ["address", "locality"] }]
            }]
        })
    }

    /// The PID query with one change made to its only credential.
    fn pid_query_with(change: impl FnOnce(&mut Map<String, Value>)) -> Value {
        let mut query = pid_query();
        if let Some(Value::Object(credential)) = query.pointer_mut("/credentials/0") {
            change(credential);
        }
        query
    }

    fn identity_query() -> Value {
        json!({
            "credentials": [{
                "id": "identity",
                "format": "ldp_vc",
                "meta": { "type_values": [[
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    "https://issuer.example/vocab#IdentityCredential"
                ]] },
                "claims": [{ "path": ["credentialSubject", "fullName"] }]
            }]
        })
    }

    #[test]
    fn a_query_for_json_ld_credentials_is_askable() {
        assert_eq!(check_query(&identity_query()), Ok(()));
        let both = json!({ "credentials": [
            pid_query()["credentials"][0],
            identity_query()["credentials"][0],
        ] });
        assert_eq!(check_query(&both), Ok(()));
        let alternatives = json!({ "credentials": [{
            "id": "identity",
            "format": "ldp_vc",
            "meta": { "type_values": [
                ["https://issuer.example/vocab#IdentityCredential"],
                ["urn:example:credential:identity"]
            ] }
        }] });
        assert_eq!(check_query(&alternatives), Ok(()));
    }

    /// A JSON-LD query names each type as a credential's contexts expand it:
    /// one left unexpanded names nothing a credential read here holds.
    #[test]
    fn a_json_ld_query_names_the_types_it_accepts_expanded() {
        for meta in [
            json!({}),
            json!({ "type_values": [] }),
            json!({ "type_values": [[]] }),
            json!({ "type_values": [["VerifiableCredential"]] }),
            json!({ "type_values": ["https://issuer.example/vocab#IdentityCredential"] }),
            json!({ "type_values": [[7]] }),
            json!({ "vct_values": ["urn:eudi:pid:1"] }),
        ] {
            let mut query = identity_query();
            query["credentials"][0]["meta"] = meta.clone();
            assert!(
                matches!(check_query(&query), Err(Unaskable::NotAQuery(_))),
                "{meta}"
            );
        }
        let sd_jwt_named_as_json_ld = pid_query_with(|credential| {
            credential.insert(
                "meta".into(),
                identity_query()["credentials"][0]["meta"].clone(),
            );
        });
        assert!(matches!(
            check_query(&sd_jwt_named_as_json_ld),
            Err(Unaskable::NotAQuery(_))
        ));
    }

    #[test]
    fn a_query_for_sd_jwt_credentials_is_askable() {
        assert_eq!(check_query(&pid_query()), Ok(()));
        let without_claims = pid_query_with(|credential| {
            credential.remove("claims");
        });
        assert_eq!(check_query(&without_claims), Ok(()));
        let once = pid_query_with(|credential| {
            credential.insert("multiple".into(), json!(false));
        });
        assert_eq!(check_query(&once), Ok(()));
    }

    #[test]
    fn a_query_this_verifier_cannot_check_is_refused() {
        let refused = |query: Value| {
            assert!(
                matches!(check_query(&query), Err(Unaskable::NotAQuery(_))),
                "{query}"
            );
        };
        refused(json!([]));
        refused(json!({ "credentials": [] }));
        refused(json!({ "credentials": pid_query()["credentials"], "credential_sets": [] }));
        let six: Vec<Value> = (0..6)
            .map(|at| {
                let mut credential = pid_query()["credentials"][0].clone();
                credential["id"] = json!(format!("pid{at}"));
                credential
            })
            .collect();
        refused(json!({ "credentials": six }));
        let twice = pid_query()["credentials"][0].clone();
        refused(json!({ "credentials": [twice.clone(), twice] }));
        for id in [json!("p id"), json!(""), json!("x".repeat(65)), json!(7)] {
            refused(pid_query_with(|credential| {
                credential.insert("id".into(), id);
            }));
        }
        refused(pid_query_with(|credential| {
            credential.insert("format".into(), json!("mso_mdoc"));
        }));
        for types in [
            json!({}),
            json!({ "vct_values": [] }),
            json!({ "vct_values": [1] }),
        ] {
            refused(pid_query_with(|credential| {
                credential.insert("meta".into(), types);
            }));
        }
        refused(pid_query_with(|credential| {
            credential.insert("multiple".into(), json!(true));
        }));
        for claims in [
            json!([]),
            json!([{ "path": [] }]),
            json!([{ "path": ["nationalities", 0] }]),
            json!([{ "path": ["address", null] }]),
            json!([{ "path": [""] }]),
            json!([{ "id": "given" }]),
        ] {
            refused(pid_query_with(|credential| {
                credential.insert("claims".into(), claims);
            }));
        }
    }

    #[test]
    fn a_request_names_its_answer_under_both_versions_of_the_metadata() {
        let now = DateTime::from_timestamp(1_790_000_000, 0).expect("a time");
        let query = pid_query();
        let claims = request_claims(&RequestParts {
            client_id: "decentralized_identifier:did:web:id.test:realms:acme",
            issuer: "https://id.test/realms/acme",
            request_id: "0f0e",
            nonce: "n-0S6",
            answer_key: json!({ "kty": "EC", "kid": "k1", "alg": "ECDH-ES", "use": "enc" }),
            query: &query,
            now,
            expires_at: now + Duration::seconds(LIFETIME_SECONDS),
        });
        assert_eq!(claims["iss"], claims["client_id"]);
        assert_eq!(claims["aud"], "https://self-issued.me/v2");
        assert_eq!(claims["response_type"], "vp_token");
        assert_eq!(claims["response_mode"], "direct_post.jwt");
        assert_eq!(
            claims["response_uri"],
            "https://id.test/realms/acme/vp/response"
        );
        assert_eq!(claims["state"], "0f0e");
        assert_eq!(claims["nonce"], "n-0S6");
        assert_eq!(claims["dcql_query"], query);
        assert_eq!(claims["exp"], json!(1_790_000_000 + LIFETIME_SECONDS));

        let metadata = &claims["client_metadata"];
        assert_eq!(metadata["jwks"]["keys"][0]["kid"], "k1");
        assert_eq!(
            metadata["encrypted_response_enc_values_supported"],
            json!(["A256GCM", "A128GCM"])
        );
        assert_eq!(
            metadata["vp_formats_supported"]["dc+sd-jwt"]["kb-jwt_alg_values"],
            json!(HOLDER_ALGORITHMS)
        );
        assert_eq!(
            metadata["vp_formats_supported"]["ldp_vc"]["proof_type_values"],
            json!(["Ed25519Signature2020", "JsonWebSignature2020"])
        );
        assert_eq!(metadata["vp_formats"], metadata["vp_formats_supported"]);
        assert_eq!(metadata["authorization_encrypted_response_alg"], "ECDH-ES");
        assert_eq!(metadata["authorization_encrypted_response_enc"], "A256GCM");
    }

    fn with_header(header: Value) -> String {
        format!(
            "{}.key.iv.text.tag",
            BASE64URL_NOPAD.encode(header.to_string().as_bytes())
        )
    }

    #[test]
    fn an_answer_names_its_key_under_an_encryption_the_request_offered() {
        for enc in RESPONSE_ENCRYPTIONS {
            let response = with_header(json!({ "alg": "ECDH-ES", "enc": enc, "kid": "k1" }));
            assert_eq!(answer_key_id(&response).as_deref(), Ok("k1"));
        }
        for header in [
            json!({ "alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": "k1" }),
            json!({ "alg": "ECDH-ES+A256KW", "enc": "A256GCM", "kid": "k1" }),
            json!({ "alg": "ECDH-ES", "enc": "A192GCM", "kid": "k1" }),
            json!({ "alg": "ECDH-ES", "enc": "A256GCM" }),
            json!({ "alg": "ECDH-ES", "enc": "A256GCM", "kid": "k1", "zip": "DEF" }),
            json!({ "alg": "ECDH-ES", "enc": "A256GCM", "kid": 1 }),
            json!(["ECDH-ES"]),
        ] {
            assert_eq!(
                answer_key_id(&with_header(header.clone())),
                Err(Unanswerable::Unreadable),
                "{header}"
            );
        }
        assert_eq!(answer_key_id("%%%.a.b.c.d"), Err(Unanswerable::Unreadable));
    }

    #[test]
    fn a_keyless_header_is_answered_by_every_key_and_a_named_one_by_its_own() {
        let named = CredentialIssuer {
            issuer_id: "i".into(),
            name: "PID".into(),
            issuer: "https://issuer.test/pid".into(),
            keys: vec![json!({ "kid": "a" }), json!({ "kid": "b" }), json!({})],
            read_from: "https://issuer.test/.well-known/jwt-vc-issuer/pid".into(),
            read_at: DateTime::from_timestamp(0, 0).expect("a time"),
            created_by: "admin".into(),
            created_at: DateTime::from_timestamp(0, 0).expect("a time"),
        };
        assert_eq!(candidate_keys(&named, None).len(), 3);
        assert_eq!(
            candidate_keys(&named, Some("b")),
            vec![json!({ "kid": "b" }).as_object().cloned().expect("a key")]
        );
        assert!(candidate_keys(&named, Some("c")).is_empty());
    }

    #[test]
    fn an_algorithm_is_paired_with_its_own_family_of_keys() {
        let ed = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
        });
        let ed = ed.as_object().expect("a key");
        assert!(verifier_for("EdDSA", ed).is_some());
        assert!(verifier_for("ES256", ed).is_none());
        assert!(verifier_for("none", ed).is_none());
        assert!(verifier_for("HS256", ed).is_none());
    }
}
