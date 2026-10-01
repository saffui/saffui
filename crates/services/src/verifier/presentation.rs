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
use crypto::provider::{CryptoProvider, HashAlg, SignAlg};
use crypto::sd_jwt::{self, KeyBinding, VerifyingPolicy};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use jsonld::built_in::HeldContexts;
use models::entities::keys::{KeyUse, RealmSigningKey};
use serde_json::{Map, Value, json};
use store::keyring::Signing;
use store::providers::protocol::presentations::{self, Answering, ForLogin, KeptRequest, Standing};
use store::providers::realms::{credential_issuers, realm_keys, wallet_identity};
use store::tenancy::UnitOfWork;

use super::did::realm_did;
use super::linked_data::{Binding, verify_ldp_presentation};
use super::status::{self, Citation};

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

/// The members of a credential query this verifier checks, and those of a
/// claims query.
const CREDENTIAL_QUERY_MEMBERS: [&str; 6] = [
    "id",
    "format",
    "multiple",
    "meta",
    "claims",
    "require_cryptographic_holder_binding",
];
const CLAIMS_QUERY_MEMBERS: [&str; 2] = ["id", "path"];

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
/// or JSON-LD credentials, each naming the types it accepts and bound to its
/// holder, with claims named by paths of member names. Whatever else a query
/// may say is refused rather than passed over, so that a verified answer never
/// seems to have been held to it.
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
        if credential.get("claim_sets").is_some() {
            return Err(refused(
                "claim sets are not read yet: name the claims every credential must hold",
            ));
        }
        if credential.get("trusted_authorities").is_some() {
            return Err(refused(
                "trusted authorities are not matched: the issuers the realm names decide",
            ));
        }
        if has_member_outside(credential, &CREDENTIAL_QUERY_MEMBERS) {
            return Err(refused(
                "a credential is asked for by its id, format, multiple, meta, claims and require_cryptographic_holder_binding alone",
            ));
        }
        let types_member = match credential.get("format").and_then(Value::as_str) {
            Some(SD_JWT_VC) => {
                credential
                    .pointer("/meta/vct_values")
                    .and_then(Value::as_array)
                    .filter(|types| !types.is_empty() && types.iter().all(Value::is_string))
                    .ok_or(refused(
                        "each dc+sd-jwt credential names the types it accepts in meta.vct_values",
                    ))?;
                "vct_values"
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
                "type_values"
            }
            _ => {
                return Err(refused(
                    "each credential is asked for as dc+sd-jwt or ldp_vc",
                ));
            }
        };
        if credential
            .get("meta")
            .is_some_and(|meta| has_member_outside(meta, &[types_member]))
        {
            return Err(refused("meta names the types a credential may be of alone"));
        }
        if credential
            .get("multiple")
            .is_some_and(|many| many != &json!(false))
        {
            return Err(refused("each credential is asked for once"));
        }
        if credential
            .get("require_cryptographic_holder_binding")
            .is_some_and(|required| required != &json!(true))
        {
            return Err(refused("each credential is asked for bound to its holder"));
        }
        if let Some(claims) = credential.get("claims") {
            check_claims_query(claims)?;
        }
    }
    Ok(())
}

/// The claims one credential is asked for: each named once, by a path of
/// member names. A claim's values are refused: the verifier checks that a claim
/// is held, never what it holds, and the specification leaves value matching to
/// the wallet's discretion.
fn check_claims_query(claims: &Value) -> Result<(), Unaskable> {
    let refused = Unaskable::NotAQuery;
    let claims = claims
        .as_array()
        .filter(|listed| !listed.is_empty() && listed.len() <= MOST_CLAIMS)
        .ok_or(refused("claims, when given, are one to thirty-two paths"))?;
    let (mut ids, mut paths) = (HashSet::new(), HashSet::new());
    for claim in claims {
        if claim.get("values").is_some() {
            return Err(refused(
                "a claim's values are not matched: the verifier checks a claim is held, never its value",
            ));
        }
        if has_member_outside(claim, &CLAIMS_QUERY_MEMBERS) {
            return Err(refused("a claim is asked for by its id and path alone"));
        }
        if let Some(id) = claim.get("id") {
            let id = id
                .as_str()
                .filter(|id| is_query_id(id))
                .ok_or(refused("a claim's id is letters, digits, `_` and `-`"))?;
            if !ids.insert(id) {
                return Err(refused("each claim has an id of its own"));
            }
        }
        let path =
            claim_path(claim).ok_or(refused("each claim is named by a path of member names"))?;
        if !paths.insert(path) {
            return Err(refused("each claim is asked for once"));
        }
    }
    Ok(())
}

/// Whether `object` holds a member `known` does not name.
fn has_member_outside(object: &Value, known: &[&str]) -> bool {
    object.as_object().is_some_and(|members| {
        members
            .keys()
            .any(|member| !known.contains(&member.as_str()))
    })
}

/// A request the realm asked, with where a wallet reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub request_id: String,
    /// The `openid4vp://authorize` link a wallet opens, or a QR code carries.
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
    issue_request(transaction, signing, issuer, query, by, None, now).await
}

/// Ask for the presentation a login needs, bound to that login and the person
/// it names when it names one, so its answer is read by that login alone.
pub async fn ask_for_login(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    issuer: &str,
    query: &Value,
    for_login: ForLogin<'_>,
    now: DateTime<Utc>,
) -> Result<Asked, Unaskable> {
    issue_request(
        transaction,
        signing,
        issuer,
        query,
        // Asked by the person the login names, or by the sign-in itself while
        // it names nobody.
        for_login.user_id.unwrap_or(for_login.purpose),
        Some(for_login),
        now,
    )
    .await
}

/// The key the realm signs its requests with: its active Ed25519 one.
pub(crate) async fn find_request_key(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
) -> Result<RealmSigningKey, Unaskable> {
    realm_keys::active(
        transaction,
        signing.ring,
        signing.envelope,
        KeyUse::Sig,
        Some(SignAlg::EdDsa),
    )
    .await
    .map_err(|_| Unaskable::Unwritable)?
    .ok_or(Unaskable::NoSigningKey)
}

async fn issue_request(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    issuer: &str,
    query: &Value,
    by: &str,
    for_login: Option<ForLogin<'_>>,
    now: DateTime<Utc>,
) -> Result<Asked, Unaskable> {
    check_query(query)?;
    let did = realm_did(issuer).ok_or(Unaskable::NoDid)?;
    let key = find_request_key(transaction, signing).await?;

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
            for_login,
        },
    )
    .await
    .map_err(|_| Unaskable::Unwritable)?;

    let uri = format!(
        "openid4vp://authorize?client_id={}&request_uri={}",
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

/// What an answer came to, and the code a sign-in's browser spends it with:
/// handed to the wallet, which brings the person back carrying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    pub settled: Settled,
    pub response_code: Option<String>,
}

/// Settle the request an answer is for, once.
pub async fn settle_answer(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    issuer: &str,
    answer: Answer<'_>,
    now: DateTime<Utc>,
) -> Result<Settlement, Unanswerable> {
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
            // A login's request is answered by who it identifies, read by the
            // claim the realm names today.
            let profile = match held.purpose {
                Some(_) => wallet_identity::load(transaction)
                    .await
                    .map_err(|_| Unanswerable::Unwritable)?,
                None => None,
            };
            let verified = verify_answer(
                transaction,
                signing,
                &realm_client_id(&did),
                &held,
                response,
                profile
                    .as_ref()
                    .map(|profile| profile.identifier_path.as_slice()),
                now,
            )
            .await?;
            let identified = match (&verified, held.purpose.is_some()) {
                (Ok(answer), true) => Some(
                    digest_presented_identity(transaction, signing, profile.as_ref(), answer)
                        .await?,
                ),
                _ => None,
            };
            match (verified, identified) {
                (Ok(answer), None) => (
                    held,
                    Settled::Verified,
                    json!({ "credentials": answer.credentials }),
                ),
                (Ok(answer), Some(Ok(identity))) => (
                    held,
                    Settled::Verified,
                    json!({ "credentials": answer.credentials, "identity": identity }),
                ),
                (Ok(_), Some(Err(why))) | (Err(why), _) => {
                    (held, Settled::Failed(why), json!({ "reason": why }))
                }
            }
        }
    };
    let status = match settled {
        Settled::Verified => "verified",
        Settled::Refused => "refused",
        Settled::Failed(_) => "failed",
    };
    // A sign-in names the person only once the browser that asked brings back
    // what the wallet was handed. A refusal is handed a code too, so the
    // person comes back to be asked again; an answer that failed is told so.
    let response_code = match (held.purpose.as_deref(), &settled) {
        (Some(signing_in), Settled::Verified | Settled::Refused)
            if signing_in == auth::login::wallet::Purpose::SignIn.as_str() =>
        {
            let drawn = draw::<32>(signing.provider).map_err(|_| Unanswerable::Unwritable)?;
            Some(BASE64URL_NOPAD.encode(&drawn))
        }
        _ => None,
    };
    let kept_digest = response_code
        .as_deref()
        .map(|code| digest_response_code(signing.provider, code))
        .transpose()
        .map_err(|()| Unanswerable::Unwritable)?;
    presentations::settle(
        transaction,
        &held.request_id,
        status,
        &outcome,
        kept_digest.as_deref(),
        &now,
    )
    .await
    .map_err(|_| Unanswerable::Unwritable)?
    .then_some(Settlement {
        settled,
        response_code,
    })
    .ok_or(Unanswerable::Unknown)
}

/// The digest a sign-in's code is kept under, so nothing the store holds is a
/// code anybody could spend.
pub(crate) fn digest_response_code(
    provider: &dyn CryptoProvider,
    code: &str,
) -> Result<String, ()> {
    provider
        .digest()
        .hash(HashAlg::Sha256, code.as_bytes())
        .map(|digest| HEXLOWER.encode(&digest))
        .map_err(|_| ())
}

/// The identity a login's answer proves, as the realm keeps identities: the
/// issuer that vouched, and the digest of the identifier under the realm's
/// own key. The identifier goes no further than this.
async fn digest_presented_identity(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    profile: Option<&wallet_identity::WalletIdentity>,
    answer: &VerifiedAnswer,
) -> Result<Result<Value, &'static str>, Unanswerable> {
    let Some(profile) = profile else {
        return Ok(Err(
            "the realm no longer knows people by a wallet credential",
        ));
    };
    let Some(presented) = &answer.identifier else {
        return Ok(Err(
            "a credential does not identify its holder by the claim the realm names",
        ));
    };
    if presented.issuer != profile.issuer {
        return Ok(Err(
            "a credential's issuer is not the one the realm knows people by",
        ));
    }
    let key = wallet_identity::open_digest_key(transaction, signing.ring, signing.envelope)
        .await
        .map_err(|_| Unanswerable::Unwritable)?
        .ok_or(Unanswerable::Unwritable)?;
    let digest = digest_identity(signing.provider, &key, &presented.issuer, &presented.value)
        .map_err(|_| Unanswerable::Unwritable)?;
    Ok(Ok(json!({ "issuer": presented.issuer, "digest": digest })))
}

/// The digest an identity is kept under: HMAC-SHA256 under the realm's key,
/// over the issuer and the identifier each written after its length, so no
/// two pairs run together into the same bytes.
fn digest_identity(
    provider: &dyn CryptoProvider,
    key: &secrecy::SecretBox<Vec<u8>>,
    issuer: &str,
    identifier: &str,
) -> Result<String, ()> {
    let mut written = Vec::with_capacity(8 + issuer.len() + identifier.len());
    for part in [issuer, identifier] {
        let length = u32::try_from(part.len()).map_err(|_| ())?;
        written.extend_from_slice(&length.to_be_bytes());
        written.extend_from_slice(part.as_bytes());
    }
    provider
        .hmac()
        .hmac(crypto::provider::HmacAlg::Hs256, key, &written)
        .map(|tag| HEXLOWER.encode(&tag))
        .map_err(|_| ())
}

/// The text a claim holds at `path` below `root`. A number, a list or an
/// object identifies nobody by its spelling, so it reads as none.
pub(super) fn read_text_claim(root: &Value, path: &[String]) -> Option<String> {
    path.iter()
        .try_fold(root, |at, member| at.get(member))?
        .as_str()
        .map(str::to_owned)
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

/// What a verified answer says: each credential without the value of any
/// claim, and for a login's request the identifier it presents.
struct VerifiedAnswer {
    credentials: Vec<Value>,
    identifier: Option<PresentedIdentifier>,
}

/// An identifier as a credential presented it, beside the issuer that
/// vouched for it.
struct PresentedIdentifier {
    issuer: String,
    value: String,
}

/// Decrypt an answer and verify every credential the query asked for, and
/// read the identifier at `identifying` when a login asked.
///
/// The outer result is whether the store could be read; the inner one is the
/// verdict, a refusal in the realm's words when any check fails.
async fn verify_answer(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    client_id: &str,
    held: &Answering,
    response: &str,
    identifying: Option<&[String]>,
    now: DateTime<Utc>,
) -> Result<Result<VerifiedAnswer, &'static str>, Unanswerable> {
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
    let mut identifier = None;
    // The statuses each credential cites, under its issuer, read once every
    // credential has verified.
    let mut cited = Vec::with_capacity(asked.len());
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
                identifying,
                now,
            )
            .await?
            {
                Ok(outcome) => {
                    if let Some(value) = outcome.identifier {
                        identifier = Some(PresentedIdentifier {
                            issuer: outcome.issuer.clone(),
                            value,
                        });
                    }
                    cited.push((outcome.issuer_id, outcome.citation.into_iter().collect()));
                    json!({
                        "id": id,
                        "issuer": outcome.issuer,
                        "vct": outcome.vct,
                        "claims": outcome.claims,
                    })
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
                identifying,
                now,
            )
            .await?
            {
                Ok(outcome) => {
                    if let Some(value) = outcome.identifier {
                        identifier = Some(PresentedIdentifier {
                            issuer: outcome.issuer.clone(),
                            value,
                        });
                    }
                    cited.push((outcome.issuer_id, outcome.citations));
                    json!({
                        "id": id,
                        "issuer": outcome.issuer,
                        "types": outcome.types,
                        "claims": outcome.claims,
                    })
                }
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
    if let Err(why) = status::check_citations(transaction, &cited, now).await? {
        return Ok(Err(why));
    }
    Ok(Ok(VerifiedAnswer {
        credentials: verified,
        identifier,
    }))
}

/// What a verified SD-JWT VC says: its issuer, its type and the names of the
/// claims asked for, the identifier a login asked for, and the status it cites.
struct VerifiedSdJwt {
    issuer_id: String,
    issuer: String,
    vct: String,
    claims: Vec<String>,
    identifier: Option<String>,
    citation: Option<Citation>,
}

/// One SD-JWT VC presentation, verified against the issuer the realm names by
/// its `iss`: the issuer's signature, the disclosures, the holder's key
/// binding to this request, the type and the claims asked for. What comes
/// back is the issuer, the type and the names of the claims asked for, never
/// their values, except the text at `identifying` when a login asked, and the
/// status the issuer signed it as citing.
#[allow(
    clippy::too_many_arguments,
    reason = "each is a distinct fact about one presentation"
)]
async fn verify_credential(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    client_id: &str,
    nonce: &str,
    asked: &Value,
    presented: &str,
    identifying: Option<&[String]>,
    now: DateTime<Utc>,
) -> Result<Result<VerifiedSdJwt, &'static str>, Unanswerable> {
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
    let Some((signed, iss)) = read_issuer_payload(presented).and_then(|signed| {
        let iss = signed.get("iss")?.as_str()?.to_owned();
        Some((signed, iss))
    }) else {
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
    let candidates = candidate_keys(&named.keys, kid);
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
    let identifier = identifying.and_then(|path| {
        let (first, rest) = path.split_first()?;
        read_text_claim(verified.claims.get(first)?, rest)
    });
    // Read off the payload the issuer signed, which the signature just held.
    let citation = match status::read_token_citation(&signed, &verified.claims) {
        Ok(citation) => citation,
        Err(why) => return Ok(Err(why)),
    };
    Ok(Ok(VerifiedSdJwt {
        issuer_id: named.issuer_id,
        issuer: named.issuer,
        vct: vct.to_owned(),
        claims: paths.iter().map(|path| path.join(".")).collect(),
        identifier,
        citation,
    }))
}

/// The payload of an SD-JWT's issuer token. Read before its signature is,
/// only to find by its `iss` the issuer whose keys will then decide; once they
/// have, the payload that signature holds.
fn read_issuer_payload(presented: &str) -> Option<Map<String, Value>> {
    let token = presented.split('~').next()?;
    let payload = token.split('.').nth(1)?;
    let payload = BASE64URL_NOPAD.decode(payload.as_bytes()).ok()?;
    match serde_json::from_slice(&payload).ok()? {
        Value::Object(payload) => Some(payload),
        _ => None,
    }
}

/// The issuer keys a header naming `kid` may be signed under: that key alone,
/// or every key when it names none.
pub(super) fn candidate_keys(keys: &[Value], kid: Option<&str>) -> Vec<Map<String, Value>> {
    keys.iter()
        .filter_map(Value::as_object)
        .filter(|jwk| kid.is_none() || jwk.get("kid").and_then(Value::as_str) == kid)
        .cloned()
        .collect()
}

/// A verifier for the algorithm the issuer's header names, over a key of the
/// family that algorithm signs with. Any other pairing is no verifier.
pub(super) fn verifier_for(
    algorithm: &str,
    jwk: &Map<String, Value>,
) -> Option<Box<dyn JwsVerifier>> {
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
    use models::entities::credential_issuers::CredentialIssuer;

    use super::*;

    /// An identity is digested as the realm's HMAC-SHA256 over the issuer and
    /// the identifier, each written after its length, so a character moved
    /// from one to the other digests apart. Vectors computed outside this code.
    #[test]
    fn an_identity_digests_its_issuer_and_identifier_apart() {
        let provider = crypto::provider::openssl::OpenSslProvider::new(
            &crypto::provider::CryptoConfig::default(),
        )
        .expect("a provider");
        let key = secrecy::SecretBox::new(Box::new((0u8..32).collect::<Vec<u8>>()));
        assert_eq!(
            digest_identity(&provider, &key, "did:web:id.example", "4819265307").as_deref(),
            Ok("fa0951450dfded4ad319d186edb1ceb4b7be401cc5adba085b6302f5d879ebdb")
        );
        assert_eq!(
            digest_identity(&provider, &key, "did:web:id.example4", "819265307").as_deref(),
            Ok("3c92fa09a07c0a7c4d00455b9126fa1876833a711df84cfa9c806f4d79f1200b")
        );
    }

    /// An identifier is text: a number, a list or an object at the path, or
    /// nothing there, identifies nobody.
    #[test]
    fn an_identifier_is_read_as_text_alone() {
        let credential = json!({
            "credentialSubject": {
                "UIN": "4819265307",
                "number": 4819265307u64,
                "listed": ["4819265307"],
                "nested": { "UIN": "4819265307" },
            }
        });
        let path = |members: &[&str]| -> Vec<String> {
            members.iter().map(|member| (*member).to_owned()).collect()
        };
        assert_eq!(
            read_text_claim(&credential, &path(&["credentialSubject", "UIN"])).as_deref(),
            Some("4819265307")
        );
        for members in [
            &["credentialSubject", "number"][..],
            &["credentialSubject", "listed"],
            &["credentialSubject", "nested"],
            &["credentialSubject", "absent"],
            &["UIN"],
        ] {
            assert_eq!(
                read_text_claim(&credential, &path(members)),
                None,
                "{members:?}"
            );
        }
    }

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

    /// Why `check_query` refuses `query`, which it must.
    fn refusal_of(query: &Value) -> &'static str {
        match check_query(query) {
            Err(Unaskable::NotAQuery(why)) => why,
            other => panic!("{query} was taken: {other:?}"),
        }
    }

    /// A JSON-LD query names each type as a credential's contexts expand it:
    /// one left unexpanded names nothing a credential read here holds. A
    /// query's `meta` names types as its format does, and nothing beside them.
    #[test]
    fn a_json_ld_query_names_the_types_it_accepts_expanded() {
        let unnamed = "each ldp_vc credential names the types it accepts in meta.type_values, lists of absolute IRIs";
        let beside = "meta names the types a credential may be of alone";
        let expanded = identity_query()["credentials"][0]["meta"]["type_values"].clone();
        for (meta, why) in [
            (json!({}), unnamed),
            (json!({ "type_values": [] }), unnamed),
            (json!({ "type_values": [[]] }), unnamed),
            (
                json!({ "type_values": [["VerifiableCredential"]] }),
                unnamed,
            ),
            (
                json!({ "type_values": ["https://issuer.example/vocab#IdentityCredential"] }),
                unnamed,
            ),
            (json!({ "type_values": [[7]] }), unnamed),
            (json!({ "vct_values": ["urn:eudi:pid:1"] }), unnamed),
            (
                json!({ "type_values": expanded.clone(), "vct_values": ["urn:eudi:pid:1"] }),
                beside,
            ),
        ] {
            let mut query = identity_query();
            query["credentials"][0]["meta"] = meta.clone();
            assert_eq!(refusal_of(&query), why, "{meta}");
        }
        for (meta, why) in [
            (
                json!({ "type_values": expanded.clone() }),
                "each dc+sd-jwt credential names the types it accepts in meta.vct_values",
            ),
            (
                json!({ "vct_values": ["urn:eudi:pid:1"], "type_values": expanded.clone() }),
                beside,
            ),
        ] {
            let query = pid_query_with(|credential| {
                credential.insert("meta".into(), meta.clone());
            });
            assert_eq!(refusal_of(&query), why, "{meta}");
        }
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
        let bound = pid_query_with(|credential| {
            credential.insert("require_cryptographic_holder_binding".into(), json!(true));
            credential.insert(
                "claims".into(),
                json!([{ "id": "given", "path": ["given_name"] }, { "path": ["family_name"] }]),
            );
        });
        assert_eq!(check_query(&bound), Ok(()));
    }

    /// What the verifier would not hold an answer to is refused where it is
    /// asked, rather than passed over for a verified answer to seem to meet.
    #[test]
    fn a_query_saying_what_the_verifier_does_not_check_is_refused() {
        for (member, value, why) in [
            (
                "claim_sets",
                json!([["given"]]),
                "claim sets are not read yet: name the claims every credential must hold",
            ),
            (
                "trusted_authorities",
                json!([{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }]),
                "trusted authorities are not matched: the issuers the realm names decide",
            ),
            (
                "require_cryptographic_holder_binding",
                json!(false),
                "each credential is asked for bound to its holder",
            ),
            (
                "require_cryptographic_holder_binding",
                json!("true"),
                "each credential is asked for bound to its holder",
            ),
            (
                "purpose",
                json!("age check"),
                "a credential is asked for by its id, format, multiple, meta, claims and require_cryptographic_holder_binding alone",
            ),
            (
                "meta",
                json!({ "vct_values": ["urn:eudi:pid:1"], "doctype_value": "org.iso.18013.5.1.mDL" }),
                "meta names the types a credential may be of alone",
            ),
        ] {
            let query = pid_query_with(|credential| {
                credential.insert(member.into(), value.clone());
            });
            assert_eq!(refusal_of(&query), why, "{member}: {value}");
        }
        for (claims, why) in [
            (
                json!([{ "path": ["given_name"], "values": ["Ada"] }]),
                "a claim's values are not matched: the verifier checks a claim is held, never its value",
            ),
            (
                json!([{ "path": ["given_name"], "intent_to_retain": false }]),
                "a claim is asked for by its id and path alone",
            ),
            (
                json!([{ "id": "given name", "path": ["given_name"] }]),
                "a claim's id is letters, digits, `_` and `-`",
            ),
            (
                json!([{ "id": 7, "path": ["given_name"] }]),
                "a claim's id is letters, digits, `_` and `-`",
            ),
            (
                json!([
                    { "id": "given", "path": ["given_name"] },
                    { "id": "given", "path": ["family_name"] }
                ]),
                "each claim has an id of its own",
            ),
            (
                json!([{ "path": ["given_name"] }, { "path": ["given_name"] }]),
                "each claim is asked for once",
            ),
        ] {
            let query = pid_query_with(|credential| {
                credential.insert("claims".into(), claims.clone());
            });
            assert_eq!(refusal_of(&query), why, "{claims}");
        }
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
        assert_eq!(candidate_keys(&named.keys, None).len(), 3);
        assert_eq!(
            candidate_keys(&named.keys, Some("b")),
            vec![json!({ "kid": "b" }).as_object().cloned().expect("a key")]
        );
        assert!(candidate_keys(&named.keys, Some("c")).is_empty());
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
