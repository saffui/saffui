//! How a realm presents itself to the wallets it asks for presentations: by
//! its did:web, or by the certificate an authority issued for a key of its
//! own, under the `x509_hash` prefix HAIP requires; and what the European
//! profile (ETSI TS 119 472-2) adds to the requests it signs.
//!
//! The key is drawn here, ES256, with the certificate request an authority
//! certifies it from; it is in no key set the realm publishes and signs
//! nothing but requests. Whether the authority is to be trusted is for the
//! wallets to say: what is checked here is that the chain is for this key.

use chrono::{DateTime, SubsecRound, TimeZone, Utc};
use crypto::jose::jwk::KeyPair;
use crypto::jose::jwk::alg::ec::{EcCurve, EcKeyPair};
use crypto::provider::{CryptoProvider, HashAlg, PrivateKey};
use crypto::public_jwk::public_key_from_jwk;
use crypto::thumbprint::jwk_sha256_thumbprint;
use crypto::x509::{RequestedSubject, Untaken, take_certificate_chain};
use data_encoding::BASE64URL_NOPAD;
use models::entities::verifier::{
    DrawnVerifierKey, VerifierCertificate, VerifierIdentity, VerifierKeyState, VerifierKeyView,
    VerifierSettings, VerifierSubject,
};
use secrecy::SecretBox;
use serde_json::{Map, Value};
use store::error::StoreError;
use store::keyring::Signing;
use store::providers::realms::verifier;
use store::tenancy::UnitOfWork;

/// The longest chain text taken: a certificate and the authorities that
/// issued it, PEM encoded.
pub const MAX_CHAIN_BYTES: usize = 32 * 1024;

/// The longest registration certificate kept.
pub const MAX_REGISTRATION_BYTES: usize = 16 * 1024;

/// The longest registrar's dataset kept, written compact: half of what the
/// table holds, which writes it with a blank after every separator.
pub const MAX_DATASET_BYTES: usize = 8 * 1024;

/// The longest a name in a certificate request may be, as X.520 bounds a
/// common name and an organization name.
const MAX_NAME_CHARS: usize = 64;

/// The type a registration certificate is issued under (TS 119 475,
/// GEN-5.2.2-01).
const REGISTRATION_TYPE: &str = "rc-wrp+jwt";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unsettable {
    #[error("{0}")]
    NotASubject(&'static str),
    #[error(
        "a key already awaits its certificate: take the certificate issued for it, or withdraw it"
    )]
    AlreadyAwaiting,
    #[error("no key awaits a certificate: request one first")]
    NothingAwaits,
    #[error(
        "send the certificate and the authorities that issued it, PEM encoded, in at most 32 KiB"
    )]
    ChainTooLarge,
    #[error("{0}")]
    Untaken(Untaken),
    #[error(
        "the realm presents itself by this key's certificate: present it by its did:web before \
         withdrawing the key"
    )]
    InService,
    #[error(
        "the realm holds no certificate valid now to present itself by: take one for its \
         verifier key first"
    )]
    NoCertificate,
    #[error("{0}")]
    NotADataset(&'static str),
    #[error("{0}")]
    NotARegistration(&'static str),
    #[error("this realm holds no such key")]
    NotFound,
    #[error("the verifier's identity could not be read or written")]
    Unwritable,
}

/// How the realm presents itself, as it last said, and the keys it holds to
/// present itself by a certificate.
#[derive(Debug, Clone, PartialEq)]
pub struct Verifier {
    pub settings: Option<VerifierSettings>,
    pub keys: Vec<VerifierKeyView>,
}

/// What an administrator wrote of how the realm presents itself.
pub struct WantedSettings {
    pub identity: VerifierIdentity,
    pub registrar_dataset: Option<Value>,
    pub registration_certificate: Option<String>,
}

pub async fn read(transaction: &UnitOfWork) -> Result<Verifier, Unsettable> {
    Ok(Verifier {
        settings: verifier::load_settings(transaction)
            .await
            .map_err(|_| Unsettable::Unwritable)?,
        keys: verifier::list_keys(transaction)
            .await
            .map_err(|_| Unsettable::Unwritable)?,
    })
}

/// Keep how the realm presents itself. By its certificate only while it
/// holds one valid at `now`; the registrar's dataset and the registration
/// certificate, when given, in the forms the European profile names.
pub async fn write_settings(
    transaction: &UnitOfWork,
    wanted: WantedSettings,
    by: &str,
    now: DateTime<Utc>,
) -> Result<VerifierSettings, Unsettable> {
    if let Some(dataset) = &wanted.registrar_dataset {
        check_registrar_dataset(dataset)?;
    }
    let registration_certificate = wanted
        .registration_certificate
        .map(|written| written.trim().to_owned());
    if let Some(certificate) = &registration_certificate {
        check_registration_certificate(certificate, now)?;
    }
    verifier::hold_changes(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    if wanted.identity == VerifierIdentity::X509Hash {
        let keys = verifier::list_keys(transaction)
            .await
            .map_err(|_| Unsettable::Unwritable)?;
        let certified = keys
            .iter()
            .filter(|key| key.state == VerifierKeyState::Serving)
            .filter_map(|key| key.certificate.as_ref())
            .any(|certificate| is_valid_at(certificate, now));
        if !certified {
            return Err(Unsettable::NoCertificate);
        }
    }
    let settings = VerifierSettings {
        identity: wanted.identity,
        registrar_dataset: wanted.registrar_dataset,
        registration_certificate,
        updated_by: by.to_owned(),
        updated_at: now.trunc_subsecs(6),
    };
    verifier::keep_settings(transaction, &settings)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    Ok(settings)
}

/// Draw a key and the request an authority certifies it from, naming
/// `subject`. The key awaits its certificate, signing nothing; while it
/// does, the key serving goes on serving. One key awaits at most.
pub async fn request_certificate(
    transaction: &UnitOfWork,
    signing: &Signing<'_>,
    subject: VerifierSubject,
    by: &str,
    now: DateTime<Utc>,
) -> Result<VerifierKeyView, Unsettable> {
    let subject = normalize_subject(subject)?;
    verifier::hold_changes(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    if verifier::hold_awaiting(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .is_some()
    {
        return Err(Unsettable::AlreadyAwaiting);
    }

    let pair = EcKeyPair::generate(EcCurve::P256).map_err(|_| Unsettable::Unwritable)?;
    let mut public = pair.to_jwk_public_key();
    let kid =
        jwk_sha256_thumbprint(signing.provider, &public).map_err(|_| Unsettable::Unwritable)?;
    public.set_key_id(kid.clone());
    public.set_key_use("sig");
    public.set_algorithm("ES256");
    let request_pem = crypto::x509::request_certificate(
        &PrivateKey::from_der(pair.to_der_private_key()),
        &RequestedSubject {
            common_name: &subject.common_name,
            organization: subject.organization.as_deref(),
            organization_identifier: subject.organization_identifier.as_deref(),
            country: subject.country.as_deref(),
        },
    )
    .ok_or(Unsettable::Unwritable)?;
    let drawn = DrawnVerifierKey {
        kid,
        private_pem: SecretBox::new(Box::new(pair.to_pem_private_key())),
        public_jwk: Value::Object(public.as_ref().clone()),
        subject,
        request_pem,
        created_by: by.to_owned(),
        created_at: now.trunc_subsecs(6),
    };
    match verifier::keep_drawn(transaction, signing.ring, signing.envelope, &drawn).await {
        Ok(()) => {}
        Err(StoreError::AlreadyExists) => return Err(Unsettable::AlreadyAwaiting),
        Err(_) => return Err(Unsettable::Unwritable),
    }
    Ok(VerifierKeyView {
        kid: drawn.kid,
        state: VerifierKeyState::Awaiting,
        public_jwk: drawn.public_jwk,
        subject: drawn.subject,
        request_pem: drawn.request_pem,
        certificate: None,
        created_by: drawn.created_by,
        created_at: drawn.created_at,
    })
}

/// Take the chain an authority issued for the key awaiting its certificate,
/// refused in words when it is not for that key or not valid at `now`. The
/// key then serves in place of the one serving, which is dropped.
pub async fn take_certificate(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    pem: &str,
    now: DateTime<Utc>,
) -> Result<VerifierKeyView, Unsettable> {
    if pem.len() > MAX_CHAIN_BYTES {
        return Err(Unsettable::ChainTooLarge);
    }
    verifier::hold_changes(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    let awaiting = verifier::hold_awaiting(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .ok_or(Unsettable::NothingAwaits)?;
    let key = awaiting
        .public_jwk
        .as_object()
        .and_then(public_key_from_jwk)
        .ok_or(Unsettable::Unwritable)?;
    let taken = take_certificate_chain(pem.as_bytes(), &key, now.timestamp())
        .map_err(Unsettable::Untaken)?;
    let leaf = taken.chain.first().ok_or(Unsettable::Unwritable)?;
    let digest = provider
        .digest()
        .hash(HashAlg::Sha256, leaf)
        .map_err(|_| Unsettable::Unwritable)?;
    let certificate = VerifierCertificate {
        leaf_hash: BASE64URL_NOPAD.encode(&digest),
        not_before: instant_of(taken.not_before)?,
        not_after: instant_of(taken.not_after)?,
        certified_at: now.trunc_subsecs(6),
        chain: taken.chain,
    };
    if !verifier::certify(transaction, &awaiting.kid, &certificate)
        .await
        .map_err(|_| Unsettable::Unwritable)?
    {
        return Err(Unsettable::NothingAwaits);
    }
    Ok(VerifierKeyView {
        state: VerifierKeyState::Serving,
        certificate: Some(certificate),
        ..awaiting
    })
}

/// Withdraw a key: one awaiting its certificate, or the one serving while
/// the realm does not present itself by it.
pub async fn withdraw_key(transaction: &UnitOfWork, kid: &str) -> Result<(), Unsettable> {
    verifier::hold_changes(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    let keys = verifier::list_keys(transaction)
        .await
        .map_err(|_| Unsettable::Unwritable)?;
    let key = keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or(Unsettable::NotFound)?;
    if key.state == VerifierKeyState::Serving {
        let identity = verifier::load_settings(transaction)
            .await
            .map_err(|_| Unsettable::Unwritable)?
            .map(|settings| settings.identity);
        if identity == Some(VerifierIdentity::X509Hash) {
            return Err(Unsettable::InService);
        }
    }
    verifier::withdraw(transaction, kid)
        .await
        .map_err(|_| Unsettable::Unwritable)?
        .then_some(())
        .ok_or(Unsettable::NotFound)
}

/// Whether a certificate is valid at `now`: from its first instant, until
/// its last one excluded.
pub fn is_valid_at(certificate: &VerifierCertificate, now: DateTime<Utc>) -> bool {
    certificate.not_before <= now && now < certificate.not_after
}

fn instant_of(seconds: i64) -> Result<DateTime<Utc>, Unsettable> {
    Utc.timestamp_opt(seconds, 0)
        .single()
        .ok_or(Unsettable::Unwritable)
}

/// The subject as the request names it: each name trimmed, an optional one
/// left empty taken as absent.
fn normalize_subject(subject: VerifierSubject) -> Result<VerifierSubject, Unsettable> {
    let common_name = subject.common_name.trim().to_owned();
    if common_name.is_empty() || common_name.chars().count() > MAX_NAME_CHARS {
        return Err(Unsettable::NotASubject(
            "a certificate request names a common name of 1 to 64 characters",
        ));
    }
    let optional = |name: Option<String>| {
        name.map(|written| written.trim().to_owned())
            .filter(|written| !written.is_empty())
    };
    let normalized = VerifierSubject {
        common_name,
        organization: optional(subject.organization),
        organization_identifier: optional(subject.organization_identifier),
        country: optional(subject.country),
    };
    let names = [
        Some(&normalized.common_name),
        normalized.organization.as_ref(),
        normalized.organization_identifier.as_ref(),
    ];
    if names
        .iter()
        .flatten()
        .any(|name| name.chars().count() > MAX_NAME_CHARS)
    {
        return Err(Unsettable::NotASubject(
            "a name in a certificate request is at most 64 characters",
        ));
    }
    if names
        .iter()
        .flatten()
        .any(|name| name.chars().any(char::is_control))
    {
        return Err(Unsettable::NotASubject(
            "a name in a certificate request holds no control character",
        ));
    }
    if normalized.country.as_ref().is_some_and(|country| {
        country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase())
    }) {
        return Err(Unsettable::NotASubject(
            "a country is two capital letters, as ISO 3166-1 writes it",
        ));
    }
    Ok(normalized)
}

/// The registrar's dataset holds what OIDFVP-HAIP-COMMON-REQ-RO-05 to RO-12
/// require of it, in the forms TS 119 475 Annex B writes them in.
fn check_registrar_dataset(dataset: &Value) -> Result<(), Unsettable> {
    let refuse = |why: &'static str| Err(Unsettable::NotADataset(why));
    let Some(members) = dataset.as_object() else {
        return refuse("the registrar's dataset is a JSON object");
    };
    if serde_json::to_vec(dataset).map_or(true, |written| written.len() > MAX_DATASET_BYTES) {
        return refuse("the registrar's dataset is at most 8 KiB");
    }
    let identified = members
        .get("identifier")
        .and_then(Value::as_array)
        .is_some_and(|identifiers| {
            !identifiers.is_empty()
                && identifiers.iter().all(|identifier| {
                    identifier
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| url::Url::parse(kind).is_ok())
                        && is_filled_text(identifier.get("identifier"))
                })
        });
    if !identified {
        return refuse(
            "the registrar's dataset names the relying party by an identifier: a type URI and a value",
        );
    }
    if !is_multilingual(members.get("srvDescription")) {
        return refuse(
            "the registrar's dataset describes the service in one language or more, each a lang \
             and a content",
        );
    }
    if !is_https(members.get("registryURI")) {
        return refuse("the registrar's dataset gives the registrar's API as an https URI");
    }
    if !is_filled_text(members.get("intendedUseIdentifier")) {
        return refuse("the registrar's dataset names the intended use the registrar registered");
    }
    if !is_multilingual(members.get("purpose")) {
        return refuse(
            "the registrar's dataset states the purpose of the processing in one language or \
             more, each a lang and a content",
        );
    }
    if !is_https(members.get("policyURI")) {
        return refuse("the registrar's dataset gives the privacy policy as an https URI");
    }
    let credentials_named = members.get("credential").is_none_or(|credentials| {
        credentials.as_array().is_some_and(|credentials| {
            !credentials.is_empty()
                && credentials
                    .iter()
                    .all(|credential| is_filled_text(credential.get("format")))
        })
    });
    if !credentials_named {
        return refuse(
            "the registrar's dataset lists the credentials of the intended use, each naming its \
             format",
        );
    }
    Ok(())
}

fn is_filled_text(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
}

fn is_https(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .and_then(|written| url::Url::parse(written).ok())
        .is_some_and(|parsed| parsed.scheme() == "https" && parsed.host().is_some())
}

/// An array of MultiLangString (TS 119 475 B.2.6), one at least: a language
/// written as ISO 639-1 with the subtags RFC 5646 adds, and its text.
fn is_multilingual(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(|texts| {
        !texts.is_empty()
            && texts.iter().all(|text| {
                text.get("lang")
                    .and_then(Value::as_str)
                    .is_some_and(is_language_tag)
                    && is_filled_text(text.get("content"))
            })
    })
}

fn is_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let language = subtags.next().unwrap_or_default();
    language.len() == 2
        && language.bytes().all(|byte| byte.is_ascii_lowercase())
        && subtags.all(|subtag| {
            (1..=8).contains(&subtag.len())
                && subtag.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

/// A registration certificate is a JWT in compact serialization typed
/// `rc-wrp+jwt`, carrying the chain it is verified with, issued and still
/// unexpired (TS 119 475, GEN-5.2.2-01 and GEN-5.2.4). Its signature is the
/// wallet's to verify, against the registrars its trusted lists name.
fn check_registration_certificate(written: &str, now: DateTime<Utc>) -> Result<(), Unsettable> {
    let refuse = |why: &'static str| Err(Unsettable::NotARegistration(why));
    if written.len() > MAX_REGISTRATION_BYTES {
        return refuse("send the registration certificate as a compact JWT in at most 16 KiB");
    }
    let parts: Vec<&str> = written.split('.').collect();
    let [header, payload, signature] = parts.as_slice() else {
        return refuse("send the registration certificate as a compact JWT in at most 16 KiB");
    };
    let decode = |part: &str| -> Option<Map<String, Value>> {
        let bytes = BASE64URL_NOPAD.decode(part.as_bytes()).ok()?;
        match serde_json::from_slice(&bytes).ok()? {
            Value::Object(members) => Some(members),
            _ => None,
        }
    };
    let (Some(header), Some(payload)) = (decode(header), decode(payload)) else {
        return refuse("send the registration certificate as a compact JWT in at most 16 KiB");
    };
    if signature.is_empty() || BASE64URL_NOPAD.decode(signature.as_bytes()).is_err() {
        return refuse("send the registration certificate as a compact JWT in at most 16 KiB");
    }
    if header.get("typ").and_then(Value::as_str) != Some(REGISTRATION_TYPE) {
        return refuse("the registration certificate is not typed rc-wrp+jwt");
    }
    let signed = header
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|alg| !alg.is_empty() && alg != "none");
    if !signed {
        return refuse("the registration certificate names no algorithm it is signed under");
    }
    let chained = header
        .get("x5c")
        .and_then(Value::as_array)
        .is_some_and(|chain| !chain.is_empty() && chain.iter().all(Value::is_string));
    if !chained {
        return refuse("the registration certificate carries no chain to verify it with");
    }
    if !payload.get("iat").is_some_and(Value::is_i64) || !is_filled_text(payload.get("sub")) {
        return refuse("the registration certificate states no subject or issuance time");
    }
    let unexpired = payload.get("exp").is_none_or(|expiry| {
        expiry
            .as_i64()
            .is_some_and(|expiry| expiry > now.timestamp())
    });
    if !unexpired {
        return refuse("the registration certificate has expired");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn subject(
        common_name: &str,
        organization: Option<&str>,
        organization_identifier: Option<&str>,
        country: Option<&str>,
    ) -> VerifierSubject {
        VerifierSubject {
            common_name: common_name.to_owned(),
            organization: organization.map(str::to_owned),
            organization_identifier: organization_identifier.map(str::to_owned),
            country: country.map(str::to_owned),
        }
    }

    fn refusal(outcome: Result<impl std::fmt::Debug, Unsettable>) -> String {
        outcome.expect_err("refused").to_string()
    }

    #[test]
    fn a_subject_is_trimmed_and_its_empty_names_left_out() {
        assert_eq!(
            normalize_subject(subject(
                " Acme verifier ",
                Some("  "),
                Some(" VATFR-1 "),
                Some("FR")
            )),
            Ok(subject("Acme verifier", None, Some("VATFR-1"), Some("FR")))
        );
    }

    #[test]
    fn a_subject_no_request_can_name_is_refused_in_words() {
        let long = "x".repeat(65);
        for (wanted, said) in [
            (
                subject(" ", None, None, None),
                "a certificate request names a common name of 1 to 64 characters",
            ),
            (
                subject(&long, None, None, None),
                "a certificate request names a common name of 1 to 64 characters",
            ),
            (
                subject("Acme", Some(&long), None, None),
                "a name in a certificate request is at most 64 characters",
            ),
            (
                subject("Acme", None, Some(&long), None),
                "a name in a certificate request is at most 64 characters",
            ),
            (
                subject("Acme\u{7}", None, None, None),
                "a name in a certificate request holds no control character",
            ),
            (
                subject("Acme", Some("Acme\nSA"), None, None),
                "a name in a certificate request holds no control character",
            ),
            (
                subject("Acme", None, None, Some("fr")),
                "a country is two capital letters, as ISO 3166-1 writes it",
            ),
            (
                subject("Acme", None, None, Some("FRA")),
                "a country is two capital letters, as ISO 3166-1 writes it",
            ),
        ] {
            assert_eq!(
                refusal(normalize_subject(wanted.clone())),
                said,
                "{wanted:?}"
            );
        }
        assert!(normalize_subject(subject(&"x".repeat(64), None, None, Some("DE"))).is_ok());
    }

    fn dataset() -> Value {
        json!({
            "identifier": [
                { "type": "http://data.europa.eu/eudi/id/LEI", "identifier": "529900T8BM49AURSDO55" }
            ],
            "srvDescription": [{ "lang": "en", "content": "Account opening" }],
            "registryURI": "https://registrar.example/api",
            "intendedUseIdentifier": "use-1",
            "purpose": [
                { "lang": "en-US", "content": "Know your customer" },
                { "lang": "fr", "content": "Connaître son client" }
            ],
            "policyURI": "https://acme.example/privacy",
            "credential": [{ "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } }],
        })
    }

    fn changed(change: impl FnOnce(&mut Map<String, Value>)) -> Value {
        let mut written = dataset();
        change(written.as_object_mut().expect("an object"));
        written
    }

    #[test]
    fn a_registrar_dataset_holds_what_the_european_profile_requires() {
        assert_eq!(check_registrar_dataset(&dataset()), Ok(()));
        assert_eq!(
            check_registrar_dataset(&changed(|members| {
                members.remove("credential");
            })),
            Ok(())
        );
        let identifier = "the registrar's dataset names the relying party by an identifier: a type \
                          URI and a value";
        let description = "the registrar's dataset describes the service in one language or more, \
                           each a lang and a content";
        let purpose = "the registrar's dataset states the purpose of the processing in one \
                       language or more, each a lang and a content";
        let credential = "the registrar's dataset lists the credentials of the intended use, each \
                          naming its format";
        let cases: Vec<(Value, &str)> = vec![
            (json!([]), "the registrar's dataset is a JSON object"),
            (
                changed(|members| {
                    members.insert("padding".into(), json!("x".repeat(MAX_DATASET_BYTES)));
                }),
                "the registrar's dataset is at most 8 KiB",
            ),
            (
                changed(|members| {
                    members.remove("identifier");
                }),
                identifier,
            ),
            (
                changed(|members| {
                    members.insert("identifier".into(), json!([]));
                }),
                identifier,
            ),
            (
                changed(|members| {
                    members.insert(
                        "identifier".into(),
                        json!([{ "type": "LEI", "identifier": "529900T8BM49AURSDO55" }]),
                    );
                }),
                identifier,
            ),
            (
                changed(|members| {
                    members.insert(
                        "identifier".into(),
                        json!([{ "type": "http://data.europa.eu/eudi/id/LEI", "identifier": " " }]),
                    );
                }),
                identifier,
            ),
            (
                changed(|members| {
                    members.remove("srvDescription");
                }),
                description,
            ),
            (
                changed(|members| {
                    members.insert(
                        "srvDescription".into(),
                        json!([{ "lang": "english", "content": "Account opening" }]),
                    );
                }),
                description,
            ),
            (
                changed(|members| {
                    members.insert(
                        "srvDescription".into(),
                        json!([{ "lang": "EN", "content": "Account opening" }]),
                    );
                }),
                description,
            ),
            (
                changed(|members| {
                    members.insert(
                        "srvDescription".into(),
                        json!([{ "lang": "en", "content": "" }]),
                    );
                }),
                description,
            ),
            (
                changed(|members| {
                    members.insert("registryURI".into(), json!("http://registrar.example/api"));
                }),
                "the registrar's dataset gives the registrar's API as an https URI",
            ),
            (
                changed(|members| {
                    members.remove("intendedUseIdentifier");
                }),
                "the registrar's dataset names the intended use the registrar registered",
            ),
            (
                changed(|members| {
                    members.insert("purpose".into(), json!([]));
                }),
                purpose,
            ),
            (
                changed(|members| {
                    members.insert("policyURI".into(), json!("privacy"));
                }),
                "the registrar's dataset gives the privacy policy as an https URI",
            ),
            (
                changed(|members| {
                    members.insert("credential".into(), json!([]));
                }),
                credential,
            ),
            (
                changed(|members| {
                    members.insert("credential".into(), json!([{ "meta": {} }]));
                }),
                credential,
            ),
        ];
        for (written, said) in cases {
            assert_eq!(
                check_registrar_dataset(&written)
                    .expect_err("refused")
                    .to_string(),
                said,
                "{written}"
            );
        }
    }

    fn jwt(header: Value, payload: Value, signature: &str) -> String {
        format!(
            "{}.{}.{signature}",
            BASE64URL_NOPAD.encode(header.to_string().as_bytes()),
            BASE64URL_NOPAD.encode(payload.to_string().as_bytes())
        )
    }

    #[test]
    fn a_registration_certificate_is_a_typed_signed_and_unexpired_jwt() {
        let now = Utc.timestamp_opt(1_790_000_000, 0).unwrap();
        let header = json!({ "typ": "rc-wrp+jwt", "alg": "ES256", "x5c": ["MIIB"] });
        let payload = json!({ "sub": "LEIXG-529900T8BM49AURSDO55", "iat": 1_789_990_000, "exp": 1_790_000_001 });
        assert_eq!(
            check_registration_certificate(&jwt(header.clone(), payload.clone(), "c2ln"), now),
            Ok(())
        );
        let unexpiring = json!({ "sub": "LEIXG-529900T8BM49AURSDO55", "iat": 1_789_990_000 });
        assert_eq!(
            check_registration_certificate(&jwt(header.clone(), unexpiring, "c2ln"), now),
            Ok(())
        );

        let compact = "send the registration certificate as a compact JWT in at most 16 KiB";
        let with_header = |change: Value| {
            let mut written = header.clone();
            written
                .as_object_mut()
                .expect("an object")
                .extend(change.as_object().expect("an object").clone());
            jwt(written, payload.clone(), "c2ln")
        };
        let with_payload = |written: Value| jwt(header.clone(), written, "c2ln");
        for (written, said) in [
            ("h.p".to_owned(), compact),
            (
                format!("{}.c2ln", jwt(header.clone(), payload.clone(), "c2ln")),
                compact,
            ),
            (format!("!!.{}", "e30.c2ln"), compact),
            (jwt(header.clone(), json!([]), "c2ln"), compact),
            (jwt(header.clone(), payload.clone(), ""), compact),
            (jwt(header.clone(), payload.clone(), "c2ln!"), compact),
            (
                jwt(
                    header.clone(),
                    json!({ "sub": "LEIXG-529900T8BM49AURSDO55", "iat": 1_789_990_000, "padding": "x".repeat(MAX_REGISTRATION_BYTES) }),
                    "c2ln",
                ),
                compact,
            ),
            (
                with_header(json!({ "typ": "JWT" })),
                "the registration certificate is not typed rc-wrp+jwt",
            ),
            (
                with_header(json!({ "alg": "none" })),
                "the registration certificate names no algorithm it is signed under",
            ),
            (
                with_header(json!({ "x5c": [] })),
                "the registration certificate carries no chain to verify it with",
            ),
            (
                with_payload(json!({ "sub": "LEIXG-529900T8BM49AURSDO55" })),
                "the registration certificate states no subject or issuance time",
            ),
            (
                with_payload(json!({ "iat": 1_789_990_000 })),
                "the registration certificate states no subject or issuance time",
            ),
            (
                with_payload(
                    json!({ "sub": "LEIXG-529900T8BM49AURSDO55", "iat": 1_789_990_000, "exp": 1_790_000_000 }),
                ),
                "the registration certificate has expired",
            ),
            (
                with_payload(
                    json!({ "sub": "LEIXG-529900T8BM49AURSDO55", "iat": 1_789_990_000, "exp": "soon" }),
                ),
                "the registration certificate has expired",
            ),
        ] {
            assert_eq!(
                refusal(check_registration_certificate(&written, now)),
                said,
                "{written}"
            );
        }
    }

    #[test]
    fn a_certificate_is_valid_from_its_first_instant_to_its_last_excluded() {
        let from = Utc.timestamp_opt(1_790_000_000, 0).unwrap();
        let until = Utc.timestamp_opt(1_790_086_400, 0).unwrap();
        let certificate = VerifierCertificate {
            chain: vec![b"leaf".to_vec()],
            leaf_hash: "h".to_owned(),
            not_before: from,
            not_after: until,
            certified_at: from,
        };
        assert!(is_valid_at(&certificate, from));
        assert!(is_valid_at(
            &certificate,
            until - chrono::Duration::seconds(1)
        ));
        assert!(!is_valid_at(&certificate, until));
        assert!(!is_valid_at(
            &certificate,
            from - chrono::Duration::seconds(1)
        ));
    }
}
