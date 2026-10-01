//! A credential's status, as the list its issuer publishes says it: an IETF
//! Token Status List for an SD-JWT VC (draft-ietf-oauth-status-list-21), a W3C
//! Bitstring Status List for a JSON-LD credential (Recommendation of
//! 2025-05-15).
//!
//! No presentation sends this server out to ask. A scheduled pass reads each
//! list a realm's credentials cite, under the keys the realm read from the
//! issuer of those credentials, and keeps it expanded; a presentation reads the
//! one byte holding the status it cites. A list nobody has read yet is written
//! down by the first credential citing it, and that credential is refused, as
//! is one citing a list that could not be read, may no longer be relied on, or
//! holds no status at the index cited. Revoked and suspended are both refused.

use std::collections::{HashMap, HashSet};
use std::io::Read;

use chrono::{DateTime, Duration, Utc};
use crypto::jose::jws;
use crypto::provider::CryptoProvider;
use data_encoding::BASE64URL_NOPAD;
use flate2::read::{GzDecoder, ZlibDecoder};
use jsonld::built_in::HeldContexts;
use jsonld::json::parse_strict;
use jsonld::proof::{Unproven, read_proof, verify_proof};
use jsonld::rdf::{Literal, Node, Object, Quad, XSD_STRING};
use jsonld::{Contexts, Unreadable, to_rdf};
use serde_json::{Map, Value};
use store::providers::realms::status_lists::{self, DueList, KeptReading, ListSigners};
use store::tenancy::UnitOfWork;

use super::linked_data::{BOUNDS, asserting_keys};
use super::presentation::{LEEWAY_SECONDS, Unanswerable, candidate_keys, verifier_for};

/// The most a list's statuses may take once expanded: some thirty million
/// statuses of one bit.
pub const MOST_STATUS_BYTES: usize = 4 * 1024 * 1024;
/// The fewest statuses a bitstring list holds, for the privacy of the herd
/// (Bitstring Status List §3.2).
const FEWEST_BITSTRING_STATUSES: usize = 131_072;
/// The most statuses one credential cites: a revocation and a suspension, and
/// room beside them.
const MOST_CITATIONS: usize = 4;
/// The most lists a realm keeps.
const MOST_LISTS: i64 = 1_000;
/// How many lists of one realm one pass reads.
const MOST_LISTS_PER_PASS: i64 = 20;
/// The bounds a list is read again within, whatever its issuer asks: often
/// enough that a revocation is seen within the hour, seldom enough that an
/// issuer asking for every second is not dialled every second.
const REFRESH_AT_LEAST: Duration = Duration::minutes(5);
const REFRESH_AT_MOST: Duration = Duration::hours(1);
/// How long after it was read a list may be relied on, when its issuer says
/// less; past that, its credentials are refused until it is read again.
const RELIED_ON_AT_MOST: Duration = Duration::hours(24);
/// When a list that could not be read is tried again.
const READ_AGAIN_AFTER_FAILURE: Duration = Duration::minutes(5);
/// How often a citation is written down, so the sweep knows a list in use.
const CITED_NOTED_EVERY: Duration = Duration::days(1);

const RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
const VERIFIABLE_CREDENTIAL: &str = "https://www.w3.org/2018/credentials#VerifiableCredential";
const CREDENTIAL_STATUS: &str = "https://www.w3.org/2018/credentials#credentialStatus";
const CREDENTIAL_SUBJECT: &str = "https://www.w3.org/2018/credentials#credentialSubject";
const ISSUER: &str = "https://www.w3.org/2018/credentials#issuer";
const VALID_FROM: [&str; 2] = [
    "https://www.w3.org/2018/credentials#validFrom",
    "https://www.w3.org/2018/credentials#issuanceDate",
];
const VALID_UNTIL: [&str; 2] = [
    "https://www.w3.org/2018/credentials#validUntil",
    "https://www.w3.org/2018/credentials#expirationDate",
];
const STATUS_ENTRY: &str = "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry";
const STATUS_PURPOSE: &str = "https://www.w3.org/ns/credentials/status#statusPurpose";
const STATUS_INDEX: &str = "https://www.w3.org/ns/credentials/status#statusListIndex";
const STATUS_LIST: &str = "https://www.w3.org/ns/credentials/status#statusListCredential";
const STATUS_SIZE: &str = "https://www.w3.org/ns/credentials/status#statusSize";
const LIST_CREDENTIAL: &str =
    "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential";
const LIST_SUBJECT: &str = "https://www.w3.org/ns/credentials/status#BitstringStatusList";
const ENCODED_LIST: &str = "https://www.w3.org/ns/credentials/status#encodedList";
const LIST_TIME_TO_LIVE: &str = "https://www.w3.org/ns/credentials/status#ttl";
const MULTIBASE: &str = "https://w3id.org/security#multibase";

pub const STATUS_DISCLOSED: &str = "a credential discloses its status selectively";
pub const STATUS_UNREAD: &str =
    "a credential's status is declared in a form this verifier does not read";
pub const TOO_MANY_CITATIONS: &str = "a credential cites more statuses than this verifier reads";
pub const MANY_BITS: &str =
    "a credential's status takes more than one bit, which this verifier does not read";
pub const LIST_NOT_READ_YET: &str =
    "a credential's status list has not been read yet: it will be shortly";
pub const LISTS_FULL: &str = "the realm already follows as many status lists as it keeps";
pub const LIST_NEVER_READ: &str = "a credential's status list could not be read";
pub const LIST_STALE: &str = "a credential's status list may no longer be relied on";
pub const LIST_OTHER_PURPOSE: &str =
    "a credential's status list does not serve the purpose its status names";
pub const STATUS_OUT_OF_LIST: &str = "a credential's status is not in its list";
pub const REVOKED: &str = "a credential has been revoked by its issuer";
pub const SUSPENDED: &str = "a credential has been suspended by its issuer";
pub const STATUS_DENIES: &str = "a credential's status says it does not hold";

pub const LIST_UNFETCHED: &str = "nothing could be read at the status list's address";
pub const LIST_UNREAD: &str = "the status list is not one this verifier reads";
pub const NOT_A_LIST_TOKEN: &str = "the status list is not a token typed statuslist+jwt";
pub const LIST_SIGNATURE: &str = "the status list is not signed by its credentials' issuer";
pub const LIST_PROOF: &str = "the status list carries no proof this verifier reads";
pub const LIST_NOT_ASSERTED: &str = "the status list's proof is not an assertion";
pub const LIST_CONTEXT: &str = "the status list names a JSON-LD context this realm does not pin";
pub const LIST_ELSEWHERE: &str = "the status list speaks for another address";
pub const LIST_OF_ANOTHER_ISSUER: &str = "the status list is not its credentials' issuer's";
pub const LIST_NOT_YET: &str = "the status list is not valid yet";
pub const LIST_EXPIRED: &str = "the status list has expired";
pub const UNREADABLE_STATUSES: &str = "the status list's statuses could not be expanded";
pub const TOO_MANY_STATUSES: &str = "the status list holds more statuses than this verifier keeps";
pub const TOO_FEW_STATUSES: &str = "the status list holds fewer statuses than herd privacy asks";
pub const LIST_OLDER: &str = "the status list served is older than the one kept";

/// How a list is written, and so how a status is read from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    Token,
    Bitstring,
}

impl ListFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Bitstring => "bitstring",
        }
    }

    pub fn parse(written: &str) -> Option<Self> {
        [Self::Token, Self::Bitstring]
            .into_iter()
            .find(|format| format.as_str() == written)
    }

    /// The media type a list of this format is asked for as (§8.1); a
    /// bitstring list is asked for as its address serves it.
    pub fn asked_as(self) -> Option<&'static str> {
        match self {
            Self::Token => Some("application/statuslist+jwt"),
            Self::Bitstring => None,
        }
    }
}

/// What a bitstring entry's bit stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Revocation,
    Suspension,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Revocation => "revocation",
            Self::Suspension => "suspension",
        }
    }
}

/// One status a credential cites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Citation {
    pub format: ListFormat,
    pub uri: String,
    pub index: u64,
    /// What a bitstring entry's bit stands for; a token list's status says it.
    pub purpose: Option<Purpose>,
}

/// Expand what a compressed list holds, refusing more than
/// `MOST_STATUS_BYTES` however little it took compressed.
fn inflate(reader: impl Read) -> Result<Vec<u8>, &'static str> {
    let mut expanded = Vec::new();
    reader
        .take(MOST_STATUS_BYTES as u64 + 1)
        .read_to_end(&mut expanded)
        .map_err(|_| UNREADABLE_STATUSES)?;
    if expanded.is_empty() {
        return Err(UNREADABLE_STATUSES);
    }
    if expanded.len() > MOST_STATUS_BYTES {
        return Err(TOO_MANY_STATUSES);
    }
    Ok(expanded)
}

/// A token list's statuses: base64url without padding over ZLIB (§4.1, §4.2).
pub fn expand_token_statuses(lst: &str) -> Result<Vec<u8>, &'static str> {
    let compressed = BASE64URL_NOPAD
        .decode(lst.as_bytes())
        .map_err(|_| UNREADABLE_STATUSES)?;
    inflate(ZlibDecoder::new(compressed.as_slice()))
}

/// A bitstring list's statuses: multibase base64url without padding, `u`,
/// over GZIP (§2.2).
pub fn expand_bitstring(encoded: &str) -> Result<Vec<u8>, &'static str> {
    let encoded = encoded.strip_prefix('u').ok_or(UNREADABLE_STATUSES)?;
    let compressed = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .map_err(|_| UNREADABLE_STATUSES)?;
    inflate(GzDecoder::new(compressed.as_slice()))
}

/// The status at `index`, in the byte of the list holding it, `bits` to a
/// status: a token list packs its statuses from the least significant bit of
/// each byte (§4.1), a bitstring list from the most significant (§2.2).
pub fn status_in_byte(format: ListFormat, byte: u8, index: u64, bits: u8) -> u8 {
    match format {
        ListFormat::Token => {
            let shift = (index * u64::from(bits) % 8) as u32;
            let mask = u8::MAX >> (8 - u32::from(bits.clamp(1, 8)));
            (byte >> shift) & mask
        }
        ListFormat::Bitstring => (byte >> (7 - (index % 8) as u32)) & 1,
    }
}

/// The status at `index` of a whole list, or nothing past its end.
pub fn status_at(format: ListFormat, statuses: &[u8], index: u64, bits: u8) -> Option<u8> {
    let byte = index.checked_mul(u64::from(bits))? / 8;
    let byte = statuses.get(usize::try_from(byte).ok()?)?;
    Some(status_in_byte(format, *byte, index, bits))
}

/// Whether a list may be read at this address: https, or plain http to the
/// machine itself, with no credentials, and of a length an address has.
fn is_list_address(uri: &str) -> bool {
    uri.len() <= 2048
        && commons::address::is_https_or_loopback(uri)
        && url::Url::parse(uri)
            .is_ok_and(|parsed| parsed.username().is_empty() && parsed.password().is_none())
}

/// The status an SD-JWT VC cites, read off what its issuer signed. The
/// `status` claim may not be disclosed selectively (SD-JWT VC §3.2.2.2): one a
/// disclosure wrote, or changed, refuses the credential, as does one naming any
/// mechanism but a status list.
pub(super) fn read_token_citation(
    signed: &Map<String, Value>,
    disclosed: &Map<String, Value>,
) -> Result<Option<Citation>, &'static str> {
    let status = match (signed.get("status"), disclosed.get("status")) {
        (None, None) => return Ok(None),
        (Some(signed), Some(disclosed)) if signed == disclosed => signed,
        _ => return Err(STATUS_DISCLOSED),
    };
    let reference = status
        .as_object()
        .filter(|mechanisms| mechanisms.len() == 1)
        .and_then(|mechanisms| mechanisms.get("status_list"))
        .and_then(Value::as_object)
        .ok_or(STATUS_UNREAD)?;
    let index = reference
        .get("idx")
        .and_then(Value::as_u64)
        .ok_or(STATUS_UNREAD)?;
    let uri = reference
        .get("uri")
        .and_then(Value::as_str)
        .filter(|uri| is_list_address(uri))
        .ok_or(STATUS_UNREAD)?;
    Ok(Some(Citation {
        format: ListFormat::Token,
        uri: uri.to_owned(),
        index,
        purpose: None,
    }))
}

/// The objects `quads` give `predicate` of `subject` in the default graph,
/// each once: a dataset is a set.
fn values_of<'q>(quads: &'q [Quad], subject: &Node, predicate: &str) -> Vec<&'q Object> {
    let mut seen = HashSet::new();
    quads
        .iter()
        .filter(|quad| quad.graph.is_none() && &quad.subject == subject)
        .filter(|quad| quad.predicate == predicate)
        .map(|quad| &quad.object)
        .filter(|object| seen.insert(*object))
        .collect()
}

fn names_iri(objects: &[&Object], iri: &str) -> bool {
    objects
        .iter()
        .any(|object| matches!(object, Object::Node(Node::Iri(named)) if named == iri))
}

/// The one value among `objects`, when there is exactly one.
fn one<'q>(objects: &[&'q Object]) -> Option<&'q Object> {
    match objects {
        [only] => Some(*only),
        _ => None,
    }
}

fn as_literal(object: &Object) -> Option<&Literal> {
    match object {
        Object::Literal(literal) => Some(literal),
        Object::Node(_) => None,
    }
}

/// A plain string, as JSON-LD writes a JSON string no context types.
fn as_text(object: &Object) -> Option<&str> {
    as_literal(object)
        .filter(|literal| literal.datatype == XSD_STRING && literal.language.is_none())
        .map(|literal| literal.lexical.as_str())
}

/// The statuses a JSON-LD credential cites, read off the dataset its proof
/// signs: each `BitstringStatusListEntry` of the one node holding
/// `credentialStatus`, each member of each entry holding one value. An entry
/// for `refresh` says nothing of whether the credential holds and is passed
/// over. Any other purpose than revocation and suspension, any other kind of
/// entry, and an entry of more than one bit refuse the credential.
pub(super) fn read_bitstring_citations(quads: &[Quad]) -> Result<Vec<Citation>, &'static str> {
    let declared: Vec<&Quad> = quads
        .iter()
        .filter(|quad| quad.predicate == CREDENTIAL_STATUS)
        .collect();
    if declared.is_empty() {
        return Ok(Vec::new());
    }
    let holders: HashSet<&Node> = declared.iter().map(|quad| &quad.subject).collect();
    if holders.len() != 1 || declared.iter().any(|quad| quad.graph.is_some()) {
        return Err(STATUS_UNREAD);
    }
    if declared.len() > MOST_CITATIONS {
        return Err(TOO_MANY_CITATIONS);
    }
    let mut citations = Vec::with_capacity(declared.len());
    for quad in declared {
        let Object::Node(entry) = &quad.object else {
            return Err(STATUS_UNREAD);
        };
        if !names_iri(&values_of(quads, entry, RDF_TYPE), STATUS_ENTRY) {
            return Err(STATUS_UNREAD);
        }
        let purpose = match one(&values_of(quads, entry, STATUS_PURPOSE)).and_then(as_text) {
            Some("revocation") => Purpose::Revocation,
            Some("suspension") => Purpose::Suspension,
            Some("refresh") => continue,
            _ => return Err(STATUS_UNREAD),
        };
        let index = one(&values_of(quads, entry, STATUS_INDEX))
            .and_then(as_text)
            .filter(|index| index.len() <= 20 && index.bytes().all(|digit| digit.is_ascii_digit()))
            .and_then(|index| index.parse::<u64>().ok())
            .ok_or(STATUS_UNREAD)?;
        let uri = match one(&values_of(quads, entry, STATUS_LIST)) {
            Some(Object::Node(Node::Iri(uri))) if is_list_address(uri) => uri.clone(),
            _ => return Err(STATUS_UNREAD),
        };
        match values_of(quads, entry, STATUS_SIZE).as_slice() {
            [] => {}
            [size] if as_literal(size).is_some_and(|size| size.lexical == "1") => {}
            _ => return Err(MANY_BITS),
        }
        citations.push(Citation {
            format: ListFormat::Bitstring,
            uri,
            index,
            purpose: Some(purpose),
        });
    }
    Ok(citations)
}

/// What the lists kept say of the statuses the credentials of one answer cite,
/// each list under the issuer of the credential citing it: the first refusal,
/// once every list not read yet has been written down for the pass.
pub(super) async fn check_citations(
    transaction: &UnitOfWork,
    cited: &[(String, Vec<Citation>)],
    now: DateTime<Utc>,
) -> Result<Result<(), &'static str>, Unanswerable> {
    let mut refusal = None;
    for (issuer_id, citations) in cited {
        for citation in citations {
            if let Err(why) = check_citation(transaction, issuer_id, citation, now).await? {
                refusal.get_or_insert(why);
            }
        }
    }
    Ok(refusal.map_or(Ok(()), Err))
}

async fn check_citation(
    transaction: &UnitOfWork,
    issuer_id: &str,
    citation: &Citation,
    now: DateTime<Utc>,
) -> Result<Result<(), &'static str>, Unanswerable> {
    let format = citation.format.as_str();
    // No list kept reaches past this, whatever the bits to a status.
    let Some(index) = i64::try_from(citation.index)
        .ok()
        .filter(|index| *index < (MOST_STATUS_BYTES * 8) as i64)
    else {
        return Ok(Err(STATUS_OUT_OF_LIST));
    };
    let Some(cited) =
        status_lists::read_cited(transaction, issuer_id, &citation.uri, format, index)
            .await
            .map_err(|_| Unanswerable::Unwritable)?
    else {
        let written = status_lists::write_down(
            transaction,
            issuer_id,
            &citation.uri,
            format,
            &now,
            MOST_LISTS,
        )
        .await
        .map_err(|_| Unanswerable::Unwritable)?;
        return Ok(Err(if written {
            LIST_NOT_READ_YET
        } else {
            LISTS_FULL
        }));
    };
    if now - cited.cited_at >= CITED_NOTED_EVERY {
        status_lists::note_cited(transaction, issuer_id, &citation.uri, format, &now)
            .await
            .map_err(|_| Unanswerable::Unwritable)?;
    }
    let Some(reading) = cited.reading else {
        return Ok(Err(if cited.failed {
            LIST_NEVER_READ
        } else {
            LIST_NOT_READ_YET
        }));
    };
    if reading.usable_until <= now {
        return Ok(Err(LIST_STALE));
    }
    if let Some(purpose) = citation.purpose {
        let served = reading.purposes.as_deref().unwrap_or_default();
        if !served.iter().any(|served| served == purpose.as_str()) {
            return Ok(Err(LIST_OTHER_PURPOSE));
        }
    }
    let bits = match citation.format {
        ListFormat::Token => reading
            .bits
            .and_then(|bits| u8::try_from(bits).ok())
            .ok_or(Unanswerable::Unwritable)?,
        ListFormat::Bitstring => 1,
    };
    let Some(byte) = reading.byte else {
        return Ok(Err(STATUS_OUT_OF_LIST));
    };
    let status = status_in_byte(citation.format, byte, citation.index, bits);
    Ok(match (citation.format, citation.purpose, status) {
        (_, _, 0) => Ok(()),
        (ListFormat::Token, _, 1) | (ListFormat::Bitstring, Some(Purpose::Revocation), _) => {
            Err(REVOKED)
        }
        (ListFormat::Token, _, 2) | (ListFormat::Bitstring, Some(Purpose::Suspension), _) => {
            Err(SUSPENDED)
        }
        _ => Err(STATUS_DENIES),
    })
}

/// A reading of a list, verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadList {
    pub statuses: Vec<u8>,
    /// Bits to a status of a token list.
    pub bits: Option<u8>,
    /// The purposes a bitstring list serves.
    pub purposes: Vec<String>,
    /// When the issuer wrote it, when it says.
    pub issued_at: Option<DateTime<Utc>>,
    /// When its issuer says it may no longer be relied on.
    pub expires_at: Option<DateTime<Utc>>,
    /// How soon its issuer asks for it to be read again.
    pub time_to_live: Option<Duration>,
}

/// A JSON number of seconds since the epoch, as JWT writes times.
fn read_epoch(written: &Value) -> Result<DateTime<Utc>, &'static str> {
    written
        .as_f64()
        .filter(|seconds| seconds.is_finite())
        .and_then(|seconds| DateTime::from_timestamp(seconds.floor() as i64, 0))
        .ok_or(LIST_UNREAD)
}

/// A header's `typ`, which RFC 7515 lets be written with or without its
/// `application/` and in any case.
fn is_list_token_type(written: &str) -> bool {
    let written = written.to_ascii_lowercase();
    written.strip_prefix("application/").unwrap_or(&written) == "statuslist+jwt"
}

/// A Token Status List read from the token its address served (§5.1, §8.3):
/// typed, signed under a key of the issuer of the credentials citing it,
/// speaking for that address, issued, not expired, its statuses expanded.
pub fn read_token_list(
    issuer: &str,
    keys: &[Value],
    uri: &str,
    token: &str,
    now: DateTime<Utc>,
) -> Result<ReadList, &'static str> {
    let token = token.trim();
    let header = token
        .split('.')
        .next()
        .and_then(|header| BASE64URL_NOPAD.decode(header.as_bytes()).ok())
        .and_then(|header| match serde_json::from_slice::<Value>(&header) {
            Ok(Value::Object(header)) => Some(header),
            _ => None,
        })
        .ok_or(NOT_A_LIST_TOKEN)?;
    if !header
        .get("typ")
        .and_then(Value::as_str)
        .is_some_and(is_list_token_type)
    {
        return Err(NOT_A_LIST_TOKEN);
    }
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(LIST_SIGNATURE)?;
    let kid = header.get("kid").and_then(Value::as_str);
    let payload = candidate_keys(keys, kid)
        .iter()
        .filter_map(|jwk| verifier_for(algorithm, jwk))
        .find_map(|verifier| jws::deserialize_compact(token, verifier.as_ref()).ok())
        .map(|(payload, _)| payload)
        .ok_or(LIST_SIGNATURE)?;
    let Ok(Value::Object(claims)) = serde_json::from_slice::<Value>(&payload) else {
        return Err(LIST_UNREAD);
    };
    if claims.get("sub").and_then(Value::as_str) != Some(uri) {
        return Err(LIST_ELSEWHERE);
    }
    if claims
        .get("iss")
        .is_some_and(|named| named.as_str() != Some(issuer))
    {
        return Err(LIST_OF_ANOTHER_ISSUER);
    }
    let leeway = Duration::seconds(LEEWAY_SECONDS);
    let issued_at = read_epoch(claims.get("iat").ok_or(LIST_UNREAD)?)?;
    let not_before = claims.get("nbf").map(read_epoch).transpose()?;
    if issued_at.max(not_before.unwrap_or(issued_at)) > now + leeway {
        return Err(LIST_NOT_YET);
    }
    let expires_at = claims.get("exp").map(read_epoch).transpose()?;
    if expires_at.is_some_and(|at| at + leeway <= now) {
        return Err(LIST_EXPIRED);
    }
    let time_to_live = claims
        .get("ttl")
        .map(|ttl| {
            ttl.as_f64()
                .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
                .map(|seconds| Duration::seconds(seconds.ceil().min(1e9) as i64))
                .ok_or(LIST_UNREAD)
        })
        .transpose()?;
    let list = claims
        .get("status_list")
        .and_then(Value::as_object)
        .ok_or(LIST_UNREAD)?;
    let bits = list
        .get("bits")
        .and_then(Value::as_u64)
        .filter(|bits| matches!(bits, 1 | 2 | 4 | 8))
        .and_then(|bits| u8::try_from(bits).ok())
        .ok_or(LIST_UNREAD)?;
    let lst = list.get("lst").and_then(Value::as_str).ok_or(LIST_UNREAD)?;
    Ok(ReadList {
        statuses: expand_token_statuses(lst)?,
        bits: Some(bits),
        purposes: Vec::new(),
        issued_at: Some(issued_at),
        expires_at,
        time_to_live,
    })
}

/// A list's dates, read under VCDM 2.0's names or 1.1's, at most one each.
fn read_date(
    quads: &[Quad],
    list: &Node,
    names: [&str; 2],
) -> Result<Option<DateTime<Utc>>, &'static str> {
    let written: Vec<&Object> = names
        .iter()
        .flat_map(|name| values_of(quads, list, name))
        .collect();
    match written.as_slice() {
        [] => Ok(None),
        [date] => as_literal(date)
            .and_then(|date| DateTime::parse_from_rfc3339(&date.lexical).ok())
            .map(|date| Some(date.with_timezone(&Utc)))
            .ok_or(LIST_UNREAD),
        _ => Err(LIST_UNREAD),
    }
}

/// A proof over a list that does not hold, in the realm's words.
fn refused_list_proof(why: Unproven) -> &'static str {
    match why {
        Unproven::Signature => LIST_SIGNATURE,
        Unproven::Unreadable(Unreadable::UnknownContext(_)) => LIST_CONTEXT,
        _ => LIST_PROOF,
    }
}

/// A Bitstring Status List read from the credential its address served
/// (§2.2, §3.2): asserted by a key the issuer of the credentials citing it
/// asserts with, issued by that issuer at that address, valid now, serving one
/// purpose or more, its bitstring expanded to the length herd privacy asks.
/// Everything is read off the dataset its proof signs.
pub fn read_bitstring_list(
    provider: &dyn CryptoProvider,
    contexts: &dyn Contexts,
    issuer: &str,
    keys: &[Value],
    uri: &str,
    document: &str,
    now: DateTime<Utc>,
) -> Result<ReadList, &'static str> {
    let mut document = parse_strict(document.as_bytes()).map_err(|_| LIST_UNREAD)?;
    let proof = read_proof(&document).map_err(|_| LIST_PROOF)?;
    if proof.proof_purpose.as_deref() != Some("assertionMethod") {
        return Err(LIST_NOT_ASSERTED);
    }
    let asserting = asserting_keys(keys, &proof.verification_method);
    if asserting.is_empty() {
        return Err(LIST_SIGNATURE);
    }
    verify_proof(provider, &document, contexts, &asserting, BOUNDS).map_err(refused_list_proof)?;
    if let Some(members) = document.as_object_mut() {
        members.remove("proof");
    }
    let quads = to_rdf(&document, contexts, BOUNDS.most_quads).map_err(|_| LIST_UNREAD)?;

    let list = Node::Iri(uri.to_owned());
    let types = values_of(&quads, &list, RDF_TYPE);
    if types.is_empty() {
        return Err(LIST_ELSEWHERE);
    }
    if !names_iri(&types, VERIFIABLE_CREDENTIAL) || !names_iri(&types, LIST_CREDENTIAL) {
        return Err(LIST_UNREAD);
    }
    match one(&values_of(&quads, &list, ISSUER)) {
        Some(Object::Node(Node::Iri(named))) if named == issuer => {}
        _ => return Err(LIST_OF_ANOTHER_ISSUER),
    }
    let leeway = Duration::seconds(LEEWAY_SECONDS);
    if read_date(&quads, &list, VALID_FROM)?.is_some_and(|from| from > now + leeway) {
        return Err(LIST_NOT_YET);
    }
    let expires_at = read_date(&quads, &list, VALID_UNTIL)?;
    if expires_at.is_some_and(|until| until + leeway <= now) {
        return Err(LIST_EXPIRED);
    }

    let Some(Object::Node(subject)) = one(&values_of(&quads, &list, CREDENTIAL_SUBJECT)) else {
        return Err(LIST_UNREAD);
    };
    if !names_iri(&values_of(&quads, subject, RDF_TYPE), LIST_SUBJECT) {
        return Err(LIST_UNREAD);
    }
    let purposes: Vec<String> = values_of(&quads, subject, STATUS_PURPOSE)
        .into_iter()
        .map(|purpose| as_text(purpose).map(str::to_owned))
        .collect::<Option<_>>()
        .filter(|purposes: &Vec<String>| (1..=8).contains(&purposes.len()))
        .ok_or(LIST_UNREAD)?;
    let encoded = one(&values_of(&quads, subject, ENCODED_LIST))
        .and_then(as_literal)
        .filter(|encoded| encoded.datatype == MULTIBASE)
        .ok_or(LIST_UNREAD)?;
    let statuses = expand_bitstring(&encoded.lexical)?;
    if statuses.len() * 8 < FEWEST_BITSTRING_STATUSES {
        return Err(TOO_FEW_STATUSES);
    }
    let time_to_live = match values_of(&quads, subject, LIST_TIME_TO_LIVE).as_slice() {
        [] => None,
        [milliseconds] => Some(
            as_literal(milliseconds)
                .map(|milliseconds| milliseconds.lexical.as_str())
                .filter(|milliseconds| {
                    !milliseconds.is_empty()
                        && milliseconds.len() <= 15
                        && milliseconds.bytes().all(|digit| digit.is_ascii_digit())
                })
                .and_then(|milliseconds| milliseconds.parse::<i64>().ok())
                .map(Duration::milliseconds)
                .ok_or(LIST_UNREAD)?,
        ),
        _ => return Err(LIST_UNREAD),
    };
    let issued_at = proof
        .created
        .as_deref()
        .map(|created| {
            DateTime::parse_from_rfc3339(created)
                .map(|created| created.with_timezone(&Utc))
                .map_err(|_| LIST_UNREAD)
        })
        .transpose()?;
    Ok(ReadList {
        statuses,
        bits: None,
        purposes,
        issued_at,
        expires_at,
        time_to_live,
    })
}

/// The lists of one realm a pass reads, claimed, with the contexts a bitstring
/// list is read under.
#[derive(Debug, Default)]
pub struct DueLists {
    pub lists: Vec<DueList>,
    pub contexts: HashMap<String, Value>,
}

/// Claim the lists of the realm this transaction is scoped to that are due:
/// none where the realm does not run the verifier.
pub async fn claim_due_lists(transaction: &UnitOfWork, now: DateTime<Utc>) -> Result<DueLists, ()> {
    if !crate::realm::feature::runs_for_realm(
        transaction,
        commons::feature::Feature::WalletVerifier,
    )
    .await
    {
        return Ok(DueLists::default());
    }
    let lists = status_lists::claim_due(
        transaction,
        &now,
        &(now + READ_AGAIN_AFTER_FAILURE),
        MOST_LISTS_PER_PASS,
    )
    .await
    .map_err(|_| ())?;
    let contexts = if lists
        .iter()
        .any(|list| list.format == ListFormat::Bitstring.as_str())
    {
        crate::admin::jsonld_contexts::pinned_documents(transaction)
            .await
            .map_err(|_| ())?
    } else {
        HashMap::new()
    };
    Ok(DueLists { lists, contexts })
}

/// Read a due list from what its address served, or say why it was not.
pub fn read_due_list(
    provider: &dyn CryptoProvider,
    contexts: &HashMap<String, Value>,
    due: &DueList,
    served: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ReadList, &'static str> {
    let served = served.ok_or(LIST_UNFETCHED)?;
    let ListSigners::Keys(keys) = &due.signers else {
        return Err(LIST_SIGNATURE);
    };
    match ListFormat::parse(&due.format) {
        Some(ListFormat::Token) => read_token_list(&due.issuer, keys, &due.uri, served, now),
        Some(ListFormat::Bitstring) => read_bitstring_list(
            provider,
            &HeldContexts::new(contexts),
            &due.issuer,
            keys,
            &due.uri,
            served,
            now,
        ),
        None => Err(LIST_UNREAD),
    }
}

/// Until when a reading made `now` may be relied on, and when its list is due
/// again: relied on until its issuer says or a day has passed; due when its
/// issuer asks within the bounds this server sets, and before it expires, a
/// tenth later at most by `drawn` so that lists read together are not read
/// again together.
fn plan_reading(read: &ReadList, now: DateTime<Utc>, drawn: u32) -> (DateTime<Utc>, DateTime<Utc>) {
    let relied_on = now + RELIED_ON_AT_MOST;
    let usable_until = read.expires_at.map_or(relied_on, |at| at.min(relied_on));
    let refresh = read
        .time_to_live
        .unwrap_or(REFRESH_AT_MOST)
        .clamp(REFRESH_AT_LEAST, REFRESH_AT_MOST);
    let spread = i64::from(drawn) % (refresh.num_seconds() / 10 + 1);
    let mut due_at = now + refresh + Duration::seconds(spread);
    if let Some(expires_at) = read.expires_at {
        due_at = due_at.min(expires_at.max(now + REFRESH_AT_LEAST));
    }
    (usable_until, due_at)
}

/// Keep a reading made `now`, planned as `plan_reading` says. False when the
/// issuer wrote the reading kept later than this one.
pub async fn keep_list(
    transaction: &UnitOfWork,
    provider: &dyn CryptoProvider,
    due: &DueList,
    read: &ReadList,
    now: DateTime<Utc>,
) -> Result<bool, ()> {
    let mut drawn = [0u8; 4];
    provider.rand().fill(&mut drawn).map_err(|_| ())?;
    let (usable_until, due_at) = plan_reading(read, now, u32::from_be_bytes(drawn));
    let bits = read.bits.map(i16::from);
    let purposes = (!read.purposes.is_empty()).then_some(read.purposes.as_slice());
    status_lists::keep_reading(
        transaction,
        &KeptReading {
            issuer_id: &due.issuer_id,
            uri: &due.uri,
            format: &due.format,
            statuses: &read.statuses,
            bits,
            purposes,
            issued_at: read.issued_at,
            read_at: now,
            usable_until,
            due_at,
        },
    )
    .await
    .map_err(|_| ())
}

/// Say why a list was not kept. The reading kept before stays, until it may
/// no longer be relied on.
pub async fn note_unread_list(
    transaction: &UnitOfWork,
    due: &DueList,
    why: &str,
) -> Result<(), ()> {
    status_lists::note_unread(transaction, &due.issuer_id, &due.uri, &due.format, why)
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The examples of §4.1: sixteen statuses of one bit, twelve of two.
    #[test]
    fn a_token_list_is_read_from_its_least_significant_bit() {
        let one_bit = expand_token_statuses("eNrbuRgAAhcBXQ").expect("statuses");
        assert_eq!(one_bit, [0xb9, 0xa3]);
        let expected = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        for (index, status) in expected.iter().enumerate() {
            assert_eq!(
                status_at(ListFormat::Token, &one_bit, index as u64, 1),
                Some(*status),
                "{index}"
            );
        }
        assert_eq!(status_at(ListFormat::Token, &one_bit, 16, 1), None);

        let two_bits = expand_token_statuses("eNo76fITAAPfAgc").expect("statuses");
        assert_eq!(two_bits, [0xc9, 0x44, 0xf9]);
        let expected = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
        for (index, status) in expected.iter().enumerate() {
            assert_eq!(
                status_at(ListFormat::Token, &two_bits, index as u64, 2),
                Some(*status),
                "{index}"
            );
        }
        assert_eq!(status_at(ListFormat::Token, &two_bits, 12, 2), None);
    }

    /// Statuses of four and eight bits keep to their byte.
    #[test]
    fn a_wider_status_keeps_to_its_byte() {
        assert_eq!(status_at(ListFormat::Token, &[0x2b], 0, 4), Some(0xb));
        assert_eq!(status_at(ListFormat::Token, &[0x2b], 1, 4), Some(0x2));
        assert_eq!(
            status_at(ListFormat::Token, &[0x2b, 0x07], 1, 8),
            Some(0x07)
        );
        assert_eq!(status_at(ListFormat::Token, &[0x2b, 0x07], 2, 8), None);
    }

    /// The list MOSIP's mock issuer revoked a credential in: that credential's
    /// index is set reading from the most significant bit, and a reading from
    /// the least would find it valid.
    #[test]
    fn a_bitstring_list_is_read_from_its_most_significant_bit() {
        let written =
            include_str!("../../../jsonld/tests/proofs/vc-verifier/mosipRevokedStatusList.json");
        let list: Value = serde_json::from_str(written).expect("JSON");
        let encoded = list["credentialSubject"]["encodedList"]
            .as_str()
            .expect("an encoded list");
        let statuses = expand_bitstring(encoded).expect("statuses");
        assert_eq!(statuses.len() * 8, FEWEST_BITSTRING_STATUSES);
        let set: Vec<u64> = (0..FEWEST_BITSTRING_STATUSES as u64)
            .filter(|index| status_at(ListFormat::Bitstring, &statuses, *index, 1) == Some(1))
            .collect();
        assert_eq!(set, [44_156, 53_347, 54_216, 74_167, 86_365, 104_282]);
        assert_eq!(status_at(ListFormat::Token, &statuses, 104_282, 1), Some(0));
    }

    /// A list is expanded to a bound however small it travels: a gigabyte of
    /// zeroes compresses to a megabyte.
    #[test]
    fn a_list_expanding_past_the_bound_is_refused() {
        use std::io::Write;
        let zeroes = vec![0u8; MOST_STATUS_BYTES + 1];
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        zlib.write_all(&zeroes).expect("compressed");
        let lst = BASE64URL_NOPAD.encode(&zlib.finish().expect("compressed"));
        assert_eq!(expand_token_statuses(&lst), Err(TOO_MANY_STATUSES));
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gzip.write_all(&zeroes).expect("compressed");
        let encoded = format!(
            "u{}",
            BASE64URL_NOPAD.encode(&gzip.finish().expect("compressed"))
        );
        assert_eq!(expand_bitstring(&encoded), Err(TOO_MANY_STATUSES));

        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        zlib.write_all(&zeroes[1..]).expect("compressed");
        let lst = BASE64URL_NOPAD.encode(&zlib.finish().expect("compressed"));
        assert_eq!(
            expand_token_statuses(&lst).map(|held| held.len()),
            Ok(MOST_STATUS_BYTES)
        );
    }

    /// The encodings the specifications fix, and nothing near them.
    #[test]
    fn a_list_encoded_otherwise_is_not_expanded() {
        let w3c_example = "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";
        assert_eq!(
            expand_bitstring(w3c_example).map(|held| held.len()),
            Ok(16_384)
        );
        for encoded in [
            &w3c_example[1..],
            &format!("z{}", &w3c_example[1..]),
            &format!("{w3c_example}="),
            "uAAAA",
            "u",
        ] {
            assert_eq!(
                expand_bitstring(encoded),
                Err(UNREADABLE_STATUSES),
                "{encoded}"
            );
        }
        for lst in [
            "eNrbuRgAAhcBXQ==",
            "eNrbuRgAAhcBX",
            "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA",
            "",
        ] {
            assert_eq!(
                expand_token_statuses(lst),
                Err(UNREADABLE_STATUSES),
                "{lst}"
            );
        }
    }

    fn citation(index: u64) -> Option<Citation> {
        Some(Citation {
            format: ListFormat::Token,
            uri: "https://issuer.example/statuslists/1".to_owned(),
            index,
            purpose: None,
        })
    }

    fn claims(status: Value) -> Map<String, Value> {
        let mut claims = Map::new();
        claims.insert("status".to_owned(), status);
        claims
    }

    /// A status list cited as the issuer signed it is read, and only so.
    #[test]
    fn a_token_citation_is_read_as_the_issuer_signed_it() {
        let status = serde_json::json!({
            "status_list": { "idx": 412, "uri": "https://issuer.example/statuslists/1" }
        });
        assert_eq!(
            read_token_citation(&claims(status.clone()), &claims(status)),
            Ok(citation(412))
        );
        assert_eq!(read_token_citation(&Map::new(), &Map::new()), Ok(None));
        let signed = serde_json::json!({
            "status_list": { "idx": 412, "uri": "https://issuer.example/statuslists/1" }
        });
        let changed = serde_json::json!({
            "status_list": { "idx": 413, "uri": "https://issuer.example/statuslists/1" }
        });
        assert_eq!(
            read_token_citation(&claims(signed.clone()), &claims(changed)),
            Err(STATUS_DISCLOSED)
        );
        assert_eq!(
            read_token_citation(&Map::new(), &claims(signed.clone())),
            Err(STATUS_DISCLOSED)
        );
        assert_eq!(
            read_token_citation(&claims(signed), &Map::new()),
            Err(STATUS_DISCLOSED)
        );
    }

    #[test]
    fn a_token_citation_of_another_shape_is_not_read() {
        for status in [
            serde_json::json!("https://issuer.example/statuslists/1"),
            serde_json::json!({}),
            serde_json::json!({ "identifier_list": { "id": "a", "uri": "https://issuer.example/l" } }),
            serde_json::json!({
                "status_list": { "idx": 1, "uri": "https://issuer.example/statuslists/1" },
                "identifier_list": { "id": "a", "uri": "https://issuer.example/l" }
            }),
            serde_json::json!({ "status_list": { "idx": -1, "uri": "https://issuer.example/l" } }),
            serde_json::json!({ "status_list": { "idx": 1.5, "uri": "https://issuer.example/l" } }),
            serde_json::json!({ "status_list": { "idx": "1", "uri": "https://issuer.example/l" } }),
            serde_json::json!({ "status_list": { "idx": 1, "uri": "http://issuer.example/l" } }),
            serde_json::json!({ "status_list": { "idx": 1, "uri": "https://user:pass@issuer.example/l" } }),
            serde_json::json!({ "status_list": { "idx": 1 } }),
        ] {
            assert_eq!(
                read_token_citation(&claims(status.clone()), &claims(status.clone())),
                Err(STATUS_UNREAD),
                "{status}"
            );
        }
    }

    const LIST: &str = "https://issuer.example/statuslists/1";
    const ISSUER: &str = "https://issuer.example";

    fn provider() -> crypto::provider::openssl::OpenSslProvider {
        crypto::provider::openssl::OpenSslProvider::new(&crypto::provider::CryptoConfig::default())
            .expect("a provider")
    }

    /// An issuer's Ed25519 key pair, and its public half as the realm keeps it.
    fn issuer_key() -> (crypto::jose::jwk::alg::ed::EdKeyPair, Vec<Value>) {
        use crypto::jose::jwk::KeyPair;
        let pair = crypto::jose::jwk::alg::ed::EdKeyPair::generate(crypto::jose::jwk::Ed25519)
            .expect("a key pair");
        let mut public = pair.to_jwk_public_key().as_ref().clone();
        public.insert("kid".to_owned(), serde_json::json!("k1"));
        (pair, vec![Value::Object(public)])
    }

    /// A status list token, `claims` signed under `pair` with `header`.
    fn signed_list(
        pair: &crypto::jose::jwk::alg::ed::EdKeyPair,
        typ: &str,
        claims: &Value,
    ) -> String {
        use crypto::jose::jwk::KeyPair;
        let mut header = crypto::jose::jws::JwsHeader::new();
        header.set_token_type(typ);
        header.set_key_id("k1");
        let signer = crypto::jose::jws::EdDSA
            .signer_from_pem(pair.to_pem_private_key())
            .expect("a signer");
        jws::serialize_compact(claims.to_string().as_bytes(), &header, &signer).expect("a token")
    }

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000, 0).expect("a time")
    }

    fn list_claims() -> Value {
        serde_json::json!({
            "sub": LIST,
            "iss": ISSUER,
            "iat": now().timestamp() - 600,
            "exp": now().timestamp() + 3_600,
            "ttl": 900,
            "status_list": { "bits": 2, "lst": "eNo76fITAAPfAgc" }
        })
    }

    #[test]
    fn a_status_list_token_is_read_as_its_issuer_signed_it() {
        let (pair, keys) = issuer_key();
        let token = signed_list(&pair, "statuslist+jwt", &list_claims());
        assert_eq!(
            read_token_list(ISSUER, &keys, LIST, &format!("{token}\n"), now()),
            Ok(ReadList {
                statuses: vec![0xc9, 0x44, 0xf9],
                bits: Some(2),
                purposes: Vec::new(),
                issued_at: Some(now() - Duration::seconds(600)),
                expires_at: Some(now() + Duration::seconds(3_600)),
                time_to_live: Some(Duration::seconds(900)),
            })
        );
        let mut without_issuer = list_claims();
        for optional in ["iss", "exp", "ttl"] {
            without_issuer
                .as_object_mut()
                .expect("claims")
                .remove(optional);
        }
        assert!(
            read_token_list(
                ISSUER,
                &keys,
                LIST,
                &signed_list(&pair, "statuslist+jwt", &without_issuer),
                now()
            )
            .is_ok()
        );
    }

    #[test]
    fn a_status_list_token_is_refused_for_what_it_does_not_hold() {
        let (pair, keys) = issuer_key();
        let (other, _) = issuer_key();
        let read = |token: &str| read_token_list(ISSUER, &keys, LIST, token, now());
        let with = |change: &dyn Fn(&mut Value)| {
            let mut claims = list_claims();
            change(&mut claims);
            signed_list(&pair, "statuslist+jwt", &claims)
        };
        assert_eq!(
            read(&signed_list(&pair, "jwt", &list_claims())),
            Err(NOT_A_LIST_TOKEN)
        );
        assert_eq!(
            read(&signed_list(&other, "statuslist+jwt", &list_claims())),
            Err(LIST_SIGNATURE)
        );
        assert_eq!(read("not a token"), Err(NOT_A_LIST_TOKEN));
        for (change, why) in [
            (
                &(|claims: &mut Value| {
                    claims["sub"] = serde_json::json!("https://issuer.example/statuslists/2")
                }) as &dyn Fn(&mut Value),
                LIST_ELSEWHERE,
            ),
            (
                &|claims: &mut Value| {
                    claims["iss"] = serde_json::json!("https://elsewhere.example")
                },
                LIST_OF_ANOTHER_ISSUER,
            ),
            (
                &|claims: &mut Value| {
                    claims.as_object_mut().expect("claims").remove("iat");
                },
                LIST_UNREAD,
            ),
            (
                &|claims: &mut Value| {
                    claims["iat"] = serde_json::json!(now().timestamp() + LEEWAY_SECONDS + 1)
                },
                LIST_NOT_YET,
            ),
            (
                &|claims: &mut Value| {
                    claims["nbf"] = serde_json::json!(now().timestamp() + LEEWAY_SECONDS + 1)
                },
                LIST_NOT_YET,
            ),
            (
                &|claims: &mut Value| {
                    claims["exp"] = serde_json::json!(now().timestamp() - LEEWAY_SECONDS)
                },
                LIST_EXPIRED,
            ),
            (
                &|claims: &mut Value| claims["ttl"] = serde_json::json!(0),
                LIST_UNREAD,
            ),
            (
                &|claims: &mut Value| claims["ttl"] = serde_json::json!("900"),
                LIST_UNREAD,
            ),
            (
                &|claims: &mut Value| claims["status_list"]["bits"] = serde_json::json!(3),
                LIST_UNREAD,
            ),
            (
                &|claims: &mut Value| {
                    claims["status_list"]["lst"] = serde_json::json!("eNo76fITAAPfAgc=")
                },
                UNREADABLE_STATUSES,
            ),
            (
                &|claims: &mut Value| {
                    claims
                        .as_object_mut()
                        .expect("claims")
                        .remove("status_list");
                },
                LIST_UNREAD,
            ),
        ] {
            let token = with(change);
            assert_eq!(read(&token), Err(why), "{why}");
        }
        let unnamed = issuer_key().1;
        assert_eq!(
            read_token_list(
                ISSUER,
                &unnamed,
                LIST,
                &signed_list(&pair, "statuslist+jwt", &list_claims()),
                now()
            ),
            Err(LIST_SIGNATURE)
        );
    }

    /// The key MOSIP's mock issuer signs its lists with, as vc-verifier's copy
    /// of its DID document writes it.
    fn mosip_list() -> (Vec<Value>, String, String) {
        let raw = jsonld::base58::decode("6Mki13hAgnc8jDw86MnBhNQ12C4DuMs5kjmpg9orskHTd45")
            .expect("base58");
        let key = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": BASE64URL_NOPAD.encode(&raw[2..]),
            "kid": "did:web:mosip.github.io:inji-config:qa-inji1:mock#kMVyZTvx8G0h1YZnUW4OJtr2LRVZUuGl8pQuJl3ymXI",
        });
        let document =
            include_str!("../../../jsonld/tests/proofs/vc-verifier/mosipRevokedStatusList.json");
        let uri = serde_json::from_str::<Value>(document).expect("JSON")["id"]
            .as_str()
            .expect("an address")
            .to_owned();
        (vec![key], uri, document.to_owned())
    }

    #[test]
    fn a_bitstring_list_mosip_signed_is_read_off_what_its_proof_signs() {
        let (keys, uri, document) = mosip_list();
        let issuer = "did:web:mosip.github.io:inji-config:qa-inji1:mock";
        let none_pinned = HashMap::new();
        let contexts = HeldContexts::new(&none_pinned);
        let read = read_bitstring_list(
            &provider(),
            &contexts,
            issuer,
            &keys,
            &uri,
            &document,
            now(),
        )
        .expect("a reading");
        assert_eq!(read.purposes, ["revocation"]);
        assert_eq!(read.bits, None);
        assert_eq!(read.issued_at, DateTime::from_timestamp(1_762_846_140, 0));
        assert_eq!((read.expires_at, read.time_to_live), (None, None));
        assert_eq!(
            status_at(ListFormat::Bitstring, &read.statuses, 104_282, 1),
            Some(1)
        );

        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                issuer,
                &keys,
                &format!("{uri}x"),
                &document,
                now()
            ),
            Err(LIST_ELSEWHERE)
        );
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                "did:web:elsewhere.example",
                &keys,
                &uri,
                &document,
                now()
            ),
            Err(LIST_OF_ANOTHER_ISSUER)
        );
        let (_, others) = issuer_key();
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                issuer,
                &others,
                &uri,
                &document,
                now()
            ),
            Err(LIST_SIGNATURE)
        );
        let before = DateTime::from_timestamp(1_762_846_140 - 3_600, 0).expect("a time");
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                issuer,
                &keys,
                &uri,
                &document,
                before
            ),
            Err(LIST_NOT_YET)
        );
        let tampered = document.replace("uH4sIAAAAAAAA_", "uH4sIAAAAAAAB_");
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                issuer,
                &keys,
                &uri,
                &tampered,
                now()
            ),
            Err(LIST_SIGNATURE)
        );
    }

    /// The statuses of a credential under the VCDM 2.0 context, as its
    /// dataset holds them.
    fn citations_of(status: Value) -> Result<Vec<Citation>, &'static str> {
        let credential = serde_json::json!({
            "@context": [jsonld::built_in::CREDENTIALS_V2],
            "type": ["VerifiableCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": "did:example:holder" },
            "credentialStatus": status,
        });
        let none_pinned = HashMap::new();
        let quads =
            to_rdf(&credential, &HeldContexts::new(&none_pinned), 1_000).expect("a dataset");
        read_bitstring_citations(&quads)
    }

    fn entry(purpose: &str, index: &str) -> Value {
        serde_json::json!({
            "type": "BitstringStatusListEntry",
            "statusPurpose": purpose,
            "statusListIndex": index,
            "statusListCredential": LIST,
        })
    }

    #[test]
    fn a_json_ld_credential_cites_each_status_its_dataset_holds() {
        let cited = |index, purpose| Citation {
            format: ListFormat::Bitstring,
            uri: LIST.to_owned(),
            index,
            purpose: Some(purpose),
        };
        assert_eq!(
            citations_of(entry("revocation", "94567")),
            Ok(vec![cited(94_567, Purpose::Revocation)])
        );
        let mut sized = entry("suspension", "23452");
        sized["statusSize"] = serde_json::json!(1);
        assert_eq!(
            citations_of(serde_json::json!([
                entry("revocation", "94567"),
                sized,
                entry("refresh", "7")
            ])),
            Ok(vec![
                cited(94_567, Purpose::Revocation),
                cited(23_452, Purpose::Suspension)
            ])
        );
        let none_pinned = HashMap::new();
        let without = serde_json::json!({
            "@context": [jsonld::built_in::CREDENTIALS_V2],
            "type": ["VerifiableCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": { "id": "did:example:holder" },
        });
        let quads = to_rdf(&without, &HeldContexts::new(&none_pinned), 1_000).expect("a dataset");
        assert_eq!(read_bitstring_citations(&quads), Ok(Vec::new()));
    }

    #[test]
    fn a_json_ld_status_this_verifier_does_not_read_refuses_the_credential() {
        let mut two_bits = entry("message", "4");
        two_bits["statusSize"] = serde_json::json!(2);
        let mut sized_two = entry("revocation", "4");
        sized_two["statusSize"] = serde_json::json!(2);
        let mut elsewhere = entry("revocation", "4");
        elsewhere["statusListCredential"] =
            serde_json::json!("http://issuer.example/statuslists/1");
        let mut named_twice = entry("revocation", "4");
        named_twice["id"] = serde_json::json!("https://issuer.example/statuslists/1#4");
        let mut named_again = entry("suspension", "5");
        named_again["id"] = serde_json::json!("https://issuer.example/statuslists/1#4");
        for (status, why) in [
            (entry("message", "4"), STATUS_UNREAD),
            (entry("Revocation", "4"), STATUS_UNREAD),
            (two_bits, STATUS_UNREAD),
            (sized_two, MANY_BITS),
            (entry("revocation", "4a"), STATUS_UNREAD),
            (entry("revocation", "-4"), STATUS_UNREAD),
            (entry("revocation", "123456789012345678901"), STATUS_UNREAD),
            (elsewhere, STATUS_UNREAD),
            (serde_json::json!([named_twice, named_again]), STATUS_UNREAD),
            (
                serde_json::json!({ "id": "https://issuer.example/statuslists/1#4", "type": "https://w3id.org/vc/status-list#StatusList2021Entry" }),
                STATUS_UNREAD,
            ),
            (
                serde_json::json!(
                    (0..5)
                        .map(|index| entry("revocation", &index.to_string()))
                        .collect::<Vec<_>>()
                ),
                TOO_MANY_CITATIONS,
            ),
        ] {
            assert_eq!(citations_of(status.clone()), Err(why), "{status}");
        }
        let mut number = entry("revocation", "4");
        number["statusListIndex"] = serde_json::json!(4);
        assert_eq!(citations_of(number), Err(STATUS_UNREAD));
    }

    fn planned(expires_in: Option<i64>, time_to_live: Option<i64>, drawn: u32) -> (i64, i64) {
        let read = ReadList {
            statuses: vec![0],
            bits: Some(1),
            purposes: Vec::new(),
            issued_at: None,
            expires_at: expires_in.map(|seconds| now() + Duration::seconds(seconds)),
            time_to_live: time_to_live.map(Duration::seconds),
        };
        let (usable_until, due_at) = plan_reading(&read, now(), drawn);
        (
            (usable_until - now()).num_seconds(),
            (due_at - now()).num_seconds(),
        )
    }

    /// A list is read again when its issuer asks, between five minutes and an
    /// hour, spread over a tenth more, and before it expires, five minutes on
    /// at the soonest; it is relied on until it expires, a day at most.
    #[test]
    fn a_reading_is_relied_on_and_renewed_within_the_bounds() {
        let day = 86_400;
        assert_eq!(planned(None, None, 0), (day, 3_600));
        assert_eq!(planned(None, None, 360), (day, 3_960));
        assert_eq!(planned(None, None, 361), (day, 3_600));
        assert_eq!(planned(None, Some(900), 7), (day, 907));
        assert_eq!(planned(None, Some(1), 0), (day, 300));
        assert_eq!(planned(None, Some(36_000), 0), (day, 3_600));
        assert_eq!(planned(Some(600), Some(3_600), 0), (600, 600));
        assert_eq!(planned(Some(120), None, 0), (120, 300));
        assert_eq!(planned(Some(2 * day), None, 0), (day, 3_600));
    }

    /// A context aliasing `credentialStatus` lets two nodes, or a node in a
    /// named graph, hold a status; which of them the credential's is no
    /// reading can say, and the credential is refused, even when the entry a
    /// graph names is written out in the default graph.
    #[test]
    fn a_status_held_by_two_nodes_or_in_a_graph_refuses_the_credential() {
        let aliasing = "https://issuer.example/contexts/aliasing";
        let pinned = HashMap::from([(
            aliasing.to_owned(),
            serde_json::json!({ "@context": {
                "statusOf": { "@id": "https://www.w3.org/2018/credentials#credentialStatus", "@type": "@id" },
                "graphed": { "@id": "https://issuer.example/vocab#graphed", "@container": "@graph" },
                "related": { "@id": "https://issuer.example/vocab#related", "@type": "@id" },
                "Entry": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
                "purpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
                "position": "https://www.w3.org/ns/credentials/status#statusListIndex",
                "list": { "@id": "https://www.w3.org/ns/credentials/status#statusListCredential", "@type": "@id" }
            } }),
        )]);
        let entry = serde_json::json!({
            "type": "Entry", "purpose": "revocation", "position": "4", "list": LIST
        });
        let credential = |subject: Value| {
            serde_json::json!({
                "@context": [jsonld::built_in::CREDENTIALS_V2, aliasing],
                "type": ["VerifiableCredential"],
                "issuer": "did:web:issuer.example",
                "credentialSubject": subject,
                "credentialStatus": entry,
            })
        };
        let read = |document: &Value| {
            let quads = to_rdf(document, &HeldContexts::new(&pinned), 1_000).expect("a dataset");
            read_bitstring_citations(&quads)
        };
        assert_eq!(
            read(&credential(
                serde_json::json!({ "id": "did:example:holder" })
            ))
            .map(|cited| cited.len()),
            Ok(1)
        );
        assert_eq!(
            read(&credential(
                serde_json::json!({ "id": "did:example:holder", "statusOf": entry })
            )),
            Err(STATUS_UNREAD)
        );
        assert_eq!(
            read(&credential(serde_json::json!({
                "id": "did:example:holder",
                "graphed": { "id": "did:example:inner", "statusOf": entry }
            }))),
            Err(STATUS_UNREAD)
        );
        let mut signed_plus = credential(serde_json::json!({ "id": "did:example:holder" }));
        signed_plus["credentialStatus"]["position"] = serde_json::json!("+4");
        assert_eq!(read(&signed_plus), Err(STATUS_UNREAD));

        let entry_written = "https://issuer.example/entries/4";
        let mut written_out = entry.clone();
        written_out["id"] = serde_json::json!(entry_written);
        let named_in_a_graph = serde_json::json!({
            "@context": [jsonld::built_in::CREDENTIALS_V2, aliasing],
            "type": ["VerifiableCredential"],
            "issuer": "did:web:issuer.example",
            "credentialSubject": {
                "id": "did:example:holder",
                "graphed": { "id": "did:example:inner", "statusOf": entry_written }
            },
            "related": written_out,
        });
        assert_eq!(read(&named_in_a_graph), Err(STATUS_UNREAD));
    }

    /// A Bitstring Status List the issuer signs here as Inji Certify signs
    /// one: its options under the suite's own context.
    fn signed_bitstring_list(
        pair: &crypto::jose::jwk::alg::ed::EdKeyPair,
        list: Value,
        purpose: &str,
    ) -> Value {
        use crypto::jose::jwk::KeyPair;
        use crypto::provider::HashAlg;
        let provider = provider();
        let pinned = raw_list_context();
        let hash = |document: &Value| {
            let quads = to_rdf(document, &HeldContexts::new(&pinned), 1_000).expect("a dataset");
            let canonical = jsonld::canon::canonicalize(&provider, HashAlg::Sha256, &quads, 500)
                .expect("canonical");
            provider
                .digest()
                .hash(HashAlg::Sha256, canonical.nquads.as_bytes())
                .expect("a digest")
        };
        let mut options = serde_json::json!({
            "@context": jsonld::built_in::ED25519_2020_V1,
            "type": "Ed25519Signature2020",
            "created": "2026-09-21T10:00:00Z",
            "verificationMethod": format!("{ISSUER}#k1"),
            "proofPurpose": purpose,
        });
        let signed = [hash(&options), hash(&list)].concat();
        let signer = crypto::jose::jws::EdDSA
            .signer_from_pem(pair.to_pem_private_key())
            .expect("a signer");
        let signature = crypto::jose::jws::JwsSigner::sign(&signer, &signed).expect("a signature");
        let proof = options.as_object_mut().expect("options");
        proof.remove("@context");
        proof.insert(
            "proofValue".to_owned(),
            serde_json::json!(format!("z{}", jsonld::base58::encode(&signature))),
        );
        let mut list = list;
        list["proof"] = options;
        list
    }

    const RAW_LIST_CONTEXT: &str = "https://issuer.example/contexts/raw-list";

    /// A context naming the encoded list's property as a plain string.
    fn raw_list_context() -> HashMap<String, Value> {
        HashMap::from([(
            RAW_LIST_CONTEXT.to_owned(),
            serde_json::json!({ "@context": {
                "rawList": "https://www.w3.org/ns/credentials/status#encodedList"
            } }),
        )])
    }

    fn bitstring_list(subject: Value) -> Value {
        serde_json::json!({
            "@context": [jsonld::built_in::CREDENTIALS_V2],
            "id": LIST,
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": ISSUER,
            "validFrom": "2026-09-21T09:00:00Z",
            "credentialSubject": subject,
        })
    }

    fn encoded(statuses: &[u8]) -> String {
        use std::io::Write;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gzip.write_all(statuses).expect("compressed");
        format!(
            "u{}",
            BASE64URL_NOPAD.encode(&gzip.finish().expect("compressed"))
        )
    }

    #[test]
    fn a_bitstring_list_says_its_purposes_its_lifetime_and_its_statuses() {
        let (pair, keys) = issuer_key();
        let none_pinned = HashMap::new();
        let contexts = HeldContexts::new(&none_pinned);
        let mut list = bitstring_list(serde_json::json!({
            "id": format!("{LIST}#list"),
            "type": "BitstringStatusList",
            "statusPurpose": ["revocation", "suspension"],
            "encodedList": encoded(&[0u8; 16_384]),
            "ttl": 300_000,
        }));
        list["validUntil"] = serde_json::json!("2026-09-29T10:00:00Z");
        let signed = signed_bitstring_list(&pair, list, "assertionMethod").to_string();
        let read = read_bitstring_list(&provider(), &contexts, ISSUER, &keys, LIST, &signed, now())
            .expect("a reading");
        assert_eq!(read.purposes, ["revocation", "suspension"]);
        assert_eq!(read.time_to_live, Some(Duration::minutes(5)));
        assert_eq!(read.expires_at, DateTime::from_timestamp(1_790_676_000, 0));
        assert_eq!(read.issued_at, DateTime::from_timestamp(1_789_984_800, 0));
        assert_eq!(read.statuses.len(), 16_384);

        let after = DateTime::from_timestamp(1_790_676_000 + LEEWAY_SECONDS, 0).expect("a time");
        assert_eq!(
            read_bitstring_list(&provider(), &contexts, ISSUER, &keys, LIST, &signed, after),
            Err(LIST_EXPIRED)
        );
        let short = signed_bitstring_list(
            &pair,
            bitstring_list(serde_json::json!({
                "id": format!("{LIST}#list"),
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encoded(&[0u8; 16_383]),
            })),
            "assertionMethod",
        )
        .to_string();
        assert_eq!(
            read_bitstring_list(&provider(), &contexts, ISSUER, &keys, LIST, &short, now()),
            Err(TOO_FEW_STATUSES)
        );
        let authenticating = signed_bitstring_list(
            &pair,
            bitstring_list(serde_json::json!({
                "id": format!("{LIST}#list"),
                "type": "BitstringStatusList",
                "statusPurpose": "revocation",
                "encodedList": encoded(&[0u8; 16_384]),
            })),
            "authentication",
        )
        .to_string();
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                ISSUER,
                &keys,
                LIST,
                &authenticating,
                now()
            ),
            Err(LIST_NOT_ASSERTED)
        );
        let unpurposed = signed_bitstring_list(
            &pair,
            bitstring_list(serde_json::json!({
                "id": format!("{LIST}#list"),
                "type": "BitstringStatusList",
                "encodedList": encoded(&[0u8; 16_384]),
            })),
            "assertionMethod",
        )
        .to_string();
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &contexts,
                ISSUER,
                &keys,
                LIST,
                &unpurposed,
                now()
            ),
            Err(LIST_UNREAD)
        );
        let mut untyped = bitstring_list(serde_json::json!({
            "id": format!("{LIST}#list"),
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encoded(&[0u8; 16_384]),
        }));
        untyped["type"] = serde_json::json!(["VerifiableCredential"]);
        let untyped = signed_bitstring_list(&pair, untyped, "assertionMethod").to_string();
        assert_eq!(
            read_bitstring_list(&provider(), &contexts, ISSUER, &keys, LIST, &untyped, now()),
            Err(LIST_UNREAD)
        );
        let mut raw = bitstring_list(serde_json::json!({
            "id": format!("{LIST}#list"),
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "rawList": encoded(&[0u8; 16_384]),
        }));
        raw["@context"] = serde_json::json!([jsonld::built_in::CREDENTIALS_V2, RAW_LIST_CONTEXT]);
        let raw = signed_bitstring_list(&pair, raw, "assertionMethod").to_string();
        let pinned = raw_list_context();
        assert_eq!(
            read_bitstring_list(
                &provider(),
                &HeldContexts::new(&pinned),
                ISSUER,
                &keys,
                LIST,
                &raw,
                now()
            ),
            Err(LIST_UNREAD),
            "an encoded list not written as multibase was read"
        );
    }

    #[test]
    fn a_header_types_a_list_token_in_either_spelling() {
        for typ in [
            "statuslist+jwt",
            "StatusList+JWT",
            "application/statuslist+jwt",
        ] {
            assert!(is_list_token_type(typ), "{typ}");
        }
        for typ in [
            "jwt",
            "statuslist+cwt",
            "application/jwt",
            "vnd/statuslist+jwt",
        ] {
            assert!(!is_list_token_type(typ), "{typ}");
        }
    }
}
