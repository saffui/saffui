use chrono::{DateTime, Utc};
use deadpool_postgres::Transaction;
use models::entities::attributes;
use models::entities::keys::RealmSigningKeyView;
use models::entities::user::{UserModel, address, profile};
use serde_json::{Map, Value, json};
use store::providers::{client_scopes, clients, sessions, users};

use crate::token;
use crate::token::issuance::Kind;
use models::claims_request::{self, ClaimsRequest};

/// Why nothing was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Untold {
    /// Not a token this realm accepts, or not one that speaks for a person.
    /// RFC 6750 §3.1 spells this `invalid_token`, and it is one answer for
    /// every way of being wrong so nothing here reports which.
    #[error("the token presented is not one this realm accepts")]
    InvalidToken,
    #[error("the store could not be read")]
    Unreadable,
}

/// The claims this token allows.
///
/// Two ways a claim gets in, and they add up: the scopes the token carries
/// name sets of claims (§5.4), and the `claims` the request named one by one
/// (§5.5) are read off the client session the login opened for this client.
/// What a client is told, and how it asked to be told it.
pub struct Answer {
    pub claims: Map<String, Value>,
    /// Set when the client registered a signed response, §5.3.2.
    pub signed_with: Option<crypto::provider::SignAlg>,
    /// The client itself, when one was named: encrypting is to a key it
    /// published, so the registration alone is not enough to do it.
    pub party: Option<Box<models::entities::client::ClientModel>>,
    pub client_id: Option<String>,
}

impl Answer {
    /// Whether this answer travels as a JWT rather than as claims.
    pub fn is_a_token(&self) -> bool {
        self.signed_with.is_some()
            || self
                .party
                .as_ref()
                .is_some_and(|held| held.userinfo_encryption.is_some())
    }
}

/// The answer as this client registered to receive it, §5.3.2.
///
/// Signed, encrypted, or signed and then encrypted. Signed first when both are
/// registered, which is a nested JWT: the header says `cty: "JWT"` so the
/// recipient verifies what it decrypts rather than reading it as claims.
///
/// A client that registered encryption and cannot be encrypted to is an error,
/// never a reply in the clear: answering it with readable claims tells it
/// nothing about what it asked for.
pub async fn told_answer(
    transaction: &Transaction<'_>,
    signing: &crate::grant::Signing<'_>,
    issuer: &str,
    answer: &Answer,
) -> Result<String, Untold> {
    let encryption = answer
        .party
        .as_ref()
        .and_then(|held| held.userinfo_encryption);

    let body = match answer.signed_with {
        Some(_) => signed_answer(transaction, signing, issuer, answer).await?,
        // Encrypted and not signed: the claims themselves are what travels,
        // with the same two the signed form carries for the same reason.
        None => {
            let mut claims = answer.claims.clone();
            claims.insert("iss".into(), json!(issuer));
            if let Some(client_id) = &answer.client_id {
                claims.insert("aud".into(), json!(client_id));
            }
            serde_json::to_string(&claims).map_err(|_| Untold::Unreadable)?
        }
    };

    let Some(registration) = encryption else {
        return Ok(body);
    };
    let party = answer.party.as_ref().ok_or(Untold::Unreadable)?;
    let wrapped = answer.signed_with.is_some().then_some("JWT");
    crate::encryption::sealed_for(party, registration, body.as_bytes(), wrapped)
        .map_err(|_| Untold::Unreadable)
}

/// The same claims, as the JWS §5.3.2 describes.
///
/// The issuer and the audience join them, because a signed response that named
/// neither could be replayed at another client as its own.
pub async fn signed_answer(
    transaction: &Transaction<'_>,
    signing: &crate::grant::Signing<'_>,
    issuer: &str,
    answer: &Answer,
) -> Result<String, Untold> {
    let algorithm = answer.signed_with.ok_or(Untold::Unreadable)?;
    let key = store::providers::realm_keys::active(
        transaction,
        signing.ring,
        signing.envelope,
        models::entities::keys::KeyUse::Sig,
        Some(algorithm),
    )
    .await
    .map_err(|_| Untold::Unreadable)?
    .ok_or(Untold::Unreadable)?;

    let mut claims = answer.claims.clone();
    claims.insert("iss".into(), json!(issuer));
    if let Some(client_id) = &answer.client_id {
        claims.insert("aud".into(), json!(client_id));
    }
    crate::token::issuance::sign_claims(&key, &claims).map_err(|_| Untold::Unreadable)
}

pub async fn claims_for(
    transaction: &Transaction<'_>,
    keys: &[RealmSigningKeyView],
    bearer: &str,
    // What the caller proved: a key it signed with, a certificate a trusted
    // proxy said it presented, or neither. A token naming one is refused here
    // without it.
    proofs: token::Proofs<'_>,
    now: DateTime<Utc>,
) -> Result<Answer, Untold> {
    let verified = token::verify_presented(
        transaction,
        keys,
        bearer,
        token::Binding::Presented(proofs),
        now,
    )
    .await
    .map_err(|_| Untold::InvalidToken)?;

    // An id token is a record of a login, not a credential, and it names the
    // client as its audience. Accepting one here would let anything that saw a
    // login read the person behind it.
    if verified.claims.get("typ").and_then(Value::as_str) != Some(Kind::Access.claimed()) {
        return Err(Untold::InvalidToken);
    }

    // §8: the identifier in the token is what this client is told, and it is
    // the account's own only where the client asked for nothing else.
    let party = match verified.claims.get("azp").and_then(Value::as_str) {
        Some(client_id) => clients::load(transaction, client_id)
            .await
            .map_err(|_| Untold::Unreadable)?,
        None => None,
    };
    let account = crate::pairwise::account_for(transaction, party.as_ref(), &verified.subject)
        .await
        .map_err(|_| Untold::InvalidToken)?;
    let subject = users::load(transaction, &account)
        .await
        .map_err(|_| Untold::Unreadable)?
        .filter(|user| user.enabled)
        .ok_or(Untold::InvalidToken)?;
    let held = held_claims(&subject);

    // OIDC Core §5.3.2. A response whose `sub` differs from the token's is one a
    // client must reject, so it is the token's or there is no response.
    let mut claims = claims_of_scope(&verified.scope, &held);
    claims.insert("sub".into(), json!(verified.subject));

    // Echoed from the token, not resolved again: the answer describes the
    // confinement the presented token acts within.
    for named in ["org_id", "org_name"] {
        if let Some(value) = verified.claims.get(named) {
            claims.insert(named.into(), value.clone());
        }
    }

    let asked = match (
        verified.claims.get("sid").and_then(Value::as_str),
        verified.claims.get("azp").and_then(Value::as_str),
    ) {
        (Some(sid), Some(client_id)) => sessions::requested_claims_of(transaction, sid, client_id)
            .await
            .map_err(|_| Untold::Unreadable)?,
        _ => None,
    };
    let asked_names = asked
        .as_ref()
        .map(|asked| ClaimsRequest::from_value(asked).userinfo)
        .unwrap_or_default();
    if !asked_names.is_empty() {
        let entitled = entitled_scopes(
            transaction,
            verified
                .claims
                .get("azp")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .await
        .map_err(|_| Untold::Unreadable)?;
        claims.extend(within_entitlement(
            claims_request::release(&asked_names, &held),
            &entitled,
        ));
    }

    // §5.6.2: what other providers answer for about this person, spoken as
    // theirs. Read after the realm's own claims, so a source only ever
    // speaks where the realm is silent, and bounded by what the token's
    // scopes stand for plus what was asked by name.
    let sources = store::providers::brokering::claim_sources_of(transaction, &account)
        .await
        .map_err(|_| Untold::Unreadable)?;
    if !sources.is_empty()
        && let Some((names, carried)) = sourced_claims(
            &sources,
            &claims,
            &entitled_claim_names(&verified.scope, asked_names.keys()),
        )
    {
        claims.insert("_claim_names".into(), Value::Object(names));
        claims.insert("_claim_sources".into(), Value::Object(carried));
    }

    // The mapper claims this grant is under, on the person already in hand.
    // Filled where the flow said nothing: `sub` is set above, so no rule from
    // a registration can rename the account. An `aud` a mapper asked for is
    // dropped here, since a UserInfo answer carries no audience to widen.
    if let Some(client) = party.as_ref() {
        let resolved =
            crate::mappers::resolve(transaction, &client.client_id, &account, &verified.scope)
                .await
                .map_err(|_| Untold::Unreadable)?;
        if !resolved.is_empty() {
            let mut overlay =
                crate::mappers::evaluate(crate::mappers::Target::UserInfo, &resolved, &subject);
            overlay.remove("aud");
            crate::mappers::fill(&mut claims, overlay);
        }
    }

    Ok(Answer {
        claims,
        signed_with: party
            .as_ref()
            .and_then(|held| held.userinfo_signed_response_alg),
        client_id: party.as_ref().map(|held| held.client_id.clone()),
        party: party.map(Box::new),
    })
}

/// Of what the realm holds of a person, what these scopes name: §5.4.
pub fn claims_of_scope(scope: &str, held: &Map<String, Value>) -> Map<String, Value> {
    let mut claims = Map::new();
    for (named, behind) in SCOPE_CLAIMS {
        if !granted(scope, named) {
            continue;
        }
        for claim in behind {
            if let Some(value) = held.get(*claim) {
                claims.insert((*claim).to_owned(), value.clone());
            }
        }
    }
    claims
}

/// What the request named for the identity token, §5.5, of what the realm
/// holds of this person and of what the client is entitled to be told.
pub async fn asked_id_token_claims(
    transaction: &Transaction<'_>,
    asked: Option<&Value>,
    client_id: &str,
    user_id: &str,
) -> Result<Map<String, Value>, ()> {
    let Some(asked) = asked.map(ClaimsRequest::from_value) else {
        return Ok(Map::new());
    };
    if asked.id_token.is_empty() {
        return Ok(Map::new());
    }
    let Some(person) = users::load(transaction, user_id).await.map_err(|_| ())? else {
        return Ok(Map::new());
    };
    let entitled = entitled_scopes(transaction, client_id).await?;
    let mut released = within_entitlement(
        claims_request::release(&asked.id_token, &held_claims(&person)),
        &entitled,
    );

    // 5.6.2 over the identity token too: what was asked by name and another
    // provider answers for is pointed at that provider, where this realm is
    // silent. The same ceiling as the release above; the mint writes these
    // last-if-absent, so no registered claim can be displaced.
    let sources = store::providers::brokering::claim_sources_of(transaction, user_id)
        .await
        .map_err(|_| ())?;
    if !sources.is_empty() {
        let askable: Vec<String> = asked.id_token.keys().cloned().collect();
        let names = entitled_claim_names("", askable.iter())
            .into_iter()
            .filter(|name| {
                within_entitlement(
                    Map::from_iter([((*name).to_owned(), Value::Null)]),
                    &entitled,
                )
                .contains_key(*name)
            })
            .collect::<Vec<_>>();
        if let Some((pointed, carried)) = sourced_claims(&sources, &released, &names) {
            released.insert("_claim_names".into(), Value::Object(pointed));
            released.insert("_claim_sources".into(), Value::Object(carried));
        }
    }
    Ok(released)
}

/// The standard scopes this client may have at all, attached as default or
/// as optional. What a client may be told by name is bounded by the same
/// registration that bounds what it may be told by scope: §5.5.1 makes a
/// scope shorthand for a set of claims, and naming one of the set is not a
/// way around the registration that never granted the set.
pub async fn entitled_scopes(
    transaction: &Transaction<'_>,
    client_id: &str,
) -> Result<Vec<String>, ()> {
    let attached = client_scopes::scopes_of_client(transaction, client_id)
        .await
        .map_err(|_| ())?;
    Ok(attached.into_iter().map(|(scope, _)| scope.name).collect())
}

/// Of claims released by name, those whose scope the client may have. A
/// claim no standard scope names is nobody's to give this way.
pub fn within_entitlement(released: Map<String, Value>, entitled: &[String]) -> Map<String, Value> {
    released
        .into_iter()
        .filter(|(claim, _)| {
            claim == "sub"
                || SCOPE_CLAIMS.iter().any(|(scope, named)| {
                    named.contains(&claim.as_str()) && entitled.iter().any(|held| held == scope)
                })
        })
        .collect()
}

/// What OIDC Core §5.4 puts behind each scope, by name.
const SCOPE_CLAIMS: [(&str, &[&str]); 4] = [
    (
        "profile",
        &[
            "name",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "preferred_username",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "updated_at",
        ],
    ),
    ("email", &["email", "email_verified"]),
    ("phone", &["phone_number", "phone_number_verified"]),
    ("address", &["address"]),
];

/// Every standard claim this realm holds of a person, regardless of who may
/// have it. Resolved once, and selected from by scope and by name.
///
/// Only what is there. A claim released empty is one a relying party reads as
/// a value, and `name` composed from nothing would be a blank the client shows.
pub fn held_claims(subject: &UserModel) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("sub".into(), json!(subject.user_id));
    claims.insert("preferred_username".into(), json!(subject.user_name));

    let attributes = subject.attributes.as_ref();
    let held = |named: &str| {
        attributes
            .and_then(|held| attributes::string_at(held, named))
            .filter(|value| !value.is_empty())
    };
    for (claim, attribute) in [
        ("given_name", profile::FIRST_NAME),
        ("family_name", profile::LAST_NAME),
        ("middle_name", profile::MIDDLE_NAME),
        ("nickname", profile::NICK_NAME),
        ("profile", profile::PROFILE_PAGE),
        ("picture", profile::PICTURE),
        ("website", profile::WEBSITE),
        ("gender", profile::GENDER),
        ("birthdate", profile::BIRTH_DATE),
        ("zoneinfo", profile::ZONEINFO),
        ("locale", profile::LOCALE),
    ] {
        if let Some(value) = held(attribute) {
            claims.insert(claim.into(), json!(value));
        }
    }
    // §5.4 lists `name` as the full name in displayable form. Composed from the
    // two halves, because the realm stores those and not the whole, and left out
    // when neither is there rather than released as a space.
    let full: Vec<&str> = [profile::FIRST_NAME, profile::LAST_NAME]
        .into_iter()
        .filter_map(held)
        .collect();
    if !full.is_empty() {
        claims.insert("name".into(), json!(full.join(" ")));
    }
    // §5.1: when the profile was last changed, as seconds. The record's own
    // stamp, because nothing else knows; a record never changed since it was
    // made was last changed when it was made.
    if let Some(updated) = subject.metadata.updated_at.or(subject.metadata.created_at) {
        claims.insert("updated_at".into(), json!(updated.timestamp()));
    }

    // An address the realm holds but never checked is still an address, so it
    // is released with the flag that says which it is rather than withheld.
    if !subject.email.is_empty() {
        claims.insert("email".into(), json!(subject.email));
        claims.insert(
            "email_verified".into(),
            json!(subject.email_verified.unwrap_or(false)),
        );
    }
    if let Some(number) = subject
        .phone_number
        .as_deref()
        .filter(|held| !held.is_empty())
    {
        claims.insert("phone_number".into(), json!(number));
        claims.insert(
            "phone_number_verified".into(),
            json!(subject.phone_number_verified.unwrap_or(false)),
        );
    }
    // §5.1.1: one object, of whichever components the realm holds. A realm
    // that holds a country and nothing finer releases a country, which the
    // spec allows by name; an address with no component at all is no address.
    let postal: Map<String, Value> = address::COMPONENTS
        .into_iter()
        .filter_map(|(member, attribute)| {
            held(attribute).map(|value| (member.to_owned(), json!(value)))
        })
        .collect();
    if !postal.is_empty() {
        claims.insert("address".into(), Value::Object(postal));
    }
    claims
}

/// Whole scopes, never prefixes. `profile_extended` is not `profile`, and a
/// substring test would read it as one.
fn granted(scope: &str, named: &str) -> bool {
    scope.split_whitespace().any(|held| held == named)
}

#[cfg(test)]
mod tests {
    use super::granted;

    #[test]
    fn a_scope_is_matched_whole() {
        assert!(granted("openid profile email", "profile"));
        assert!(granted("profile", "profile"));
        assert!(!granted("openid email", "profile"));
        assert!(!granted("", "profile"));
        assert!(
            !granted("profile_extended", "profile"),
            "a longer name that starts the same is not the same scope"
        );
    }
}

/// What other providers answer for, said the way OIDC Core §5.6.2 says it:
/// `_claim_names` points each claim at a source, `_claim_sources` carries
/// the source itself, a signed document or where to fetch one.
///
/// A source only speaks where this realm is silent and the client is
/// entitled to hear: a claim already released locally is never re-pointed,
/// because the local answer is the realm's own and a supplement is not a
/// mask. Sources are walked oldest first, so which source a claim points
/// at does not move between reads.
pub fn sourced_claims(
    sources: &[models::entities::brokering::UserClaimSourceModel],
    released: &Map<String, Value>,
    entitled: &[&str],
) -> Option<(Map<String, Value>, Map<String, Value>)> {
    use models::entities::brokering::ClaimSourceKind;

    let mut names = Map::new();
    let mut carried = Map::new();
    for source in sources {
        let speaks: Vec<&str> = source
            .claims
            .iter()
            .map(String::as_str)
            .filter(|name| !released.contains_key(*name))
            .filter(|name| entitled.contains(name))
            .filter(|name| !names.contains_key(*name))
            .collect();
        if speaks.is_empty() {
            continue;
        }
        let document = match source.kind {
            ClaimSourceKind::Jwt => match &source.jwt {
                Some(jwt) => json!({ "JWT": jwt }),
                None => continue,
            },
            ClaimSourceKind::Endpoint => match &source.endpoint {
                Some(endpoint) => {
                    let mut told = Map::new();
                    told.insert("endpoint".into(), json!(endpoint));
                    if let Some(token) = &source.endpoint_token {
                        told.insert("access_token".into(), json!(token));
                    }
                    Value::Object(told)
                }
                None => continue,
            },
        };
        for name in speaks {
            names.insert(name.to_owned(), json!(source.source_id));
        }
        carried.insert(source.source_id.clone(), document);
    }
    (!names.is_empty()).then_some((names, carried))
}

/// Every standard claim name these scopes stand for, plus what the claims
/// request asked by name: the ceiling on what a source may be pointed at.
pub fn entitled_claim_names<'a>(
    scope: &str,
    asked: impl IntoIterator<Item = &'a String>,
) -> Vec<&'a str> {
    let mut names: Vec<&str> = Vec::new();
    for granted in scope.split_whitespace() {
        if let Some((_, held)) = SCOPE_CLAIMS.iter().find(|(name, _)| *name == granted) {
            names.extend(held.iter().copied());
        }
    }
    for name in asked {
        if !names.contains(&name.as_str()) {
            names.push(name.as_str());
        }
    }
    names
}

#[cfg(test)]
mod sourced_tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::brokering::{ClaimSourceKind, UserClaimSourceModel};

    fn source(id: &str, claims: &[&str], kind: ClaimSourceKind) -> UserClaimSourceModel {
        UserClaimSourceModel {
            source_id: id.to_owned(),
            realm_id: "main".into(),
            user_id: "ada".into(),
            claims: claims.iter().map(|held| (*held).to_owned()).collect(),
            kind,
            jwt: matches!(kind, ClaimSourceKind::Jwt).then(|| "eyJ.a.b".to_owned()),
            endpoint: matches!(kind, ClaimSourceKind::Endpoint)
                .then(|| "https://claims.example/ada".to_owned()),
            endpoint_token: Some("carry-me".to_owned()),
            metadata: AuditableModel::unassigned(),
        }
    }

    /// The §5.6.2.1 shape, with the local answer winning, the entitlement
    /// bounding, and the first source keeping a contested name.
    #[test]
    fn sources_speak_only_where_the_realm_is_silent() {
        let sources = [
            source("src1", &["address", "email"], ClaimSourceKind::Jwt),
            source("src2", &["address", "birthdate"], ClaimSourceKind::Endpoint),
        ];
        let mut released = Map::new();
        released.insert("email".into(), json!("ada@here.example"));

        let (names, carried) =
            sourced_claims(&sources, &released, &["address", "email", "birthdate"])
                .expect("something is sourced");
        assert_eq!(names["address"], json!("src1"), "the first source keeps it");
        assert!(
            names.get("email").is_none(),
            "the local answer was re-pointed"
        );
        assert_eq!(names["birthdate"], json!("src2"));
        assert_eq!(carried["src1"], json!({ "JWT": "eyJ.a.b" }));
        assert_eq!(
            carried["src2"],
            json!({ "endpoint": "https://claims.example/ada", "access_token": "carry-me" })
        );

        // Nothing entitled, nothing said: the block is absent, not empty.
        assert!(sourced_claims(&sources, &released, &["phone_number"]).is_none());
    }

    /// The ceiling: what the scopes stand for, plus what was asked by name.
    #[test]
    fn the_entitlement_is_scopes_plus_the_asked() {
        let asked = ["employment".to_owned()];
        let names = entitled_claim_names("openid email", asked.iter());
        assert!(names.contains(&"email") && names.contains(&"email_verified"));
        assert!(names.contains(&"employment"));
        assert!(!names.contains(&"address"));
    }
}
