//! The rules of claims: what a mapper and the attributes of a person may be,
//! and the one evaluator.

use serde_json::{Map, Value, json};
use time::OffsetDateTime;

use super::{ClaimInputs, ClaimTarget, Mapper, MapperKind, NewMapper, PersonProperty};
use crate::authz::admin::ADMIN_SCOPE;
use crate::authz::capability::{Capability, check_capabilities_held};
use crate::authz::grants::{ROLES_SCOPE, RoleClaims};
use crate::authz::roles::is_role_name;
use crate::clients::{check_client_identifier, is_unshowable};
use crate::directory::Person;
use crate::error::{ErrorCode, Failure};

/// The most mappers one client has: each is read for every token.
pub const MAX_MAPPERS_PER_CLIENT: u32 = 50;
/// The most a token carries of what the mappers wrote, in bytes of compact
/// JSON: a token is signed on the thread that serves, and resent each time.
pub const MAX_MAPPED_BYTES: usize = 32 * 1024;

/// The most attributes a person has.
pub const MAX_ATTRIBUTES: usize = 64;
/// The longest document, in bytes, as compact JSON: it goes into tokens.
/// Measured here, and nowhere else.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
/// The most values one attribute holds.
const MAX_VALUES: usize = 32;
/// The longest value, in bytes.
const MAX_VALUE_BYTES: usize = 1024;
/// What the name of an attribute policies read starts with.
pub const POLICY_ATTRIBUTE_PREFIX: &str = "policy.";

/// Claims the protocol writes. A mapper that wrote one could pass a token
/// for another subject, session or level.
const PROTOCOL_CLAIMS: [&str; 26] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    "sid",
    "auth_time",
    "acr",
    "amr",
    "azp",
    "nonce",
    "client_id",
    "scope",
    "cnf",
    "act",
    "may_act",
    "typ",
    "at_hash",
    "c_hash",
    "s_hash",
    "org_id",
    "org_name",
    "realm_access",
    "resource_access",
];

/// The claims of the `profile` scope said from the attributes of a person
/// when they hold them (OpenID Connect Core, section 5.4).
const PROFILE_ATTRIBUTES: [&str; 11] = [
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
];

/// The other claims of the scopes, and those of a phone number: that an
/// address or a number was verified is said by the person, never a mapper.
const SCOPE_CLAIMS: [&str; 6] = [
    "preferred_username",
    "name",
    "email",
    "email_verified",
    "phone_number",
    "phone_number_verified",
];

/// Names common libraries read as the identity of a person or of their
/// tenant, some ahead of `sub`: a mapper that wrote one could pass for another.
const IDENTITY_ALIASES: [&str; 9] = [
    "nameid",
    "unique_name",
    "upn",
    "prn",
    "oid",
    "tid",
    "primarysid",
    "winaccountname",
    "actort",
];

/// The lowercase letters and digits of a name: `sub_`, `e_mail` and
/// `given-name` fold to `sub`, `email` and `givenname`.
fn fold_name(text: &str) -> impl Iterator<Item = u8> + '_ {
    text.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .map(|byte| byte.to_ascii_lowercase())
}

/// Whether a mapper may write a claim of this name: 1 to 64 lowercase
/// letters, digits, dots, colons, hyphens or underscores, and none that
/// folds to a name the protocol or a scope writes, whole or before its first
/// dot. A reader that ignores case or separators, or reads a dotted name as
/// a path, takes no name for a reserved one.
#[must_use]
pub fn is_claim_name(text: &str) -> bool {
    let written = (1..=64).contains(&text.len())
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._:-".contains(&byte)
        });
    let head = text.split('.').next().unwrap_or(text);
    written
        && ![
            PROTOCOL_CLAIMS.as_slice(),
            &PROFILE_ATTRIBUTES,
            &SCOPE_CLAIMS,
            &IDENTITY_ALIASES,
        ]
        .iter()
        .flat_map(|reserved| reserved.iter())
        .any(|reserved| {
            fold_name(reserved).eq(fold_name(text)) || fold_name(reserved).eq(fold_name(head))
        })
}

/// Whether a mapper of this kind says something of the person.
fn reads_person(kind: &MapperKind) -> bool {
    !matches!(kind, MapperKind::Audience { .. })
}

/// Checks what a mapper is asked to be. A mapper that says something of the
/// person names a scope the person is asked about, never `openid`; their
/// address and whether it was verified are said under `email` only.
///
/// # Errors
///
/// Returns [`ErrorCode::MapperInvalid`] for a name, a claim, a target, a
/// scope or a kind that does not hold together.
pub fn check_mapper(wanted: &NewMapper<'_>) -> Result<(), Failure> {
    let invalid = |why: &str| Failure::with_detail(ErrorCode::MapperInvalid, why);
    if !is_role_name(wanted.name) {
        return Err(invalid("name"));
    }
    let mut targets = wanted.targets.to_vec();
    targets.sort();
    targets.dedup();
    if targets.is_empty() || targets.len() != wanted.targets.len() {
        return Err(invalid("targets"));
    }
    let scope = wanted.scope;
    match &wanted.kind {
        // An audience is a property of the access token, not a claim of it.
        MapperKind::Audience { audience } => {
            let printable = (1..=255).contains(&audience.len())
                && audience.bytes().all(|byte| byte.is_ascii_graphic());
            if !printable || wanted.claim.is_some() || targets != [ClaimTarget::AccessToken] {
                return Err(invalid("audience"));
            }
            return Ok(());
        }
        MapperKind::Property {
            property: PersonProperty::Email | PersonProperty::EmailVerified,
        } if scope != Some("email") => return Err(invalid("scope")),
        MapperKind::Attribute { attribute } if !is_attribute_name(attribute) => {
            return Err(invalid("attribute"));
        }
        MapperKind::ClientRoles { client_id } => {
            check_client_identifier(client_id).map_err(|_| invalid("client"))?;
        }
        _ => {}
    }
    if scope.is_none_or(|scope| scope == "openid") {
        return Err(invalid("scope"));
    }
    match wanted.claim {
        Some(claim) if is_claim_name(claim) => Ok(()),
        _ => Err(invalid("claim")),
    }
}

/// What a mapper or a scope makes tokens say of a person, by what it takes
/// to read it: one table for both.
#[derive(Clone, Copy)]
enum Said {
    Nothing,
    People,
    PolicyAttributes,
    Roles,
}

impl Said {
    fn of_scope(scope: &str) -> Self {
        match scope {
            ROLES_SCOPE => Self::Roles,
            "profile" | "email" | "phone" => Self::People,
            _ => Self::Nothing,
        }
    }

    fn of_mapper(kind: &MapperKind) -> Self {
        match kind {
            MapperKind::Audience { .. } => Self::Nothing,
            MapperKind::Attribute { attribute } if is_policy_attribute(attribute) => {
                Self::PolicyAttributes
            }
            MapperKind::Property { .. } | MapperKind::Attribute { .. } | MapperKind::FullName => {
                Self::People
            }
            MapperKind::RealmRoles | MapperKind::ClientRoles { .. } => Self::Roles,
        }
    }

    /// What a caller holds to make tokens say it.
    fn asks(self) -> &'static [Capability] {
        match self {
            Self::Nothing => &[],
            Self::People => &[Capability::UserRead],
            Self::PolicyAttributes => &[Capability::UserRead, Capability::PolicyRead],
            Self::Roles => &[Capability::RoleRead],
        }
    }
}

/// Checks that whoever writes a mapper may read what it would make tokens
/// say: the people with `user:read`, their roles with `role:read`, and an
/// attribute policies read with `policy:read` too.
///
/// # Errors
///
/// Returns [`ErrorCode::CapabilityMissing`].
pub fn check_mapper_capabilities(kind: &MapperKind, held: &[Capability]) -> Result<(), Failure> {
    check_capabilities_held(held, Said::of_mapper(kind).asks())
}

/// Checks that whoever gives a client scopes may read what they make its
/// tokens say: `profile`, `email` and `phone` ask for `user:read`, and
/// `roles` for `role:read`.
///
/// # Errors
///
/// Returns [`ErrorCode::CapabilityMissing`].
pub fn check_scope_capabilities(scopes: &[String], held: &[Capability]) -> Result<(), Failure> {
    scopes
        .iter()
        .try_for_each(|scope| check_capabilities_held(held, Said::of_scope(scope).asks()))
}

/// Checks a mapper against those its client keeps: one name each, fifty at
/// most, and no two that write one claim, or read one source, for a target
/// they share. Each source is said once in a token, whatever the mappers ask.
///
/// # Errors
///
/// Returns [`ErrorCode::MapperNameTaken`], [`ErrorCode::MapperLimitReached`]
/// or [`ErrorCode::MapperOverlaps`].
pub fn check_mapper_beside(kept: &[Mapper], wanted: &NewMapper<'_>) -> Result<(), Failure> {
    if kept.iter().any(|other| other.name == wanted.name) {
        return Err(Failure::new(ErrorCode::MapperNameTaken));
    }
    if kept.len() >= MAX_MAPPERS_PER_CLIENT as usize {
        return Err(Failure::new(ErrorCode::MapperLimitReached));
    }
    let overlaps = kept.iter().any(|other| {
        let shares_target = wanted
            .targets
            .iter()
            .any(|target| other.targets.contains(target));
        let same_claim = wanted.claim.is_some() && wanted.claim == other.claim.as_deref();
        let same_source = reads_person(&wanted.kind) && wanted.kind == other.kind;
        shares_target && (same_claim || same_source)
    });
    if overlaps {
        return Err(Failure::new(ErrorCode::MapperOverlaps));
    }
    Ok(())
}

/// Whether a text may name an attribute of a person: 1 to 64 letters,
/// digits, dots, hyphens or underscores.
#[must_use]
pub fn is_attribute_name(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// Whether an attribute is one policies read.
#[must_use]
pub fn is_policy_attribute(name: &str) -> bool {
    is_attribute_name(name)
        && name
            .strip_prefix(POLICY_ATTRIBUTE_PREFIX)
            .is_some_and(|rest| !rest.is_empty())
}

fn is_attribute_text(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| text.len() <= MAX_VALUE_BYTES && !text.chars().any(is_unshowable))
}

/// Checks attributes before they are kept: at most 64, a known name for
/// each, a text, a truth value or a list of texts, and the whole in 16 KiB.
///
/// # Errors
///
/// Returns [`ErrorCode::AttributesInvalid`].
pub fn check_attributes(attributes: &Map<String, Value>) -> Result<(), Failure> {
    let invalid = |why: &str| Failure::with_detail(ErrorCode::AttributesInvalid, why);
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(invalid("too many"));
    }
    for (name, value) in attributes {
        if !is_attribute_name(name) {
            return Err(invalid("name"));
        }
        let acceptable = match value {
            Value::Bool(_) => true,
            Value::String(_) => is_attribute_text(value),
            Value::Array(values) => {
                values.len() <= MAX_VALUES && values.iter().all(is_attribute_text)
            }
            _ => false,
        };
        if !acceptable {
            return Err(invalid("value"));
        }
    }
    let small =
        serde_json::to_vec(attributes).is_ok_and(|written| written.len() <= MAX_DOCUMENT_BYTES);
    if !small {
        return Err(invalid("size"));
    }
    Ok(())
}

/// What a caller reaches of the attributes of a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeReach {
    /// Every attribute: the caller may write, or read, policies too.
    Every,
    /// Every attribute but those policies read.
    OutsidePolicies,
}

impl AttributeReach {
    /// What a caller with these capabilities writes.
    #[must_use]
    pub fn written_by(capabilities: &[Capability]) -> Self {
        if capabilities.contains(&Capability::PolicyWrite) {
            Self::Every
        } else {
            Self::OutsidePolicies
        }
    }

    /// What a caller with these capabilities reads.
    #[must_use]
    pub fn read_by(capabilities: &[Capability]) -> Self {
        if capabilities.contains(&Capability::PolicyRead) {
            Self::Every
        } else {
            Self::OutsidePolicies
        }
    }

    /// What a write by a caller with these capabilities replaces: what it
    /// both reads and writes. What it cannot see, it does not take away.
    #[must_use]
    pub fn replaced_by(capabilities: &[Capability]) -> Self {
        match (Self::read_by(capabilities), Self::written_by(capabilities)) {
            (Self::Every, Self::Every) => Self::Every,
            _ => Self::OutsidePolicies,
        }
    }

    #[must_use]
    pub fn covers(self, name: &str) -> bool {
        match self {
            Self::Every => true,
            Self::OutsidePolicies => !is_policy_attribute(name),
        }
    }
}

/// The attributes a write leaves: what it wrote, and those it cannot reach
/// as they were kept.
#[must_use]
pub fn merge_attributes(
    kept: Map<String, Value>,
    written: &Map<String, Value>,
    reach: AttributeReach,
) -> Map<String, Value> {
    let mut merged: Map<String, Value> = kept
        .into_iter()
        .filter(|(name, _)| !reach.covers(name))
        .collect();
    merged.extend(
        written
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    merged
}

/// The grant claims are written for.
#[derive(Clone, Copy)]
pub struct ClaimGrant<'a> {
    /// The person, or nobody when a client acts as itself.
    pub person: Option<&'a Person>,
    pub client_id: &'a str,
    pub scopes: &'a [String],
}

/// What the evaluator wrote for one target.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WrittenClaims {
    pub claims: Map<String, Value>,
    /// The audiences of an access token beyond the realm that issued it.
    pub audiences: Vec<String>,
    /// When the first role said ends: a token that says it lives no longer.
    pub until: Option<OffsetDateTime>,
}

impl WrittenClaims {
    fn limit_lifetime(&mut self, until: Option<OffsetDateTime>) {
        if let Some(until) = until {
            self.until = Some(self.until.map_or(until, |first| first.min(until)));
        }
    }
}

fn is_scope_granted(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|granted| granted == scope)
}

/// Whether a mapper writes one of `targets` for a grant of `scopes`. One
/// that says something of the person and names no scope the person is
/// asked about, as one kept before the rule, says nothing.
fn is_applicable(mapper: &Mapper, targets: &[ClaimTarget], scopes: &[String]) -> bool {
    let granted = match (mapper.scope.as_deref(), reads_person(&mapper.kind)) {
        (None, reads) => !reads,
        (Some("openid"), true) => false,
        (Some(scope), _) => is_scope_granted(scopes, scope),
    };
    granted && mapper.targets.iter().any(|target| targets.contains(target))
}

fn read_property(person: &Person, property: PersonProperty) -> Option<Value> {
    match property {
        PersonProperty::Id => Some(json!(person.id.to_string())),
        PersonProperty::Username => Some(json!(person.username)),
        PersonProperty::Email => person.email.as_ref().map(|email| json!(email)),
        PersonProperty::EmailVerified => Some(json!(person.email_verified)),
        PersonProperty::DisplayName => person.display_name.as_ref().map(|name| json!(name)),
    }
}

fn compose_full_name(person: &Person, attributes: &Map<String, Value>) -> Option<Value> {
    let parts: Vec<&str> = ["given_name", "family_name"]
        .iter()
        .filter_map(|name| attributes.get(*name).and_then(Value::as_str))
        .collect();
    if parts.is_empty() {
        person.display_name.as_ref().map(|name| json!(name))
    } else {
        Some(json!(parts.join(" ")))
    }
}

/// What the scopes of a grant say, before any mapper.
fn write_scope_claims(
    target: ClaimTarget,
    grant: &ClaimGrant<'_>,
    inputs: &ClaimInputs,
    written: &mut WrittenClaims,
) {
    let granted = |scope: &str| is_scope_granted(grant.scopes, scope);
    match (target, grant.person) {
        (ClaimTarget::AccessToken, Some(_)) if granted(ROLES_SCOPE) => {
            let roles = RoleClaims::gather(&inputs.held, grant.client_id);
            let claims = &mut written.claims;
            claims.insert("realm_access".to_owned(), roles.write_realm_access());
            claims.insert(
                "resource_access".to_owned(),
                roles.write_resource_access(grant.client_id),
            );
            written.limit_lifetime(roles.until);
        }
        (ClaimTarget::IdToken | ClaimTarget::Userinfo, Some(person)) => {
            let claims = &mut written.claims;
            if granted("profile") {
                claims.insert("preferred_username".to_owned(), json!(person.username));
                if let Some(name) = &person.display_name {
                    claims.insert("name".to_owned(), json!(name));
                }
                for name in PROFILE_ATTRIBUTES {
                    if let Some(value) = inputs
                        .attributes
                        .get(name)
                        .filter(|value| value.is_string())
                    {
                        claims.insert(name.to_owned(), value.clone());
                    }
                }
            }
            if let (true, Some(email)) = (granted("email"), &person.email) {
                claims.insert("email".to_owned(), json!(email));
                claims.insert("email_verified".to_owned(), json!(person.email_verified));
            }
        }
        _ => {}
    }
}

/// Writes what `target` says: what the granted scopes say, then what each
/// mapper that applies says, in the order of their names.
///
/// # Errors
///
/// Returns [`ErrorCode::ClaimsTooLarge`] when the mappers write more than a
/// token carries. The detail names the client, for the journal.
pub fn write_claims(
    target: ClaimTarget,
    grant: &ClaimGrant<'_>,
    inputs: &ClaimInputs,
) -> Result<WrittenClaims, Failure> {
    let mut written = WrittenClaims::default();
    write_scope_claims(target, grant, inputs, &mut written);
    let mut applying: Vec<&Mapper> = inputs
        .mappers
        .iter()
        .filter(|mapper| is_applicable(mapper, &[target], grant.scopes))
        .collect();
    applying.sort_by(|one, other| one.name.cmp(&other.name));
    // A token for the administration plane is for the realm alone: one the
    // resource servers of a client may also hold could be replayed there.
    let for_the_plane = is_scope_granted(grant.scopes, ADMIN_SCOPE);
    let mut mapped = Map::new();
    for mapper in applying {
        let value = match (&mapper.kind, grant.person) {
            (MapperKind::Audience { .. }, _) if for_the_plane => continue,
            (MapperKind::Audience { audience }, _) => {
                if !written.audiences.contains(audience) {
                    written.audiences.push(audience.clone());
                }
                continue;
            }
            // A mapper about a person says nothing of a client that acts as
            // itself, and one kept before its claim was reserved says nothing.
            (_, None) => continue,
            (_, Some(_)) if !mapper.claim.as_deref().is_some_and(is_claim_name) => continue,
            (MapperKind::Property { property }, Some(person)) => read_property(person, *property),
            (MapperKind::Attribute { attribute }, Some(_)) => {
                inputs.attributes.get(attribute).cloned()
            }
            (MapperKind::FullName, Some(person)) => compose_full_name(person, &inputs.attributes),
            // Gathered from the roles said alone: a token lives as long as
            // they do, not as long as roles it does not say.
            (MapperKind::RealmRoles, Some(_)) => {
                let realm = inputs.held.iter().filter(|way| way.client_id.is_none());
                let roles = RoleClaims::gather(realm, grant.client_id);
                written.limit_lifetime(roles.until);
                Some(json!(roles.realm))
            }
            (MapperKind::ClientRoles { client_id }, Some(_)) => {
                let named = inputs
                    .held
                    .iter()
                    .filter(|way| way.client_id.as_deref() == Some(client_id.as_str()));
                let roles = RoleClaims::gather(named, client_id);
                written.limit_lifetime(roles.until);
                Some(json!(roles.client))
            }
        };
        if let (Some(claim), Some(value)) = (&mapper.claim, value) {
            mapped.insert(claim.clone(), value);
        }
    }
    // What the mappers write, audiences included, measured once.
    let carried = serde_json::to_vec(&(&mapped, &written.audiences))
        .is_ok_and(|bytes| bytes.len() <= MAX_MAPPED_BYTES);
    if !carried {
        return Err(Failure::with_detail(
            ErrorCode::ClaimsTooLarge,
            format!(
                "the mappers of the client {} write too much",
                grant.client_id
            ),
        ));
    }
    written.claims.extend(mapped);
    Ok(written)
}

/// Whether writing `targets` for a grant of `scopes` reads the roles of
/// the person: reading them costs a query.
#[must_use]
pub fn needs_roles(mappers: &[Mapper], scopes: &[String], targets: &[ClaimTarget]) -> bool {
    (is_scope_granted(scopes, ROLES_SCOPE) && targets.contains(&ClaimTarget::AccessToken))
        || mappers.iter().any(|mapper| {
            is_applicable(mapper, targets, scopes)
                && matches!(
                    mapper.kind,
                    MapperKind::RealmRoles | MapperKind::ClientRoles { .. }
                )
        })
}

/// Whether writing `targets` for a grant of `scopes` reads the attributes
/// of the person: reading them costs a query.
#[must_use]
pub fn needs_attributes(mappers: &[Mapper], scopes: &[String], targets: &[ClaimTarget]) -> bool {
    let says_profile = targets
        .iter()
        .any(|target| matches!(target, ClaimTarget::IdToken | ClaimTarget::Userinfo));
    (is_scope_granted(scopes, "profile") && says_profile)
        || mappers.iter().any(|mapper| {
            is_applicable(mapper, targets, scopes)
                && matches!(
                    mapper.kind,
                    MapperKind::Attribute { .. } | MapperKind::FullName
                )
        })
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::{
        AttributeReach, ClaimGrant, MAX_DOCUMENT_BYTES, check_attributes, check_mapper,
        check_mapper_beside, check_mapper_capabilities, is_claim_name, is_policy_attribute,
        merge_attributes, needs_attributes, needs_roles, write_claims,
    };
    use crate::authz::capability::Capability;
    use crate::authz::grants::HeldRole;
    use crate::claims::{ClaimInputs, ClaimTarget, Mapper, MapperKind, NewMapper, PersonProperty};
    use crate::directory::Person;
    use crate::error::ErrorCode;
    use crate::testkit::fixtures::fill_attributes;

    fn ada() -> Person {
        Person {
            id: Uuid::from_u128(1),
            username: "ada".to_owned(),
            email: Some("ada@example.org".to_owned()),
            email_verified: true,
            display_name: Some("Ada L.".to_owned()),
            enabled: true,
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn make_mapper(
        name: &str,
        kind: MapperKind,
        claim: Option<&str>,
        targets: &[ClaimTarget],
        scope: Option<&str>,
    ) -> Mapper {
        Mapper {
            id: Uuid::from_u128(9),
            client_id: "webapp".to_owned(),
            name: name.to_owned(),
            kind,
            claim: claim.map(str::to_owned),
            targets: targets.to_vec(),
            scope: scope.map(str::to_owned),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn held(name: &str, client_id: Option<&str>, until: Option<i64>) -> HeldRole {
        HeldRole {
            role: Uuid::from_u128(name.bytes().fold(100_u128, |sum, byte| {
                sum.wrapping_mul(257).wrapping_add(u128::from(byte))
            })),
            client_id: client_id.map(str::to_owned),
            name: name.to_owned(),
            through: None,
            until: until
                .map(|seconds| OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds)),
        }
    }

    fn scopes(text: &str) -> Vec<String> {
        text.split(' ').map(str::to_owned).collect()
    }

    fn read_object(document: &Value) -> Map<String, Value> {
        document.as_object().cloned().expect("an object")
    }

    fn attribute(name: &str) -> MapperKind {
        MapperKind::Attribute {
            attribute: name.to_owned(),
        }
    }

    /// Whether `check_mapper` takes a mapper of the `profile` scope.
    fn is_taken(kind: MapperKind, claim: Option<&str>, targets: &[ClaimTarget]) -> bool {
        check_mapper(&NewMapper {
            name: "a-mapper",
            kind,
            claim,
            targets,
            scope: Some("profile"),
        })
        .is_ok()
    }

    #[test]
    fn a_mapper_claim_is_lowercase_and_no_claim_of_the_protocol_or_of_a_scope_in_any_case() {
        for fine in [
            "department",
            "dept",
            "a.b",
            "billing_roles",
            "x:y",
            "team-2",
        ] {
            assert!(is_claim_name(fine), "{fine}");
        }
        for reserved in [
            "iss",
            "sub",
            "aud",
            "exp",
            "nbf",
            "iat",
            "jti",
            "sid",
            "auth_time",
            "acr",
            "amr",
            "azp",
            "nonce",
            "client_id",
            "scope",
            "cnf",
            "act",
            "may_act",
            "typ",
            "at_hash",
            "c_hash",
            "s_hash",
            "org_id",
            "org_name",
            "realm_access",
            "resource_access",
            "given_name",
            "family_name",
            "middle_name",
            "nickname",
            "profile",
            "picture",
            "website",
            "gender",
            "birthdate",
            "zoneinfo",
            "locale",
            "preferred_username",
            "name",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
        ] {
            assert!(!is_claim_name(reserved), "{reserved}");
            assert!(
                !is_taken(
                    attribute("department"),
                    Some(reserved),
                    &[ClaimTarget::IdToken]
                ),
                "{reserved}"
            );
        }
        for disguised in [
            "Email_verified",
            "EMAIL",
            "Sub",
            "Phone_number_verified",
            "Realm_Access",
            "realm_access.roles",
            "email.x",
            "sub_",
            "_sub",
            "email_",
            "email-verified",
            "e_mail",
            "preferred_username_",
            "given-name",
            "realm.access",
            "Department",
            "",
            &"a".repeat(65),
        ] {
            assert!(!is_claim_name(disguised), "{disguised:?}");
            assert!(
                !is_taken(
                    attribute("department"),
                    Some(disguised),
                    &[ClaimTarget::IdToken]
                ),
                "{disguised:?}"
            );
        }
    }

    #[test]
    fn a_name_libraries_read_as_the_identity_of_a_person_or_a_tenant_is_reserved() {
        for alias in [
            "nameid",
            "unique_name",
            "upn",
            "prn",
            "oid",
            "tid",
            "primarysid",
            "winaccountname",
            "actort",
        ] {
            assert!(!is_claim_name(alias), "{alias}");
            assert!(
                !is_taken(
                    attribute("department"),
                    Some(alias),
                    &[ClaimTarget::IdToken]
                ),
                "{alias}"
            );
        }
        for kept in ["roles", "groups"] {
            assert!(
                is_claim_name(kept),
                "{kept}: the realm already holds what it says"
            );
        }
    }

    #[test]
    fn an_audience_is_a_printable_text_of_255_bytes_at_most_for_the_access_token_alone() {
        let audience = |text: &str| MapperKind::Audience {
            audience: text.to_owned(),
        };
        let access = [ClaimTarget::AccessToken];
        assert!(is_taken(audience("https://api.example.org"), None, &access));
        assert!(is_taken(audience(&"a".repeat(255)), None, &access));
        for wrong in ["", &"a".repeat(256), "api one", "api\u{7f}", "api\u{e9}"] {
            assert!(!is_taken(audience(wrong), None, &access), "{wrong:?}");
        }
        assert!(!is_taken(audience("api"), Some("aud2"), &access), "a claim");
        assert!(
            !is_taken(audience("api"), None, &[ClaimTarget::IdToken]),
            "another target"
        );
        let unscoped = NewMapper {
            name: "api",
            kind: audience("api"),
            claim: None,
            targets: &access,
            scope: None,
        };
        assert_eq!(
            check_mapper(&unscoped),
            Ok(()),
            "an audience needs no scope"
        );
    }

    #[test]
    fn a_mapper_holds_a_known_name_a_claim_and_targets_once_each() {
        let identity = [ClaimTarget::IdToken];
        assert!(is_taken(
            attribute("department"),
            Some("dept"),
            &[ClaimTarget::IdToken, ClaimTarget::Userinfo]
        ));
        assert!(
            !is_taken(attribute("department"), None, &identity),
            "no claim"
        );
        assert!(
            !is_taken(attribute("department"), Some("dept"), &[]),
            "no target"
        );
        assert!(
            !is_taken(
                attribute("department"),
                Some("dept"),
                &[ClaimTarget::IdToken, ClaimTarget::IdToken]
            ),
            "a target twice"
        );
        assert!(!is_taken(attribute("has space"), Some("dept"), &identity));
        let roles_of = |client_id: &str| MapperKind::ClientRoles {
            client_id: client_id.to_owned(),
        };
        assert!(!is_taken(roles_of("two words"), Some("roles"), &identity));
        let unnamed = NewMapper {
            name: "two words",
            kind: attribute("department"),
            claim: Some("dept"),
            targets: &identity,
            scope: Some("profile"),
        };
        assert!(check_mapper(&unnamed).is_err());
    }

    #[test]
    fn a_mapper_that_says_something_of_the_person_names_a_scope_other_than_openid() {
        let property = |property| MapperKind::Property { property };
        for kind in [
            property(PersonProperty::Id),
            attribute("department"),
            MapperKind::FullName,
            MapperKind::RealmRoles,
            MapperKind::ClientRoles {
                client_id: "billing".to_owned(),
            },
        ] {
            for scope in [None, Some("openid")] {
                let wanted = NewMapper {
                    name: "a-mapper",
                    kind: kind.clone(),
                    claim: Some("said"),
                    targets: &[ClaimTarget::IdToken],
                    scope,
                };
                assert_eq!(
                    check_mapper(&wanted).map_err(|failure| failure.code),
                    Err(ErrorCode::MapperInvalid),
                    "{kind:?} under {scope:?}"
                );
            }
        }
        let address = |property, scope| NewMapper {
            name: "address",
            kind: MapperKind::Property { property },
            claim: Some("mail"),
            targets: &[ClaimTarget::IdToken],
            scope: Some(scope),
        };
        for said in [PersonProperty::Email, PersonProperty::EmailVerified] {
            assert!(check_mapper(&address(said, "profile")).is_err(), "{said:?}");
            assert_eq!(check_mapper(&address(said, "email")), Ok(()), "{said:?}");
        }
    }

    #[test]
    fn whoever_writes_a_mapper_may_read_what_it_says() {
        let check = |kind: &MapperKind, held: &[Capability]| {
            check_mapper_capabilities(kind, held).map_err(|failure| failure.code)
        };
        let missing = Err(ErrorCode::CapabilityMissing);
        let audience = MapperKind::Audience {
            audience: "api".to_owned(),
        };
        assert_eq!(check(&audience, &[]), Ok(()));
        for of_people in [
            attribute("department"),
            MapperKind::FullName,
            MapperKind::Property {
                property: PersonProperty::Username,
            },
        ] {
            assert_eq!(check(&of_people, &[Capability::RoleRead]), missing);
            assert_eq!(check(&of_people, &[Capability::UserRead]), Ok(()));
        }
        for of_roles in [
            MapperKind::RealmRoles,
            MapperKind::ClientRoles {
                client_id: "billing".to_owned(),
            },
        ] {
            assert_eq!(check(&of_roles, &[Capability::UserRead]), missing);
            assert_eq!(check(&of_roles, &[Capability::RoleRead]), Ok(()));
        }
        let of_policies = attribute("policy.team");
        assert_eq!(check(&of_policies, &[Capability::UserRead]), missing);
        assert_eq!(
            check(
                &of_policies,
                &[Capability::UserRead, Capability::PolicyRead]
            ),
            Ok(())
        );
    }

    #[test]
    fn two_mappers_of_a_client_write_no_claim_and_read_no_source_twice_for_one_target() {
        let kept = [make_mapper(
            "dept",
            attribute("department"),
            Some("dept"),
            &[ClaimTarget::IdToken, ClaimTarget::Userinfo],
            Some("profile"),
        )];
        let check = |kind: MapperKind, claim: &'static str, targets: &'static [ClaimTarget]| {
            let wanted = NewMapper {
                name: "other",
                kind,
                claim: Some(claim),
                targets,
                scope: Some("profile"),
            };
            check_mapper_beside(&kept, &wanted).map_err(|failure| failure.code)
        };
        let overlaps = Err(ErrorCode::MapperOverlaps);

        assert_eq!(
            check(attribute("team"), "dept", &[ClaimTarget::Userinfo]),
            overlaps,
            "the same claim"
        );
        assert_eq!(
            check(attribute("department"), "team", &[ClaimTarget::IdToken]),
            overlaps,
            "the same source"
        );
        assert_eq!(
            check(attribute("department"), "dept", &[ClaimTarget::AccessToken]),
            Ok(()),
            "another target"
        );
        assert_eq!(
            check(attribute("team"), "team", &[ClaimTarget::IdToken]),
            Ok(())
        );
        let again = NewMapper {
            name: "dept",
            kind: attribute("team"),
            claim: Some("team"),
            targets: &[ClaimTarget::AccessToken],
            scope: Some("profile"),
        };
        assert_eq!(
            check_mapper_beside(&kept, &again).map_err(|failure| failure.code),
            Err(ErrorCode::MapperNameTaken)
        );
        let full: Vec<Mapper> = (0..50)
            .map(|index| {
                make_mapper(
                    &format!("m{index:02}"),
                    attribute(&format!("a{index:02}")),
                    Some(&format!("c{index:02}")),
                    &[ClaimTarget::IdToken],
                    Some("profile"),
                )
            })
            .collect();
        let wanted = NewMapper {
            name: "one-too-many",
            kind: attribute("team"),
            claim: Some("team"),
            targets: &[ClaimTarget::Userinfo],
            scope: Some("profile"),
        };
        assert_eq!(
            check_mapper_beside(&full, &wanted).map_err(|failure| failure.code),
            Err(ErrorCode::MapperLimitReached)
        );
        assert_eq!(check_mapper_beside(&full[..49], &wanted), Ok(()));
    }

    #[test]
    fn the_scopes_say_the_profile_and_the_address_in_identity_and_roles_in_access() {
        let person = ada();
        let granted = scopes("openid profile email roles");
        let grant = ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes: &granted,
        };
        let inputs = ClaimInputs {
            mappers: Vec::new(),
            attributes: read_object(&json!({
                "given_name": "Ada",
                "family_name": "Lovelace",
                "locale": ["fr", "en"],
                "nickname": true,
                "secret": "x",
            })),
            held: vec![
                held("reader", None, Some(600)),
                held("editor", Some("webapp"), None),
            ],
        };

        let identity = write_claims(ClaimTarget::IdToken, &grant, &inputs).expect("claims");
        assert_eq!(
            Value::Object(identity.claims),
            json!({
                "preferred_username": "ada",
                "name": "Ada L.",
                "given_name": "Ada",
                "family_name": "Lovelace",
                "email": "ada@example.org",
                "email_verified": true,
            }),
            "an attribute outside the profile, or of the profile and not a text, is not said"
        );
        let access = write_claims(ClaimTarget::AccessToken, &grant, &inputs).expect("claims");
        assert_eq!(
            access.claims["realm_access"],
            json!({ "roles": ["reader"] })
        );
        assert_eq!(
            access.claims["resource_access"],
            json!({ "webapp": { "roles": ["editor"] } })
        );
        assert_eq!(
            access.until,
            Some(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(600))
        );
        assert!(access.claims.get("email").is_none());
    }

    #[test]
    fn mappers_apply_to_their_targets_when_their_scope_is_granted_in_the_order_of_their_names() {
        let person = ada();
        let inputs = ClaimInputs {
            mappers: vec![
                make_mapper(
                    "b-dept",
                    attribute("department"),
                    Some("dept"),
                    &[ClaimTarget::IdToken, ClaimTarget::AccessToken],
                    Some("profile"),
                ),
                make_mapper(
                    "a-dept-first",
                    MapperKind::Property {
                        property: PersonProperty::Username,
                    },
                    Some("dept"),
                    &[ClaimTarget::IdToken],
                    Some("profile"),
                ),
                make_mapper(
                    "c-billing",
                    MapperKind::ClientRoles {
                        client_id: "billing".to_owned(),
                    },
                    Some("billing_roles"),
                    &[ClaimTarget::AccessToken],
                    Some("billing"),
                ),
                make_mapper(
                    "d-full",
                    MapperKind::FullName,
                    Some("full"),
                    &[ClaimTarget::Userinfo],
                    Some("profile"),
                ),
                make_mapper(
                    "e-api",
                    MapperKind::Audience {
                        audience: "https://api.example.org".to_owned(),
                    },
                    None,
                    &[ClaimTarget::AccessToken],
                    None,
                ),
                make_mapper(
                    "f-realm",
                    MapperKind::RealmRoles,
                    Some("roles"),
                    &[ClaimTarget::AccessToken],
                    Some("profile"),
                ),
            ],
            attributes: read_object(&json!({ "department": ["research"], "given_name": "Ada" })),
            held: vec![
                held("reader", None, None),
                held("approver", Some("billing"), Some(60)),
            ],
        };
        let without_billing = scopes("openid profile");
        let with_billing = scopes("openid profile billing");
        let grant = |scopes| ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes,
        };
        let write = |target, scopes| write_claims(target, &grant(scopes), &inputs).expect("claims");

        let identity = write(ClaimTarget::IdToken, &without_billing);
        assert_eq!(
            identity.claims["dept"],
            json!(["research"]),
            "the later name wins"
        );
        let access = write(ClaimTarget::AccessToken, &without_billing);
        assert_eq!(access.audiences, ["https://api.example.org"]);
        assert_eq!(access.claims["roles"], json!(["reader"]));
        assert!(
            access.claims.get("billing_roles").is_none(),
            "its scope was not granted"
        );
        assert_eq!(access.until, None);
        let access = write(ClaimTarget::AccessToken, &with_billing);
        assert_eq!(access.claims["billing_roles"], json!(["approver"]));
        assert_eq!(
            access.until,
            Some(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60)),
            "a token that says a role lives no longer than the role"
        );
        let userinfo = write(ClaimTarget::Userinfo, &without_billing);
        assert_eq!(
            Value::Object(userinfo.claims),
            json!({
                "full": "Ada",
                "given_name": "Ada",
                "name": "Ada L.",
                "preferred_username": "ada",
            })
        );
    }

    #[test]
    fn a_token_lives_as_long_as_the_roles_it_says_and_not_as_those_it_does_not() {
        let person = ada();
        let granted = scopes("openid profile");
        let grant = ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes: &granted,
        };
        let only = |kind| ClaimInputs {
            mappers: vec![make_mapper(
                "roles",
                kind,
                Some("roles"),
                &[ClaimTarget::AccessToken],
                Some("profile"),
            )],
            attributes: Map::new(),
            held: vec![
                held("auditor", None, Some(60)),
                held("editor", Some("billing"), Some(120)),
                held("viewer", Some("webapp"), Some(30)),
            ],
        };
        let of_billing = MapperKind::ClientRoles {
            client_id: "billing".to_owned(),
        };

        let said =
            write_claims(ClaimTarget::AccessToken, &grant, &only(of_billing)).expect("claims");
        assert_eq!(said.claims["roles"], json!(["editor"]));
        assert_eq!(
            said.until,
            Some(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(120))
        );
        let said = write_claims(
            ClaimTarget::AccessToken,
            &grant,
            &only(MapperKind::RealmRoles),
        )
        .expect("claims");
        assert_eq!(said.claims["roles"], json!(["auditor"]));
        assert_eq!(
            said.until,
            Some(OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60))
        );
        let lasting = ClaimInputs {
            held: vec![
                held("auditor", None, Some(60)),
                held("editor", Some("billing"), None),
            ],
            ..only(MapperKind::ClientRoles {
                client_id: "billing".to_owned(),
            })
        };
        let said = write_claims(ClaimTarget::AccessToken, &grant, &lasting).expect("claims");
        assert_eq!(
            said.until, None,
            "the role of the realm that ends is not said"
        );
    }

    #[test]
    fn a_mapper_kept_with_a_reserved_claim_writes_nothing_and_the_person_alone_says_verified() {
        let mut person = ada();
        person.email_verified = false;
        let mut mappers = Vec::new();
        for (name, source, claim) in [
            ("a", "verified", "email_verified"),
            ("b", "mail", "email"),
            ("c", "verified", "phone_number_verified"),
            ("d", "mail", "phone_number"),
            ("e", "mail", "sub"),
            ("f", "mail", "name"),
            ("g", "mail", "preferred_username"),
            ("h", "mail", "given_name"),
            ("i", "mail", "realm_access"),
            ("j", "verified", "Email_verified"),
            ("k", "mail", "EMAIL"),
            ("l", "mail", "Sub"),
            ("m", "verified", "Phone_number_verified"),
            ("n", "mail", "Realm_Access"),
            ("o", "mail", "realm_access.roles"),
            ("p", "mail", "sub_"),
            ("q", "verified", "email-verified"),
            ("r", "mail", "e_mail"),
            ("s", "mail", "nameid"),
        ] {
            mappers.push(make_mapper(
                name,
                attribute(source),
                Some(claim),
                &ClaimTarget::ALL,
                Some("profile"),
            ));
        }
        let inputs = ClaimInputs {
            mappers,
            attributes: read_object(&json!({ "verified": true, "mail": "boss@example.org" })),
            held: Vec::new(),
        };
        let with_email = scopes("openid profile email");
        let without_email = scopes("openid profile");
        let grant = |scopes| ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes,
        };

        let access = write_claims(ClaimTarget::AccessToken, &grant(&without_email), &inputs)
            .expect("claims");
        assert!(access.claims.is_empty(), "{:?}", access.claims);
        for target in [ClaimTarget::IdToken, ClaimTarget::Userinfo] {
            let said = write_claims(target, &grant(&with_email), &inputs).expect("claims");
            assert_eq!(
                Value::Object(said.claims),
                json!({
                    "email": "ada@example.org",
                    "email_verified": false,
                    "name": "Ada L.",
                    "preferred_username": "ada",
                }),
                "{target:?}: what the scopes say is the person's"
            );
        }
    }

    #[test]
    fn a_mapper_kept_without_a_scope_or_under_openid_says_nothing_of_the_person() {
        let person = ada();
        let inputs = ClaimInputs {
            mappers: vec![
                make_mapper(
                    "unscoped",
                    MapperKind::Property {
                        property: PersonProperty::Username,
                    },
                    Some("who"),
                    &[ClaimTarget::IdToken],
                    None,
                ),
                make_mapper(
                    "openid",
                    MapperKind::Property {
                        property: PersonProperty::Id,
                    },
                    Some("id"),
                    &[ClaimTarget::IdToken],
                    Some("openid"),
                ),
            ],
            ..ClaimInputs::default()
        };
        let granted = scopes("openid profile");
        let grant = ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes: &granted,
        };

        let said = write_claims(ClaimTarget::IdToken, &grant, &inputs).expect("claims");

        assert!(said.claims.get("who").is_none(), "{:?}", said.claims);
        assert!(said.claims.get("id").is_none(), "{:?}", said.claims);
    }

    #[test]
    fn a_client_acting_as_itself_gets_its_audiences_once_each_and_nothing_about_a_person() {
        let api = || MapperKind::Audience {
            audience: "https://api.example.org".to_owned(),
        };
        let inputs = ClaimInputs {
            mappers: vec![
                make_mapper("api", api(), None, &[ClaimTarget::AccessToken], None),
                make_mapper("api-again", api(), None, &[ClaimTarget::AccessToken], None),
                make_mapper(
                    "who",
                    MapperKind::Property {
                        property: PersonProperty::Id,
                    },
                    Some("who"),
                    &[ClaimTarget::AccessToken],
                    Some("roles"),
                ),
            ],
            ..ClaimInputs::default()
        };
        let granted = scopes("roles");
        let grant = ClaimGrant {
            person: None,
            client_id: "webapp",
            scopes: &granted,
        };

        let access = write_claims(ClaimTarget::AccessToken, &grant, &inputs).expect("claims");

        assert_eq!(access.audiences, ["https://api.example.org"]);
        assert!(access.claims.is_empty(), "{:?}", access.claims);
    }

    #[test]
    fn what_the_mappers_write_for_a_token_is_bounded_and_refused_past_it_by_name() {
        let person = ada();
        let granted = scopes("openid profile");
        let grant = ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes: &granted,
        };
        let copies: Vec<Mapper> = (0..50)
            .map(|index| {
                make_mapper(
                    &format!("m{index:02}"),
                    attribute("big"),
                    Some(&format!("c{index:02}")),
                    &[ClaimTarget::IdToken],
                    Some("profile"),
                )
            })
            .collect();
        let large = ClaimInputs {
            mappers: copies.clone(),
            attributes: read_object(&json!({ "big": vec!["x".repeat(1000); 15] })),
            held: Vec::new(),
        };
        assert_eq!(check_attributes(&large.attributes), Ok(()));
        let long_roles = ClaimInputs {
            mappers: vec![make_mapper(
                "roles",
                MapperKind::RealmRoles,
                Some("roles"),
                &[ClaimTarget::IdToken],
                Some("profile"),
            )],
            attributes: Map::new(),
            held: (0..1000)
                .map(|index| held(&format!("{index:04}-{}", "r".repeat(59)), None, None))
                .collect(),
        };
        let small = ClaimInputs {
            mappers: copies,
            attributes: read_object(&json!({ "big": "x" })),
            held: Vec::new(),
        };
        let write = |inputs| {
            write_claims(ClaimTarget::IdToken, &grant, inputs).map_err(|failure| failure.code)
        };

        assert_eq!(write(&large).map(|_| ()), Err(ErrorCode::ClaimsTooLarge));
        assert_eq!(
            write(&long_roles).map(|_| ()),
            Err(ErrorCode::ClaimsTooLarge)
        );
        assert_eq!(
            write(&small).map(|written| {
                let mapped = |name: &&String| name.starts_with('c') && name.len() == 3;
                written.claims.keys().filter(mapped).count()
            }),
            Ok(50),
            "fifty small claims are carried"
        );
    }

    #[test]
    fn a_token_for_the_administration_plane_carries_no_audience_of_a_mapper() {
        let api = MapperKind::Audience {
            audience: "https://api.example.org".to_owned(),
        };
        let inputs = ClaimInputs {
            mappers: vec![make_mapper(
                "api",
                api,
                None,
                &[ClaimTarget::AccessToken],
                None,
            )],
            ..ClaimInputs::default()
        };
        let write = |granted: &str| {
            let granted = scopes(granted);
            let grant = ClaimGrant {
                person: None,
                client_id: "operator",
                scopes: &granted,
            };
            write_claims(ClaimTarget::AccessToken, &grant, &inputs)
                .expect("claims")
                .audiences
        };

        assert_eq!(write("invoices:read"), ["https://api.example.org"]);
        assert!(write("admin invoices:read").is_empty());
    }

    /// One mapper that writes a text of `length` bytes, beside `audiences`.
    fn write_mapped(length: usize, audiences: usize) -> Result<(), ErrorCode> {
        let person = ada();
        let granted = scopes("openid profile");
        let grant = ClaimGrant {
            person: Some(&person),
            client_id: "webapp",
            scopes: &granted,
        };
        let mut mappers = vec![make_mapper(
            "big",
            attribute("big"),
            Some("c"),
            &[ClaimTarget::AccessToken],
            Some("profile"),
        )];
        for index in 0..audiences {
            mappers.push(make_mapper(
                &format!("aud-{index}"),
                MapperKind::Audience {
                    audience: format!("a{index}"),
                },
                None,
                &[ClaimTarget::AccessToken],
                None,
            ));
        }
        let inputs = ClaimInputs {
            mappers,
            attributes: read_object(&json!({ "big": "x".repeat(length) })),
            held: Vec::new(),
        };
        write_claims(ClaimTarget::AccessToken, &grant, &inputs)
            .map(|_| ())
            .map_err(|failure| failure.code)
    }

    #[test]
    fn what_the_mappers_write_is_carried_up_to_32_kib_exactly_their_audiences_included() {
        let shell = serde_json::to_vec(&(read_object(&json!({ "c": "" })), Vec::<String>::new()))
            .expect("JSON")
            .len();
        // Written out: a bound moved in the code must fail here.
        let at_the_bound = 32 * 1024 - shell;

        assert_eq!(write_mapped(at_the_bound, 0), Ok(()));
        assert_eq!(
            write_mapped(at_the_bound + 1, 0),
            Err(ErrorCode::ClaimsTooLarge)
        );
        assert_eq!(
            write_mapped(at_the_bound - 3, 1),
            Err(ErrorCode::ClaimsTooLarge),
            "the audience is measured with the claims"
        );
    }

    #[test]
    fn a_full_name_said_in_the_access_token_reads_the_attributes_without_openid() {
        let full = make_mapper(
            "full",
            MapperKind::FullName,
            Some("full"),
            &[ClaimTarget::AccessToken],
            Some("profile"),
        );
        let of_billing = make_mapper(
            "billing",
            MapperKind::ClientRoles {
                client_id: "billing".to_owned(),
            },
            Some("billing_roles"),
            &[ClaimTarget::AccessToken],
            Some("profile"),
        );
        let access = [ClaimTarget::AccessToken];

        assert!(needs_attributes(
            std::slice::from_ref(&full),
            &scopes("profile"),
            &access
        ));
        assert!(needs_roles(
            std::slice::from_ref(&of_billing),
            &scopes("profile"),
            &access
        ));
    }

    #[test]
    fn roles_and_attributes_are_read_only_for_a_target_and_a_scope_that_say_them() {
        let roles = make_mapper(
            "roles",
            MapperKind::RealmRoles,
            Some("roles"),
            &[ClaimTarget::Userinfo],
            Some("billing"),
        );
        let department = make_mapper(
            "dept",
            attribute("department"),
            Some("dept"),
            &[ClaimTarget::AccessToken],
            Some("email"),
        );
        let tokens = [ClaimTarget::AccessToken, ClaimTarget::IdToken];
        let userinfo = [ClaimTarget::Userinfo];

        assert!(needs_roles(&[], &scopes("openid roles"), &tokens));
        assert!(
            !needs_roles(&[], &scopes("openid roles"), &userinfo),
            "the scope says roles in an access token alone"
        );
        assert!(!needs_roles(
            std::slice::from_ref(&roles),
            &scopes("openid billing"),
            &tokens
        ));
        assert!(!needs_roles(
            std::slice::from_ref(&roles),
            &scopes("openid"),
            &userinfo
        ));
        assert!(needs_roles(
            std::slice::from_ref(&roles),
            &scopes("openid billing"),
            &userinfo
        ));
        assert!(needs_attributes(&[], &scopes("openid profile"), &userinfo));
        assert!(!needs_attributes(&[], &scopes("openid"), &tokens));
        assert!(needs_attributes(
            std::slice::from_ref(&department),
            &scopes("openid email"),
            &[ClaimTarget::AccessToken]
        ));
        assert!(!needs_attributes(
            std::slice::from_ref(&department),
            &scopes("openid"),
            &[ClaimTarget::AccessToken]
        ));
        assert!(
            !needs_attributes(
                std::slice::from_ref(&department),
                &scopes("openid email"),
                &userinfo
            ),
            "a mapper of another target"
        );
    }

    #[test]
    fn attributes_are_texts_truths_or_lists_of_texts_under_known_names() {
        let fine = read_object(&json!({
            "given_name": "Ada",
            "department": ["research", "engineering"],
            "contractor": false,
            "teams": vec!["t"; 32],
        }));
        assert_eq!(check_attributes(&fine), Ok(()));

        for wrong in [
            json!({ "has space": "x" }),
            json!({ "": "x" }),
            json!({ "with:colon": "x" }),
            json!({ "age": 36 }),
            json!({ "nested": { "a": "b" } }),
            json!({ "line": "a\nb" }),
            json!({ "hidden": "a\u{202e}b" }),
            json!({ "list": [1, 2] }),
            json!({ "long": "x".repeat(1025) }),
            json!({ "teams": vec!["t"; 33] }),
        ] {
            assert!(check_attributes(&read_object(&wrong)).is_err(), "{wrong}");
        }
        let many: Map<String, Value> = (0..65).map(|n| (format!("a{n}"), json!("x"))).collect();
        assert!(check_attributes(&many).is_err());
    }

    #[test]
    fn the_size_of_the_attributes_is_their_compact_json_up_to_16_kib() {
        let largest = fill_attributes(MAX_DOCUMENT_BYTES);
        assert_eq!(check_attributes(&largest), Ok(()));

        let past = fill_attributes(MAX_DOCUMENT_BYTES + 1);
        assert_eq!(
            check_attributes(&past).map_err(|failure| failure.detail),
            Err(Some("size".to_owned()))
        );
    }

    #[test]
    fn policies_read_the_attributes_of_their_space_and_a_writer_without_policy_write_keeps_them() {
        assert!(is_policy_attribute("policy.clearance"));
        for other in ["clearance", "policy.", "policy", "policies.clearance"] {
            assert!(!is_policy_attribute(other), "{other}");
        }
        assert_eq!(
            AttributeReach::written_by(&[Capability::UserWrite]),
            AttributeReach::OutsidePolicies
        );
        assert_eq!(
            AttributeReach::written_by(&[Capability::UserWrite, Capability::PolicyWrite]),
            AttributeReach::Every
        );
        let kept = read_object(&json!({ "department": "audit", "policy.clearance": "secret" }));
        let written = read_object(&json!({ "locale": "fr" }));

        assert_eq!(
            Value::Object(merge_attributes(
                kept.clone(),
                &written,
                AttributeReach::OutsidePolicies
            )),
            json!({ "locale": "fr", "policy.clearance": "secret" })
        );
        assert_eq!(
            Value::Object(merge_attributes(kept, &written, AttributeReach::Every)),
            json!({ "locale": "fr" })
        );
    }
}
