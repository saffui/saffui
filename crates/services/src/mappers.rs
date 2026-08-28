use std::collections::BTreeMap;

use deadpool_postgres::Transaction;
use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::client::ProtocolMapperModel;
use models::entities::user::{UserModel, profile};
use serde_json::{Map, Value};
use store::providers::{client_scopes, roles, users};

/// Map a user scalar (`username` / `email` / `emailVerified`) to a claim.
pub const PROPERTY_MAPPER: &str = "oidc-usermodel-property-mapper";
/// Map a user attribute to a claim, honoring `multivalued`.
pub const ATTRIBUTE_MAPPER: &str = "oidc-usermodel-attribute-mapper";
/// Join the first and last name attributes into one claim, `name` unless said.
pub const FULL_NAME_MAPPER: &str = "oidc-full-name-mapper";
/// The user's realm roles, `realm_access.roles` unless said.
pub const REALM_ROLE_MAPPER: &str = "oidc-usermodel-realm-role-mapper";
/// The user's client roles, `resource_access.{client}.roles` per client.
pub const CLIENT_ROLE_MAPPER: &str = "oidc-usermodel-client-role-mapper";
/// Add a named audience to `aud`.
pub const AUDIENCE_MAPPER: &str = "oidc-audience-mapper";

/// Every rule this build applies. The store keeps no catalogue on purpose, so
/// this list is the one place that says what a mapper type can mean, and the
/// plane refuses names outside it rather than recording rules nothing runs.
pub const KNOWN_TYPES: [&str; 6] = [
    PROPERTY_MAPPER,
    ATTRIBUTE_MAPPER,
    FULL_NAME_MAPPER,
    REALM_ROLE_MAPPER,
    CLIENT_ROLE_MAPPER,
    AUDIENCE_MAPPER,
];

pub const CLAIM_NAME: &str = "claim.name";
pub const JSON_TYPE: &str = "jsonType.label";
pub const ID_TOKEN_CLAIM: &str = "id.token.claim";
pub const ACCESS_TOKEN_CLAIM: &str = "access.token.claim";
pub const USERINFO_TOKEN_CLAIM: &str = "userinfo.token.claim";
pub const MULTIVALUED: &str = "multivalued";
pub const USER_ATTRIBUTE: &str = "user.attribute";
pub const INCLUDED_CLIENT_AUDIENCE: &str = "included.client.audience";
pub const INCLUDED_CUSTOM_AUDIENCE: &str = "included.custom.audience";

/// Which answer a mapper evaluation is shaping. A mapper contributes to a
/// target only when its flag says so, and an absent flag says yes: a
/// minimally configured mapper reaches everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    AccessToken,
    IdToken,
    UserInfo,
}

impl Target {
    fn flag(self) -> &'static str {
        match self {
            Target::AccessToken => ACCESS_TOKEN_CLAIM,
            Target::IdToken => ID_TOKEN_CLAIM,
            Target::UserInfo => USERINFO_TOKEN_CLAIM,
        }
    }
}

/// Everything an evaluation reads, resolved once and borrowed three times so
/// the access token, the identity token and the UserInfo answer cannot be
/// shaped from two different states.
pub struct Resolved {
    pub mappers: Vec<ProtocolMapperModel>,
    pub realm_roles: Vec<String>,
    pub client_roles: BTreeMap<String, Vec<String>>,
}

impl Resolved {
    pub fn is_empty(&self) -> bool {
        self.mappers.is_empty()
    }
}

/// The mapper set a grant is under, and the roles it needs.
///
/// A client's own mappers always apply. A scope's apply as the scope does:
/// attached as required, or attached as optional and named by the grant.
/// Roles are read only when a role mapper is present, so a grant with none
/// costs no role query.
pub async fn resolve(
    transaction: &Transaction<'_>,
    client_id: &str,
    user_id: &str,
    scope: &str,
) -> Result<Resolved, ()> {
    let granted: Vec<String> = scope.split_whitespace().map(str::to_owned).collect();
    let mappers = client_scopes::mappers_for_grant(transaction, client_id, &granted)
        .await
        .map_err(|_| ())?;

    let needs_realm = mappers
        .iter()
        .any(|mapper| mapper.mapper_type == REALM_ROLE_MAPPER);
    let needs_client = mappers
        .iter()
        .any(|mapper| mapper.mapper_type == CLIENT_ROLE_MAPPER);
    let mut realm_roles = Vec::new();
    let mut client_roles: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if needs_realm || needs_client {
        for role in roles::effective_roles(transaction, user_id)
            .await
            .map_err(|_| ())?
        {
            match role.client_id {
                None if needs_realm => realm_roles.push(role.name),
                Some(owner) if needs_client => {
                    client_roles.entry(owner).or_default().push(role.name);
                }
                _ => {}
            }
        }
    }
    Ok(Resolved {
        mappers,
        realm_roles,
        client_roles,
    })
}

/// What a grant's mappers add to each token, shaped once so the two cannot
/// be shaped from different states. The audiences ride apart from the claim
/// bags: `aud` is a named claim the mint writes from its audience list, so
/// what a mapper says joins that list instead of dying in the bag.
#[derive(Default)]
pub struct Overlay {
    pub access: Map<String, Value>,
    pub identity: Map<String, Value>,
    pub access_audiences: Vec<String>,
    pub identity_audiences: Vec<String>,
}

/// The overlay this grant mints under. The person is read only when a mapper
/// applies, so a grant with none costs nothing new.
pub async fn overlay_for(
    transaction: &Transaction<'_>,
    client_id: &str,
    user_id: &str,
    scope: &str,
) -> Result<Overlay, ()> {
    let resolved = resolve(transaction, client_id, user_id, scope).await?;
    if resolved.is_empty() {
        return Ok(Overlay::default());
    }
    let Some(user) = users::load(transaction, user_id).await.map_err(|_| ())? else {
        return Ok(Overlay::default());
    };
    let mut access = evaluate(Target::AccessToken, &resolved, &user);
    let mut identity = evaluate(Target::IdToken, &resolved, &user);
    Ok(Overlay {
        access_audiences: take_audiences(&mut access),
        identity_audiences: take_audiences(&mut identity),
        access,
        identity,
    })
}

fn take_audiences(claims: &mut Map<String, Value>) -> Vec<String> {
    match claims.remove("aud") {
        Some(Value::Array(entries)) => entries
            .into_iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect(),
        Some(Value::String(one)) => vec![one],
        _ => Vec::new(),
    }
}

/// Add what the mappers said, where the flow said nothing. A mapper extends a
/// token; it never displaces a claim the flow wrote, because a rule from a
/// registration must not rewrite what an authentication established.
pub fn fill(into: &mut Map<String, Value>, overlay: Map<String, Value>) {
    for (name, value) in overlay {
        into.entry(name).or_insert(value);
    }
}

/// Union the mapper audiences into the token's, without duplicates.
pub fn widen(audiences: &mut Vec<String>, extra: &[String]) {
    for one in extra {
        if !audiences.iter().any(|held| held == one) {
            audiences.push(one.clone());
        }
    }
}

/// What the resolved mappers say for one target, on one person.
pub fn evaluate(target: Target, resolved: &Resolved, user: &UserModel) -> Map<String, Value> {
    let mut claims = Map::new();
    for mapper in &resolved.mappers {
        if !config_bool(&mapper.configs, target.flag(), true) {
            continue;
        }
        match mapper.mapper_type.as_str() {
            PROPERTY_MAPPER => apply_property(mapper, user, &mut claims),
            ATTRIBUTE_MAPPER => apply_attribute(mapper, user, &mut claims),
            FULL_NAME_MAPPER => apply_full_name(mapper, user, &mut claims),
            REALM_ROLE_MAPPER => apply_realm_roles(mapper, &resolved.realm_roles, &mut claims),
            CLIENT_ROLE_MAPPER => apply_client_roles(&resolved.client_roles, &mut claims),
            AUDIENCE_MAPPER => apply_audience(mapper, &mut claims),
            // A rule this build does not know decides nothing here; the plane
            // refuses to record one, so this arm answers only rows written
            // some other way, and breaking issuance over them helps nobody.
            _ => {}
        }
    }
    claims
}

fn apply_property(mapper: &ProtocolMapperModel, user: &UserModel, claims: &mut Map<String, Value>) {
    let (Some(claim_name), Some(property)) = (
        config_str(&mapper.configs, CLAIM_NAME),
        config_str(&mapper.configs, USER_ATTRIBUTE),
    ) else {
        return;
    };
    let raw = match property {
        "username" => Value::String(user.user_name.clone()),
        // An empty email is no email: nothing, rather than a blank claim.
        "email" if !user.email.is_empty() => Value::String(user.email.clone()),
        "emailVerified" => Value::Bool(user.email_verified.unwrap_or(false)),
        _ => return,
    };
    insert_claim(claims, claim_name, coerce(&mapper.configs, raw));
}

fn apply_attribute(
    mapper: &ProtocolMapperModel,
    user: &UserModel,
    claims: &mut Map<String, Value>,
) {
    let (Some(claim_name), Some(attribute)) = (
        config_str(&mapper.configs, CLAIM_NAME),
        config_str(&mapper.configs, USER_ATTRIBUTE),
    ) else {
        return;
    };
    let Some(value) = user
        .attributes
        .as_ref()
        .and_then(|held| held.get(attribute))
    else {
        return;
    };
    let multivalued = config_bool(&mapper.configs, MULTIVALUED, false);
    insert_claim(
        claims,
        claim_name,
        attribute_to_json(value.clone(), multivalued, &mapper.configs),
    );
}

fn apply_full_name(
    mapper: &ProtocolMapperModel,
    user: &UserModel,
    claims: &mut Map<String, Value>,
) {
    let parts: Vec<&str> = [profile::FIRST_NAME, profile::LAST_NAME]
        .into_iter()
        .filter_map(|key| {
            user.attributes
                .as_ref()
                .and_then(|held| held.get(key))
                .and_then(AttributeValue::as_str)
        })
        .filter(|part| !part.is_empty())
        .collect();
    if parts.is_empty() {
        return;
    }
    let claim_name = config_str(&mapper.configs, CLAIM_NAME).unwrap_or("name");
    insert_claim(claims, claim_name, Value::String(parts.join(" ")));
}

fn apply_realm_roles(
    mapper: &ProtocolMapperModel,
    realm_roles: &[String],
    claims: &mut Map<String, Value>,
) {
    if realm_roles.is_empty() {
        return;
    }
    let claim_name = config_str(&mapper.configs, CLAIM_NAME).unwrap_or("realm_access.roles");
    insert_claim(claims, claim_name, string_array(realm_roles));
}

fn apply_client_roles(
    client_roles: &BTreeMap<String, Vec<String>>,
    claims: &mut Map<String, Value>,
) {
    for (client, roles) in client_roles {
        if roles.is_empty() {
            continue;
        }
        insert_claim(
            claims,
            &format!("resource_access.{client}.roles"),
            string_array(roles),
        );
    }
}

/// Emitted under `aud` as an array; the mint site unions it into the token's
/// audiences rather than letting it displace them.
fn apply_audience(mapper: &ProtocolMapperModel, claims: &mut Map<String, Value>) {
    let Some(audience) = config_str(&mapper.configs, INCLUDED_CLIENT_AUDIENCE)
        .or_else(|| config_str(&mapper.configs, INCLUDED_CUSTOM_AUDIENCE))
    else {
        return;
    };
    insert_claim(
        claims,
        "aud",
        Value::Array(vec![Value::String(audience.to_owned())]),
    );
}

/// Insert at a dot-nested path: `realm_access.roles` lands under
/// `{"realm_access": {"roles": ...}}`. A segment already holding a non-object
/// drops the claim rather than clobbering a different shape.
fn insert_claim(claims: &mut Map<String, Value>, dotted: &str, value: Value) {
    let parts: Vec<&str> = dotted.split('.').filter(|part| !part.is_empty()).collect();
    insert_nested(claims, &parts, value);
}

fn insert_nested(map: &mut Map<String, Value>, parts: &[&str], value: Value) {
    match parts {
        [] => {}
        [leaf] => {
            map.insert((*leaf).to_owned(), value);
        }
        [head, tail @ ..] => {
            let entry = map
                .entry((*head).to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Value::Object(inner) = entry {
                insert_nested(inner, tail, value);
            }
        }
    }
}

fn string_array<S: AsRef<str>>(values: &[S]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::String(value.as_ref().to_owned()))
            .collect(),
    )
}

fn config_str<'a>(configs: &'a Option<AttributesMap>, key: &str) -> Option<&'a str> {
    configs
        .as_ref()
        .and_then(|map| map.get(key))
        .and_then(AttributeValue::as_str)
}

/// A configuration flag, read as stored or as the string a JSON bag carries.
fn config_bool(configs: &Option<AttributesMap>, key: &str, resting: bool) -> bool {
    match configs.as_ref().and_then(|map| map.get(key)) {
        Some(AttributeValue::Bool(value)) => *value,
        Some(AttributeValue::Str(value)) => {
            matches!(value.trim().to_ascii_lowercase().as_str(), "true" | "1")
        }
        _ => resting,
    }
}

/// Coerce a string to the type `jsonType.label` names. Values already of
/// another shape pass through: the label narrows strings, it does not cast.
fn coerce(configs: &Option<AttributesMap>, raw: Value) -> Value {
    match config_str(configs, JSON_TYPE) {
        Some("long") | Some("int") => match &raw {
            Value::String(value) => value.parse::<i64>().map(Value::from).unwrap_or(raw),
            _ => raw,
        },
        Some("boolean") => match &raw {
            Value::String(value) => Value::Bool(matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "true" | "1"
            )),
            _ => raw,
        },
        _ => raw,
    }
}

fn attribute_to_json(
    value: AttributeValue,
    multivalued: bool,
    configs: &Option<AttributesMap>,
) -> Value {
    match value {
        AttributeValue::Str(value) => {
            if multivalued {
                Value::Array(vec![Value::String(value)])
            } else {
                coerce(configs, Value::String(value))
            }
        }
        AttributeValue::Int(value) => Value::from(value),
        AttributeValue::Bool(value) => Value::Bool(value),
        AttributeValue::ListStr(list) => {
            if multivalued {
                Value::Array(list.into_iter().map(Value::String).collect())
            } else {
                list.into_iter()
                    .next()
                    .map(Value::String)
                    .unwrap_or(Value::Null)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use models::auditable::AuditableModel;
    use models::entities::client::Protocol;
    use serde_json::json;

    fn person() -> UserModel {
        UserModel {
            user_id: "u1".into(),
            realm_id: "main".into(),
            user_name: "bob".into(),
            enabled: true,
            email: "bob@acme.test".into(),
            email_verified: Some(true),
            phone_number: None,
            phone_number_verified: None,
            required_actions: None,
            not_before: None,
            user_storage: None,
            attributes: Some(AttributesMap::from([
                (
                    profile::FIRST_NAME.to_owned(),
                    AttributeValue::Str("Bob".into()),
                ),
                (
                    profile::LAST_NAME.to_owned(),
                    AttributeValue::Str("Martin".into()),
                ),
                ("department".to_owned(), AttributeValue::Str("mines".into())),
                (
                    "badges".to_owned(),
                    AttributeValue::ListStr(vec!["red".into(), "gold".into()]),
                ),
                ("floor".to_owned(), AttributeValue::Str("7".into())),
            ])),
            is_service_account: None,
            service_account_client_link: None,
            metadata: AuditableModel::unassigned(),
        }
    }

    fn rule(mapper_type: &str, configs: &[(&str, &str)]) -> ProtocolMapperModel {
        ProtocolMapperModel {
            mapper_id: "m1".into(),
            realm_id: "main".into(),
            name: "rule".into(),
            protocol: Protocol::OpenId,
            mapper_type: mapper_type.into(),
            configs: Some(
                configs
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), AttributeValue::Str((*value).into())))
                    .collect(),
            ),
            metadata: AuditableModel::unassigned(),
        }
    }

    fn alone(mapper: ProtocolMapperModel) -> Resolved {
        Resolved {
            mappers: vec![mapper],
            realm_roles: Vec::new(),
            client_roles: BTreeMap::new(),
        }
    }

    /// A user scalar lands under the configured name, coerced when asked.
    #[test]
    fn a_property_becomes_a_claim_of_the_named_type() {
        let told = evaluate(
            Target::IdToken,
            &alone(rule(
                PROPERTY_MAPPER,
                &[(CLAIM_NAME, "who"), (USER_ATTRIBUTE, "username")],
            )),
            &person(),
        );
        assert_eq!(told, Map::from_iter([("who".into(), json!("bob"))]));

        let told = evaluate(
            Target::IdToken,
            &alone(rule(
                ATTRIBUTE_MAPPER,
                &[
                    (CLAIM_NAME, "floor"),
                    (USER_ATTRIBUTE, "floor"),
                    (JSON_TYPE, "int"),
                ],
            )),
            &person(),
        );
        assert_eq!(told["floor"], json!(7), "the label narrows the string");
    }

    /// An empty email is no email, and an unknown property is nothing at all.
    #[test]
    fn what_is_not_there_is_not_claimed() {
        let mut nobody = person();
        nobody.email = String::new();
        let told = evaluate(
            Target::IdToken,
            &alone(rule(
                PROPERTY_MAPPER,
                &[(CLAIM_NAME, "mail"), (USER_ATTRIBUTE, "email")],
            )),
            &nobody,
        );
        assert!(told.is_empty(), "an empty email became a blank claim");

        let told = evaluate(
            Target::IdToken,
            &alone(rule(
                ATTRIBUTE_MAPPER,
                &[(CLAIM_NAME, "x"), (USER_ATTRIBUTE, "absent")],
            )),
            &person(),
        );
        assert!(told.is_empty(), "an absent attribute became a claim");
    }

    /// A list attribute answers whole when multivalued and first when not.
    #[test]
    fn multivalued_decides_the_shape() {
        let whole = evaluate(
            Target::AccessToken,
            &alone(rule(
                ATTRIBUTE_MAPPER,
                &[
                    (CLAIM_NAME, "badges"),
                    (USER_ATTRIBUTE, "badges"),
                    (MULTIVALUED, "true"),
                ],
            )),
            &person(),
        );
        assert_eq!(whole["badges"], json!(["red", "gold"]));

        let first = evaluate(
            Target::AccessToken,
            &alone(rule(
                ATTRIBUTE_MAPPER,
                &[(CLAIM_NAME, "badge"), (USER_ATTRIBUTE, "badges")],
            )),
            &person(),
        );
        assert_eq!(first["badge"], json!("red"));
    }

    /// The two name halves join; a person with neither says nothing.
    #[test]
    fn the_full_name_is_composed_or_absent() {
        let told = evaluate(
            Target::UserInfo,
            &alone(rule(FULL_NAME_MAPPER, &[])),
            &person(),
        );
        assert_eq!(told["name"], json!("Bob Martin"));

        let mut nameless = person();
        nameless.attributes = None;
        let told = evaluate(
            Target::UserInfo,
            &alone(rule(FULL_NAME_MAPPER, &[])),
            &nameless,
        );
        assert!(told.is_empty());
    }

    /// Roles land nested: the dotted resting name builds the object a relying
    /// party expects, and each client's land under its own name.
    #[test]
    fn roles_land_under_their_nested_names() {
        let resolved = Resolved {
            mappers: vec![rule(REALM_ROLE_MAPPER, &[]), rule(CLIENT_ROLE_MAPPER, &[])],
            realm_roles: vec!["auditor".into()],
            client_roles: BTreeMap::from([("app".to_owned(), vec!["editor".to_owned()])]),
        };
        let told = evaluate(Target::AccessToken, &resolved, &person());
        assert_eq!(told["realm_access"]["roles"], json!(["auditor"]));
        assert_eq!(told["resource_access"]["app"]["roles"], json!(["editor"]));
    }

    /// A mapper reaches only the answers its flags allow; absent flags allow
    /// everything.
    #[test]
    fn the_target_flags_gate_each_answer() {
        let quiet = alone(rule(
            PROPERTY_MAPPER,
            &[
                (CLAIM_NAME, "who"),
                (USER_ATTRIBUTE, "username"),
                (ACCESS_TOKEN_CLAIM, "false"),
            ],
        ));
        assert!(evaluate(Target::AccessToken, &quiet, &person()).is_empty());
        assert!(!evaluate(Target::IdToken, &quiet, &person()).is_empty());
        assert!(!evaluate(Target::UserInfo, &quiet, &person()).is_empty());
    }

    /// The audience rides out under `aud` and is taken apart from the claims;
    /// a rule this build does not know decides nothing.
    #[test]
    fn audiences_ride_apart_and_unknown_rules_are_silent() {
        let mut told = evaluate(
            Target::AccessToken,
            &alone(rule(
                AUDIENCE_MAPPER,
                &[(INCLUDED_CLIENT_AUDIENCE, "resource-server")],
            )),
            &person(),
        );
        assert_eq!(
            take_audiences(&mut told),
            vec!["resource-server".to_owned()]
        );
        assert!(told.is_empty());

        let told = evaluate(
            Target::AccessToken,
            &alone(rule("oidc-invented-elsewhere", &[(CLAIM_NAME, "x")])),
            &person(),
        );
        assert!(told.is_empty());
    }

    /// What the flow wrote stays written, and a widened audience never
    /// repeats one already named.
    #[test]
    fn the_flow_wins_and_audiences_do_not_repeat() {
        let mut extra = Map::from_iter([("acr".to_owned(), json!("strong"))]);
        fill(
            &mut extra,
            Map::from_iter([
                ("acr".to_owned(), json!("weak")),
                ("department".to_owned(), json!("mines")),
            ]),
        );
        assert_eq!(extra["acr"], json!("strong"));
        assert_eq!(extra["department"], json!("mines"));

        let mut audiences = vec!["app".to_owned()];
        widen(&mut audiences, &["app".to_owned(), "other".to_owned()]);
        assert_eq!(audiences, vec!["app".to_owned(), "other".to_owned()]);
    }

    /// A dotted path never clobbers a claim of another shape on its way down.
    #[test]
    fn a_dotted_path_does_not_clobber_a_scalar() {
        let mut claims = Map::from_iter([("realm_access".to_owned(), json!("opaque"))]);
        insert_claim(&mut claims, "realm_access.roles", json!(["auditor"]));
        assert_eq!(claims["realm_access"], json!("opaque"));
    }
}
