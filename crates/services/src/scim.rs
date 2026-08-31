use models::entities::attributes::{AttributeValue, AttributesMap};
use models::entities::authz::GroupModel;
use models::entities::user::{UserModel, profile};
use serde_json::{Value, json};

/// The user attribute carrying the provisioner's own identifier.
pub const EXTERNAL_ID: &str = "scim.external_id";

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
pub const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

/// A refusal in the protocol's own vocabulary: the HTTP status and, where
/// the RFC names one, the scimType that lets a provisioner react rather
/// than retry blindly.
#[derive(Debug, PartialEq)]
pub struct Refusal {
    pub status: u16,
    pub scim_type: Option<&'static str>,
    pub detail: String,
}

impl Refusal {
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self {
            status: 400,
            scim_type: Some("invalidValue"),
            detail: detail.into(),
        }
    }

    pub fn invalid_filter(detail: impl Into<String>) -> Self {
        Self {
            status: 400,
            scim_type: Some("invalidFilter"),
            detail: detail.into(),
        }
    }

    pub fn invalid_path(detail: impl Into<String>) -> Self {
        Self {
            status: 400,
            scim_type: Some("invalidPath"),
            detail: detail.into(),
        }
    }

    pub fn uniqueness(detail: impl Into<String>) -> Self {
        Self {
            status: 409,
            scim_type: Some("uniqueness"),
            detail: detail.into(),
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: 404,
            scim_type: None,
            detail: "no such resource".into(),
        }
    }

    pub fn body(&self) -> Value {
        let mut body = json!({
            "schemas": [ERROR_SCHEMA],
            "status": self.status.to_string(),
            "detail": self.detail,
        });
        if let Some(kind) = self.scim_type {
            body["scimType"] = json!(kind);
        }
        body
    }
}

/// What a User payload asserts, reduced to the fields this realm keeps.
#[derive(Debug, Default, Clone)]
pub struct AssertedUser {
    pub user_name: Option<String>,
    pub external_id: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub active: Option<bool>,
    pub password: Option<String>,
}

impl AssertedUser {
    /// Read a full User document, POST and PUT alike. Unknown fields pass
    /// unread, per §3.12: a provisioner sends the whole kitchen and a server
    /// keeps what its schema says.
    pub fn read(body: &Value) -> Result<Self, Refusal> {
        let text = |field: &Value| -> Result<Option<String>, Refusal> {
            match field {
                Value::Null => Ok(None),
                Value::String(held) => Ok(Some(held.trim().to_owned()).filter(|it| !it.is_empty())),
                _ => Err(Refusal::invalid("a string field held something else")),
            }
        };
        let mut asserted = Self {
            user_name: text(&body["userName"])?,
            external_id: text(&body["externalId"])?,
            password: text(&body["password"])?,
            active: match &body["active"] {
                Value::Null => None,
                Value::Bool(held) => Some(*held),
                _ => return Err(Refusal::invalid("active is a boolean")),
            },
            ..Self::default()
        };
        if let Some(name) = body.get("name") {
            asserted.given_name = text(&name["givenName"])?;
            asserted.family_name = text(&name["familyName"])?;
        }
        asserted.email = primary_value(body.get("emails"))?;
        asserted.phone = primary_value(body.get("phoneNumbers"))?;
        Ok(asserted)
    }

    /// Fold this assertion over an existing person, PUT semantics: what the
    /// document says replaces what stood, field by field of the mapping.
    pub fn apply(&self, person: &mut UserModel) {
        if let Some(active) = self.active {
            person.enabled = active;
        }
        if let Some(email) = &self.email
            && &person.email != email
        {
            person.email = email.clone();
            person.email_verified = Some(false);
        }
        person.phone_number = self.phone.clone().or(person.phone_number.take());
        let bag = person.attributes.get_or_insert_with(AttributesMap::new);
        for (key, held) in [
            (profile::FIRST_NAME, &self.given_name),
            (profile::LAST_NAME, &self.family_name),
            (EXTERNAL_ID, &self.external_id),
        ] {
            if let Some(value) = held {
                bag.insert(key.to_owned(), AttributeValue::Str(value.clone()));
            }
        }
    }
}

fn primary_value(field: Option<&Value>) -> Result<Option<String>, Refusal> {
    let Some(Value::Array(entries)) = field else {
        return match field {
            None | Some(Value::Null) => Ok(None),
            _ => Err(Refusal::invalid("a multi-valued field holds an array")),
        };
    };
    let chosen = entries
        .iter()
        .find(|entry| entry["primary"] == json!(true))
        .or_else(|| entries.first());
    Ok(chosen
        .and_then(|entry| entry["value"].as_str())
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .map(str::to_owned))
}

/// One person as the protocol shows them. The password never appears: its
/// mutability is writeOnly, and the schema says so.
pub fn shown_user(base: &str, person: &UserModel, groups: &[GroupModel]) -> Value {
    let held = |named: &str| {
        person
            .attributes
            .as_ref()
            .and_then(|bag| bag.get(named))
            .and_then(AttributeValue::as_str)
    };
    let mut body = json!({
        "schemas": [USER_SCHEMA],
        "id": person.user_id,
        "userName": person.user_name,
        "active": person.enabled,
        "meta": {
            "resourceType": "User",
            "location": format!("{base}/Users/{}", person.user_id),
            "version": weak_tag(person.metadata.version),
            "created": person.metadata.created_at,
            "lastModified": person.metadata.updated_at.or(person.metadata.created_at),
        },
    });
    if let Some(external) = held(EXTERNAL_ID) {
        body["externalId"] = json!(external);
    }
    let (given, family) = (held(profile::FIRST_NAME), held(profile::LAST_NAME));
    if given.is_some() || family.is_some() {
        let mut name = json!({});
        if let Some(value) = given {
            name["givenName"] = json!(value);
        }
        if let Some(value) = family {
            name["familyName"] = json!(value);
        }
        body["name"] = name;
    }
    if !person.email.is_empty() {
        body["emails"] = json!([{ "value": person.email, "primary": true }]);
    }
    if let Some(phone) = &person.phone_number {
        body["phoneNumbers"] = json!([{ "value": phone }]);
    }
    if !groups.is_empty() {
        body["groups"] = Value::Array(
            groups
                .iter()
                .map(|group| {
                    json!({
                        "value": group.group_id,
                        "display": group.name,
                        "$ref": format!("{base}/Groups/{}", group.group_id),
                    })
                })
                .collect(),
        );
    }
    body
}

pub fn shown_group(base: &str, group: &GroupModel, members: &[UserModel]) -> Value {
    json!({
        "schemas": [GROUP_SCHEMA],
        "id": group.group_id,
        "displayName": group.name,
        "members": members
            .iter()
            .map(|person| {
                json!({
                    "value": person.user_id,
                    "display": person.user_name,
                    "$ref": format!("{base}/Users/{}", person.user_id),
                })
            })
            .collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "location": format!("{base}/Groups/{}", group.group_id),
            "version": weak_tag(group.metadata.version),
            "created": group.metadata.created_at,
            "lastModified": group.metadata.updated_at.or(group.metadata.created_at),
        },
    })
}

pub fn weak_tag(version: i32) -> String {
    format!("W/\"{version}\"")
}

pub fn list_response(start_index: i64, total: i64, resources: Vec<Value>) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

/// The one filter shape a provisioner reconciles with: an attribute, `eq`,
/// a quoted value. Anything else is refused whole.
#[derive(Debug, PartialEq)]
pub enum Matched {
    UserName(String),
    ExternalId(String),
    Email(String),
    GroupName(String),
}

pub fn folded_filter(filter: &str, on_groups: bool) -> Result<Matched, Refusal> {
    let refused = || Refusal::invalid_filter("only <attribute> eq \"value\" is answered here");
    let mut pieces = filter.splitn(3, ' ');
    let (attribute, op, value) = (
        pieces.next().unwrap_or_default(),
        pieces.next().unwrap_or_default(),
        pieces.next().unwrap_or_default().trim(),
    );
    if !op.eq_ignore_ascii_case("eq") {
        return Err(refused());
    }
    let value = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .ok_or_else(refused)?;
    if value.is_empty() {
        return Err(refused());
    }
    let value = value.to_owned();
    if on_groups {
        return if attribute.eq_ignore_ascii_case("displayName") {
            Ok(Matched::GroupName(value))
        } else {
            Err(refused())
        };
    }
    if attribute.eq_ignore_ascii_case("userName") {
        Ok(Matched::UserName(value))
    } else if attribute.eq_ignore_ascii_case("externalId") {
        Ok(Matched::ExternalId(value))
    } else if attribute.eq_ignore_ascii_case("emails.value")
        || attribute.eq_ignore_ascii_case("emails[value")
    {
        Ok(Matched::Email(value))
    } else {
        Err(refused())
    }
}

/// One PATCH operation folded to what this realm can do.
#[derive(Debug, PartialEq)]
pub enum UserPatch {
    Active(bool),
    GivenName(Option<String>),
    FamilyName(Option<String>),
    ExternalId(String),
    Password(String),
    Email(String),
}

pub fn folded_user_patch(body: &Value) -> Result<Vec<UserPatch>, Refusal> {
    let mut folded = Vec::new();
    for operation in operations(body)? {
        let op = operation["op"].as_str().unwrap_or_default().to_lowercase();
        let path = operation["path"].as_str().unwrap_or_default();
        let value = &operation["value"];
        match (op.as_str(), path) {
            ("replace" | "add", "") => {
                // No path: the value is a partial document, §3.5.2.1.
                let asserted = AssertedUser::read(value)?;
                if let Some(active) = asserted.active {
                    folded.push(UserPatch::Active(active));
                }
                if let Some(given) = asserted.given_name {
                    folded.push(UserPatch::GivenName(Some(given)));
                }
                if let Some(family) = asserted.family_name {
                    folded.push(UserPatch::FamilyName(Some(family)));
                }
                if let Some(external) = asserted.external_id {
                    folded.push(UserPatch::ExternalId(external));
                }
                if let Some(password) = asserted.password {
                    folded.push(UserPatch::Password(password));
                }
                if let Some(email) = asserted.email {
                    folded.push(UserPatch::Email(email));
                }
            }
            ("replace" | "add", "active") => match value {
                Value::Bool(held) => folded.push(UserPatch::Active(*held)),
                // Entra spells booleans as strings in PATCH bodies.
                Value::String(held) if held.eq_ignore_ascii_case("true") => {
                    folded.push(UserPatch::Active(true));
                }
                Value::String(held) if held.eq_ignore_ascii_case("false") => {
                    folded.push(UserPatch::Active(false));
                }
                _ => return Err(Refusal::invalid("active is a boolean")),
            },
            ("replace" | "add", "name.givenName") => {
                folded.push(UserPatch::GivenName(value.as_str().map(str::to_owned)));
            }
            ("replace" | "add", "name.familyName") => {
                folded.push(UserPatch::FamilyName(value.as_str().map(str::to_owned)));
            }
            ("replace" | "add", "externalId") => {
                let held = value
                    .as_str()
                    .filter(|it| !it.is_empty())
                    .ok_or_else(|| Refusal::invalid("externalId is a string"))?;
                folded.push(UserPatch::ExternalId(held.to_owned()));
            }
            ("replace" | "add", "password") => {
                let held = value
                    .as_str()
                    .filter(|it| !it.is_empty())
                    .ok_or_else(|| Refusal::invalid("password is a string"))?;
                folded.push(UserPatch::Password(held.to_owned()));
            }
            (_, other) => {
                return Err(Refusal::invalid_path(format!(
                    "this server does not patch {}",
                    if other.is_empty() { &op } else { other }
                )));
            }
        }
    }
    Ok(folded)
}

#[derive(Debug, PartialEq)]
pub enum GroupPatch {
    Rename(String),
    AddMembers(Vec<String>),
    RemoveMembers(Vec<String>),
    ReplaceMembers(Vec<String>),
}

pub fn folded_group_patch(body: &Value) -> Result<Vec<GroupPatch>, Refusal> {
    let mut folded = Vec::new();
    for operation in operations(body)? {
        let op = operation["op"].as_str().unwrap_or_default().to_lowercase();
        let path = operation["path"].as_str().unwrap_or_default();
        let value = &operation["value"];
        match (op.as_str(), path) {
            ("replace", "displayName") => {
                let name = value
                    .as_str()
                    .filter(|it| !it.is_empty())
                    .ok_or_else(|| Refusal::invalid("displayName is a string"))?;
                folded.push(GroupPatch::Rename(name.to_owned()));
            }
            ("replace", "") => {
                if let Some(name) = value["displayName"].as_str().filter(|it| !it.is_empty()) {
                    folded.push(GroupPatch::Rename(name.to_owned()));
                }
                if let Some(members) = value.get("members") {
                    folded.push(GroupPatch::ReplaceMembers(member_ids(members)?));
                }
            }
            ("add", "members") => folded.push(GroupPatch::AddMembers(member_ids(value)?)),
            ("replace", "members") => folded.push(GroupPatch::ReplaceMembers(member_ids(value)?)),
            ("remove", "members") => folded.push(GroupPatch::RemoveMembers(member_ids(value)?)),
            (_, other) if other.starts_with("members[") => {
                // The filtered-path removal Entra sends:
                // members[value eq "some-id"].
                let inner = other
                    .strip_prefix("members[value eq \"")
                    .and_then(|rest| rest.strip_suffix("\"]"))
                    .ok_or_else(|| {
                        Refusal::invalid_path("only members[value eq \"…\"] is understood")
                    })?;
                match op.as_str() {
                    "remove" => folded.push(GroupPatch::RemoveMembers(vec![inner.to_owned()])),
                    _ => return Err(Refusal::invalid_path("a filtered member path only removes")),
                }
            }
            (_, other) => {
                return Err(Refusal::invalid_path(format!(
                    "this server does not patch {}",
                    if other.is_empty() { &op } else { other }
                )));
            }
        }
    }
    Ok(folded)
}

fn operations(body: &Value) -> Result<&Vec<Value>, Refusal> {
    if !body["schemas"]
        .as_array()
        .is_some_and(|held| held.iter().any(|schema| schema == PATCH_SCHEMA))
    {
        return Err(Refusal::invalid("a patch names the PatchOp schema"));
    }
    body["Operations"]
        .as_array()
        .filter(|held| !held.is_empty())
        .ok_or_else(|| Refusal::invalid("a patch carries operations"))
}

fn member_ids(value: &Value) -> Result<Vec<String>, Refusal> {
    let entries = value
        .as_array()
        .ok_or_else(|| Refusal::invalid("members is an array"))?;
    entries
        .iter()
        .map(|entry| {
            entry["value"]
                .as_str()
                .filter(|held| !held.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| Refusal::invalid("a member names its value"))
        })
        .collect()
}

/// What this server says of itself, §5. Honest above complete: what is
/// refused is announced as unsupported rather than discovered by a 400.
pub fn service_provider_config(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/saffui/saffui",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": true },
        "sort": { "supported": false },
        "etag": { "supported": true },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "A bearer token minted by this realm, carrying the scim capabilities.",
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{base}/ServiceProviderConfig"),
        },
    })
}

pub fn resource_types(base: &str) -> Value {
    list_response(
        1,
        2,
        vec![
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "User",
                "name": "User",
                "endpoint": "/Users",
                "schema": USER_SCHEMA,
                "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") },
            }),
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "schema": GROUP_SCHEMA,
                "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") },
            }),
        ],
    )
}

/// The two schemas, written from the mapping this module actually keeps.
pub fn schemas(base: &str) -> Value {
    let string_attr = |name: &str, mutability: &str, uniqueness: &str| {
        json!({
            "name": name, "type": "string", "multiValued": false,
            "mutability": mutability, "returned": if mutability == "writeOnly" { "never" } else { "default" },
            "uniqueness": uniqueness,
        })
    };
    list_response(
        1,
        2,
        vec![
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                "id": USER_SCHEMA,
                "name": "User",
                "attributes": [
                    string_attr("userName", "readWrite", "server"),
                    string_attr("externalId", "readWrite", "server"),
                    string_attr("password", "writeOnly", "none"),
                    { "name": "active", "type": "boolean", "multiValued": false, "mutability": "readWrite", "returned": "default" },
                    { "name": "name", "type": "complex", "multiValued": false, "mutability": "readWrite", "returned": "default",
                      "subAttributes": [string_attr("givenName", "readWrite", "none"), string_attr("familyName", "readWrite", "none")] },
                    { "name": "emails", "type": "complex", "multiValued": true, "mutability": "readWrite", "returned": "default" },
                    { "name": "phoneNumbers", "type": "complex", "multiValued": true, "mutability": "readWrite", "returned": "default" },
                    { "name": "groups", "type": "complex", "multiValued": true, "mutability": "readOnly", "returned": "default" },
                ],
                "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{USER_SCHEMA}") },
            }),
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
                "id": GROUP_SCHEMA,
                "name": "Group",
                "attributes": [
                    string_attr("displayName", "readWrite", "server"),
                    { "name": "members", "type": "complex", "multiValued": true, "mutability": "readWrite", "returned": "default" },
                ],
                "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{GROUP_SCHEMA}") },
            }),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_reads_to_the_mapping_and_no_further() {
        let asserted = AssertedUser::read(&json!({
            "schemas": [USER_SCHEMA],
            "userName": "ada",
            "externalId": "hr-77",
            "name": { "givenName": "Ada", "familyName": "Lovelace" },
            "emails": [
                { "value": "old@example.test" },
                { "value": "ada@example.test", "primary": true },
            ],
            "password": "a-password-of-decent-length",
            "active": true,
            "title": "unread and unrefused",
        }))
        .expect("a whole document reads");
        assert_eq!(asserted.user_name.as_deref(), Some("ada"));
        assert_eq!(asserted.external_id.as_deref(), Some("hr-77"));
        assert_eq!(
            asserted.email.as_deref(),
            Some("ada@example.test"),
            "primary wins"
        );
        assert_eq!(asserted.active, Some(true));

        assert!(AssertedUser::read(&json!({ "active": "yes" })).is_err());
    }

    #[test]
    fn the_filter_folds_the_reconciliation_shapes_and_refuses_the_rest() {
        assert_eq!(
            folded_filter("userName eq \"ada\"", false),
            Ok(Matched::UserName("ada".into()))
        );
        assert_eq!(
            folded_filter("externalId eq \"hr-77\"", false),
            Ok(Matched::ExternalId("hr-77".into()))
        );
        assert_eq!(
            folded_filter("emails.value eq \"ada@example.test\"", false),
            Ok(Matched::Email("ada@example.test".into()))
        );
        assert_eq!(
            folded_filter("displayName eq \"crew\"", true),
            Ok(Matched::GroupName("crew".into()))
        );
        for wrong in [
            "userName co \"ad\"",
            "userName sw \"ad\"",
            "title eq \"boss\"",
            "userName eq ada",
            "userName eq \"\"",
        ] {
            assert!(folded_filter(wrong, false).is_err(), "{wrong} folded");
        }
    }

    #[test]
    fn a_patch_folds_whole_or_refuses_whole() {
        let entra = json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                { "op": "Replace", "path": "active", "value": "False" },
                { "op": "replace", "value": { "name": { "givenName": "Augusta" } } },
            ],
        });
        assert_eq!(
            folded_user_patch(&entra).unwrap(),
            vec![
                UserPatch::Active(false),
                UserPatch::GivenName(Some("Augusta".into())),
            ]
        );

        let stray = json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{ "op": "remove", "path": "userName" }],
        });
        assert!(folded_user_patch(&stray).is_err());

        let members = json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [
                { "op": "add", "path": "members", "value": [{ "value": "ada" }] },
                { "op": "remove", "path": "members[value eq \"grace\"]" },
            ],
        });
        assert_eq!(
            folded_group_patch(&members).unwrap(),
            vec![
                GroupPatch::AddMembers(vec!["ada".into()]),
                GroupPatch::RemoveMembers(vec!["grace".into()]),
            ]
        );

        let unschemaed =
            json!({ "Operations": [{ "op": "replace", "path": "active", "value": true }] });
        assert!(
            folded_user_patch(&unschemaed).is_err(),
            "a patch without its schema held"
        );
    }
}
