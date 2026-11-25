//! The `claims` parameter of an authorization request (OpenID Connect Core
//! 1.0, section 5.5): the claims a client names one by one, for the identity
//! token and for the userinfo answer. Read once, at the door, into the shape
//! kept with the request, its code and its refresh tokens.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::ClaimTarget;

/// The longest parameter read, in bytes: it is kept with every refresh token
/// of its grant, and no request names claims by the hundred.
pub const MAX_CLAIMS_PARAMETER_BYTES: usize = 2 * 1024;

/// What a client asked of one claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaimAsk {
    /// It changes nothing, but for `acr` (section 5.5.1).
    pub essential: bool,
    /// `value` and `values` as one list: the claim is said only with one of
    /// them. Empty, it is said with whatever value is held.
    pub values: Vec<Value>,
}

impl ClaimAsk {
    /// Whether a value held is one the client takes.
    #[must_use]
    pub fn accepts(&self, held: &Value) -> bool {
        self.values.is_empty() || self.values.contains(held)
    }
}

/// The claims a request names, for the identity token and for userinfo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClaimsRequest {
    pub id_token: BTreeMap<String, ClaimAsk>,
    pub userinfo: BTreeMap<String, ClaimAsk>,
}

impl ClaimsRequest {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.id_token.is_empty() && self.userinfo.is_empty()
    }

    /// The request, when it names a claim: one that names none asks nothing.
    #[must_use]
    pub fn into_named(self) -> Option<Self> {
        (!self.is_empty()).then_some(self)
    }

    /// The claims named for `target`. An access token is named none.
    #[must_use]
    pub fn list_asked(&self, target: ClaimTarget) -> Option<&BTreeMap<String, ClaimAsk>> {
        match target {
            ClaimTarget::IdToken => Some(&self.id_token),
            ClaimTarget::Userinfo => Some(&self.userinfo),
            ClaimTarget::AccessToken => None,
        }
    }

    /// Whether the person `subject` answers the request: a `sub` named with
    /// values, for either target, names them (sections 3.1.2.2 and 5.5.1).
    #[must_use]
    pub fn admits_subject(&self, subject: &str) -> bool {
        let named = Value::String(subject.to_owned());
        [&self.id_token, &self.userinfo]
            .into_iter()
            .filter_map(|asked| asked.get("sub"))
            .all(|asked| asked.accepts(&named))
    }

    /// The values of the `acr` the identity token is asked to say as
    /// essential, when it names any (section 5.5.1.1).
    #[must_use]
    pub fn read_essential_levels(&self) -> Option<&[Value]> {
        self.id_token
            .get("acr")
            .filter(|asked| asked.essential && !asked.values.is_empty())
            .map(|asked| asked.values.as_slice())
    }

    /// The request as it is kept: what was read of it, and nothing it
    /// carried beside. [`read_claims_document`] reads it back.
    #[must_use]
    pub fn write_document(&self) -> Value {
        let write_half = |asked: &BTreeMap<String, ClaimAsk>| -> Value {
            let claims = asked.iter().map(|(name, ask)| {
                let mut members = Map::new();
                if ask.essential {
                    members.insert("essential".to_owned(), Value::Bool(true));
                }
                if !ask.values.is_empty() {
                    members.insert("values".to_owned(), Value::Array(ask.values.clone()));
                }
                (name.clone(), Value::Object(members))
            });
            Value::Object(claims.collect())
        };
        json!({
            "id_token": write_half(&self.id_token),
            "userinfo": write_half(&self.userinfo),
        })
    }
}

/// Reads the parameter as a client sent it, in the query or in its request
/// object. A member this build does not know is ignored, at each level
/// (section 5.5.1); one it knows that is not written as the specification
/// writes it refuses the whole, as does a text past the bound, read no further.
/// So does a control character in a name or a value: the database would
/// refuse only `\u0000` in the document kept, but no client writes any of
/// them on purpose, and one rule for all, as for `state` and `nonce`, tells
/// the client at once and keeps none. So does a subject named with several
/// values: a request names one person or none (section 3.1.2.2).
#[must_use]
pub fn read_claims_parameter(text: &str) -> Option<ClaimsRequest> {
    if text.len() > MAX_CLAIMS_PARAMETER_BYTES {
        return None;
    }
    read_claims_document(&serde_json::from_str(text).ok()?)
}

/// Reads a request as [`read_claims_parameter`] does, from a document already
/// parsed: the one a request object carries, or the one kept.
#[must_use]
pub fn read_claims_document(document: &Value) -> Option<ClaimsRequest> {
    let members = document.as_object()?;
    Some(ClaimsRequest {
        id_token: read_half(members.get("id_token"))?,
        userinfo: read_half(members.get("userinfo"))?,
    })
}

/// One target: absent or null, it names nothing.
fn read_half(member: Option<&Value>) -> Option<BTreeMap<String, ClaimAsk>> {
    match member {
        None | Some(Value::Null) => Some(BTreeMap::new()),
        Some(Value::Object(claims)) => claims
            .iter()
            .map(|(name, asked)| {
                let ask = read_ask(asked)?;
                let one_subject = name != "sub" || ask.values.len() <= 1;
                (!holds_control(name) && one_subject).then(|| (name.clone(), ask))
            })
            .collect(),
        Some(_) => None,
    }
}

fn holds_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// Whether no text of a value, in any list or member, holds a control
/// character.
fn is_free_of_controls(value: &Value) -> bool {
    match value {
        Value::String(text) => !holds_control(text),
        Value::Array(values) => values.iter().all(is_free_of_controls),
        Value::Object(members) => members
            .iter()
            .all(|(name, member)| !holds_control(name) && is_free_of_controls(member)),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

/// One claim: null asks for it in the default manner. A member written null
/// is one that was not written.
fn read_ask(asked: &Value) -> Option<ClaimAsk> {
    let members = match asked {
        Value::Null => return Some(ClaimAsk::default()),
        Value::Object(members) => members,
        _ => return None,
    };
    let essential = match members.get("essential") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(essential)) => *essential,
        Some(_) => return None,
    };
    let mut values: Vec<Value> = members
        .get("value")
        .filter(|value| !value.is_null())
        .cloned()
        .into_iter()
        .collect();
    match members.get("values") {
        None | Some(Value::Null) => {}
        Some(Value::Array(listed)) => values.extend(listed.iter().cloned()),
        Some(_) => return None,
    }
    values
        .iter()
        .all(is_free_of_controls)
        .then_some(ClaimAsk { essential, values })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        ClaimAsk, ClaimsRequest, MAX_CLAIMS_PARAMETER_BYTES, read_claims_document,
        read_claims_parameter,
    };

    #[test]
    fn each_way_of_asking_for_a_claim_is_read() {
        let read = read_claims_parameter(
            r#"{"userinfo": {"name": null, "email": {"essential": true}},
                "id_token": {"acr": {"essential": true, "values": ["2", "1"]},
                             "sub": {"value": "ada"}, "auth_time": {"unknown": 1}}}"#,
        )
        .expect("a request");

        assert_eq!(read.userinfo["name"], ClaimAsk::default());
        assert!(read.userinfo["email"].essential);
        assert_eq!(read.id_token["acr"].values, [json!("2"), json!("1")]);
        assert_eq!(read.id_token["sub"].values, [json!("ada")]);
        assert_eq!(
            read.id_token["auth_time"],
            ClaimAsk::default(),
            "a member this build does not know is ignored, not the claim it sits on"
        );
        assert_eq!(
            read.read_essential_levels(),
            Some(&[json!("2"), json!("1")][..])
        );
    }

    #[test]
    fn a_member_nobody_knows_is_ignored_at_every_level() {
        let read = read_claims_parameter(
            r#"{"access_token": {"x": 1}, "userinfo": {"name": {"purpose": "x", "lang": 2}}}"#,
        )
        .expect("a request");

        assert_eq!(read.userinfo["name"], ClaimAsk::default());
        assert!(read.id_token.is_empty());
    }

    #[test]
    fn a_known_member_written_otherwise_refuses_the_whole() {
        for written in [
            "[]",
            "not json",
            r#""text""#,
            r#"{"userinfo": ["name"]}"#,
            r#"{"id_token": "sub"}"#,
            r#"{"userinfo": {"name": "yes"}}"#,
            r#"{"userinfo": {"name": 1}}"#,
            r#"{"userinfo": {"name": {"essential": "true"}}}"#,
            r#"{"id_token": {"acr": {"values": "2"}}}"#,
            r#"{"id_token": {"sub": {"values": ["ada", "bob"]}}}"#,
            r#"{"userinfo": {"sub": {"value": "ada", "values": ["bob"]}}}"#,
        ] {
            assert_eq!(read_claims_parameter(written), None, "{written}");
        }
        assert!(
            read_claims_parameter(r#"{"id_token": {"acr": {"values": ["1", "2"]}}}"#).is_some(),
            "several values are for any claim but the subject"
        );
    }

    #[test]
    fn a_control_character_in_a_name_or_a_value_refuses_the_whole() {
        for written in [
            r#"{"userinfo": {"na\u0000me": null}}"#,
            r#"{"userinfo": {"name": {"value": "A\u0000da"}}}"#,
            r#"{"id_token": {"locale": {"values": ["fr", "e\u001bn"]}}}"#,
            r#"{"userinfo": {"address": {"value": {"street": ["a\u007f"]}}}}"#,
            r#"{"userinfo": {"address": {"value": {"stre\u0000et": "a"}}}}"#,
        ] {
            assert_eq!(read_claims_parameter(written), None, "{written}");
        }
        assert!(
            read_claims_parameter(r#"{"userinfo": {"name": {"purpose": "a\u0000"}}}"#).is_some(),
            "a member nobody reads is not kept, and not judged"
        );
    }

    #[test]
    fn a_parameter_past_the_bound_is_not_read() {
        let named = "n".repeat(MAX_CLAIMS_PARAMETER_BYTES - 24);
        let within = format!(r#"{{"userinfo": {{"{named}": null}}}}"#);
        assert_eq!(within.len(), MAX_CLAIMS_PARAMETER_BYTES);
        assert!(read_claims_parameter(&within).is_some());

        let past = format!(r#"{{"userinfo": {{"{named}x": null}}}}"#);
        assert_eq!(
            read_claims_parameter(&past),
            None,
            "one byte past the bound"
        );
    }

    #[test]
    fn what_is_kept_reads_back_as_it_was_read() {
        let read = read_claims_parameter(
            r#"{"userinfo": {"name": null, "locale": {"values": ["fr", "de"]}},
                "id_token": {"acr": {"essential": true, "value": "2"}, "sub": null}}"#,
        )
        .expect("a request");

        assert_eq!(read_claims_document(&read.write_document()), Some(read));
        assert_eq!(read_claims_document(&json!(["garbage"])), None);
        assert!(
            read_claims_parameter(r#"{"userinfo": null, "id_token": {}}"#)
                .expect("a request")
                .is_empty()
        );
    }

    #[test]
    fn a_subject_named_with_a_value_admits_that_person_alone() {
        let named = |text: &str| read_claims_parameter(text).expect("a request");

        assert!(named(r#"{"id_token": {"sub": null}}"#).admits_subject("ada"));
        assert!(named(r#"{"id_token": {"sub": {"value": "ada"}}}"#).admits_subject("ada"));
        assert!(!named(r#"{"id_token": {"sub": {"value": "ada"}}}"#).admits_subject("bob"));
        assert!(
            !named(r#"{"userinfo": {"sub": {"values": ["eve"]}}}"#).admits_subject("ada"),
            "a subject named for userinfo binds the request as well"
        );
        assert!(!named(r#"{"id_token": {"sub": {"value": 7}}}"#).admits_subject("7"));
        assert!(ClaimsRequest::default().admits_subject("ada"));
    }

    #[test]
    fn only_an_essential_acr_with_values_is_a_requirement() {
        let levels = |text: &str| {
            read_claims_parameter(text)
                .expect("a request")
                .read_essential_levels()
                .map(<[serde_json::Value]>::to_vec)
        };

        assert_eq!(
            levels(r#"{"id_token": {"acr": {"essential": true, "value": "2"}}}"#),
            Some(vec![json!("2")])
        );
        assert_eq!(levels(r#"{"id_token": {"acr": {"values": ["2"]}}}"#), None);
        assert_eq!(
            levels(r#"{"id_token": {"acr": {"essential": true}}}"#),
            None
        );
        assert_eq!(
            levels(r#"{"userinfo": {"acr": {"essential": true, "value": "2"}}}"#),
            None,
            "the level is what the identity token says"
        );
    }
}
