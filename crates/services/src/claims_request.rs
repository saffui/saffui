//! The `claims` request parameter, OIDC Core §5.5.
//!
//! A client naming the claims it wants, one by one, beside the scopes that
//! name them in sets. Two halves, one for each place a claim can be returned:
//! the userinfo endpoint and the identity token. A claim may be voluntary or
//! essential, and may ask for one value or one of several; none of that ever
//! makes a missing claim an error, §5.5.1 says so in as many words, with two
//! exceptions the spec names and this module leaves to the callers that own
//! them: `sub` and `acr`.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The most a request may weigh, in bytes. It travels in a login's notes,
/// which are bounded, and no honest request names claims by the hundred.
const MOST: usize = 2048;

/// What was asked of one claim.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ask {
    pub essential: bool,
    /// `value` and `values`, folded: one acceptable value is a set of one.
    /// Empty means any value.
    pub acceptable: Vec<Value>,
}

impl Ask {
    /// Whether a value the realm holds is one the client will take.
    fn takes(&self, held: &Value) -> bool {
        self.acceptable.is_empty() || self.acceptable.contains(held)
    }
}

/// The whole request, both halves.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClaimsRequest {
    pub userinfo: BTreeMap<String, Ask>,
    pub id_token: BTreeMap<String, Ask>,
}

/// Why a request could not be read. Each is `invalid_request` on the wire;
/// the distinction is for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Unreadable {
    #[error("the claims parameter is longer than a request has any reason to be")]
    TooLong,
    #[error("the claims parameter is not a JSON object")]
    NotAnObject,
    #[error("a member of the claims parameter is not an object of claim requests")]
    MalformedMember,
}

impl ClaimsRequest {
    /// Read the parameter as the client sent it.
    ///
    /// Members this build does not know are ignored, as §5.5.1 requires of
    /// members it does not understand; a member it does know and cannot read
    /// is refused, because a claim request half read is a claim request
    /// answered wrongly.
    pub fn parse(raw: &str) -> Result<Self, Unreadable> {
        if raw.len() > MOST {
            return Err(Unreadable::TooLong);
        }
        let document: Value = serde_json::from_str(raw).map_err(|_| Unreadable::NotAnObject)?;
        let Value::Object(members) = document else {
            return Err(Unreadable::NotAnObject);
        };
        Ok(ClaimsRequest {
            userinfo: half(members.get("userinfo"))?,
            id_token: half(members.get("id_token"))?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.userinfo.is_empty() && self.id_token.is_empty()
    }

    /// The request as the store keeps it: the parsed shape, not the raw text,
    /// so what was refused at the door is never read again past it.
    pub fn to_value(&self) -> Value {
        let render = |half: &BTreeMap<String, Ask>| {
            Value::Object(
                half.iter()
                    .map(|(name, ask)| {
                        let mut detail = Map::new();
                        if ask.essential {
                            detail.insert("essential".into(), Value::Bool(true));
                        }
                        if !ask.acceptable.is_empty() {
                            detail.insert("values".into(), Value::Array(ask.acceptable.clone()));
                        }
                        (name.clone(), Value::Object(detail))
                    })
                    .collect(),
            )
        };
        let mut whole = Map::new();
        whole.insert("userinfo".into(), render(&self.userinfo));
        whole.insert("id_token".into(), render(&self.id_token));
        Value::Object(whole)
    }

    /// The request back from the store. Written by [`Self::to_value`], so a
    /// shape it cannot read is a corrupted row and reads as nothing asked.
    pub fn from_value(stored: &Value) -> Self {
        let Value::Object(members) = stored else {
            return Self::default();
        };
        ClaimsRequest {
            userinfo: half(members.get("userinfo")).unwrap_or_default(),
            id_token: half(members.get("id_token")).unwrap_or_default(),
        }
    }

    /// The one value `sub` was asked to be, for the identity token.
    ///
    /// §3.1.2.2: a request for a particular subject may only be answered
    /// for that subject. The callers that know who is logging in compare.
    pub fn subject_asked(&self) -> Option<&str> {
        self.id_token
            .get("sub")
            .and_then(|ask| ask.acceptable.first())
            .and_then(Value::as_str)
    }

    /// What `acr` was asked to be, for the identity token, and how hard:
    /// the values and whether they are essential. Nothing when no value was
    /// named, since an `acr` asked for without one is the session's own.
    pub fn contexts_asked(&self) -> Option<(Vec<String>, bool)> {
        let ask = self.id_token.get("acr")?;
        let named: Vec<String> = ask
            .acceptable
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        (!named.is_empty()).then_some((named, ask.essential))
    }
}

/// One half, `userinfo` or `id_token`. Absent or null is nothing asked.
fn half(member: Option<&Value>) -> Result<BTreeMap<String, Ask>, Unreadable> {
    let Some(member) = member else {
        return Ok(BTreeMap::new());
    };
    let entries = match member {
        Value::Null => return Ok(BTreeMap::new()),
        Value::Object(entries) => entries,
        _ => return Err(Unreadable::MalformedMember),
    };
    entries
        .iter()
        .map(|(name, detail)| Ok((name.clone(), ask(detail)?)))
        .collect()
}

/// One claim's request: `null` for the default manner, or an object whose
/// known members are read and whose others are ignored.
fn ask(detail: &Value) -> Result<Ask, Unreadable> {
    let detail = match detail {
        Value::Null => return Ok(Ask::default()),
        Value::Object(detail) => detail,
        _ => return Err(Unreadable::MalformedMember),
    };
    let essential = match detail.get("essential") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(Unreadable::MalformedMember),
    };
    let mut acceptable = Vec::new();
    if let Some(value) = detail.get("value").filter(|value| !value.is_null()) {
        acceptable.push(value.clone());
    }
    match detail.get("values") {
        None | Some(Value::Null) => {}
        Some(Value::Array(values)) => acceptable.extend(values.iter().cloned()),
        Some(_) => return Err(Unreadable::MalformedMember),
    }
    Ok(Ask {
        essential,
        acceptable,
    })
}

/// What one half of a request lets through, of what the realm holds.
///
/// Only what was asked for, and only when the realm's value is one the client
/// will take: §5.5.1 has a claim with the wrong value left out, never an
/// error. Essential changes nothing here, and deliberately: it is a promise
/// about the client's needs, not an instruction to the server.
pub fn release(asked: &BTreeMap<String, Ask>, held: &Map<String, Value>) -> Map<String, Value> {
    asked
        .iter()
        .filter_map(|(name, ask)| {
            let value = held.get(name)?;
            ask.takes(value).then(|| (name.clone(), value.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_three_shapes_of_a_claim_request_are_read() {
        let request = ClaimsRequest::parse(
            r#"{"userinfo": {"name": null, "email": {"essential": true}},
                "id_token": {"acr": {"essential": true, "values": ["gold", "silver"]},
                             "sub": {"value": "ada"}, "auth_time": {"unknown": 1}}}"#,
        )
        .unwrap();
        assert_eq!(request.userinfo["name"], Ask::default());
        assert!(request.userinfo["email"].essential);
        assert_eq!(
            request.id_token["acr"].acceptable,
            vec![json!("gold"), json!("silver")]
        );
        assert_eq!(request.subject_asked(), Some("ada"));
        assert_eq!(
            request.contexts_asked(),
            Some((vec!["gold".to_owned(), "silver".to_owned()], true))
        );
        assert!(
            request.id_token.contains_key("auth_time"),
            "a member nobody understands is ignored, not the claim it sits on"
        );
    }

    #[test]
    fn what_cannot_be_read_is_refused_and_what_is_absent_is_nothing() {
        assert_eq!(ClaimsRequest::parse("[]"), Err(Unreadable::NotAnObject));
        assert_eq!(
            ClaimsRequest::parse("not json"),
            Err(Unreadable::NotAnObject)
        );
        assert_eq!(
            ClaimsRequest::parse(r#"{"userinfo": ["name"]}"#),
            Err(Unreadable::MalformedMember)
        );
        assert_eq!(
            ClaimsRequest::parse(r#"{"userinfo": {"name": "yes"}}"#),
            Err(Unreadable::MalformedMember)
        );
        assert_eq!(
            ClaimsRequest::parse(&format!(
                r#"{{"userinfo": {{"{}": null}}}}"#,
                "n".repeat(MOST)
            )),
            Err(Unreadable::TooLong)
        );
        let nothing = ClaimsRequest::parse(r#"{"userinfo": null, "other": 1}"#).unwrap();
        assert!(nothing.is_empty());
    }

    #[test]
    fn the_store_shape_round_trips() {
        let request = ClaimsRequest::parse(
            r#"{"userinfo": {"name": null}, "id_token": {"acr": {"essential": true, "value": "gold"}}}"#,
        )
        .unwrap();
        assert_eq!(ClaimsRequest::from_value(&request.to_value()), request);
        assert!(ClaimsRequest::from_value(&json!("garbage")).is_empty());
    }

    #[test]
    fn a_release_is_what_was_asked_with_a_value_the_client_takes() {
        let request = ClaimsRequest::parse(
            r#"{"userinfo": {"name": null, "email": {"value": "ada@example.test"},
                             "locale": {"values": ["fr", "de"]}, "picture": null}}"#,
        )
        .unwrap();
        let held = json!({
            "name": "Ada", "email": "ada@example.test", "locale": "en", "gender": "female"
        });
        let released = release(&request.userinfo, held.as_object().unwrap());
        assert_eq!(
            released,
            json!({"name": "Ada", "email": "ada@example.test"})
                .as_object()
                .unwrap()
                .clone()
        );
    }
}
