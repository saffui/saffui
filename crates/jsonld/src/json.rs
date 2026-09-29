//! JSON read strictly: a member named twice in one object is refused. A reader
//! that kept the last one would hand the processor a document other than the
//! one another reader sees, and what one of them signs the other would not.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::Unreadable;

/// Read `text` as JSON, refusing a member named twice in one object.
pub fn parse_strict(text: &[u8]) -> Result<Value, Unreadable> {
    let mut deserializer = serde_json::Deserializer::from_slice(text);
    let Strict(value) = Strict::deserialize(&mut deserializer).map_err(|error| {
        match error.to_string().strip_prefix(DUPLICATE) {
            Some(rest) => Unreadable::DuplicateMember(
                rest.split(" at line").next().unwrap_or_default().to_owned(),
            ),
            None => Unreadable::NotJson,
        }
    })?;
    deserializer.end().map_err(|_| Unreadable::NotJson)?;
    Ok(value)
}

const DUPLICATE: &str = "duplicate member ";

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number JSON cannot hold"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Value, A::Error> {
        let mut array = Vec::new();
        while let Some(Strict(item)) = items.next_element()? {
            array.push(item);
        }
        Ok(Value::Array(array))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(name) = members.next_key::<String>()? {
            if object.contains_key(&name) {
                return Err(de::Error::custom(format!("{DUPLICATE}{name}")));
            }
            let Strict(value) = members.next_value()?;
            object.insert(name, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_document_reads_as_json_does() {
        assert_eq!(
            parse_strict(br#"{"a": [1, -2, 2.5, true, null, "x"], "b": {}}"#),
            Ok(json!({"a": [1, -2, 2.5, true, null, "x"], "b": {}}))
        );
    }

    #[test]
    fn a_member_named_twice_is_refused_at_any_depth() {
        assert_eq!(
            parse_strict(br#"{"a": 1, "a": 2}"#),
            Err(Unreadable::DuplicateMember("a".into()))
        );
        assert_eq!(
            parse_strict(br#"{"x": [{"id": "1", "id": "2"}]}"#),
            Err(Unreadable::DuplicateMember("id".into()))
        );
    }

    #[test]
    fn what_is_not_one_json_document_is_refused() {
        assert_eq!(parse_strict(b"{"), Err(Unreadable::NotJson));
        assert_eq!(parse_strict(b"{} {}"), Err(Unreadable::NotJson));
    }
}
