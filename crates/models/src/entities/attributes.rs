use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// A value stored under an attribute name.
///
/// Four shapes rather than an arbitrary JSON value: an attribute is read back by
/// code that expects a type, and a nested object would be a schema nobody
/// declared and nobody validates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttributeValue {
    Int(i64),
    Str(String),
    Bool(bool),
    ListStr(Vec<String>),
}

pub type AttributesMap = HashMap<String, AttributeValue>;

impl AttributeValue {
    /// The string, if it is stored as one.
    ///
    /// Does not render an `Int` or a `Bool`: an attribute read as a string
    /// because it happened to be a number is a comparison against `"1"` that
    /// works until someone stores `1.0`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttributeValue::Str(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            AttributeValue::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AttributeValue::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// A number, widening an `Int` and parsing a `Str`.
    ///
    /// The one accessor that coerces, because a decimal has no variant of its
    /// own and is stored as text. Text that is not a finite number is `None`,
    /// not zero — `NaN` and the infinities parse, and either one read out of an
    /// open map defeats every comparison a caller then makes with it.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            AttributeValue::Int(value) => Some(*value as f64),
            AttributeValue::Str(value) => value
                .parse::<f64>()
                .ok()
                .filter(|number| number.is_finite()),
            _ => None,
        }
    }

    /// The list, treating a lone `Str` as a one-element list.
    ///
    /// Widening only. The reverse — reading a one-element list as a string —
    /// would silently drop the second element on the day one is added.
    pub fn as_list(&self) -> Option<Vec<String>> {
        match self {
            AttributeValue::ListStr(values) => Some(values.clone()),
            AttributeValue::Str(value) => Some(vec![value.clone()]),
            _ => None,
        }
    }
}

/// The string at `name`, if present and stored as a string.
pub fn string_at<'a>(attributes: &'a AttributesMap, name: &str) -> Option<&'a str> {
    attributes.get(name)?.as_str()
}

pub fn int_at(attributes: &AttributesMap, name: &str) -> Option<i64> {
    attributes.get(name)?.as_int()
}

pub fn bool_at(attributes: &AttributesMap, name: &str) -> Option<bool> {
    attributes.get(name)?.as_bool()
}

pub fn f64_at(attributes: &AttributesMap, name: &str) -> Option<f64> {
    attributes.get(name)?.as_f64()
}

/// The list at `name`, treating a lone string as a one-element list, so a
/// single-valued attribute reads as a list without a schema change.
pub fn list_at(attributes: &AttributesMap, name: &str) -> Option<Vec<String>> {
    attributes.get(name)?.as_list()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> AttributesMap {
        AttributesMap::from([
            ("name".to_owned(), AttributeValue::Str("ada".to_owned())),
            ("age".to_owned(), AttributeValue::Int(36)),
            ("active".to_owned(), AttributeValue::Bool(true)),
            (
                "roles".to_owned(),
                AttributeValue::ListStr(vec!["admin".to_owned(), "auditor".to_owned()]),
            ),
            // A one-element list, because that is the only shape from which
            // narrowing to a string would look reasonable.
            (
                "tags".to_owned(),
                AttributeValue::ListStr(vec!["sole".to_owned()]),
            ),
            ("rate".to_owned(), AttributeValue::Str("1.5".to_owned())),
        ])
    }

    #[test]
    fn every_variant_survives_the_wire() {
        for value in [
            AttributeValue::Int(456),
            AttributeValue::Str("My test".to_owned()),
            AttributeValue::Bool(true),
            AttributeValue::ListStr(vec!["Test1".to_owned()]),
        ] {
            let encoded = serde_json::to_string(&value).unwrap();
            assert_eq!(
                serde_json::from_str::<AttributeValue>(&encoded).unwrap(),
                value
            );
        }
    }

    /// Each accessor answers for its own shape and refuses the others, so a
    /// caller cannot read a stored number as a string and compare it to one.
    #[test]
    fn an_accessor_answers_only_for_its_own_shape() {
        let attributes = map();
        assert_eq!(string_at(&attributes, "name"), Some("ada"));
        assert_eq!(string_at(&attributes, "age"), None);
        assert_eq!(string_at(&attributes, "active"), None);
        assert_eq!(string_at(&attributes, "roles"), None);

        // Every foreign shape, not only the one that would fail to parse
        // anyway: a string that happens not to be a number refuses the accessor
        // for the same reason a bool does, and only one of the two says so.
        assert_eq!(int_at(&attributes, "age"), Some(36));
        assert_eq!(int_at(&attributes, "name"), None);
        assert_eq!(
            int_at(&attributes, "rate"),
            None,
            "numeric text is not an int"
        );
        assert_eq!(int_at(&attributes, "active"), None);
        assert_eq!(int_at(&attributes, "roles"), None);

        assert_eq!(bool_at(&attributes, "active"), Some(true));
        assert_eq!(bool_at(&attributes, "age"), None);
        assert_eq!(bool_at(&attributes, "name"), None);
        assert_eq!(bool_at(&attributes, "roles"), None);
    }

    /// The map accessors reach the value accessors rather than answering on
    /// their own, so a present name yields what the shape holds.
    #[test]
    fn the_map_accessors_return_what_the_value_holds() {
        let attributes = map();
        assert_eq!(f64_at(&attributes, "age"), Some(36.0));
        assert_eq!(f64_at(&attributes, "rate"), Some(1.5));
        assert_eq!(f64_at(&attributes, "name"), None);
        assert_eq!(f64_at(&attributes, "active"), None);
    }

    /// A name nobody stored is absent, not a default.
    #[test]
    fn a_missing_name_is_absent_everywhere() {
        let attributes = map();
        assert_eq!(string_at(&attributes, "absent"), None);
        assert_eq!(int_at(&attributes, "absent"), None);
        assert_eq!(bool_at(&attributes, "absent"), None);
        assert_eq!(f64_at(&attributes, "absent"), None);
        assert_eq!(list_at(&attributes, "absent"), None);
        assert_eq!(string_at(&AttributesMap::new(), "name"), None);
    }

    /// A single value reads as a list; a list does not read as a single value.
    #[test]
    fn the_list_accessor_widens_and_nothing_narrows() {
        let attributes = map();
        assert_eq!(
            list_at(&attributes, "roles"),
            Some(vec!["admin".to_owned(), "auditor".to_owned()])
        );
        assert_eq!(list_at(&attributes, "name"), Some(vec!["ada".to_owned()]));
        assert_eq!(list_at(&attributes, "age"), None);

        assert_eq!(list_at(&attributes, "tags"), Some(vec!["sole".to_owned()]));

        assert_eq!(
            string_at(&attributes, "roles"),
            None,
            "a list never collapses to its first element"
        );
        assert_eq!(
            string_at(&attributes, "tags"),
            None,
            "not even a list holding exactly one element"
        );
    }

    /// The one coercion, and its floor: text that is not a number is absent.
    #[test]
    fn a_number_is_read_from_an_int_or_from_numeric_text() {
        assert_eq!(AttributeValue::Int(36).as_f64(), Some(36.0));
        assert_eq!(AttributeValue::Str("1.5".to_owned()).as_f64(), Some(1.5));
        assert_eq!(AttributeValue::Str("-2".to_owned()).as_f64(), Some(-2.0));
        assert_eq!(AttributeValue::Str("ada".to_owned()).as_f64(), None);
        assert_eq!(AttributeValue::Str(String::new()).as_f64(), None);
        assert_eq!(AttributeValue::Bool(true).as_f64(), None);

        // These three parse. A caller comparing against a quota would find that
        // NaN fails every comparison and an infinity passes every one.
        for text in ["NaN", "inf", "infinity", "-inf", "1e400"] {
            assert_eq!(
                AttributeValue::Str(text.to_owned()).as_f64(),
                None,
                "{text} is not a number a comparison can use"
            );
        }
    }
}
