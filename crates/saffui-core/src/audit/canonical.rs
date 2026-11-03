//! Canonical JSON (RFC 8785). The bytes written here are the bytes hashed
//! and the bytes stored: nothing re-serializes an envelope afterwards.

use std::fmt::Write as _;

use serde_json::Value;

/// The largest integer every JSON reader agrees on.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    /// A fraction has more than one canonical writing across readers: an
    /// envelope carries integers and text only.
    #[error("a number that is not an integer")]
    NotAnInteger,
    #[error("an integer no JSON reader is bound to keep exact")]
    IntegerTooLarge,
}

/// Writes `value` in its one canonical form.
///
/// # Errors
///
/// Returns why a number of `value` has no canonical form here.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut text = String::new();
    write_value(&mut text, value)?;
    Ok(text.into_bytes())
}

fn write_value(text: &mut String, value: &Value) -> Result<(), CanonicalError> {
    match value {
        Value::Null => text.push_str("null"),
        Value::Bool(true) => text.push_str("true"),
        Value::Bool(false) => text.push_str("false"),
        Value::Number(number) => {
            let magnitude = match (number.as_u64(), number.as_i64()) {
                (Some(positive), _) => positive,
                (None, Some(negative)) => negative.unsigned_abs(),
                (None, None) => return Err(CanonicalError::NotAnInteger),
            };
            if magnitude > MAX_SAFE_INTEGER {
                return Err(CanonicalError::IntegerTooLarge);
            }
            let _ = write!(text, "{number}");
        }
        Value::String(string) => write_string(text, string),
        Value::Array(items) => {
            text.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    text.push(',');
                }
                write_value(text, item)?;
            }
            text.push(']');
        }
        Value::Object(members) => {
            // Sorted by UTF-16 code units, as the specification says, which
            // is not the order of the UTF-8 bytes above the basic plane.
            let mut names: Vec<&String> = members.keys().collect();
            names.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            text.push('{');
            for (position, name) in names.into_iter().enumerate() {
                if position > 0 {
                    text.push(',');
                }
                write_string(text, name);
                text.push(':');
                write_value(text, &members[name])?;
            }
            text.push('}');
        }
    }
    Ok(())
}

fn write_string(text: &mut String, string: &str) {
    text.push('"');
    for character in string.chars() {
        match character {
            '"' => text.push_str("\\\""),
            '\\' => text.push_str("\\\\"),
            '\u{8}' => text.push_str("\\b"),
            '\t' => text.push_str("\\t"),
            '\n' => text.push_str("\\n"),
            '\u{c}' => text.push_str("\\f"),
            '\r' => text.push_str("\\r"),
            control if control < '\u{20}' => {
                let _ = write!(text, "\\u{:04x}", u32::from(control));
            }
            other => text.push(other),
        }
    }
    text.push('"');
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{CanonicalError, canonicalize};

    fn write(value: &Value) -> String {
        String::from_utf8(canonicalize(value).expect("a canonical form")).expect("text")
    }

    #[test]
    fn members_are_sorted_and_nothing_separates_them() {
        let value = json!({ "ts": "2026", "id": 7, "kind": "realm.created", "payload": { "b": 1, "a": [true, null] } });

        assert_eq!(
            write(&value),
            r#"{"id":7,"kind":"realm.created","payload":{"a":[true,null],"b":1},"ts":"2026"}"#
        );
    }

    #[test]
    fn names_are_sorted_by_utf16_code_units_as_the_specification_orders_them() {
        // The example of RFC 8785, section 3.2.3.
        let value = json!({
            "\u{20ac}": "Euro Sign",
            "\r": "Carriage Return",
            "\u{fb33}": "Hebrew Letter Dalet With Dagesh",
            "1": "One",
            "\u{1f600}": "Emoji: Grinning Face",
            "\u{80}": "Control",
            "\u{f6}": "Latin Small Letter O With Diaeresis",
        });

        let written = write(&value);
        let order: Vec<usize> = [
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ]
        .iter()
        .map(|text| written.find(text).expect("every value is written"))
        .collect();

        assert!(order.is_sorted(), "{written}");
    }

    #[test]
    fn a_string_escapes_only_what_it_must() {
        let value = json!("a\"b\\c\n\u{1}\u{7f}é\u{20ac}/");

        assert_eq!(write(&value), "\"a\\\"b\\\\c\\n\\u0001\u{7f}é\u{20ac}/\"");
    }

    #[test]
    fn a_fraction_and_an_integer_past_53_bits_have_no_canonical_form_here() {
        assert_eq!(canonicalize(&json!(1.5)), Err(CanonicalError::NotAnInteger));
        assert_eq!(
            canonicalize(&json!(9_007_199_254_740_992_u64)),
            Err(CanonicalError::IntegerTooLarge)
        );
        assert_eq!(
            write(&json!(-9_007_199_254_740_991_i64)),
            "-9007199254740991"
        );
    }
}
