//! One table per string enum: the variants, their wire spelling, and the tests.
//!
//! Written once because the same enum otherwise gets spelled three times — the
//! variants, a `match` for the text, a `match` back — and nothing keeps the
//! three in step. A variant added to two of them and forgotten in the third
//! parses to something the writer never named.

/// A stored or submitted value that names no variant.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{found:?} is not a {expected}")]
pub struct UnknownVariant {
    pub expected: &'static str,
    pub found: String,
}

impl UnknownVariant {
    pub fn new(expected: &'static str, found: &str) -> Self {
        Self {
            expected,
            found: found.to_owned(),
        }
    }
}

/// Declare an enum whose variants are also a fixed set of strings.
///
/// The literal in the table is the only place the spelling appears: serde is
/// derived from it and `as_str` returns it, so the wire form and the Rust form
/// cannot drift apart. `ALL` is generated rather than written, and parsing is
/// strict — an unrecognised value is an error, never the first variant.
macro_rules! str_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash,
                 ::serde::Serialize, ::serde::Deserialize)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                #[serde(rename = $text)]
                $variant,
            )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The wire spelling.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $text),+
                }
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::str_enum::UnknownVariant;

            fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
                match value {
                    $($text => ::std::result::Result::Ok($name::$variant),)+
                    other => ::std::result::Result::Err(
                        $crate::str_enum::UnknownVariant::new(stringify!($name), other),
                    ),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

pub(crate) use str_enum;

/// Assert that a generated enum agrees with itself: every variant is in `ALL`,
/// parses back from its own text, and serialises to that same text.
///
/// Called by each declaring module rather than generated into it, so a module
/// that forgets to call it is visible as a missing test rather than as a test
/// that silently tests nothing.
#[cfg(test)]
pub(crate) fn assert_round_trips<T>(variants: &'static [T])
where
    T: Copy + PartialEq + std::fmt::Debug + serde::Serialize + std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    for (index, variant) in variants.iter().enumerate() {
        let text = serde_json::to_string(variant).expect("a string enum serialises");
        let text = text.trim_matches('"');

        assert_eq!(
            &T::from_str(text).expect("its own text parses"),
            variant,
            "variant {index} does not parse back from {text:?}"
        );

        for (other_index, other) in variants.iter().enumerate() {
            if index != other_index {
                assert_ne!(
                    serde_json::to_string(other).unwrap(),
                    serde_json::to_string(variant).unwrap(),
                    "variants {index} and {other_index} share a spelling"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    str_enum! {
        /// A stand-in, so the macro is tested without depending on a domain
        /// enum that may later gain variants for reasons of its own.
        enum Sample {
            First => "first",
            Second => "second-hand",
        }
    }

    #[test]
    fn the_text_in_the_table_is_the_only_spelling() {
        assert_eq!(Sample::Second.as_str(), "second-hand");
        assert_eq!(
            serde_json::to_string(&Sample::Second).unwrap(),
            "\"second-hand\""
        );
        assert_eq!(Sample::Second.to_string(), "second-hand");
        assert_round_trips(Sample::ALL);
    }

    #[test]
    fn all_lists_every_variant_in_order() {
        assert_eq!(Sample::ALL, &[Sample::First, Sample::Second]);
    }

    /// Nothing outside the table parses. A lenient parser that fell back to the
    /// first variant would turn an unreadable stored value into a confident
    /// wrong answer.
    #[test]
    fn an_unknown_value_is_refused_rather_than_defaulted() {
        let error = Sample::from_str("Second-Hand").unwrap_err();
        assert_eq!(error.expected, "Sample");
        assert_eq!(error.found, "Second-Hand");

        assert!(Sample::from_str("").is_err());
        assert!(Sample::from_str("first ").is_err());
        assert!(serde_json::from_str::<Sample>("\"third\"").is_err());
    }
}
