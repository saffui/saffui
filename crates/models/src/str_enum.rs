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
macro_rules! str_enum_impls {
    ($name:ident { $( $variant:ident => $text:literal ),+ $(,)? }) => {
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

/// Declare an enum whose variants are also a fixed set of strings.
///
/// The literal in the table is the only place the spelling appears: serde is
/// derived from it and `as_str` returns it, so the wire form and the Rust form
/// cannot drift apart. `ALL` is generated rather than written, and parsing is
/// strict — an unrecognised value is an error, never the first variant.
///
/// Prefixing the declaration with `#[postgres(name = "...")]` also derives
/// `ToSql`/`FromSql` and labels each variant from the same literal, so a
/// database enum type cannot spell a variant differently from the wire.
macro_rules! str_enum {
    (
        #[postgres(name = $pg_name:literal)]
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$variant_meta:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash,
                 ::serde::Serialize, ::serde::Deserialize,
                 ::postgres_types::ToSql, ::postgres_types::FromSql)]
        #[postgres(name = $pg_name)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                #[serde(rename = $text)]
                #[postgres(name = $text)]
                $variant,
            )+
        }

        $crate::str_enum::str_enum_impls!($name { $($variant => $text),+ });
    };

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

        $crate::str_enum::str_enum_impls!($name { $($variant => $text),+ });
    };
}

pub(crate) use str_enum_impls;

pub(crate) use str_enum;

/// Assert that a generated enum agrees with itself: each variant serialises to
/// its own text, parses back from that text, and decodes back from its own
/// encoding.
///
/// Called by each declaring module rather than generated into it, so a module
/// that forgets to call it is visible as a missing test rather than as a test
/// that silently tests nothing.
#[cfg(test)]
pub(crate) fn assert_round_trips<T>(variants: &'static [T])
where
    T: Copy
        + PartialEq
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::str::FromStr,
    <T as std::str::FromStr>::Err: std::fmt::Debug,
{
    for (index, variant) in variants.iter().enumerate() {
        let encoded = serde_json::to_string(variant).expect("a string enum serialises");
        // Unquoted by the JSON parser rather than by trimming, so a spelling
        // holding a quote or a backslash reaches `from_str` as it was written.
        let text: String =
            serde_json::from_str(&encoded).expect("a string enum encodes as a JSON string");

        assert_eq!(
            &T::from_str(&text).expect("its own text parses"),
            variant,
            "variant {index} does not parse back from {text:?}"
        );

        // The half the name promises and the serialize-only bound would miss:
        // a rename that applies in one direction reads back as a spelling the
        // domain never writes.
        assert_eq!(
            &serde_json::from_str::<T>(&encoded).expect("its own encoding decodes"),
            variant,
            "variant {index} does not decode from {encoded}"
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
            /// A spelling JSON has to escape, so the round trip is shown to go
            /// through the encoding rather than around it.
            Escaped => "a\\b",
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
        assert_eq!(
            Sample::ALL,
            &[Sample::First, Sample::Second, Sample::Escaped]
        );
    }

    str_enum! {
        #[postgres(name = "sample_stored_enum")]
        enum Stored {
            Kept => "kept",
            Dropped => "let-go",
        }
    }

    /// The database label comes from the same literal as the wire spelling.
    ///
    /// Checked against a type that declares the labels rather than trusted to
    /// the macro: `to_sql` refuses a value the enum type does not list, so a
    /// variant labelled by its Rust name would fail here instead of failing on
    /// the first insert.
    #[test]
    fn a_database_enum_is_labelled_from_the_same_table() {
        use postgres_types::{Kind, ToSql, Type};

        let declared = Type::new(
            "sample_stored_enum".to_owned(),
            0,
            Kind::Enum(Stored::ALL.iter().map(|v| v.as_str().to_owned()).collect()),
            "public".to_owned(),
        );

        assert!(
            <Stored as ToSql>::accepts(&declared),
            "a type declaring exactly these labels must be accepted"
        );

        for variant in Stored::ALL {
            let mut buffer = bytes::BytesMut::new();
            variant
                .to_sql(&declared, &mut buffer)
                .expect("the variant is one the type declares");
            assert_eq!(
                &buffer[..],
                variant.as_str().as_bytes(),
                "{variant} is stored under another label"
            );
        }

        assert_eq!(Stored::Dropped.as_str(), "let-go");
        assert_round_trips(Stored::ALL);
    }

    /// A label the type does not declare is refused rather than written.
    #[test]
    fn a_label_the_type_does_not_declare_is_refused() {
        use postgres_types::{Kind, ToSql, Type};

        let mismatched = Type::new(
            "sample_stored_enum".to_owned(),
            0,
            Kind::Enum(vec!["Kept".to_owned(), "Dropped".to_owned()]),
            "public".to_owned(),
        );

        assert!(
            !<Stored as ToSql>::accepts(&mismatched),
            "a type labelled by Rust names must not accept the wire spelling"
        );

        // And the check is not vacuous: it is the labels that decide, not the
        // type name, which is identical in both.
        let renamed = Type::new(
            "another_name".to_owned(),
            0,
            Kind::Enum(Stored::ALL.iter().map(|v| v.as_str().to_owned()).collect()),
            "public".to_owned(),
        );
        assert!(!<Stored as ToSql>::accepts(&renamed));
    }

    /// A spelling the encoding has to escape survives both directions.
    #[test]
    fn an_escaped_spelling_round_trips_through_its_encoding() {
        assert_eq!(Sample::Escaped.as_str(), "a\\b");
        assert_eq!(
            serde_json::to_string(&Sample::Escaped).unwrap(),
            r#""a\\b""#
        );
        assert_eq!(Sample::from_str("a\\b").unwrap(), Sample::Escaped);
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
