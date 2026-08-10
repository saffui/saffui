// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::fmt;

use crate::jose::util::der::DerClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerType {
    EndOfContents,
    Boolean,
    Integer,
    BitString,
    OctetString,
    Null,
    ObjectIdentifier,
    ObjectDescriptor,
    External,
    Real,
    Enumerated,
    EmbeddedPdv,
    Utf8String,
    RelativeOid,
    Time,
    Sequence,
    Set,
    NumericString,
    PrintableString,
    TeletexString,
    VideotexString,
    Ia5String,
    UtcTime,
    GeneralizedTime,
    GraphicString,
    VisibleString,
    GeneralString,
    UniversalString,
    CharacterString,
    BmpString,
    Date,
    TimeOfDay,
    DateTime,
    Duration,
    Other(DerClass, u64),
}

impl DerType {
    pub fn can_primitive(&self) -> bool {
        matches!(
            self,
            DerType::EndOfContents
                | DerType::Boolean
                | DerType::Integer
                | DerType::BitString
                | DerType::OctetString
                | DerType::Null
                | DerType::ObjectIdentifier
                | DerType::ObjectDescriptor
                | DerType::Real
                | DerType::Enumerated
                | DerType::Utf8String
                | DerType::RelativeOid
                | DerType::Time
                | DerType::NumericString
                | DerType::PrintableString
                | DerType::TeletexString
                | DerType::VideotexString
                | DerType::Ia5String
                | DerType::GraphicString
                | DerType::VisibleString
                | DerType::GeneralString
                | DerType::UniversalString
                | DerType::CharacterString
                | DerType::BmpString
                | DerType::Date
                | DerType::TimeOfDay
                | DerType::DateTime
                | DerType::Duration
                | DerType::Other(_, _)
        )
    }

    pub fn can_constructed(&self) -> bool {
        matches!(
            self,
            DerType::BitString
                | DerType::OctetString
                | DerType::External
                | DerType::EmbeddedPdv
                | DerType::Utf8String
                | DerType::Sequence
                | DerType::Set
                | DerType::NumericString
                | DerType::PrintableString
                | DerType::TeletexString
                | DerType::VideotexString
                | DerType::Ia5String
                | DerType::GraphicString
                | DerType::VisibleString
                | DerType::GeneralString
                | DerType::UniversalString
                | DerType::CharacterString
                | DerType::BmpString
                | DerType::Other(_, _)
        )
    }

    pub fn der_class(&self) -> DerClass {
        match self {
            DerType::Other(val, _) => *val,
            _ => DerClass::Universal,
        }
    }

    pub fn tag_no(&self) -> u64 {
        match self {
            DerType::EndOfContents => 0,
            DerType::Boolean => 1,
            DerType::Integer => 2,
            DerType::BitString => 3,
            DerType::OctetString => 4,
            DerType::Null => 5,
            DerType::ObjectIdentifier => 6,
            DerType::ObjectDescriptor => 7,
            DerType::External => 8,
            DerType::Real => 9,
            DerType::Enumerated => 10,
            DerType::EmbeddedPdv => 11,
            DerType::Utf8String => 12,
            DerType::RelativeOid => 13,
            DerType::Time => 14,
            DerType::Sequence => 16,
            DerType::Set => 17,
            DerType::NumericString => 18,
            DerType::PrintableString => 19,
            DerType::TeletexString => 20,
            DerType::VideotexString => 21,
            DerType::Ia5String => 22,
            DerType::UtcTime => 23,
            DerType::GeneralizedTime => 24,
            DerType::GraphicString => 25,
            DerType::VisibleString => 26,
            DerType::GeneralString => 27,
            DerType::UniversalString => 28,
            DerType::CharacterString => 29,
            DerType::BmpString => 30,
            DerType::Date => 31,
            DerType::TimeOfDay => 32,
            DerType::DateTime => 33,
            DerType::Duration => 34,
            DerType::Other(_, val) => *val,
        }
    }
}

impl fmt::Display for DerType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
