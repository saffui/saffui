// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl DerClass {
    pub fn class_no(&self) -> u8 {
        match self {
            DerClass::Universal => 0,
            DerClass::Application => 1,
            DerClass::ContextSpecific => 2,
            DerClass::Private => 3,
        }
    }
}

impl fmt::Display for DerClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
