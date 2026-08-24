// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as its `jose` module. This file replaces the upstream `lib.rs`; the
// doctest wiring is dropped and the module paths are rewritten from `crate::`
// to `crate::jose::`. See THIRD-PARTY.md at the repository root.

pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod util;

mod jose_error;
mod jose_header;

pub use crate::jose::jose_error::JoseError;
pub use crate::jose::jose_header::JoseHeader;

pub use serde_json::{Map, Number, Value};
