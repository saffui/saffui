// Derived from josekit <https://github.com/hidekatsu-izuno/josekit-rs>,
// version 0.10.3 (commit 8fc5c14, 2025-05-21),
// Copyright (c) Hidekatsu Izuno, licensed under Apache-2.0 OR MIT.
//
// Modified by Kodjo Michel Touglo, 2026: vendored into the saffui `crypto`
// crate as the `jose` module; module paths rewritten from `crate::` to
// `crate::jose::`. See THIRD-PARTY.md at the repository root.

use crate::jose::Value;

use std::{any::Any, fmt::Debug};

pub trait JoseHeader: Any + Send + Sync + Debug {
    /// Return claim count.
    fn len(&self) -> usize;

    /// Whether the header carries no claim.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the value for header claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of header claim
    fn claim(&self, key: &str) -> Option<&Value>;

    fn box_clone(&self) -> Box<dyn JoseHeader>;

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;

    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl Clone for Box<dyn JoseHeader> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
