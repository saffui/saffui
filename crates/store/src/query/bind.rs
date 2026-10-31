//! A column and its value travel together, and a statement that was built
//! carries what it binds in the order it numbers it.

use tokio_postgres::types::ToSql;
use uuid::Uuid;

use super::ident::{Column, ScopeKeys};

pub(crate) type Value<'a> = &'a (dyn ToSql + Sync);

/// One column and the value going into it.
///
/// Built only through [`col`], so a column never exists without the value
/// that goes with it: the list of columns and the list of parameters of a
/// write come from the same pairs, and cannot fall out of step.
pub(crate) struct Bind<'a> {
    pub(super) column: Column,
    pub(super) value: Value<'a>,
}

/// Pairs a column with its value.
pub(crate) fn col(column: Column, value: Value<'_>) -> Bind<'_> {
    Bind { column, value }
}

/// A statement ready to run. Its first parameters are the keys of the scope,
/// which only the unit of work supplies.
pub(crate) struct Built<'a> {
    pub(crate) sql: String,
    keys: ScopeKeys,
    values: Vec<Value<'a>>,
}

impl<'a> Built<'a> {
    pub(super) fn new(sql: String, keys: ScopeKeys, values: Vec<Value<'a>>) -> Self {
        Self { sql, keys, values }
    }

    pub(crate) fn bind<'b>(&'b self, tenant: &'b Uuid, realm: &'b Uuid) -> Vec<Value<'b>>
    where
        'a: 'b,
    {
        let mut bound: Vec<Value<'b>> = vec![tenant];
        if self.keys == ScopeKeys::TenantAndRealm {
            bound.push(realm);
        }
        bound.extend(self.values.iter().copied());
        bound
    }

    /// How many values the statement binds beside the keys of the scope.
    #[cfg(test)]
    pub(crate) fn count_values(&self) -> usize {
        self.values.len()
    }
}
