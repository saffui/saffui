//! Written by `gen-schema`, never by hand: every table and column
//! that exists, read from a database the migrations built. A change of
//! schema reads as a diff of this file, beside the migration that caused
//! it. What a statement may write is not decided here.
//!
//! The keys of the scope are no constants: the builder writes them.

use crate::query::ident::{Column, ScopeKeys, Table};

pub(crate) mod realms {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "realms",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// text
    pub(crate) const NAME: Column = Column("name");
    /// boolean
    pub(crate) const ENABLED: Column = Column("enabled");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[NAME, ENABLED, CREATED_AT];
}

pub(crate) mod tenants {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "tenants",
        keys: ScopeKeys::Tenant,
    };
    /// text
    pub(crate) const NAME: Column = Column("name");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[NAME, CREATED_AT];
}

/// Every table a statement of the builder can reach.
pub(crate) const TABLES: &[(Table, &[Column])] =
    &[(realms::TABLE, realms::ALL), (tenants::TABLE, tenants::ALL)];

// Without row security or a scope key, and so without a constant: realm_directory, schema_migrations.
