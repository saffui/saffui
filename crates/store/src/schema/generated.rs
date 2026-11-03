//! Written by `gen-schema`, never by hand: every table and column
//! that exists, read from a database the migrations built. A change of
//! schema reads as a diff of this file, beside the migration that caused
//! it. What a statement may write is not decided here.
//!
//! The keys of the scope are no constants: the builder writes them.

use crate::query::ident::{Column, ScopeKeys, Table};

pub(crate) mod audit_chain_heads {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "audit_chain_heads",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// bigint
    pub(crate) const SEQ: Column = Column("seq");
    /// bytea
    pub(crate) const HASH: Column = Column("hash");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[SEQ, HASH];
}

pub(crate) mod audit_events {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "audit_events",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// bigint
    pub(crate) const SEQ: Column = Column("seq");
    /// bytea
    pub(crate) const PREV_HASH: Column = Column("prev_hash");
    /// bytea
    pub(crate) const HASH: Column = Column("hash");
    /// bytea
    pub(crate) const ENVELOPE: Column = Column("envelope");
    /// uuid
    pub(crate) const EVENT_ID: Column = Column("event_id");
    /// text
    pub(crate) const KIND: Column = Column("kind");
    /// timestamp with time zone
    pub(crate) const OCCURRED_AT: Column = Column("occurred_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] =
        &[SEQ, PREV_HASH, HASH, ENVELOPE, EVENT_ID, KIND, OCCURRED_AT];
}

pub(crate) mod clients {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "clients",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const CLIENT_ROW_ID: Column = Column("client_row_id");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// text
    pub(crate) const NAME: Column = Column("name");
    /// bytea
    pub(crate) const SECRET_DIGEST: Column = Column("secret_digest");
    /// boolean
    pub(crate) const ALLOWS_CLIENT_CREDENTIALS: Column = Column("allows_client_credentials");
    /// ARRAY
    pub(crate) const SCOPES: Column = Column("scopes");
    /// boolean
    pub(crate) const ENABLED: Column = Column("enabled");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");
    /// ARRAY
    pub(crate) const CAPABILITIES: Column = Column("capabilities");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        CLIENT_ROW_ID,
        CLIENT_ID,
        NAME,
        SECRET_DIGEST,
        ALLOWS_CLIENT_CREDENTIALS,
        SCOPES,
        ENABLED,
        CREATED_AT,
        CAPABILITIES,
    ];
}

pub(crate) mod realm_data_keys {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "realm_data_keys",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// integer
    pub(crate) const GENERATION: Column = Column("generation");
    /// bytea
    pub(crate) const WRAPPED: Column = Column("wrapped");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[GENERATION, WRAPPED];
}

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

pub(crate) mod signing_keys {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "signing_keys",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const SIGNING_KEY_ID: Column = Column("signing_key_id");
    /// text
    pub(crate) const KID: Column = Column("kid");
    /// text
    pub(crate) const ALGORITHM: Column = Column("algorithm");
    /// jsonb
    pub(crate) const PUBLIC_JWK: Column = Column("public_jwk");
    /// bytea
    pub(crate) const SEALED_PRIVATE_KEY: Column = Column("sealed_private_key");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        SIGNING_KEY_ID,
        KID,
        ALGORITHM,
        PUBLIC_JWK,
        SEALED_PRIVATE_KEY,
        CREATED_AT,
    ];
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
pub(crate) const TABLES: &[(Table, &[Column])] = &[
    (audit_chain_heads::TABLE, audit_chain_heads::ALL),
    (audit_events::TABLE, audit_events::ALL),
    (clients::TABLE, clients::ALL),
    (realm_data_keys::TABLE, realm_data_keys::ALL),
    (realms::TABLE, realms::ALL),
    (signing_keys::TABLE, signing_keys::ALL),
    (tenants::TABLE, tenants::ALL),
];

// Without row security or a scope key, and so without a constant: realm_directory, schema_migrations.
