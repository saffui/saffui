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

pub(crate) mod authorization_codes {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "authorization_codes",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// bytea
    pub(crate) const CODE_DIGEST: Column = Column("code_digest");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// uuid
    pub(crate) const SESSION_ID: Column = Column("session_id");
    /// text
    pub(crate) const REDIRECT_URI: Column = Column("redirect_uri");
    /// ARRAY
    pub(crate) const SCOPES: Column = Column("scopes");
    /// text, nullable
    pub(crate) const NONCE: Column = Column("nonce");
    /// text
    pub(crate) const CODE_CHALLENGE: Column = Column("code_challenge");
    /// timestamp with time zone
    pub(crate) const AUTHENTICATED_AT: Column = Column("authenticated_at");
    /// timestamp with time zone
    pub(crate) const EXPIRES_AT: Column = Column("expires_at");
    /// timestamp with time zone, nullable
    pub(crate) const SPENT_AT: Column = Column("spent_at");
    /// uuid, nullable
    pub(crate) const FAMILY: Column = Column("family");
    /// timestamp with time zone, nullable
    pub(crate) const REPLAYED_AT: Column = Column("replayed_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        CODE_DIGEST,
        CLIENT_ID,
        PERSON_ID,
        SESSION_ID,
        REDIRECT_URI,
        SCOPES,
        NONCE,
        CODE_CHALLENGE,
        AUTHENTICATED_AT,
        EXPIRES_AT,
        SPENT_AT,
        FAMILY,
        REPLAYED_AT,
    ];
}

pub(crate) mod authorization_requests {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "authorization_requests",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const REQUEST_ID: Column = Column("request_id");
    /// bytea
    pub(crate) const BROWSER_DIGEST: Column = Column("browser_digest");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// text
    pub(crate) const REDIRECT_URI: Column = Column("redirect_uri");
    /// ARRAY
    pub(crate) const SCOPES: Column = Column("scopes");
    /// text, nullable
    pub(crate) const STATE: Column = Column("state");
    /// text, nullable
    pub(crate) const NONCE: Column = Column("nonce");
    /// text
    pub(crate) const CODE_CHALLENGE: Column = Column("code_challenge");
    /// timestamp with time zone
    pub(crate) const EXPIRES_AT: Column = Column("expires_at");
    /// uuid, nullable
    pub(crate) const EXPECTED_PERSON: Column = Column("expected_person");
    /// uuid, nullable
    pub(crate) const FIRST_FACTOR_PERSON_ID: Column = Column("first_factor_person_id");
    /// bytea, nullable
    pub(crate) const KEY_PROOF_STATE: Column = Column("key_proof_state");
    /// jsonb, nullable
    pub(crate) const KEY_PROOF_OPTIONS: Column = Column("key_proof_options");
    /// boolean
    pub(crate) const CONSENT_PROMPTED: Column = Column("consent_prompted");
    /// uuid, nullable
    pub(crate) const CONSENT_SESSION_ID: Column = Column("consent_session_id");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        REQUEST_ID,
        BROWSER_DIGEST,
        CLIENT_ID,
        REDIRECT_URI,
        SCOPES,
        STATE,
        NONCE,
        CODE_CHALLENGE,
        EXPIRES_AT,
        EXPECTED_PERSON,
        FIRST_FACTOR_PERSON_ID,
        KEY_PROOF_STATE,
        KEY_PROOF_OPTIONS,
        CONSENT_PROMPTED,
        CONSENT_SESSION_ID,
    ];
}

pub(crate) mod authz_definitions {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "authz_definitions",
        keys: ScopeKeys::TenantAndRealm,
    };

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[];
}

pub(crate) mod authz_policies {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "authz_policies",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const POLICY_ID: Column = Column("policy_id");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// text
    pub(crate) const NAME: Column = Column("name");
    /// text
    pub(crate) const RESOURCE_TYPE: Column = Column("resource_type");
    /// text
    pub(crate) const ACTION: Column = Column("action");
    /// text
    pub(crate) const EFFECT: Column = Column("effect");
    /// text
    pub(crate) const COMBINE: Column = Column("combine");
    /// jsonb
    pub(crate) const CONDITIONS: Column = Column("conditions");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        POLICY_ID,
        CLIENT_ID,
        NAME,
        RESOURCE_TYPE,
        ACTION,
        EFFECT,
        COMBINE,
        CONDITIONS,
        CREATED_AT,
    ];
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
    /// bytea, nullable
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
    /// boolean
    pub(crate) const ALLOWS_AUTHORIZATION_CODE: Column = Column("allows_authorization_code");
    /// ARRAY
    pub(crate) const REDIRECT_URIS: Column = Column("redirect_uris");
    /// ARRAY
    pub(crate) const POST_LOGOUT_REDIRECT_URIS: Column = Column("post_logout_redirect_uris");
    /// boolean
    pub(crate) const REQUIRES_CONSENT: Column = Column("requires_consent");

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
        ALLOWS_AUTHORIZATION_CODE,
        REDIRECT_URIS,
        POST_LOGOUT_REDIRECT_URIS,
        REQUIRES_CONSENT,
    ];
}

pub(crate) mod code_attempts {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "code_attempts",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// integer
    pub(crate) const ATTEMPTS: Column = Column("attempts");
    /// timestamp with time zone
    pub(crate) const LAST_AT: Column = Column("last_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[PERSON_ID, ATTEMPTS, LAST_AT];
}

pub(crate) mod consents {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "consents",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// ARRAY
    pub(crate) const SCOPES: Column = Column("scopes");
    /// timestamp with time zone
    pub(crate) const GRANTED_AT: Column = Column("granted_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[PERSON_ID, CLIENT_ID, SCOPES, GRANTED_AT];
}

pub(crate) mod group_members {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "group_members",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const GROUP_ID: Column = Column("group_id");
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// timestamp with time zone
    pub(crate) const VALID_FROM: Column = Column("valid_from");
    /// timestamp with time zone, nullable
    pub(crate) const VALID_UNTIL: Column = Column("valid_until");
    /// text
    pub(crate) const GRANTED_BY: Column = Column("granted_by");
    /// text, nullable
    pub(crate) const REASON: Column = Column("reason");
    /// timestamp with time zone
    pub(crate) const GRANTED_AT: Column = Column("granted_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        GROUP_ID,
        PERSON_ID,
        VALID_FROM,
        VALID_UNTIL,
        GRANTED_BY,
        REASON,
        GRANTED_AT,
    ];
}

pub(crate) mod group_roles {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "group_roles",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const GROUP_ID: Column = Column("group_id");
    /// uuid
    pub(crate) const ROLE_ID: Column = Column("role_id");
    /// timestamp with time zone
    pub(crate) const VALID_FROM: Column = Column("valid_from");
    /// timestamp with time zone, nullable
    pub(crate) const VALID_UNTIL: Column = Column("valid_until");
    /// text
    pub(crate) const GRANTED_BY: Column = Column("granted_by");
    /// text, nullable
    pub(crate) const REASON: Column = Column("reason");
    /// timestamp with time zone
    pub(crate) const GRANTED_AT: Column = Column("granted_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        GROUP_ID,
        ROLE_ID,
        VALID_FROM,
        VALID_UNTIL,
        GRANTED_BY,
        REASON,
        GRANTED_AT,
    ];
}

pub(crate) mod groups {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "groups",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const GROUP_ID: Column = Column("group_id");
    /// text
    pub(crate) const NAME: Column = Column("name");
    /// text, nullable
    pub(crate) const DESCRIPTION: Column = Column("description");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[GROUP_ID, NAME, DESCRIPTION, CREATED_AT];
}

pub(crate) mod known_browsers {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "known_browsers",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const DEVICE_ID: Column = Column("device_id");
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// timestamp with time zone
    pub(crate) const EXPIRES_AT: Column = Column("expires_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[DEVICE_ID, PERSON_ID, EXPIRES_AT];
}

pub(crate) mod login_failures {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "login_failures",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// bytea
    pub(crate) const IDENTIFIER_DIGEST: Column = Column("identifier_digest");
    /// timestamp with time zone
    pub(crate) const BUCKET_START: Column = Column("bucket_start");
    /// integer
    pub(crate) const FAILURES: Column = Column("failures");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[IDENTIFIER_DIGEST, BUCKET_START, FAILURES];
}

pub(crate) mod password_credentials {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "password_credentials",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// text
    pub(crate) const PHC: Column = Column("phc");
    /// timestamp with time zone
    pub(crate) const CHANGED_AT: Column = Column("changed_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[PERSON_ID, PHC, CHANGED_AT];
}

pub(crate) mod person_roles {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "person_roles",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// uuid
    pub(crate) const ROLE_ID: Column = Column("role_id");
    /// timestamp with time zone
    pub(crate) const VALID_FROM: Column = Column("valid_from");
    /// timestamp with time zone, nullable
    pub(crate) const VALID_UNTIL: Column = Column("valid_until");
    /// text
    pub(crate) const GRANTED_BY: Column = Column("granted_by");
    /// text, nullable
    pub(crate) const REASON: Column = Column("reason");
    /// timestamp with time zone
    pub(crate) const GRANTED_AT: Column = Column("granted_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        PERSON_ID,
        ROLE_ID,
        VALID_FROM,
        VALID_UNTIL,
        GRANTED_BY,
        REASON,
        GRANTED_AT,
    ];
}

pub(crate) mod persons {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "persons",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// text
    pub(crate) const USERNAME: Column = Column("username");
    /// text, nullable
    pub(crate) const EMAIL: Column = Column("email");
    /// boolean
    pub(crate) const EMAIL_VERIFIED: Column = Column("email_verified");
    /// text, nullable
    pub(crate) const DISPLAY_NAME: Column = Column("display_name");
    /// boolean
    pub(crate) const ENABLED: Column = Column("enabled");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        PERSON_ID,
        USERNAME,
        EMAIL,
        EMAIL_VERIFIED,
        DISPLAY_NAME,
        ENABLED,
        CREATED_AT,
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

pub(crate) mod refresh_tokens {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "refresh_tokens",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// bytea
    pub(crate) const TOKEN_DIGEST: Column = Column("token_digest");
    /// uuid
    pub(crate) const FAMILY_ID: Column = Column("family_id");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// uuid
    pub(crate) const SESSION_ID: Column = Column("session_id");
    /// ARRAY
    pub(crate) const SCOPES: Column = Column("scopes");
    /// timestamp with time zone
    pub(crate) const ISSUED_AT: Column = Column("issued_at");
    /// timestamp with time zone
    pub(crate) const EXPIRES_AT: Column = Column("expires_at");
    /// timestamp with time zone, nullable
    pub(crate) const USED_AT: Column = Column("used_at");
    /// timestamp with time zone, nullable
    pub(crate) const REVOKED_AT: Column = Column("revoked_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        TOKEN_DIGEST,
        FAMILY_ID,
        CLIENT_ID,
        PERSON_ID,
        SESSION_ID,
        SCOPES,
        ISSUED_AT,
        EXPIRES_AT,
        USED_AT,
        REVOKED_AT,
    ];
}

pub(crate) mod relation_guards {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "relation_guards",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// text
    pub(crate) const OBJECT_TYPE: Column = Column("object_type");
    /// text
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// timestamp with time zone
    pub(crate) const WRITTEN_AT: Column = Column("written_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[OBJECT_TYPE, CLIENT_ID, WRITTEN_AT];
}

pub(crate) mod relation_kinds {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "relation_kinds",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// text
    pub(crate) const OBJECT_TYPE: Column = Column("object_type");
    /// text
    pub(crate) const RELATION: Column = Column("relation");
    /// text
    pub(crate) const SUBJECT_TYPE: Column = Column("subject_type");
    /// text
    pub(crate) const SUBJECT_MEMBER: Column = Column("subject_member");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[OBJECT_TYPE, RELATION, SUBJECT_TYPE, SUBJECT_MEMBER];
}

pub(crate) mod relation_schemas {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "relation_schemas",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// text
    pub(crate) const SOURCE: Column = Column("source");
    /// jsonb
    pub(crate) const COMPILED: Column = Column("compiled");
    /// timestamp with time zone
    pub(crate) const WRITTEN_AT: Column = Column("written_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[SOURCE, COMPILED, WRITTEN_AT];
}

pub(crate) mod relation_tuples {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "relation_tuples",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// text
    pub(crate) const OBJECT_TYPE: Column = Column("object_type");
    /// text
    pub(crate) const OBJECT_ID: Column = Column("object_id");
    /// text
    pub(crate) const RELATION: Column = Column("relation");
    /// text
    pub(crate) const SUBJECT_TYPE: Column = Column("subject_type");
    /// text
    pub(crate) const SUBJECT_ID: Column = Column("subject_id");
    /// text
    pub(crate) const SUBJECT_MEMBER: Column = Column("subject_member");
    /// timestamp with time zone
    pub(crate) const WRITTEN_AT: Column = Column("written_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        OBJECT_TYPE,
        OBJECT_ID,
        RELATION,
        SUBJECT_TYPE,
        SUBJECT_ID,
        SUBJECT_MEMBER,
        WRITTEN_AT,
    ];
}

pub(crate) mod roles {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "roles",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const ROLE_ID: Column = Column("role_id");
    /// text, nullable
    pub(crate) const CLIENT_ID: Column = Column("client_id");
    /// text
    pub(crate) const NAME: Column = Column("name");
    /// text, nullable
    pub(crate) const DESCRIPTION: Column = Column("description");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[ROLE_ID, CLIENT_ID, NAME, DESCRIPTION, CREATED_AT];
}

pub(crate) mod security_key_enrollments {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "security_key_enrollments",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// bytea
    pub(crate) const STATE: Column = Column("state");
    /// timestamp with time zone
    pub(crate) const EXPIRES_AT: Column = Column("expires_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[PERSON_ID, STATE, EXPIRES_AT];
}

pub(crate) mod security_keys {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "security_keys",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// bytea
    pub(crate) const CREDENTIAL_ID: Column = Column("credential_id");
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// bytea
    pub(crate) const RECORD: Column = Column("record");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");
    /// timestamp with time zone, nullable
    pub(crate) const LAST_USED_AT: Column = Column("last_used_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[CREDENTIAL_ID, PERSON_ID, RECORD, CREATED_AT, LAST_USED_AT];
}

pub(crate) mod sessions {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "sessions",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const SESSION_ID: Column = Column("session_id");
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// bytea
    pub(crate) const SECRET_DIGEST: Column = Column("secret_digest");
    /// text
    pub(crate) const STATE: Column = Column("state");
    /// timestamp with time zone
    pub(crate) const AUTHENTICATED_AT: Column = Column("authenticated_at");
    /// timestamp with time zone
    pub(crate) const EXPIRES_AT: Column = Column("expires_at");
    /// ARRAY
    pub(crate) const METHODS: Column = Column("methods");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        SESSION_ID,
        PERSON_ID,
        SECRET_DIGEST,
        STATE,
        AUTHENTICATED_AT,
        EXPIRES_AT,
        METHODS,
    ];
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

pub(crate) mod totp_authenticators {
    use super::{Column, ScopeKeys, Table};

    pub(crate) const TABLE: Table = Table {
        name: "totp_authenticators",
        keys: ScopeKeys::TenantAndRealm,
    };
    /// uuid
    pub(crate) const PERSON_ID: Column = Column("person_id");
    /// bytea
    pub(crate) const SEALED_SECRET: Column = Column("sealed_secret");
    /// timestamp with time zone, nullable
    pub(crate) const CONFIRMED_AT: Column = Column("confirmed_at");
    /// bigint, nullable
    pub(crate) const LAST_STEP: Column = Column("last_step");
    /// timestamp with time zone
    pub(crate) const CREATED_AT: Column = Column("created_at");

    /// In the order the table declares them.
    pub(crate) const ALL: &[Column] = &[
        PERSON_ID,
        SEALED_SECRET,
        CONFIRMED_AT,
        LAST_STEP,
        CREATED_AT,
    ];
}

/// Every table a statement of the builder can reach.
pub(crate) const TABLES: &[(Table, &[Column])] = &[
    (audit_chain_heads::TABLE, audit_chain_heads::ALL),
    (audit_events::TABLE, audit_events::ALL),
    (authorization_codes::TABLE, authorization_codes::ALL),
    (authorization_requests::TABLE, authorization_requests::ALL),
    (authz_definitions::TABLE, authz_definitions::ALL),
    (authz_policies::TABLE, authz_policies::ALL),
    (clients::TABLE, clients::ALL),
    (code_attempts::TABLE, code_attempts::ALL),
    (consents::TABLE, consents::ALL),
    (group_members::TABLE, group_members::ALL),
    (group_roles::TABLE, group_roles::ALL),
    (groups::TABLE, groups::ALL),
    (known_browsers::TABLE, known_browsers::ALL),
    (login_failures::TABLE, login_failures::ALL),
    (password_credentials::TABLE, password_credentials::ALL),
    (person_roles::TABLE, person_roles::ALL),
    (persons::TABLE, persons::ALL),
    (realm_data_keys::TABLE, realm_data_keys::ALL),
    (realms::TABLE, realms::ALL),
    (refresh_tokens::TABLE, refresh_tokens::ALL),
    (relation_guards::TABLE, relation_guards::ALL),
    (relation_kinds::TABLE, relation_kinds::ALL),
    (relation_schemas::TABLE, relation_schemas::ALL),
    (relation_tuples::TABLE, relation_tuples::ALL),
    (roles::TABLE, roles::ALL),
    (
        security_key_enrollments::TABLE,
        security_key_enrollments::ALL,
    ),
    (security_keys::TABLE, security_keys::ALL),
    (sessions::TABLE, sessions::ALL),
    (signing_keys::TABLE, signing_keys::ALL),
    (tenants::TABLE, tenants::ALL),
    (totp_authenticators::TABLE, totp_authenticators::ALL),
];

// Without row security or a scope key, and so without a constant: realm_directory, schema_migrations.
