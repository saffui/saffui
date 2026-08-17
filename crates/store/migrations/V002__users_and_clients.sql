-- Who a realm knows, and what may ask for a token on their behalf.
--
-- Both are scoped by tenant and realm together. The policies read both settings,
-- so a transaction opened for a tenant without naming a realm matches nothing
-- here, which is what a directory-wide unit of work should see of a realm's
-- contents.

CREATE TYPE user_storage AS ENUM ('local', 'ldap');

CREATE TYPE required_action AS ENUM (
    'reset-password', 'update-password', 'verify-email',
    'configure-totp', 'configure-webauthn'
);

CREATE TABLE users
(
    tenant                       text        NOT NULL,
    realm_id                     text        NOT NULL,
    user_id                      text        NOT NULL,
    user_name                    text        NOT NULL,

    email                        text,
    email_verified               boolean,
    -- First class rather than an attribute, so it can be a login identifier.
    phone_number                 text,
    phone_number_verified        boolean,

    enabled                      boolean     NOT NULL DEFAULT true,
    is_service_account           boolean,
    service_account_client_link  text,
    user_storage                 user_storage,
    required_actions             required_action[],
    not_before                   bigint,
    attributes                   jsonb,

    created_by                   text,
    created_at                   timestamptz NOT NULL DEFAULT now(),
    updated_by                   text,
    updated_at                   timestamptz,
    version                      integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    -- The identifier is unique within its realm and nowhere else.
    --
    -- Made globally unique, creating a user with a chosen identifier tells the
    -- caller whether that identifier already exists somewhere they cannot read,
    -- which is one tenant learning another's identifiers by collision. Scoping
    -- it is both the correct shape and the one that says nothing.
    PRIMARY KEY (tenant, realm_id, user_id),
    -- The realm reference carries the tenant, so a user cannot name a realm
    -- belonging to somebody else. Referencing the realm alone leaves that pair
    -- free to disagree, and a row whose tenant is not its realm's tenant is
    -- visible to one and owned by the other.
    CONSTRAINT users_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT users_name_unique_per_realm UNIQUE (tenant, realm_id, user_name),
    CONSTRAINT user_id_not_blank CHECK (btrim(user_id) <> ''),
    CONSTRAINT user_name_not_blank CHECK (btrim(user_name) <> '')
);

CREATE INDEX users_by_email ON users (tenant, realm_id, email);
CREATE INDEX users_by_phone ON users (tenant, realm_id, phone_number);

CREATE TYPE protocol AS ENUM ('openid-connect', 'docker');

CREATE TABLE clients
(
    tenant                            text        NOT NULL,
    realm_id                          text        NOT NULL,
    client_id                         text        NOT NULL,
    name                              text        NOT NULL,
    display_name                      text        NOT NULL,
    description                       text,
    enabled                           boolean     NOT NULL DEFAULT true,

    -- Bearer credentials. Stored as text here and never rendered by the models
    -- that carry them; wrapping them at rest is its own step.
    secret                            text,
    registration_token                text,
    secret_created_at                 timestamptz,
    secret_expires_at                 timestamptz,

    public_client                     boolean,
    protocol                          protocol,
    client_authenticator_type         text,
    full_scope_allowed                boolean,
    consent_required                  boolean,
    bearer_only                       boolean,
    service_account_enabled           boolean,
    is_surrogate_auth_required        boolean,

    authorization_code_flow_enabled   boolean,
    implicit_flow_enabled             boolean,
    direct_access_grants_enabled      boolean,
    standard_flow_enabled             boolean,
    front_channel_logout              boolean,

    root_url                          text,
    web_origins                       text[],
    redirect_uris                     text[],
    -- Separate from the login callbacks on purpose: a logout landing page is
    -- usually not one, and requiring it to be would make every logout
    -- destination a valid authorization code destination too.
    post_logout_redirect_uris         text[],

    -- The registered algorithms. Checked against the catalogue where they are
    -- written, and held here as text because the catalogue lives in the build
    -- rather than in the database.
    id_token_signed_response_alg      text,
    userinfo_signed_response_alg      text,
    request_object_signing_alg        text,
    -- Each encryption registration is a pair. A content encryption without a
    -- key management algorithm is not a registration, so neither half is
    -- allowed without the other.
    id_token_encryption_alg           text,
    id_token_encryption_enc           text,
    userinfo_encryption_alg           text,
    userinfo_encryption_enc           text,
    request_object_encryption_alg     text,
    request_object_encryption_enc     text,

    not_before                        integer,
    configs                           jsonb,
    auth_flow_binding_overrides       jsonb,

    created_by                        text,
    created_at                        timestamptz NOT NULL DEFAULT now(),
    updated_by                        text,
    updated_at                        timestamptz,
    version                           integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, client_id),
    CONSTRAINT clients_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT clients_name_unique_per_realm UNIQUE (tenant, realm_id, name),
    CONSTRAINT client_id_not_blank CHECK (btrim(client_id) <> ''),
    CONSTRAINT id_token_encryption_is_a_pair
        CHECK ((id_token_encryption_alg IS NULL) = (id_token_encryption_enc IS NULL)),
    CONSTRAINT userinfo_encryption_is_a_pair
        CHECK ((userinfo_encryption_alg IS NULL) = (userinfo_encryption_enc IS NULL)),
    CONSTRAINT request_object_encryption_is_a_pair
        CHECK ((request_object_encryption_alg IS NULL) = (request_object_encryption_enc IS NULL))
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

CREATE POLICY user_isolation ON users
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients FORCE ROW LEVEL SECURITY;

CREATE POLICY client_isolation ON clients
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON users, clients TO saffui_app;
