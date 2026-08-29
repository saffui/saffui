-- An external identity provider a realm accepts logins from, the link rows
-- binding local users to upstream subjects, and the in-flight state of one
-- brokered login.

CREATE TABLE identity_providers
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    internal_id  text        NOT NULL,
    -- The alias, as it appears in a login URL.
    provider_id  text        NOT NULL,
    name         text        NOT NULL,
    display_name text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    enabled      boolean     NOT NULL DEFAULT true,
    -- Whether an email address this provider asserts is taken as verified,
    -- which is what account linking by email stands on.
    trust_email  boolean     NOT NULL DEFAULT false,
    configs      jsonb,

    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_by   text,
    updated_at   timestamptz,
    version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, internal_id),
    CONSTRAINT identity_providers_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    -- One provider answers to an alias: the alias is the path segment a
    -- login names, and two rows answering it would make the login a coin
    -- toss.
    CONSTRAINT identity_provider_alias_unique UNIQUE (tenant, realm_id, provider_id),
    CONSTRAINT identity_provider_alias_not_blank CHECK (btrim(provider_id) <> '')
);

ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_providers FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_providers TO saffui_app;
CREATE POLICY identity_providers_by_realm ON identity_providers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

-- Who a local user is at an upstream provider. Unique per (provider,
-- external subject): without that, one upstream account links to two local
-- users and the second login is a coin toss.
CREATE TABLE federated_identities
(
    tenant            text        NOT NULL,
    realm_id          text        NOT NULL,
    user_id           text        NOT NULL,
    provider_alias    text        NOT NULL,
    external_user_id  text        NOT NULL,
    external_username text        NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, provider_alias, external_user_id),
    CONSTRAINT federated_identities_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE
);

ALTER TABLE federated_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE federated_identities FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON federated_identities TO saffui_app;
CREATE POLICY federated_identities_by_realm ON federated_identities
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

-- One brokered login in flight: what was sent upstream, hashed, so what
-- comes back can be tied to what left and spent exactly once. The verifier
-- and the nonce live here and never in the browser.
CREATE TABLE broker_login_states
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    -- SHA-256 of the state parameter; the clear value never lands.
    state_hash     text        NOT NULL,
    provider_alias text        NOT NULL,
    auth_session   text        NOT NULL,
    code_verifier  text        NOT NULL,
    nonce          text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, state_hash)
);

ALTER TABLE broker_login_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE broker_login_states FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON broker_login_states TO saffui_app;
CREATE POLICY broker_login_states_by_realm ON broker_login_states
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
