-- Clients that register themselves through the protocol, when a realm lets
-- them. Each migration of the registration holds one table that was served
-- before it. This one and the last two close the realms, the refresh tokens
-- and the consents to writes. The next takes ACCESS EXCLUSIVE on the
-- clients until it commits: while it builds the index of a key, every read
-- of a client waits too, `/token` included.

-- The settings of a realm, one document the binary reads closed. A realm
-- has none until an administrator writes them.
CREATE TABLE realm_settings (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    settings jsonb NOT NULL
        CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 16384),
    PRIMARY KEY (tenant_id, realm_id),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

-- What an administrator hands out so that clients register themselves:
-- kept by its digest, spent one registration at a time.
CREATE TABLE initial_access_tokens (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    token_id uuid NOT NULL,
    token_digest bytea NOT NULL CHECK (octet_length(token_digest) = 32),
    uses_left integer NOT NULL CHECK (uses_left BETWEEN 0 AND 100),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, token_id),
    CONSTRAINT initial_access_tokens_digest_taken UNIQUE (tenant_id, realm_id, token_digest),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

ALTER TABLE realm_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_settings_scope ON realm_settings
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE initial_access_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE initial_access_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY initial_access_tokens_scope ON initial_access_tokens
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- The settings are written whole and never removed. A registration takes
-- the row of its realm, which asks the right to update it, and counts the
-- clients of the realm while no other registration does.
GRANT SELECT, INSERT, UPDATE (settings) ON realm_settings TO saffui_app;
-- A token loses its uses one by one, and is taken back whole.
GRANT SELECT, INSERT, UPDATE (uses_left), DELETE ON initial_access_tokens TO saffui_app;
GRANT SELECT ON realm_settings, initial_access_tokens TO saffui_maintenance;
