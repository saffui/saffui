-- The directory a realm federates its users from: at most one, holding the
-- connection and the mapping. The bind secret is sealed on the way in and
-- never read back whole.
CREATE TABLE user_federation
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    enabled    boolean     NOT NULL DEFAULT true,
    configs    jsonb,

    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by text,
    updated_at timestamptz,
    version    integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT user_federation_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_federation TO saffui_app;

ALTER TABLE user_federation ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_federation FORCE ROW LEVEL SECURITY;
CREATE POLICY user_federation_by_realm ON user_federation
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
