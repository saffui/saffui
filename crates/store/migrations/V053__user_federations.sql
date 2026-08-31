-- A realm may front several directories, tried in priority order and told
-- apart by alias. The singleton table's one row becomes the first entry.
CREATE TABLE user_federations
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    alias      text        NOT NULL,
    enabled    boolean     NOT NULL DEFAULT true,
    priority   integer     NOT NULL DEFAULT 0,
    configs    jsonb,

    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by text,
    updated_at timestamptz,
    version    integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, alias),
    CONSTRAINT user_federations_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_federations TO saffui_app;

ALTER TABLE user_federations ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_federations FORCE ROW LEVEL SECURITY;
CREATE POLICY user_federations_by_realm ON user_federations
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

INSERT INTO user_federations
    (tenant, realm_id, alias, enabled, priority, configs,
     created_by, created_at, updated_by, updated_at, version)
SELECT tenant, realm_id, 'directory', enabled, 0, configs,
       created_by, created_at, updated_by, updated_at, version
FROM user_federation;

DROP TABLE user_federation;
