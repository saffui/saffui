-- The desktop-ticket door a realm answers: at most one, holding the service
-- principal the keytab must speak for. The keytab itself lives with the
-- deployment's files, like a TLS key, and is never a column.
CREATE TABLE realm_spnego
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
    CONSTRAINT realm_spnego_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_spnego TO saffui_app;

ALTER TABLE realm_spnego ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_spnego FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_spnego_by_realm ON realm_spnego
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
