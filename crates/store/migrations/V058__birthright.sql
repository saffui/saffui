-- What a person should hold, as a function of who they are: rules an
-- operator writes, and the ledger of every grant the engine made under
-- them. The engine never touches a grant that is not in its ledger.
CREATE TABLE birthright_rules
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    rule_id        text        NOT NULL,
    -- '*' matches everybody; otherwise the user attribute that must equal
    -- when_value.
    when_attribute text        NOT NULL,
    when_value     text        NOT NULL DEFAULT '',
    roles          text[]      NOT NULL,
    priority       integer     NOT NULL DEFAULT 0,
    enabled        boolean     NOT NULL DEFAULT true,

    created_by     text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     text,
    updated_at     timestamptz,
    version        integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, rule_id),
    CONSTRAINT birthright_rules_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

CREATE TABLE governed_grants
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    user_id    text        NOT NULL,
    role_id    text        NOT NULL,
    rule_id    text        NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id, role_id),
    CONSTRAINT governed_grants_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT governed_grants_rule FOREIGN KEY (tenant, realm_id, rule_id)
        REFERENCES birthright_rules (tenant, realm_id, rule_id) ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON birthright_rules TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON governed_grants TO saffui_app;

ALTER TABLE birthright_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE birthright_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY birthright_rules_by_realm ON birthright_rules
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE governed_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE governed_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY governed_grants_by_realm ON governed_grants
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
