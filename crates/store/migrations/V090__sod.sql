-- Duties one pair of hands must not hold at once: rules an operator
-- writes, and the dated exceptions that excuse one person for one exact
-- combination. Violations are computed where they are read, never stored.
CREATE TABLE sod_rules
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    rule_id         text        NOT NULL,
    roles           text[]      NOT NULL,
    -- How many of the named roles one person may reach before the set
    -- turns toxic; written explicitly by the plane, never defaulted.
    min_conflicting integer     NOT NULL CHECK (min_conflicting >= 2),
    enabled         boolean     NOT NULL DEFAULT true,

    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text,
    updated_at      timestamptz,
    version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, rule_id),
    CONSTRAINT sod_rules_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

CREATE TABLE sod_exceptions
(
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    rule_id       text        NOT NULL,
    user_id       text        NOT NULL,
    -- The exact combination excused. A materially different one, even
    -- under the same rule, re-arms the block.
    covered_roles text[]      NOT NULL,
    justification text        NOT NULL,
    granted_by    text        NOT NULL,
    valid_until   timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, rule_id, user_id),
    CONSTRAINT sod_exceptions_rule FOREIGN KEY (tenant, realm_id, rule_id)
        REFERENCES sod_rules (tenant, realm_id, rule_id) ON DELETE CASCADE,
    CONSTRAINT sod_exceptions_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE
);

GRANT SELECT, INSERT, UPDATE, DELETE ON sod_rules TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sod_exceptions TO saffui_app;

ALTER TABLE sod_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE sod_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY sod_rules_by_realm ON sod_rules
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE sod_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sod_exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY sod_exceptions_by_realm ON sod_exceptions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
