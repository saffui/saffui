-- A composite role grants every role reachable below it.

CREATE TABLE role_composites
(
    tenant          text NOT NULL,
    realm_id        text NOT NULL,
    parent_role_id  text NOT NULL,
    child_role_id   text NOT NULL,

    PRIMARY KEY (tenant, realm_id, parent_role_id, child_role_id),
    CONSTRAINT role_composites_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT role_composites_parent FOREIGN KEY (tenant, realm_id, parent_role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE,
    CONSTRAINT role_composites_child FOREIGN KEY (tenant, realm_id, child_role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE,
    CONSTRAINT role_composites_not_self CHECK (parent_role_id <> child_role_id)
);

CREATE INDEX role_composites_by_child
    ON role_composites (tenant, realm_id, child_role_id);

ALTER TABLE role_composites ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_composites FORCE ROW LEVEL SECURITY;
CREATE POLICY role_composites_isolation ON role_composites
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON role_composites TO saffui_app;
