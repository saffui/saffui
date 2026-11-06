-- Who holds a role: a person it was granted to, or a member of a group it
-- was granted to. A grant and a membership stand from their start until
-- their end, when they have one, on the word of a client of the
-- administration plane, for a reason. A row is the grant as it stands; the
-- audit chain keeps every change to it.

CREATE TABLE person_roles (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    role_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    -- The client of the administration plane that gave it.
    granted_by text NOT NULL,
    reason text CHECK (char_length(reason) <= 255),
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id, role_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, realm_id, role_id) REFERENCES roles ON DELETE CASCADE
);
CREATE INDEX person_roles_by_role ON person_roles (tenant_id, realm_id, role_id);

CREATE TABLE group_roles (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    group_id uuid NOT NULL,
    role_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    granted_by text NOT NULL,
    reason text CHECK (char_length(reason) <= 255),
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, group_id, role_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    FOREIGN KEY (tenant_id, realm_id, group_id) REFERENCES groups ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, realm_id, role_id) REFERENCES roles ON DELETE CASCADE
);
CREATE INDEX group_roles_by_role ON group_roles (tenant_id, realm_id, role_id);

CREATE TABLE group_members (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    group_id uuid NOT NULL,
    person_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    granted_by text NOT NULL,
    reason text CHECK (char_length(reason) <= 255),
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, group_id, person_id),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    FOREIGN KEY (tenant_id, realm_id, group_id) REFERENCES groups ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);
CREATE INDEX group_members_by_person ON group_members (tenant_id, realm_id, person_id, group_id);

ALTER TABLE person_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE person_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY person_roles_scope ON person_roles
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
ALTER TABLE group_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY group_roles_scope ON group_roles
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY group_members_scope ON group_members
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A grant given again replaces its terms; its holder and its role stay.
GRANT SELECT, INSERT, UPDATE (valid_from, valid_until, granted_by, reason, granted_at), DELETE
    ON person_roles, group_roles, group_members TO saffui_app;
GRANT SELECT ON person_roles, group_roles, group_members TO saffui_maintenance;
