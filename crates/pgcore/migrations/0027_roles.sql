-- Roles, and the groups that will carry them. A role of the realm is said to
-- every client, a role of a client to that client alone.

ALTER TABLE clients
    DROP CONSTRAINT clients_capabilities_known,
    ADD CONSTRAINT clients_capabilities_known CHECK (
        capabilities <@ ARRAY[
            'realm:read', 'client:read', 'client:write', 'audit:read', 'user:read', 'user:write',
            'role:read', 'role:write'
        ]
    );

-- A name goes into tokens as it is written, and is compared and sorted byte
-- for byte, whatever the collation of the database.
CREATE TABLE roles (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    role_id uuid NOT NULL,
    -- The client the role is said to. A role of the realm has none.
    client_id text,
    name text COLLATE "C" NOT NULL CHECK (name ~ '^[A-Za-z0-9.:_-]{1,64}$'),
    description text CHECK (char_length(description) <= 255),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, role_id),
    CONSTRAINT roles_name_taken UNIQUE NULLS NOT DISTINCT (tenant_id, realm_id, client_id, name),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms,
    FOREIGN KEY (tenant_id, realm_id, client_id)
        REFERENCES clients (tenant_id, realm_id, client_id) ON DELETE CASCADE
);

CREATE TABLE groups (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    group_id uuid NOT NULL,
    name text COLLATE "C" NOT NULL CHECK (name ~ '^[A-Za-z0-9.:_-]{1,64}$'),
    description text CHECK (char_length(description) <= 255),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, group_id),
    CONSTRAINT groups_name_taken UNIQUE (tenant_id, realm_id, name),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY roles_scope ON roles
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_scope ON groups
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A role or a group is made and removed, never changed.
GRANT SELECT, INSERT, DELETE ON roles, groups TO saffui_app;
GRANT SELECT ON roles, groups TO saffui_maintenance;
