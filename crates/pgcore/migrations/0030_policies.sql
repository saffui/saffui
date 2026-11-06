-- The policies of the clients that guard resources: what a subject may do
-- with a type of resource, read from the subject, the resource and the instant.

CREATE TABLE authz_policies (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    -- The client that guards the resources, and asks.
    client_id text NOT NULL,
    name text COLLATE "C" NOT NULL CHECK (name ~ '^[A-Za-z0-9.:_-]{1,64}$'),
    resource_type text COLLATE "C" NOT NULL CHECK (resource_type ~ '^[A-Za-z0-9.:_-]{1,64}$'),
    action text COLLATE "C" NOT NULL CHECK (action ~ '^[A-Za-z0-9.:_-]{1,64}$'),
    effect text NOT NULL CHECK (effect IN ('permit', 'deny')),
    combine text NOT NULL CHECK (combine IN ('all', 'any')),
    -- Read at each decision: a document that no longer reads leaves its
    -- policy unable to tell, and such a policy never permits. The product
    -- bounds it at 16 KiB as it writes it; jsonb writes it back with spaces,
    -- so the bound here leaves room.
    conditions jsonb NOT NULL
        CHECK (jsonb_typeof(conditions) = 'array' AND octet_length(conditions::text) <= 32768),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, policy_id),
    CONSTRAINT authz_policies_name_taken UNIQUE (tenant_id, realm_id, client_id, name),
    FOREIGN KEY (tenant_id, realm_id, client_id)
        REFERENCES clients (tenant_id, realm_id, client_id) ON DELETE CASCADE
);
CREATE INDEX authz_policies_applicable
    ON authz_policies (tenant_id, realm_id, client_id, resource_type, action);

ALTER TABLE authz_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_policies_scope ON authz_policies
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A policy is written and removed, never changed.
GRANT SELECT, INSERT, DELETE ON authz_policies TO saffui_app;
GRANT SELECT ON authz_policies TO saffui_maintenance;
