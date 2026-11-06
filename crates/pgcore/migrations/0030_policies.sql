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

-- One row per realm, made and removed with the realm. Whoever checks the
-- definitions of its authorization against what it writes takes the row
-- first, for update, and keeps it until the end: a writer of policies, of the
-- schema, of the roles and groups a policy names, or of relations. Held in
-- share mode by writers of relations, it would let a stream of them starve
-- the others, since a share is granted past an update that waits.
CREATE TABLE authz_definitions (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, realm_id),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms ON DELETE CASCADE
);

-- The realms made before this migration, read from the directory of names:
-- row security, forced on realms and soon on this table, would let none of
-- them through.
INSERT INTO authz_definitions (tenant_id, realm_id)
SELECT tenant_id, realm_id FROM realm_directory;

ALTER TABLE authz_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_definitions_scope ON authz_definitions
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- Run by whoever inserts the realm, with its rights and, but for a role that
-- bypasses it, under its row security: it makes the row of that realm, from
-- the keys of the realm, and no other.
CREATE FUNCTION saffui_make_definitions_row() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
BEGIN
    INSERT INTO public.authz_definitions (tenant_id, realm_id) VALUES (NEW.tenant_id, NEW.realm_id);
    RETURN NULL;
END
$$;

CREATE TRIGGER realms_definitions
    AFTER INSERT ON realms
    FOR EACH ROW EXECUTE FUNCTION saffui_make_definitions_row();

-- A writer of relations takes the row, then reads the compiled form of the
-- schema, in one call. It waits a second at most: behind a writer of
-- definitions, it gives its connection back rather than hold it as long as
-- the pool waits. The wait of its transaction is restored as it returns.
-- Two statements: the read sees what committed while the first one waited,
-- where a join in the statement that locks would see the schema before it.
CREATE FUNCTION saffui_take_definitions_to_relate(p_tenant uuid, p_realm uuid)
    RETURNS TABLE (compiled jsonb)
    LANGUAGE sql
    SET lock_timeout = '1s'
    SET search_path = pg_catalog, public, pg_temp
    AS $$
    SELECT 1 FROM public.authz_definitions
    WHERE tenant_id = p_tenant AND realm_id = p_realm
    FOR UPDATE;
    SELECT s.compiled
    FROM public.authz_definitions d
    LEFT JOIN public.relation_schemas s ON s.tenant_id = d.tenant_id AND s.realm_id = d.realm_id
    WHERE d.tenant_id = p_tenant AND d.realm_id = p_realm;
$$;

REVOKE ALL ON FUNCTION saffui_make_definitions_row() FROM PUBLIC;
REVOKE ALL ON FUNCTION saffui_take_definitions_to_relate(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saffui_take_definitions_to_relate(uuid, uuid) TO saffui_app;

-- A row lock asks for the right to update one column. Row security keeps
-- that column where it is: no update can move the row. A role that may
-- insert a realm may insert its row, as the trigger does in its name.
GRANT SELECT, INSERT, UPDATE (realm_id) ON authz_definitions TO saffui_app;
GRANT SELECT, INSERT ON authz_definitions TO saffui_maintenance;
