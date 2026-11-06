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
-- schema, of the roles and groups a policy names, or of a relation it keeps.
-- Held in share mode by writers of relations, it would let a stream of them
-- starve the others, since a share is granted past an update that waits.
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

-- Answers a writer of relations in one call. A kind the schema refuses, and
-- a relation the realm keeps already, are answered without the row. Any other
-- takes it, then has its kind read again by a statement of its own, which sees
-- what committed while it waited. It waits a second at most for each lock,
-- behind any holder of the row, writers of relations included: its place among
-- those who wait, then the holder, about two seconds at worst. It gives its
-- connection back rather than hold it as long as the pool waits, and the wait
-- of its transaction is restored as it returns.
CREATE FUNCTION saffui_admit_relation(
    p_tenant uuid, p_realm uuid, p_object_type text, p_object_id text, p_relation text,
    p_subject_type text, p_subject_id text, p_subject_member text
) RETURNS text
    LANGUAGE plpgsql
    SET lock_timeout = '1s'
    SET search_path = pg_catalog, public, pg_temp
    AS $$
DECLARE
    v_admitted boolean;
    v_kept boolean;
BEGIN
    SELECT EXISTS (
               SELECT 1 FROM public.relation_kinds
               WHERE tenant_id = p_tenant AND realm_id = p_realm
                 AND object_type = p_object_type AND relation = p_relation
                 AND subject_type = p_subject_type AND subject_member = p_subject_member),
           EXISTS (
               SELECT 1 FROM public.relation_tuples
               WHERE tenant_id = p_tenant AND realm_id = p_realm
                 AND object_type = p_object_type AND relation = p_relation
                 AND object_id = p_object_id AND subject_type = p_subject_type
                 AND subject_id = p_subject_id AND subject_member = p_subject_member)
    INTO v_admitted, v_kept;
    IF NOT v_admitted THEN
        RETURN 'refused';
    ELSIF v_kept THEN
        RETURN 'kept';
    END IF;
    PERFORM 1 FROM public.authz_definitions
    WHERE tenant_id = p_tenant AND realm_id = p_realm
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'a realm has no row of the definitions of its authorization';
    END IF;
    PERFORM 1 FROM public.relation_kinds
    WHERE tenant_id = p_tenant AND realm_id = p_realm
      AND object_type = p_object_type AND relation = p_relation
      AND subject_type = p_subject_type AND subject_member = p_subject_member;
    RETURN CASE WHEN FOUND THEN 'taken' ELSE 'refused' END;
END
$$;

REVOKE ALL ON FUNCTION saffui_make_definitions_row() FROM PUBLIC;
REVOKE ALL ON FUNCTION saffui_admit_relation(uuid, uuid, text, text, text, text, text, text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saffui_admit_relation(uuid, uuid, text, text, text, text, text, text)
    TO saffui_app;

-- A row lock asks for the right to update one column. Row security keeps
-- that column where it is: no update can move the row. A role that may
-- insert a realm may insert its row, as the trigger does in its name.
GRANT SELECT, INSERT, UPDATE (realm_id) ON authz_definitions TO saffui_app;
GRANT SELECT, INSERT ON authz_definitions TO saffui_maintenance;
