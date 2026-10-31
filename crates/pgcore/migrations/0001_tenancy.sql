-- Tenants and realms, and the two walls between tenants: every row carries
-- its tenant and its realm, and row security shows a session nothing outside
-- the pair it has set for its transaction.

-- NULLIF: a setting local to an earlier transaction reads back as an empty
-- string, not as NULL. Either way the scope is absent and no row matches.
CREATE FUNCTION saffui_current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('saffui.tenant', true), '')::uuid $$;

CREATE FUNCTION saffui_current_realm() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('saffui.realm', true), '')::uuid $$;

CREATE TABLE tenants (
    tenant_id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    created_at timestamptz NOT NULL
);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
-- FORCE: without it the owner of the table walks through the policy.
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_scope ON tenants
    USING (tenant_id = saffui_current_tenant())
    WITH CHECK (tenant_id = saffui_current_tenant());

CREATE TABLE realms (
    tenant_id uuid NOT NULL REFERENCES tenants,
    realm_id uuid NOT NULL,
    name text NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id),
    CONSTRAINT realms_realm_id_key UNIQUE (realm_id),
    -- One name, one realm, across every tenant: the name is the whole route.
    CONSTRAINT realms_name_taken UNIQUE (name)
);

ALTER TABLE realms ENABLE ROW LEVEL SECURITY;
ALTER TABLE realms FORCE ROW LEVEL SECURITY;
-- A tenant lists its realms, so reading stops at the tenant. Writing takes
-- both keys.
CREATE POLICY realms_read ON realms FOR SELECT
    USING (tenant_id = saffui_current_tenant());
CREATE POLICY realms_insert ON realms FOR INSERT
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
CREATE POLICY realms_update ON realms FOR UPDATE
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
CREATE POLICY realms_delete ON realms FOR DELETE
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- Where each realm name leads. A request names a realm before it has a
-- scope, so this one lookup happens outside row security. No role is granted
-- the table: it is reached through the two functions below and nothing else,
-- which answers one exact name and lists nothing.
CREATE TABLE realm_directory (
    name text PRIMARY KEY,
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL UNIQUE,
    enabled boolean NOT NULL
);

CREATE FUNCTION saffui_mirror_realm() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM public.realm_directory WHERE realm_id = OLD.realm_id;
        RETURN OLD;
    END IF;
    INSERT INTO public.realm_directory (name, tenant_id, realm_id, enabled)
    VALUES (NEW.name, NEW.tenant_id, NEW.realm_id, NEW.enabled)
    ON CONFLICT (realm_id) DO UPDATE
        SET name = EXCLUDED.name, enabled = EXCLUDED.enabled;
    RETURN NEW;
END
$$;

CREATE TRIGGER realms_mirror
    AFTER INSERT OR UPDATE OR DELETE ON realms
    FOR EACH ROW EXECUTE FUNCTION saffui_mirror_realm();

CREATE FUNCTION saffui_locate_realm(wanted text)
    RETURNS TABLE (tenant_id uuid, realm_id uuid, enabled boolean)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, public
    AS $$
    SELECT d.tenant_id, d.realm_id, d.enabled
    FROM public.realm_directory d
    WHERE d.name = wanted
$$;

REVOKE ALL ON FUNCTION saffui_mirror_realm() FROM PUBLIC;
REVOKE ALL ON FUNCTION saffui_locate_realm(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saffui_locate_realm(text) TO saffui_app, saffui_maintenance;

GRANT SELECT, INSERT ON tenants TO saffui_app;
GRANT SELECT, INSERT, UPDATE ON realms TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, realms TO saffui_maintenance;
