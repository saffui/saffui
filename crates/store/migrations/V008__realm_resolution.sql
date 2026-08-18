-- Answering "whose realm is this" before anything is scoped.
--
-- Every public request arrives naming a realm and nothing else. The pair that
-- scopes a statement has to be known before the statement runs, and the row
-- that would say it cannot be read: the policies match nothing until the
-- settings are written, and they are written from the answer. Reading the
-- answer under the rules is therefore impossible by construction.
--
-- The way out is a function that runs as someone who is not subject to the
-- rules, returns exactly the pair and the residency, and is the only thing the
-- application may call to get it.

-- The role the resolvers run as.
--
-- It bypasses row level security, which is the whole point, so it owns three
-- functions and nothing else: no table is granted to it and it cannot log in.
-- The application role stays NOBYPASSRLS and reaches these answers only by
-- calling what this role owns.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saffui_resolver') THEN
        CREATE ROLE saffui_resolver NOLOGIN;
    END IF;
END
$$;
ALTER ROLE saffui_resolver NOLOGIN BYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- Bypassing the row rules is not the same as being allowed at the table, and it
-- is not the same as being allowed at the schema either: a role without USAGE
-- is told the table does not exist rather than that it may not look, so the
-- three grants below are what make the functions able to read at all.
--
-- Three tables, named one by one. This role exists to answer three questions
-- and the reach it is given is the reach those answers need.
-- Asserted rather than assumed. A role and its memberships belong to the cluster
-- and outlive any schema built on it, so a database that was once given this
-- membership keeps it through every rebuild. The application must reach these
-- answers by calling, never by being the caller that already has them.
REVOKE saffui_resolver FROM saffui_app;

GRANT USAGE ON SCHEMA public TO saffui_resolver;
GRANT SELECT ON tenants, realms, user_sessions TO saffui_resolver;

-- A realm named in a path, and the tenant it belongs to.
--
-- Answers every match rather than picking one. A name is unique within a
-- tenant and nothing makes it unique across them, so two tenants may each hold
-- a realm called "main"; choosing between them here would resolve a request to
-- whichever row was read first, and silently serve one customer's realm to
-- another's caller. The caller refuses an ambiguous name instead.
--
-- The search path is pinned because this function runs with its owner's
-- rights: without it, a caller who can create a schema ahead of public chooses
-- what "realms" means.
CREATE OR REPLACE FUNCTION resolve_realm_by_name(realm_name text)
    RETURNS TABLE (tenant text, realm_id text, region text)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT r.tenant, r.realm_id, t.region
    FROM realms r
    JOIN tenants t ON t.tenant_id = r.tenant
    WHERE r.name = realm_name AND r.enabled
    ORDER BY r.tenant
$$;

-- The same, for an identifier rather than a name.
--
-- A token names the realm it was issued for, and the tenant is not in it. The
-- identifier is unique within a tenant for the same reason the name is, so this
-- answers every match too.
CREATE OR REPLACE FUNCTION resolve_realm_by_id(realm text)
    RETURNS TABLE (tenant text, realm_id text, region text)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT r.tenant, r.realm_id, t.region
    FROM realms r
    JOIN tenants t ON t.tenant_id = r.tenant
    WHERE r.realm_id = realm AND r.enabled
    ORDER BY r.tenant
$$;

-- The realm a session belongs to.
--
-- A cookie carries a session identifier and no realm. The identifier is unique
-- within a realm, so this answers every match as the other two do.
CREATE OR REPLACE FUNCTION resolve_user_session(session text)
    RETURNS TABLE (tenant text, realm_id text, region text)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT s.tenant, s.realm_id, t.region
    FROM user_sessions s
    JOIN tenants t ON t.tenant_id = s.tenant
    WHERE s.session_id = session
    ORDER BY s.tenant
$$;

ALTER FUNCTION resolve_realm_by_name(text) OWNER TO saffui_resolver;
ALTER FUNCTION resolve_realm_by_id(text) OWNER TO saffui_resolver;
ALTER FUNCTION resolve_user_session(text) OWNER TO saffui_resolver;

-- Nobody but the application may ask.
--
-- Executing is granted to PUBLIC by default, and a function that bypasses the
-- rules is not one to leave open to whoever can connect.
REVOKE ALL ON FUNCTION resolve_realm_by_name(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_realm_by_id(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_user_session(text) FROM PUBLIC;

-- Granted last, and granted again whenever the shape of an answer changes: a
-- function whose returned columns change has to be dropped and recreated, and
-- the drop takes its grants with it without saying so.
GRANT EXECUTE ON FUNCTION resolve_realm_by_name(text) TO saffui_app;
GRANT EXECUTE ON FUNCTION resolve_realm_by_id(text) TO saffui_app;
GRANT EXECUTE ON FUNCTION resolve_user_session(text) TO saffui_app;
