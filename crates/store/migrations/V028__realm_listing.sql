-- Every realm this deployment holds, for work that visits all of them.
--
-- The fourth question the rules cannot answer, answered the way the other three
-- are: a function owned by a role that bypasses them, granted to the
-- application and to nobody else.
--
-- Disabled realms included, unlike the three resolvers. An expired code in a
-- realm nobody may log into is still a row to remove.
CREATE OR REPLACE FUNCTION every_realm()
    RETURNS TABLE (tenant text, realm_id text, region text)
    LANGUAGE sql
    STABLE
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
    SELECT r.tenant, r.realm_id, t.region
    FROM realms r
    JOIN tenants t ON t.tenant_id = r.tenant
    ORDER BY r.tenant, r.realm_id
$$;

ALTER FUNCTION every_realm() OWNER TO saffui_resolver;
REVOKE ALL ON FUNCTION every_realm() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION every_realm() TO saffui_app;
