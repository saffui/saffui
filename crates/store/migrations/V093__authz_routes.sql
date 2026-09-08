-- Which permission a request path puts at stake. A proxy asking on behalf
-- of a caller hands a method and a path and nothing else; what those mean
-- is answered here, on the server's side of the question, because a caller
-- that names the permission it faces names the one it can pass.
CREATE TABLE authz_routes
(
    tenant    text        NOT NULL,
    realm_id  text        NOT NULL,
    route_id  text        NOT NULL,
    -- An exact verb, or '*' for any of them.
    method    text        NOT NULL,
    -- An exact path, or a prefix ending in '*': the grammar every other
    -- pattern in the house already uses.
    path      text        NOT NULL,
    server_id text        NOT NULL,
    resource  text        NOT NULL,
    scope     text        NOT NULL,
    -- The verb the decision record keeps.
    action    text        NOT NULL,
    -- Lower is asked first, and the first match answers. One ordering, so
    -- what an operator reads top to bottom is what runs.
    priority  integer     NOT NULL DEFAULT 100,
    enabled   boolean     NOT NULL DEFAULT true,

    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by text,
    updated_at timestamptz,
    version    integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, route_id),
    CONSTRAINT authz_routes_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);
CREATE INDEX authz_routes_order_idx ON authz_routes (tenant, realm_id, priority, route_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON authz_routes TO saffui_app;

ALTER TABLE authz_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_routes FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_routes_by_realm ON authz_routes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
