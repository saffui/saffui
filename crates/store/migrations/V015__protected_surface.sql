-- The surface a protected application exposes, and the verbs it declares on it.
--
-- The scopes here are not the scopes a client asks for at login. Those name
-- what a token may carry and live in `client_scopes`; these name what may be
-- done to a resource, and an application declares them for itself.

-- How much a decision is allowed to refuse.
CREATE TYPE policy_enforcement_mode AS ENUM ('enforcing', 'permissive', 'disabled');

-- How several answers become one.
CREATE TYPE decision_strategy AS ENUM ('affirmative', 'unanimous', 'consensus');

-- A protected application.
--
-- Its identity is its client's, rather than an identifier of its own: an
-- application that is protected is a client that has a surface, and a separate
-- key would let the two disagree about which client that is.
CREATE TABLE resource_servers
(
    tenant                     text                    NOT NULL,
    realm_id                   text                    NOT NULL,
    server_id                  text                    NOT NULL,
    enforcement_mode           policy_enforcement_mode NOT NULL DEFAULT 'enforcing',
    decision_strategy          decision_strategy       NOT NULL DEFAULT 'unanimous',
    remote_resource_management boolean                 NOT NULL DEFAULT false,
    user_managed_access        boolean                 NOT NULL DEFAULT false,

    created_by                 text,
    created_at                 timestamptz             NOT NULL DEFAULT now(),
    updated_by                 text,
    updated_at                 timestamptz,
    version                    integer                 NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, server_id),
    CONSTRAINT resource_servers_client FOREIGN KEY (tenant, realm_id, server_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE
);

CREATE TABLE resources
(
    tenant              text        NOT NULL,
    realm_id            text        NOT NULL,
    resource_id         text        NOT NULL,
    server_id           text        NOT NULL,
    name                text        NOT NULL,
    display_name        text        NOT NULL DEFAULT '',
    description         text        NOT NULL DEFAULT '',
    resource_uris       text[]      NOT NULL DEFAULT '{}',
    resource_type       text        NOT NULL,
    resource_owner      text        NOT NULL,
    user_managed_access boolean     NOT NULL DEFAULT false,
    configs             jsonb,

    created_by          text,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_by          text,
    updated_at          timestamptz,
    version             integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, resource_id),
    CONSTRAINT resources_server FOREIGN KEY (tenant, realm_id, server_id)
        REFERENCES resource_servers (tenant, realm_id, server_id) ON DELETE CASCADE,
    -- What the binding below references, so a resource cannot be bound from a
    -- server other than its own.
    CONSTRAINT resources_server_scoped UNIQUE (tenant, realm_id, server_id, resource_id),
    -- One resource answers to a name within its server. Two would make "the
    -- document resource" a matter of which row was read first.
    CONSTRAINT resource_name_unique_per_server UNIQUE (tenant, realm_id, server_id, name),
    CONSTRAINT resource_id_not_blank CHECK (btrim(resource_id) <> ''),
    CONSTRAINT resource_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT resource_type_not_blank CHECK (btrim(resource_type) <> ''),
    CONSTRAINT resource_configs_are_a_map
        CHECK (configs IS NULL OR jsonb_typeof(configs) = 'object'),
    CONSTRAINT resource_configs_are_bounded
        CHECK (configs IS NULL OR octet_length(configs::text) <= 4096)
);

CREATE TABLE scopes
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    scope_id     text        NOT NULL,
    server_id    text        NOT NULL,
    name         text        NOT NULL,
    display_name text        NOT NULL DEFAULT '',
    description  text        NOT NULL DEFAULT '',

    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_by   text,
    updated_at   timestamptz,
    version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, scope_id),
    CONSTRAINT scopes_server FOREIGN KEY (tenant, realm_id, server_id)
        REFERENCES resource_servers (tenant, realm_id, server_id) ON DELETE CASCADE,
    CONSTRAINT scopes_server_scoped UNIQUE (tenant, realm_id, server_id, scope_id),
    CONSTRAINT scope_name_unique_per_server UNIQUE (tenant, realm_id, server_id, name),
    CONSTRAINT scope_id_not_blank CHECK (btrim(scope_id) <> ''),
    CONSTRAINT scope_name_not_blank CHECK (btrim(name) <> '')
);

-- The verbs a resource declares.
--
-- Keyed on everything it joins, and the server travels in both foreign keys, so
-- a resource cannot declare a scope belonging to another server. Without that
-- the two sides could each be valid and the pair still nonsense.
CREATE TABLE resource_scopes
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    resource_id text        NOT NULL,
    scope_id    text        NOT NULL,
    declared_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, resource_id, scope_id),
    CONSTRAINT resource_scopes_resource FOREIGN KEY (tenant, realm_id, server_id, resource_id)
        REFERENCES resources (tenant, realm_id, server_id, resource_id) ON DELETE CASCADE,
    CONSTRAINT resource_scopes_scope FOREIGN KEY (tenant, realm_id, server_id, scope_id)
        REFERENCES scopes (tenant, realm_id, server_id, scope_id) ON DELETE CASCADE
);

CREATE INDEX resources_by_server ON resources (tenant, realm_id, server_id);
CREATE INDEX resources_by_type ON resources (tenant, realm_id, server_id, resource_type);
CREATE INDEX scopes_by_server ON scopes (tenant, realm_id, server_id);
CREATE INDEX resource_scopes_by_scope
    ON resource_scopes (tenant, realm_id, server_id, scope_id);

ALTER TABLE resource_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_servers FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_server_isolation ON resource_servers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE resources FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_isolation ON resources
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_isolation ON scopes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE resource_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_scope_isolation ON resource_scopes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON resource_servers, resources, scopes, resource_scopes TO saffui_app;
