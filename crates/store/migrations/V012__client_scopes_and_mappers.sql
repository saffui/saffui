-- What a client may ask for, and what turns into a claim.

-- A role belongs to a client, or to the realm.
--
-- Without the owning client, a token's per client entitlements have to be
-- rebuilt by matching role names, and two clients that each define a role
-- called "admin" then grant each other's. The flag that was here says the same
-- thing as the presence of the client, so a check keeps the two from ever
-- disagreeing.
ALTER TABLE roles ADD COLUMN client_id text;
ALTER TABLE roles ADD CONSTRAINT roles_client
    FOREIGN KEY (tenant, realm_id, client_id)
    REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE;
ALTER TABLE roles ADD CONSTRAINT a_client_role_names_its_client
    CHECK (is_client_role = (client_id IS NOT NULL));

-- The name was unique across the realm, which is what forced the ambiguity
-- above: two clients could not both have an "admin" role, and once they can,
-- uniqueness has to be read per owner.
ALTER TABLE roles DROP CONSTRAINT roles_name_unique_per_realm;
CREATE UNIQUE INDEX realm_role_name_unique
    ON roles (tenant, realm_id, name) WHERE client_id IS NULL;
CREATE UNIQUE INDEX client_role_name_unique
    ON roles (tenant, realm_id, client_id, name) WHERE client_id IS NOT NULL;

-- A named set of claims a client may ask for.
CREATE TABLE client_scopes
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    client_scope_id text        NOT NULL,
    name            text        NOT NULL,
    description     text        NOT NULL DEFAULT '',
    protocol        protocol    NOT NULL,
    -- Whether a new client gets it without anyone attaching it.
    default_scope   boolean     NOT NULL DEFAULT false,
    configs         jsonb,

    created_by      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      text,
    updated_at      timestamptz,
    version         integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, client_scope_id),
    CONSTRAINT client_scopes_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    -- One scope answers to a name within a protocol. A request naming "profile"
    -- must resolve to one scope, and the protocol is part of that because the
    -- same word means different things to different protocols.
    CONSTRAINT scope_name_unique_per_protocol UNIQUE (tenant, realm_id, protocol, name),
    CONSTRAINT client_scope_id_not_blank CHECK (btrim(client_scope_id) <> ''),
    CONSTRAINT scope_name_not_blank CHECK (btrim(name) <> '')
);

-- A rule turning something the server knows into a claim.
CREATE TABLE protocol_mappers
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    mapper_id   text        NOT NULL,
    name        text        NOT NULL,
    protocol    protocol    NOT NULL,
    -- Which rule. The catalogue of rules lives in the build, not here: a name
    -- nobody implements fails to resolve when the token is assembled, which is
    -- the same refusal one step later.
    mapper_type text        NOT NULL,
    configs     jsonb,

    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text,
    updated_at  timestamptz,
    version     integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, mapper_id),
    CONSTRAINT protocol_mappers_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT mapper_id_not_blank CHECK (btrim(mapper_id) <> ''),
    CONSTRAINT mapper_type_not_blank CHECK (btrim(mapper_type) <> '')
);

-- The attachments. Each is keyed by everything it joins, so an attachment
-- cannot be recorded twice and cannot reach across a realm.

CREATE TABLE clients_client_scopes
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    client_id       text        NOT NULL,
    client_scope_id text        NOT NULL,
    -- Attached scopes are granted without being asked for; optional ones only
    -- when the request names them.
    optional        boolean     NOT NULL DEFAULT false,
    attached_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, client_id, client_scope_id),
    CONSTRAINT clients_client_scopes_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT clients_client_scopes_scope FOREIGN KEY (tenant, realm_id, client_scope_id)
        REFERENCES client_scopes (tenant, realm_id, client_scope_id) ON DELETE CASCADE
);

CREATE TABLE clients_protocol_mappers
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    client_id   text        NOT NULL,
    mapper_id   text        NOT NULL,
    attached_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, client_id, mapper_id),
    CONSTRAINT clients_protocol_mappers_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT clients_protocol_mappers_mapper FOREIGN KEY (tenant, realm_id, mapper_id)
        REFERENCES protocol_mappers (tenant, realm_id, mapper_id) ON DELETE CASCADE
);

CREATE TABLE client_scopes_protocol_mappers
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    client_scope_id text        NOT NULL,
    mapper_id       text        NOT NULL,
    attached_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, client_scope_id, mapper_id),
    CONSTRAINT client_scopes_protocol_mappers_scope
        FOREIGN KEY (tenant, realm_id, client_scope_id)
        REFERENCES client_scopes (tenant, realm_id, client_scope_id) ON DELETE CASCADE,
    CONSTRAINT client_scopes_protocol_mappers_mapper FOREIGN KEY (tenant, realm_id, mapper_id)
        REFERENCES protocol_mappers (tenant, realm_id, mapper_id) ON DELETE CASCADE
);

CREATE TABLE client_scopes_roles
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    client_scope_id text        NOT NULL,
    role_id         text        NOT NULL,
    attached_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, client_scope_id, role_id),
    CONSTRAINT client_scopes_roles_scope FOREIGN KEY (tenant, realm_id, client_scope_id)
        REFERENCES client_scopes (tenant, realm_id, client_scope_id) ON DELETE CASCADE,
    CONSTRAINT client_scopes_roles_role FOREIGN KEY (tenant, realm_id, role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE
);

CREATE INDEX clients_client_scopes_by_scope
    ON clients_client_scopes (tenant, realm_id, client_scope_id);
CREATE INDEX client_scopes_protocol_mappers_by_mapper
    ON client_scopes_protocol_mappers (tenant, realm_id, mapper_id);
CREATE INDEX client_scopes_roles_by_role ON client_scopes_roles (tenant, realm_id, role_id);
CREATE INDEX roles_by_client ON roles (tenant, realm_id, client_id) WHERE client_id IS NOT NULL;

ALTER TABLE client_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY client_scope_isolation ON client_scopes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE protocol_mappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE protocol_mappers FORCE ROW LEVEL SECURITY;
CREATE POLICY protocol_mapper_isolation ON protocol_mappers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE clients_client_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients_client_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY clients_client_scope_isolation ON clients_client_scopes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE clients_protocol_mappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients_protocol_mappers FORCE ROW LEVEL SECURITY;
CREATE POLICY clients_protocol_mapper_isolation ON clients_protocol_mappers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE client_scopes_protocol_mappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_scopes_protocol_mappers FORCE ROW LEVEL SECURITY;
CREATE POLICY client_scopes_protocol_mapper_isolation ON client_scopes_protocol_mappers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE client_scopes_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_scopes_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY client_scopes_role_isolation ON client_scopes_roles
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON client_scopes, protocol_mappers, clients_client_scopes,
       clients_protocol_mappers, client_scopes_protocol_mappers,
       client_scopes_roles TO saffui_app;
