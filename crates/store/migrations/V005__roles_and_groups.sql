-- Named grants, and the sets of users they are given to together.

CREATE TABLE roles
(
    tenant             text        NOT NULL,
    realm_id           text        NOT NULL,
    role_id            text        NOT NULL,
    name               text        NOT NULL,
    display_name       text        NOT NULL,
    description        text        NOT NULL DEFAULT '',
    -- Realm roles apply everywhere in the realm; client roles only where their
    -- client is the audience.
    is_client_role     boolean     NOT NULL DEFAULT false,
    -- The admin plane capabilities this role grants, by their wire names.
    --
    -- The catalogue that says which names exist lives in the build rather than
    -- here, so this column cannot check them. What does is that a name nobody
    -- declared fails to decode on the way out, which is the same refusal one
    -- statement later.
    admin_permissions  jsonb,

    created_by         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         text,
    updated_at         timestamptz,
    version            integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, role_id),
    CONSTRAINT roles_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT roles_name_unique_per_realm UNIQUE (tenant, realm_id, name),
    CONSTRAINT role_id_not_blank CHECK (btrim(role_id) <> ''),
    CONSTRAINT role_name_not_blank CHECK (btrim(name) <> '')
);

CREATE TABLE groups
(
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    group_id      text        NOT NULL,
    name          text        NOT NULL,
    display_name  text        NOT NULL,
    description   text        NOT NULL DEFAULT '',
    -- Whether new users join it without anyone adding them.
    is_default    boolean     NOT NULL DEFAULT false,

    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    text,
    updated_at    timestamptz,
    version       integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, group_id),
    CONSTRAINT groups_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT groups_name_unique_per_realm UNIQUE (tenant, realm_id, name),
    CONSTRAINT group_id_not_blank CHECK (btrim(group_id) <> '')
);

-- The attachments. Each is keyed by everything it joins, so a grant cannot be
-- recorded twice and a row cannot point at something in another realm.

CREATE TABLE users_roles
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    user_id    text        NOT NULL,
    role_id    text        NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id, role_id),
    CONSTRAINT users_roles_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT users_roles_role FOREIGN KEY (tenant, realm_id, role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE
);

CREATE TABLE users_groups
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    user_id    text        NOT NULL,
    group_id   text        NOT NULL,
    joined_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id, group_id),
    CONSTRAINT users_groups_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT users_groups_group FOREIGN KEY (tenant, realm_id, group_id)
        REFERENCES groups (tenant, realm_id, group_id) ON DELETE CASCADE
);

CREATE TABLE groups_roles
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    group_id   text        NOT NULL,
    role_id    text        NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, group_id, role_id),
    CONSTRAINT groups_roles_group FOREIGN KEY (tenant, realm_id, group_id)
        REFERENCES groups (tenant, realm_id, group_id) ON DELETE CASCADE,
    CONSTRAINT groups_roles_role FOREIGN KEY (tenant, realm_id, role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE
);

CREATE INDEX users_roles_by_role ON users_roles (tenant, realm_id, role_id);
CREATE INDEX users_groups_by_group ON users_groups (tenant, realm_id, group_id);
CREATE INDEX groups_roles_by_role ON groups_roles (tenant, realm_id, role_id);

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY role_isolation ON roles
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY group_isolation ON groups
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE users_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE users_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY users_role_isolation ON users_roles
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE users_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE users_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY users_group_isolation ON users_groups
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE groups_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY groups_role_isolation ON groups_roles
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON roles, groups, users_roles, users_groups, groups_roles TO saffui_app;
