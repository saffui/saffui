-- The isolation everything else rests on: who a row belongs to, and the rule
-- that stops one tenant reading another's.
--
-- Row level security is enabled and forced here rather than left for an operator
-- to turn on later. A policy on a table with security disabled is a policy that
-- does nothing, and one enabled without FORCE does nothing for the role that
-- owns the tables, which is usually the role the application connects as. There
-- is no data to cut over on a database this migration creates, so there is no
-- period during which the rules should be inert.

CREATE TYPE tenant_state AS ENUM ('active', 'suspended', 'archived');

-- The top of the hierarchy. A tenant carries no parent tenant because it is
-- one, so it has flat audit columns rather than the shared shape below.
CREATE TABLE tenants
(
    tenant_id     text        PRIMARY KEY,
    display_name  text        NOT NULL,
    state         tenant_state NOT NULL DEFAULT 'active',
    -- Per tenant ceilings an operator may set. Absent means unlimited, which is
    -- a different answer from a ceiling of zero.
    limits        jsonb,
    -- Residency pin.
    region        text,

    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    text,
    updated_at    timestamptz,
    version       integer     NOT NULL DEFAULT 1,

    CONSTRAINT tenant_id_not_blank CHECK (btrim(tenant_id) <> '')
);

CREATE TYPE ssl_enforcement AS ENUM ('none', 'all', 'external');

CREATE TABLE realms
(
    -- The tenant is part of the identity rather than a column beside it, so a
    -- realm cannot be addressed without saying whose it is.
    tenant                            text        NOT NULL REFERENCES tenants (tenant_id),
    realm_id                          text        NOT NULL,
    name                              text        NOT NULL,
    display_name                      text        NOT NULL,
    enabled                           boolean     NOT NULL DEFAULT true,

    registration_allowed              boolean,
    register_email_as_username        boolean,
    verify_email                      boolean,
    login_with_email_allowed          boolean,
    duplicated_email_allowed          boolean,
    edit_user_name_allowed            boolean,
    reset_password_allowed            boolean,
    remember_me                       boolean,

    ssl_enforcement                   ssl_enforcement,
    password_policy                   jsonb,

    revoke_refresh_token              boolean,
    refresh_token_max_reuse           integer,
    access_token_lifespan             integer,
    action_tokens_lifespan            integer,
    access_code_lifespan              integer,
    access_code_lifespan_user_action  integer,
    access_code_lifespan_login        integer,

    master_admin_client               text,
    events_enabled                    boolean,
    admin_events_enabled              boolean,
    not_before                        integer,
    attributes                        jsonb,
    -- The map from this realm's context values to levels of assurance. Absent
    -- means the realm maps nothing, which is not level zero: with no ordering,
    -- no request can be judged satisfied and no claim can be issued.
    acr_loa_map                       jsonb,

    created_by                        text,
    created_at                        timestamptz NOT NULL DEFAULT now(),
    updated_by                        text,
    updated_at                        timestamptz,
    version                           integer     NOT NULL DEFAULT 1,

    PRIMARY KEY (tenant, realm_id),
    -- A realm's name is what its issuer is built from, so it names one realm
    -- within a tenant.
    CONSTRAINT realm_name_unique_per_tenant UNIQUE (tenant, name),
    CONSTRAINT realm_id_not_blank CHECK (btrim(realm_id) <> ''),
    CONSTRAINT realm_name_not_blank CHECK (btrim(name) <> '')
);

CREATE INDEX realms_by_name ON realms (name);

-- The rules.
--
-- current_setting with the missing_ok flag yields NULL for a connection that
-- never set it, and a comparison against NULL is not true, so an ungoverned
-- connection matches no rows in either direction. Failing closed is the whole
-- point: the alternative is a connection that forgot to say who it is reading
-- everything.
--
-- The setting is written per transaction by whatever opens the unit of work, so
-- a statement outside one is ungoverned and therefore sees nothing.

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenants
    USING      (tenant_id = current_setting('saffui.current_tenant', true))
    WITH CHECK (tenant_id = current_setting('saffui.current_tenant', true));

ALTER TABLE realms ENABLE ROW LEVEL SECURITY;
ALTER TABLE realms FORCE ROW LEVEL SECURITY;

CREATE POLICY realm_isolation ON realms
    USING      (tenant = current_setting('saffui.current_tenant', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true));

-- The role the application connects as.
--
-- The rules above are only as good as this. A superuser bypasses row level
-- security outright, and so does any role holding BYPASSRLS, whatever a table
-- says about enabling or forcing it. A deployment that connects as the owner of
-- the database gets no isolation at all while every policy reads as if it were
-- being applied, which is the failure that looks most like success.
--
-- Created without a login here: a password belongs to a deployment rather than
-- to a schema. An operator grants LOGIN and a password, and nothing else has to
-- be remembered for the rules to hold.
-- Created if absent, and its attributes written either way. A role is
-- cluster wide and outlives the database, so one left over from before, or
-- granted a bypass since, would otherwise keep whatever it was given while this
-- migration reported success.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'saffui_app') THEN
        CREATE ROLE saffui_app NOLOGIN;
    END IF;
END
$$;

ALTER ROLE saffui_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

GRANT USAGE ON SCHEMA public TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, realms TO saffui_app;
