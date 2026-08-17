-- How a realm authenticates: the flows, the steps in them, the settings those
-- steps read, and the actions a user still owes.

-- How much a step counts towards its flow succeeding.
--
-- There is no 'conditional'. A step that runs only sometimes has something it
-- is conditional on, and this type has nowhere to put it: the value would name
-- a state whose data lives nowhere, which is the shape every check in this file
-- exists to refuse. A step that decides whether the rest of its flow runs is an
-- ordinary step whose authenticator is that decision.
CREATE TYPE authenticator_requirement AS ENUM (
    'required', 'alternative', 'disabled'
);

CREATE TABLE authentication_flows
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    flow_id     text        NOT NULL,
    -- What an admin and a client both call it.
    alias       text        NOT NULL,
    provider_id text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    -- Whether a login may start here, as opposed to it running only when
    -- another flow calls it.
    top_level   boolean     NOT NULL DEFAULT false,
    -- Whether the realm was created with it.
    built_in    boolean     NOT NULL DEFAULT false,

    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text,
    updated_at  timestamptz,
    version     integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, flow_id),
    CONSTRAINT authentication_flows_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT flow_alias_unique_per_realm UNIQUE (tenant, realm_id, alias),
    CONSTRAINT flow_id_not_blank CHECK (btrim(flow_id) <> ''),
    CONSTRAINT flow_alias_not_blank CHECK (btrim(alias) <> '')
);

CREATE TABLE authenticator_configs
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    config_id  text        NOT NULL,
    alias      text        NOT NULL,
    configs    jsonb,

    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by text,
    updated_at timestamptz,
    version    integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, config_id),
    CONSTRAINT authenticator_configs_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT config_alias_unique_per_realm UNIQUE (tenant, realm_id, alias),
    CONSTRAINT config_id_not_blank CHECK (btrim(config_id) <> '')
);

-- What a user still owes before a session is complete.
--
-- The action itself is the enum the users table already stores, so the two
-- cannot drift: a realm cannot register an action no user can be asked for.
CREATE TABLE required_actions
(
    tenant         text            NOT NULL,
    realm_id       text            NOT NULL,
    action_id      text            NOT NULL,
    action         required_action NOT NULL,
    -- The provider that shows the screen.
    provider_id    text            NOT NULL,
    name           text            NOT NULL,
    display_name   text            NOT NULL,
    description    text            NOT NULL DEFAULT '',
    enabled        boolean         NOT NULL DEFAULT true,
    -- Whether a new user is given it without anyone adding it.
    default_action boolean         NOT NULL DEFAULT false,
    -- Whether it is asked once and cleared, rather than standing.
    on_time_action boolean         NOT NULL DEFAULT false,
    priority       integer         NOT NULL DEFAULT 0,

    created_by     text,
    created_at     timestamptz     NOT NULL DEFAULT now(),
    updated_by     text,
    updated_at     timestamptz,
    version        integer         NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, action_id),
    CONSTRAINT required_actions_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    -- One registration per action. A realm that registered "verify email"
    -- twice would ask for it twice, or ask with whichever row was read first.
    CONSTRAINT one_registration_per_action UNIQUE (tenant, realm_id, action),
    CONSTRAINT action_id_not_blank CHECK (btrim(action_id) <> '')
);

-- One step of a flow.
--
-- A step runs exactly one of two things, and each carries what it needs: an
-- authenticator, with the settings it reads, or another flow. The check below
-- is what makes them exclusive, so there is no step naming both and none naming
-- neither, and no settings hanging off a step that runs a flow.
CREATE TABLE authentication_executions
(
    tenant        text                      NOT NULL,
    realm_id      text                      NOT NULL,
    execution_id  text                      NOT NULL,
    alias         text                      NOT NULL,
    -- The flow this step belongs to.
    flow_id       text                      NOT NULL,
    -- Lower runs first.
    priority      integer                   NOT NULL,
    requirement   authenticator_requirement NOT NULL,
    -- Set when the step runs an authenticator.
    authenticator text,
    config_id     text,
    -- Set when the step runs another flow.
    sub_flow_id   text,

    created_by    text,
    created_at    timestamptz               NOT NULL DEFAULT now(),
    updated_by    text,
    updated_at    timestamptz,
    version       integer                   NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, execution_id),
    CONSTRAINT authentication_executions_flow FOREIGN KEY (tenant, realm_id, flow_id)
        REFERENCES authentication_flows (tenant, realm_id, flow_id) ON DELETE CASCADE,
    CONSTRAINT authentication_executions_sub_flow FOREIGN KEY (tenant, realm_id, sub_flow_id)
        REFERENCES authentication_flows (tenant, realm_id, flow_id) ON DELETE CASCADE,
    CONSTRAINT authentication_executions_config FOREIGN KEY (tenant, realm_id, config_id)
        REFERENCES authenticator_configs (tenant, realm_id, config_id) ON DELETE SET NULL,

    CONSTRAINT a_step_runs_an_authenticator_or_a_flow
        CHECK ((authenticator IS NULL) <> (sub_flow_id IS NULL)),
    -- Settings belong to an authenticator. A flow reads its own steps'.
    CONSTRAINT only_an_authenticator_carries_settings
        CHECK (config_id IS NULL OR authenticator IS NOT NULL),
    -- A flow that ran itself would never finish, and this is the one cycle a
    -- check can see. Longer ones are refused while walking the tree, where the
    -- whole path is known.
    CONSTRAINT a_flow_does_not_run_itself
        CHECK (sub_flow_id IS NULL OR sub_flow_id <> flow_id),
    CONSTRAINT execution_id_not_blank CHECK (btrim(execution_id) <> '')
);

-- Two steps of one flow cannot share a position, or which runs first is decided
-- by whichever row is read first.
--
-- Deferrable, because reordering is a swap: moving one step past another passes
-- through a state where both hold the same position, and refusing that state
-- means a reorder has to invent a free position to park in.
ALTER TABLE authentication_executions
    ADD CONSTRAINT one_step_per_position UNIQUE (tenant, realm_id, flow_id, priority)
    DEFERRABLE INITIALLY IMMEDIATE;

CREATE INDEX authentication_executions_by_flow
    ON authentication_executions (tenant, realm_id, flow_id, priority);
CREATE INDEX authentication_executions_by_sub_flow
    ON authentication_executions (tenant, realm_id, sub_flow_id);

ALTER TABLE authentication_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE authentication_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY authentication_flow_isolation ON authentication_flows
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE authenticator_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE authenticator_configs FORCE ROW LEVEL SECURITY;
CREATE POLICY authenticator_config_isolation ON authenticator_configs
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE required_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE required_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY required_action_isolation ON required_actions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE authentication_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authentication_executions FORCE ROW LEVEL SECURITY;
CREATE POLICY authentication_execution_isolation ON authentication_executions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON authentication_flows, authenticator_configs, required_actions,
       authentication_executions TO saffui_app;
