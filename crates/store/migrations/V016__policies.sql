-- What a policy decides, and what it decides on.
--
-- The rule is one document the model owns. Transcribing its variants into
-- columns would put the enumeration in two places that have to be edited
-- together, and adding an arm would mean a migration; seventeen nullable
-- columns and a case per arm is the shape the typed rule exists to escape.
--
-- What the schema does hold is everything that is not the enumeration: that the
-- document is a document, that it is bounded, that its own tag agrees with the
-- column beside it, and that no binding hangs from a kind that would not read
-- it.

-- Whether a policy grants on a match or on the absence of one.
CREATE TYPE decision_logic AS ENUM ('positive', 'negative');

-- What a policy decides on. No value names a script: a closed vocabulary of
-- what decides cannot hold something that decides nothing.
CREATE TYPE policy_type AS ENUM (
    'role', 'group', 'user', 'client', 'client-scope', 'time', 'regex',
    'attribute', 'aggregated', 'scope-permission', 'resource-permission'
);

CREATE TABLE policies
(
    tenant       text              NOT NULL,
    realm_id     text              NOT NULL,
    policy_id    text              NOT NULL,
    server_id    text              NOT NULL,
    -- Which organization the policy is confined to, or none for the whole
    -- realm. Removing the organization removes the policy: setting this to null
    -- instead would widen a rule somebody had narrowed, which is a grant.
    org_id       text,
    name         text              NOT NULL,
    description  text              NOT NULL DEFAULT '',
    policy_type  policy_type       NOT NULL,
    -- The rule as the model serialises it: a tag and the payload of that one
    -- kind.
    rule         jsonb             NOT NULL,
    decision     decision_strategy NOT NULL DEFAULT 'unanimous',
    logic        decision_logic    NOT NULL DEFAULT 'positive',
    policy_owner text              NOT NULL,

    created_by   text,
    created_at   timestamptz       NOT NULL DEFAULT now(),
    updated_by   text,
    updated_at   timestamptz,
    version      integer           NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, policy_id),
    CONSTRAINT policies_server FOREIGN KEY (tenant, realm_id, server_id)
        REFERENCES resource_servers (tenant, realm_id, server_id) ON DELETE CASCADE,
    CONSTRAINT policies_org FOREIGN KEY (tenant, realm_id, org_id)
        REFERENCES organizations (tenant, realm_id, org_id) ON DELETE CASCADE,
    -- What the bindings reference: the policy and its kind together, so a
    -- binding cannot hang from a kind that would never read it, and a policy
    -- that has bindings cannot change kind while they exist.
    CONSTRAINT policies_typed
        UNIQUE (tenant, realm_id, server_id, policy_id, policy_type),
    CONSTRAINT policy_name_unique_per_server UNIQUE (tenant, realm_id, server_id, name),
    CONSTRAINT policy_id_not_blank CHECK (btrim(policy_id) <> ''),
    CONSTRAINT policy_name_not_blank CHECK (btrim(name) <> ''),
    -- Defence in depth rather than the load bearing check: anything that is not
    -- a document answers nothing when the tag is read, so the constraint below
    -- refuses it either way. This says it in its own terms.
    CONSTRAINT a_rule_is_a_document CHECK (jsonb_typeof(rule) = 'object'),
    CONSTRAINT a_rule_is_bounded CHECK (octet_length(rule::text) <= 8192),
    -- The one per kind check that does not transcribe the enumeration: the
    -- discriminant and the payload cannot contradict each other, and adding an
    -- arm never edits this line.
    -- Written so the absence of the tag is a refusal. A plain equality would
    -- compare NULL to the column, and a check that evaluates to NULL is a check
    -- that passed: an untagged rule would have been accepted by the one
    -- constraint whose whole purpose is to read the tag.
    CONSTRAINT a_policy_names_its_own_kind
        CHECK (rule ->> 'policy_type' IS NOT DISTINCT FROM policy_type::text)
);

-- The roles the subject must hold.
CREATE TABLE policies_roles
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    role_id     text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, role_id),
    CONSTRAINT policies_roles_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_roles_member FOREIGN KEY (tenant, realm_id, role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE,
    CONSTRAINT only_a_role_policy_names_them CHECK (policy_type = 'role')
);

-- The groups the subject must belong to.
CREATE TABLE policies_groups
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    group_id    text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, group_id),
    CONSTRAINT policies_groups_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_groups_member FOREIGN KEY (tenant, realm_id, group_id)
        REFERENCES groups (tenant, realm_id, group_id) ON DELETE CASCADE,
    CONSTRAINT only_a_group_policy_names_them CHECK (policy_type = 'group')
);

-- The users the subject must be.
CREATE TABLE policies_users
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    user_id     text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, user_id),
    CONSTRAINT policies_users_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_users_member FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT only_a_user_policy_names_them CHECK (policy_type = 'user')
);

-- The clients the request must come from.
CREATE TABLE policies_clients
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    client_id   text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, client_id),
    CONSTRAINT policies_clients_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_clients_member FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT only_a_client_policy_names_them CHECK (policy_type = 'client')
);

-- The scopes the token must carry.
CREATE TABLE policies_client_scopes
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    client_scope_id text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, client_scope_id),
    CONSTRAINT policies_client_scopes_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_client_scopes_member FOREIGN KEY (tenant, realm_id, client_scope_id)
        REFERENCES client_scopes (tenant, realm_id, client_scope_id) ON DELETE CASCADE,
    CONSTRAINT only_a_client_scope_policy_names_them CHECK (policy_type = 'client-scope')
);

-- What a permission applies to. The server travels in both foreign keys, so a
-- permission cannot reach a resource of another application.
CREATE TABLE policies_resources
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    resource_id text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, resource_id),
    CONSTRAINT policies_resources_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_resources_resource
        FOREIGN KEY (tenant, realm_id, server_id, resource_id)
        REFERENCES resources (tenant, realm_id, server_id, resource_id) ON DELETE CASCADE,
    CONSTRAINT only_a_permission_binds_resources
        CHECK (policy_type IN ('scope-permission', 'resource-permission'))
);

CREATE TABLE policies_scopes
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    server_id   text        NOT NULL,
    policy_id   text        NOT NULL,
    policy_type policy_type NOT NULL,
    scope_id    text        NOT NULL,
    bound_at    timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, scope_id),
    CONSTRAINT policies_scopes_policy
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    CONSTRAINT policies_scopes_scope FOREIGN KEY (tenant, realm_id, server_id, scope_id)
        REFERENCES scopes (tenant, realm_id, server_id, scope_id) ON DELETE CASCADE,
    CONSTRAINT only_a_permission_binds_scopes
        CHECK (policy_type IN ('scope-permission', 'resource-permission'))
);

-- Aggregation. The kind of both sides travels, because only three kinds
-- aggregate, and a permission is never the condition of another one: its own
-- resource bindings would then be read by nobody.
CREATE TABLE policies_policies
(
    tenant               text        NOT NULL,
    realm_id             text        NOT NULL,
    server_id            text        NOT NULL,
    policy_id            text        NOT NULL,
    policy_type          policy_type NOT NULL,
    associated_policy_id text        NOT NULL,
    associated_type      policy_type NOT NULL,
    bound_at             timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, server_id, policy_id, associated_policy_id),
    CONSTRAINT policies_policies_parent
        FOREIGN KEY (tenant, realm_id, server_id, policy_id, policy_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE CASCADE,
    -- No cascade, where the parent edge cascades. Removing a condition from
    -- under a policy that reads it is not a narrowing: a permission that
    -- required two conditions and now requires one grants where it refused, and
    -- nothing downstream can see that a condition was ever there. So a policy
    -- something is conditioned on cannot be deleted until it is unbound.
    --
    -- Strict, so a cascade that would take a condition out from under a
    -- surviving parent fails rather than succeeding quietly. What follows from
    -- that is that anything removing many policies at once unbinds the edges
    -- first, which the write path does.
    CONSTRAINT policies_policies_child
        FOREIGN KEY (tenant, realm_id, server_id, associated_policy_id, associated_type)
        REFERENCES policies (tenant, realm_id, server_id, policy_id, policy_type)
        ON DELETE NO ACTION,
    CONSTRAINT only_an_aggregate_or_a_permission_aggregates
        CHECK (policy_type IN ('aggregated', 'scope-permission', 'resource-permission')),
    CONSTRAINT a_permission_is_not_a_condition
        CHECK (associated_type NOT IN ('scope-permission', 'resource-permission')),
    -- A policy conditioned on itself would never finish, and it is the only
    -- cycle a constraint can see. Longer ones are refused while walking the
    -- graph, where the whole path is known.
    CONSTRAINT a_policy_is_not_its_own_condition
        CHECK (policy_id <> associated_policy_id)
);

-- What was decided, so it can be shown and replayed.
--
-- Two outcomes are recorded and not one. `reported` is what the caller was
-- told; `computed` is what the evaluation actually reached, which is not always
-- the same: a permissive server reports a permit over a denial, and a policy
-- that could not be evaluated is neither a permit nor a denial. Collapsing them
-- would hide exactly the two cases an auditor is looking for.
CREATE TABLE authz_decisions
(
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    decision_id   text        NOT NULL,
    subject_type  text        NOT NULL,
    subject_id    text        NOT NULL,
    resource_kind text        NOT NULL,
    resource_ref  text,
    action        text        NOT NULL,
    reported      text        NOT NULL,
    computed      text        NOT NULL,
    detail        jsonb       NOT NULL,
    duration_us   bigint      NOT NULL CHECK (duration_us >= 0),
    trace_id      text,
    occurred_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, decision_id),
    CONSTRAINT authz_decisions_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    -- What a caller is told is one of two things: there is no third answer to
    -- give somebody.
    CONSTRAINT a_reported_decision_is_permit_or_deny
        CHECK (reported IN ('permit', 'deny')),
    CONSTRAINT a_computed_decision_is_one_of_three
        CHECK (computed IN ('permit', 'deny', 'indeterminate')),
    CONSTRAINT a_replay_payload_is_a_document CHECK (jsonb_typeof(detail) = 'object')
);

CREATE INDEX policies_by_server ON policies (tenant, realm_id, server_id, policy_type);
CREATE INDEX policies_by_org ON policies (tenant, realm_id, org_id);
CREATE INDEX policies_policies_by_child
    ON policies_policies (tenant, realm_id, server_id, associated_policy_id);
CREATE INDEX authz_decisions_by_time
    ON authz_decisions (tenant, realm_id, occurred_at DESC);
-- The two cases an auditor looks for: a denial the caller never saw, and an
-- evaluation that reached no answer.
CREATE INDEX authz_decisions_by_disagreement
    ON authz_decisions (tenant, realm_id, occurred_at DESC) WHERE reported <> computed;

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_isolation ON policies
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_role_isolation ON policies_roles
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_group_isolation ON policies_groups
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_users FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_user_isolation ON policies_users
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_client_isolation ON policies_clients
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_client_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_client_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_client_scope_isolation ON policies_client_scopes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_resource_isolation ON policies_resources
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_scope_isolation ON policies_scopes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE policies_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY policies_policy_isolation ON policies_policies
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE authz_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE authz_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY authz_decision_isolation ON authz_decisions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON
    policies, policies_roles, policies_groups, policies_users, policies_clients,
    policies_client_scopes, policies_resources, policies_scopes,
    policies_policies, authz_decisions TO saffui_app;
