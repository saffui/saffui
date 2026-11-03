-- What signing a person in keeps: the counters of the brake, and sessions.

-- Counters per keyed digest, in buckets of five minutes. A digest stands for
-- what was typed, for an address, or for both: people type passwords into
-- the wrong field, and the key is not in the database.
CREATE TABLE login_failures (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    identifier_digest bytea NOT NULL,
    bucket_start timestamptz NOT NULL,
    failures integer NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, identifier_digest, bucket_start),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

CREATE TABLE sessions (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    session_id uuid NOT NULL,
    person_id uuid NOT NULL,
    -- The digest of the secret half of the cookie. The identifier of a
    -- session appears in tokens: alone, it must open nothing.
    secret_digest bytea NOT NULL,
    state text NOT NULL CHECK (state IN ('active', 'ended')),
    authenticated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, session_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

ALTER TABLE login_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY login_failures_scope ON login_failures
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_scope ON sessions
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A counter is added to in place: one statement opens its bucket or adds to it.
GRANT SELECT, INSERT, UPDATE ON login_failures TO saffui_app;
-- Nothing ends a session yet: the right to comes with the statement that does.
GRANT SELECT, INSERT ON sessions TO saffui_app;
GRANT SELECT ON login_failures, sessions TO saffui_maintenance;
