-- The clients each session served: a line at each answer of the
-- authorization endpoint, read when the session ends to tell them. A line
-- lives as long as its session: it keeps the expiry of its session, which
-- never changes, and retention finds it by that expiry, as it finds the
-- tokens. No key leads to the clients: a line of a client gone reads as
-- nothing, and the table locks no second table that serves.
-- The key to the sessions holds them under SHARE ROW EXCLUSIVE until the
-- commit, so that a sign-in or a sign-out waits: it is checked against a
-- table still empty, and on 2 000 000 sessions the hold took 21 ms at most
-- in three runs.
CREATE TABLE session_clients (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    session_id uuid NOT NULL,
    client_id text NOT NULL,
    first_served_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, session_id, client_id),
    FOREIGN KEY (tenant_id, realm_id, session_id) REFERENCES sessions ON DELETE CASCADE
);

ALTER TABLE session_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_clients FORCE ROW LEVEL SECURITY;
CREATE POLICY session_clients_scope ON session_clients
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

CREATE INDEX session_clients_expiry ON session_clients (expires_at);

-- A line is written once and never changed. Retention removes those of the
-- sessions that expired, before the sessions.
GRANT SELECT, INSERT ON session_clients TO saffui_app;
GRANT SELECT ON session_clients TO saffui_maintenance;
GRANT SELECT, DELETE ON session_clients TO saffui_retention;
