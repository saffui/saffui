-- The authorization code flow: a request that waits for its person to sign
-- in, and the codes it ends with.

-- A request is bound to the browser that started it by a cookie whose
-- digest is here.
CREATE TABLE authorization_requests (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    request_id uuid NOT NULL,
    browser_digest bytea NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    state text,
    nonce text,
    code_challenge text NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, request_id),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

-- Codes are kept as digests and spent by deleting them: one statement, so
-- that of two exchanges of one code exactly one finds it.
CREATE TABLE authorization_codes (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    code_digest bytea NOT NULL,
    client_id text NOT NULL,
    person_id uuid NOT NULL,
    session_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL,
    nonce text,
    code_challenge text NOT NULL,
    authenticated_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, code_digest),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

ALTER TABLE authorization_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_requests_scope ON authorization_requests
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE authorization_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY authorization_codes_scope ON authorization_codes
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A request and a code are taken by deleting them; nothing changes either.
GRANT SELECT, INSERT, DELETE ON authorization_requests, authorization_codes TO saffui_app;
GRANT SELECT ON authorization_requests, authorization_codes TO saffui_maintenance;
-- A session is ended, never removed: what it did stays explainable. Its
-- state is all that changes.
GRANT UPDATE (state) ON sessions TO saffui_app;
