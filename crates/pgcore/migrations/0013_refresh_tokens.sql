-- Refresh tokens. A token is kept by its digest and spent at each use. A
-- used token stays: presented again, it tells that someone copied it, and
-- the family it belongs to is revoked. A token never outlives its session.

CREATE TABLE refresh_tokens (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    token_digest bytea NOT NULL,
    family_id uuid NOT NULL,
    client_id text NOT NULL,
    person_id uuid NOT NULL,
    session_id uuid NOT NULL,
    scopes text[] NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id, realm_id, token_digest),
    FOREIGN KEY (tenant_id, realm_id, session_id) REFERENCES sessions ON DELETE CASCADE
);

-- A revocation reads what is live of a family, and nothing of a family
-- revoked already.
CREATE INDEX refresh_tokens_live_family ON refresh_tokens (tenant_id, realm_id, family_id)
    WHERE revoked_at IS NULL;
-- Whether a family was revoked is asked at each use. A family that was not
-- has no entry here, however many tokens it grew.
CREATE INDEX refresh_tokens_revoked_family ON refresh_tokens (tenant_id, realm_id, family_id)
    WHERE revoked_at IS NOT NULL;
CREATE INDEX refresh_tokens_session ON refresh_tokens (tenant_id, realm_id, session_id);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY refresh_tokens_scope ON refresh_tokens
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- What becomes of a token is all that changes.
GRANT SELECT, INSERT, UPDATE (used_at, revoked_at) ON refresh_tokens TO saffui_app;
GRANT SELECT ON refresh_tokens TO saffui_maintenance;
