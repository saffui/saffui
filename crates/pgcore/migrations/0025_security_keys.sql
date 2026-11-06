-- A second factor of another kind: a security key, which signs a challenge.

-- A key is enrolled once in a realm, for one person.
CREATE TABLE security_keys (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    -- The name the key gave itself when it was enrolled.
    credential_id bytea NOT NULL,
    person_id uuid NOT NULL,
    -- The public half of the key and its counter. No secret is in it.
    record bytea NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    CONSTRAINT security_keys_credential_taken PRIMARY KEY (tenant_id, realm_id, credential_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);
CREATE INDEX security_keys_by_person
    ON security_keys (tenant_id, realm_id, person_id, created_at);

-- What finishes the enrollment a person started. One at a time: a later
-- start replaces it.
CREATE TABLE security_key_enrollments (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    state bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);
CREATE INDEX security_key_enrollments_expiry ON security_key_enrollments (expires_at);

ALTER TABLE security_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY security_keys_scope ON security_keys
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
ALTER TABLE security_key_enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_key_enrollments FORCE ROW LEVEL SECURITY;
CREATE POLICY security_key_enrollments_scope ON security_key_enrollments
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A key moves its counter at each use; nothing else of it changes.
GRANT SELECT, INSERT, UPDATE (record, last_used_at), DELETE ON security_keys TO saffui_app;
GRANT SELECT, INSERT, UPDATE (state, expires_at), DELETE ON security_key_enrollments TO saffui_app;
GRANT SELECT ON security_keys, security_key_enrollments TO saffui_maintenance;
-- An enrollment nobody finished is purged when it expires.
GRANT SELECT, DELETE ON security_key_enrollments TO saffui_retention;
