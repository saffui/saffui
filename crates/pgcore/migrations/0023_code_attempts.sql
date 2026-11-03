-- The codes a person typed at the second step since their last right one,
-- whatever their address: past a bound, their codes are suspended until an
-- administrator lets them in again, or a key of theirs proves itself.

CREATE TABLE code_attempts (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    attempts integer NOT NULL CHECK (attempts >= 1),
    last_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

ALTER TABLE code_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_attempts FORCE ROW LEVEL SECURITY;
CREATE POLICY code_attempts_scope ON code_attempts
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

GRANT SELECT, INSERT, UPDATE (attempts, last_at), DELETE ON code_attempts TO saffui_app;
GRANT SELECT ON code_attempts TO saffui_maintenance;
