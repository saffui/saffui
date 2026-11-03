-- The browsers a person signed in from. A mark is believed only while its
-- browser is kept here, for that very person: a person removed takes their
-- browsers along, and a person keeps the few they used last.

CREATE TABLE known_browsers (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    device_id uuid NOT NULL,
    person_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, device_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

CREATE INDEX known_browsers_person ON known_browsers (tenant_id, realm_id, person_id);
CREATE INDEX known_browsers_expiry ON known_browsers (expires_at);

ALTER TABLE known_browsers ENABLE ROW LEVEL SECURITY;
ALTER TABLE known_browsers FORCE ROW LEVEL SECURITY;
CREATE POLICY known_browsers_scope ON known_browsers
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A browser signed in again lives longer. Nothing else of it changes.
GRANT SELECT, INSERT, UPDATE (expires_at), DELETE ON known_browsers TO saffui_app;
GRANT SELECT, DELETE ON known_browsers TO saffui_retention;
GRANT SELECT ON known_browsers TO saffui_maintenance;
