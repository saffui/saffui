-- What a person allowed a client. A consent is every scope allowed so far:
-- a client that asks for more asks again. Withdrawn, the row goes; the
-- audit chain keeps the rest. Each migration of the consent blocks writes
-- to one table that was served before it: its client comes in the next.

CREATE TABLE consents (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id, client_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

ALTER TABLE consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE consents FORCE ROW LEVEL SECURITY;
CREATE POLICY consents_scope ON consents
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A consent widens in place, or goes: its person and its client never change.
GRANT SELECT, INSERT, UPDATE (scopes, granted_at), DELETE ON consents TO saffui_app;
GRANT SELECT ON consents TO saffui_maintenance;
