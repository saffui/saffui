-- What a person allowed a client. A consent is every scope allowed so far:
-- a client that asks for more asks again. Withdrawn, the row goes; the
-- audit chain keeps the rest. The requests that wait for an answer change
-- in the next migration, so that no migration holds two tables that serve.

CREATE TABLE consents (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    client_id text NOT NULL,
    scopes text[] NOT NULL,
    granted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id, client_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, realm_id, client_id)
        REFERENCES clients (tenant_id, realm_id, client_id) ON DELETE CASCADE
);

ALTER TABLE consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE consents FORCE ROW LEVEL SECURITY;
CREATE POLICY consents_scope ON consents
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A consent widens in place, or goes: its person and its client never change.
GRANT SELECT, INSERT, UPDATE (scopes, granted_at), DELETE ON consents TO saffui_app;
GRANT SELECT ON consents TO saffui_maintenance;

-- Whether a client asks each person before it gets a code in their name.
-- A client made before asks nobody, as it did. Only a client that signs
-- people in has anyone to ask.
ALTER TABLE clients ADD COLUMN requires_consent boolean NOT NULL DEFAULT false;
ALTER TABLE clients ALTER COLUMN requires_consent DROP DEFAULT;
ALTER TABLE clients
    ADD CONSTRAINT clients_consent_for_applications
        CHECK (allows_authorization_code OR NOT requires_consent);
