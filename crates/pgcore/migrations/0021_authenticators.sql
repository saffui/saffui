-- The authenticator application of a person: one each, its secret sealed
-- under the data key of the realm for this row. It serves for nothing until
-- a first code confirms it.

CREATE TABLE totp_authenticators (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    sealed_secret bytea NOT NULL,
    -- Empty until a first code proved that the application holds the secret.
    confirmed_at timestamptz,
    -- The last time step a code was accepted for: a code serves once.
    last_step bigint,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

ALTER TABLE totp_authenticators ENABLE ROW LEVEL SECURITY;
ALTER TABLE totp_authenticators FORCE ROW LEVEL SECURITY;
CREATE POLICY totp_authenticators_scope ON totp_authenticators
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- The person a secret was made for never changes.
GRANT SELECT, INSERT, UPDATE (sealed_secret, confirmed_at, last_step, created_at), DELETE
    ON totp_authenticators TO saffui_app;
GRANT SELECT ON totp_authenticators TO saffui_maintenance;
