-- The people of a realm, and their passwords.

CREATE TABLE persons (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    -- Lowercase, so that two spellings of one name are one person.
    username text NOT NULL CHECK (username ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
    email text CHECK (email = lower(email) AND char_length(email) <= 254),
    email_verified boolean NOT NULL,
    display_name text CHECK (char_length(display_name) <= 120),
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id),
    CONSTRAINT persons_username_taken UNIQUE (tenant_id, realm_id, username),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);
CREATE UNIQUE INDEX persons_email_taken ON persons (tenant_id, realm_id, email)
    WHERE email IS NOT NULL;

CREATE TABLE password_credentials (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    person_id uuid NOT NULL,
    -- A PHC string: it names its own algorithm and parameters.
    phc text NOT NULL,
    changed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, person_id),
    FOREIGN KEY (tenant_id, realm_id, person_id) REFERENCES persons ON DELETE CASCADE
);

ALTER TABLE persons ENABLE ROW LEVEL SECURITY;
ALTER TABLE persons FORCE ROW LEVEL SECURITY;
CREATE POLICY persons_scope ON persons
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE password_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY password_credentials_scope ON password_credentials
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- Nothing changes or removes a person or a password yet: the right to comes
-- with the first statement that does.
GRANT SELECT, INSERT ON persons, password_credentials TO saffui_app;
-- Maintenance reads people, never their passwords: nothing it does needs them.
GRANT SELECT ON persons TO saffui_maintenance;
