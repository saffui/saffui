-- The clients of a realm. A client is known by an identifier of its own
-- choosing, unique in its realm and free in every other.

CREATE TABLE clients (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    client_row_id uuid NOT NULL,
    client_id text NOT NULL CHECK (client_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    -- The digest of a secret the realm generated. The secret is kept nowhere.
    secret_digest bytea NOT NULL,
    -- A grant is a column of its own: absent, it would read as allowed or
    -- refused by whoever reads it, and a grant must be refused unless written.
    allows_client_credentials boolean NOT NULL,
    scopes text[] NOT NULL,
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, client_row_id),
    CONSTRAINT clients_client_id_taken UNIQUE (tenant_id, realm_id, client_id),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE clients FORCE ROW LEVEL SECURITY;
CREATE POLICY clients_scope ON clients
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- Nothing changes or removes a client yet: the right to comes with the
-- first statement that does.
GRANT SELECT, INSERT ON clients TO saffui_app;
GRANT SELECT ON clients TO saffui_maintenance;
