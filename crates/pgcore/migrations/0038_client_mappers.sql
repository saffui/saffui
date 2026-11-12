-- What the tokens of a client say beyond what their scopes say. The kind
-- and its settings are one document: the binary reads it closed, and a
-- kind it does not know fails the read instead of being skipped.
CREATE TABLE client_mappers (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    mapper_id uuid NOT NULL,
    client_id text NOT NULL,
    name text COLLATE "C" NOT NULL CHECK (name ~ '^[A-Za-z0-9.:_-]{1,64}$'),
    definition jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object'),
    -- Lowercase: a reader that matches keys without case takes no claim for
    -- one the protocol writes.
    claim text CHECK (claim ~ '^[a-z0-9._:-]{1,64}$'),
    targets text[] NOT NULL
        CHECK (targets <@ ARRAY['access_token', 'id_token', 'userinfo'] AND cardinality(targets) >= 1),
    scope text,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, mapper_id),
    CONSTRAINT client_mappers_name_taken UNIQUE (tenant_id, realm_id, client_id, name),
    FOREIGN KEY (tenant_id, realm_id, client_id)
        REFERENCES clients (tenant_id, realm_id, client_id) ON DELETE CASCADE
);

ALTER TABLE client_mappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_mappers FORCE ROW LEVEL SECURITY;
CREATE POLICY client_mappers_scope ON client_mappers
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A mapper is never changed: it goes, and another is written.
GRANT SELECT, INSERT, DELETE ON client_mappers TO saffui_app;
GRANT SELECT ON client_mappers TO saffui_maintenance;

-- The mappers of a client are counted under the lock of its row. A row lock
-- asks for the right to update one column. Row security keeps that column
-- where it is: no update can move the row.
GRANT UPDATE (realm_id) ON clients TO saffui_app;
