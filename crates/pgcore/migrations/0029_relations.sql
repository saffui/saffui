-- What a realm says of its objects: the schema of its relations, and the
-- relations it keeps between objects and subjects.

ALTER TABLE clients
    DROP CONSTRAINT clients_capabilities_known,
    ADD CONSTRAINT clients_capabilities_known CHECK (
        capabilities <@ ARRAY[
            'realm:read', 'client:read', 'client:write', 'audit:read', 'user:read', 'user:write',
            'role:read', 'role:write', 'policy:read', 'policy:write'
        ]
    );

-- What was written, and what it compiled to. The compiled form is read, and
-- compiled again from the source when another version wrote it. The product
-- bounds it at 256 KiB as it writes it; jsonb writes a space after each `:`
-- and `,` of it, so twice that bound holds it.
CREATE TABLE relation_schemas (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    source text NOT NULL CHECK (octet_length(source) <= 65536),
    compiled jsonb NOT NULL
        CHECK (jsonb_typeof(compiled) = 'object' AND octet_length(compiled::text) <= 524288),
    written_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

-- A relation is the whole of its row: kept once, compared and sorted byte
-- for byte.
CREATE TABLE relation_tuples (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    object_type text COLLATE "C" NOT NULL CHECK (object_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    object_id text COLLATE "C" NOT NULL CHECK (object_id ~ '^[A-Za-z0-9.:@_-]{1,128}$'),
    relation text COLLATE "C" NOT NULL CHECK (relation ~ '^[a-z][a-z0-9_]{0,63}$'),
    subject_type text COLLATE "C" NOT NULL CHECK (subject_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    subject_id text COLLATE "C" NOT NULL CHECK (subject_id ~ '^[A-Za-z0-9.:@_-]{1,128}$'),
    -- Empty when the subject is the object itself, not the members of one
    -- of its members.
    subject_member text COLLATE "C" NOT NULL
        CHECK (subject_member = '' OR subject_member ~ '^[a-z][a-z0-9_]{0,63}$'),
    written_at timestamptz NOT NULL,
    -- The relation before the object: a schema that withdraws a kind, or
    -- admits one anew, reads the relations it names and no other of the type.
    PRIMARY KEY (
        tenant_id, realm_id, object_type, relation, object_id,
        subject_type, subject_id, subject_member
    ),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

-- The kinds of relations the schema admits, written with it: a writer of
-- relations reads its kind here, never the compiled form whole.
CREATE TABLE relation_kinds (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    object_type text COLLATE "C" NOT NULL CHECK (object_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    relation text COLLATE "C" NOT NULL CHECK (relation ~ '^[a-z][a-z0-9_]{0,63}$'),
    subject_type text COLLATE "C" NOT NULL CHECK (subject_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    subject_member text COLLATE "C" NOT NULL
        CHECK (subject_member = '' OR subject_member ~ '^[a-z][a-z0-9_]{0,63}$'),
    PRIMARY KEY (tenant_id, realm_id, object_type, relation, subject_type, subject_member),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES relation_schemas
);

-- The clients that guard a type of the schema: they alone are answered by
-- its relations, and any other client is answered as for a type that is not.
CREATE TABLE relation_guards (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    object_type text COLLATE "C" NOT NULL CHECK (object_type ~ '^[a-z][a-z0-9_]{0,63}$'),
    client_id text NOT NULL,
    written_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, object_type, client_id),
    FOREIGN KEY (tenant_id, realm_id, client_id)
        REFERENCES clients (tenant_id, realm_id, client_id) ON DELETE CASCADE
);

ALTER TABLE relation_schemas ENABLE ROW LEVEL SECURITY;
ALTER TABLE relation_schemas FORCE ROW LEVEL SECURITY;
CREATE POLICY relation_schemas_scope ON relation_schemas
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());
ALTER TABLE relation_tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE relation_tuples FORCE ROW LEVEL SECURITY;
CREATE POLICY relation_tuples_scope ON relation_tuples
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE relation_kinds ENABLE ROW LEVEL SECURITY;
ALTER TABLE relation_kinds FORCE ROW LEVEL SECURITY;
CREATE POLICY relation_kinds_scope ON relation_kinds
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE relation_guards ENABLE ROW LEVEL SECURITY;
ALTER TABLE relation_guards FORCE ROW LEVEL SECURITY;
CREATE POLICY relation_guards_scope ON relation_guards
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A schema is written again whole, its kinds with it; a relation or a guard
-- is kept or removed, never changed.
GRANT SELECT, INSERT, UPDATE (source, compiled, written_at) ON relation_schemas TO saffui_app;
GRANT SELECT, INSERT, DELETE ON relation_kinds, relation_tuples, relation_guards TO saffui_app;
GRANT SELECT ON relation_schemas, relation_kinds, relation_tuples, relation_guards
    TO saffui_maintenance;
