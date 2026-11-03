-- The keys of a realm. The data key is stored wrapped under the key of the
-- deployment, which never reaches the database. A private signing key is
-- stored sealed under the data key, for its own row.

CREATE TABLE realm_data_keys (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    generation integer NOT NULL CHECK (generation > 0),
    wrapped bytea NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, generation),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

CREATE TABLE signing_keys (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    signing_key_id uuid NOT NULL,
    kid text NOT NULL,
    -- The catalog of algorithms, held here too for a write that does not
    -- come through the product.
    algorithm text NOT NULL CHECK (algorithm IN ('ES256')),
    public_jwk jsonb NOT NULL,
    sealed_private_key bytea NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, signing_key_id),
    CONSTRAINT signing_keys_kid_taken UNIQUE (tenant_id, realm_id, kid),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

ALTER TABLE realm_data_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_data_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_data_keys_scope ON realm_data_keys
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY signing_keys_scope ON signing_keys
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- A key is written once and never changed: a new key is a new row.
GRANT SELECT, INSERT ON realm_data_keys, signing_keys TO saffui_app;
GRANT SELECT ON realm_data_keys, signing_keys TO saffui_maintenance;
