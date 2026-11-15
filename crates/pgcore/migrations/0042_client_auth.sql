-- How a client proves itself, and the form its secret is kept in: a digest
-- for a secret it presents, sealed for a secret the realm checks an
-- assertion with, none for a key or for a public client. A client made
-- before presents its secret in the Basic scheme, which an administrator
-- may move to the form, or proves nothing. The rules bind every row written
-- from now on, and the next migration checks those already there.
ALTER TABLE clients
    ADD COLUMN auth_method text NOT NULL DEFAULT 'client_secret_basic',
    ADD COLUMN sealed_secret bytea,
    ADD COLUMN jwks jsonb,
    ADD COLUMN auth_signing_alg text;

-- The owner names no tenant: row security is lifted for this one statement,
-- in the transaction that holds the table. Measured on 100 000 clients, 30 %
-- of them public, this migration held the table 400 ms at most in three
-- runs, and a reader of a client waited as long; the next one took 70 ms
-- and blocks no write.
ALTER TABLE clients NO FORCE ROW LEVEL SECURITY;
UPDATE clients SET auth_method = 'none' WHERE secret_digest IS NULL;
ALTER TABLE clients FORCE ROW LEVEL SECURITY;

ALTER TABLE clients
    ALTER COLUMN auth_method DROP DEFAULT,
    -- Held below, method by method.
    DROP CONSTRAINT clients_secret_for_services,
    ADD CONSTRAINT clients_proof_fits_method CHECK (
        CASE
            WHEN auth_method IN ('client_secret_basic', 'client_secret_post') THEN
                secret_digest IS NOT NULL AND sealed_secret IS NULL AND jwks IS NULL
            WHEN auth_method = 'client_secret_jwt' THEN
                secret_digest IS NULL AND sealed_secret IS NOT NULL AND jwks IS NULL
            WHEN auth_method = 'private_key_jwt' THEN
                secret_digest IS NULL AND sealed_secret IS NULL AND jwks IS NOT NULL
            -- A client that proves nothing gets no token as itself.
            WHEN auth_method = 'none' THEN
                secret_digest IS NULL AND sealed_secret IS NULL AND jwks IS NULL
                AND NOT allows_client_credentials
            ELSE false
        END
    ) NOT VALID,
    ADD CONSTRAINT clients_assertion_algorithm_fits_method CHECK (
        CASE
            WHEN auth_method = 'client_secret_jwt' THEN
                auth_signing_alg IS NULL OR auth_signing_alg = 'HS256'
            WHEN auth_method = 'private_key_jwt' THEN
                auth_signing_alg IS NULL
                OR auth_signing_alg IN ('ES256', 'ES384', 'RS256', 'PS256', 'EdDSA')
            ELSE auth_signing_alg IS NULL
        END
    ) NOT VALID,
    -- Twice the set a client registers: jsonb writes as text with spaces
    -- what a client wrote compactly.
    ADD CONSTRAINT clients_jwks_bounded CHECK (
        jsonb_typeof(jwks) = 'object' AND octet_length(jwks::text) <= 32768
    ) NOT VALID;

-- An administrator turns a secret over, or moves it between the Basic
-- scheme and the form: the serving role writes the two forms of a secret
-- and the method, and the trigger below bounds the method.
GRANT UPDATE (secret_digest, sealed_secret, auth_method) ON clients TO saffui_app;

-- A method changes between the two ways of presenting one secret, and to
-- nothing else: unbound, the right to write it would let the serving role
-- make a confidential client public, which no rule of the row refuses. The
-- function runs as whoever updates and reads no table; its path is its own,
-- or the operators it compares with would be those of that role.
CREATE FUNCTION saffui_bound_auth_method_change() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
BEGIN
    IF OLD.auth_method IN ('client_secret_basic', 'client_secret_post')
       AND NEW.auth_method IN ('client_secret_basic', 'client_secret_post')
       AND NEW.secret_digest IS NOT DISTINCT FROM OLD.secret_digest THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a client changes only how it presents its secret'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER clients_auth_method_change BEFORE UPDATE OF auth_method ON clients
    FOR EACH ROW EXECUTE FUNCTION saffui_bound_auth_method_change();
REVOKE ALL ON FUNCTION saffui_bound_auth_method_change() FROM PUBLIC;

-- The identifiers of the assertions of each client, kept until no node can
-- take the assertion for good any more: an assertion serves once. No key
-- leads to the client: it would lock the row of the client at each
-- assertion, and an identifier left by a client gone leaves with the purge.
CREATE TABLE client_assertions (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    client_id text NOT NULL,
    token_id text NOT NULL CHECK (octet_length(token_id) BETWEEN 1 AND 255),
    kept_until timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, realm_id, client_id, token_id)
);
CREATE INDEX client_assertions_expiry ON client_assertions (kept_until);

ALTER TABLE client_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_assertions FORCE ROW LEVEL SECURITY;
CREATE POLICY client_assertions_scope ON client_assertions
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- The serving role only adds: of two uses of one assertion, the key keeps one.
GRANT INSERT ON client_assertions TO saffui_app;
GRANT SELECT ON client_assertions TO saffui_maintenance;
GRANT SELECT, DELETE ON client_assertions TO saffui_retention;
