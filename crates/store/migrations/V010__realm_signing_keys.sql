-- The keys a realm signs with, and publishes the public half of.

-- What a key is for, spelled as RFC 7517 spells it, so the row and the
-- published JWK say the same word.
CREATE TYPE key_use AS ENUM ('sig', 'enc');

-- Where a key stands in its rotation.
CREATE TYPE key_status AS ENUM ('active', 'passive', 'disabled');

CREATE TABLE realm_signing_keys
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    -- The JWK thumbprint. Tokens carry it and the JWKS answers to it, so it is
    -- the identity rather than a column beside one.
    kid         text        NOT NULL,
    -- Spelled as JOSE spells it. Which values are legal depends on what the key
    -- is for, which is why this is a check and not a type: a type cannot say
    -- that its own legal values depend on another column.
    algorithm   text        NOT NULL,
    key_use     key_use     NOT NULL,
    status      key_status  NOT NULL DEFAULT 'active',
    -- Which key is preferred among equals.
    priority    bigint      NOT NULL DEFAULT 0,
    -- Sealed. A private key in the clear is the one secret whose loss is the
    -- loss of every token the realm ever signed.
    private_pem bytea       NOT NULL,
    -- The public half, as published.
    public_jwk  jsonb       NOT NULL,
    created_at  bigint      NOT NULL,

    PRIMARY KEY (tenant, realm_id, kid),
    CONSTRAINT realm_signing_keys_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    -- The key type is not stored. It is read from the algorithm, so no row can
    -- carry an elliptic curve key labelled RSA.
    CONSTRAINT the_algorithm_matches_the_use CHECK (
        CASE key_use
            WHEN 'sig' THEN algorithm IN (
                'RS256', 'RS384', 'RS512',
                'PS256', 'PS384', 'PS512',
                'ES256', 'ES384', 'ES512',
                'EdDSA'
            )
            -- Encryption keys arrive with the work that reads them, and the
            -- catalogue for them is added here then. Until something can write
            -- one and read it back, a row claiming to be one is a row nothing
            -- would understand.
            ELSE false
        END
    ),
    CONSTRAINT kid_not_blank CHECK (btrim(kid) <> ''),
    CONSTRAINT private_pem_is_not_empty CHECK (octet_length(private_pem) > 0)
);

-- One key signs, per realm and per use.
--
-- Two would have tokens signed under whichever the reader found first, and a
-- rotation would then be a change nobody could observe.
CREATE UNIQUE INDEX one_active_key_per_use
    ON realm_signing_keys (tenant, realm_id, key_use) WHERE status = 'active';

-- The JWKS reads by use and status, in priority order.
CREATE INDEX realm_signing_keys_published
    ON realm_signing_keys (tenant, realm_id, key_use, status, priority DESC);

ALTER TABLE realm_signing_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_signing_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_signing_key_isolation ON realm_signing_keys
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_signing_keys TO saffui_app;
