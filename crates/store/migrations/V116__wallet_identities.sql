-- How a realm knows people by a credential their wallet presents: the one
-- credential it asks for, the claim in it that identifies somebody, and the
-- identities its accounts linked.
--
-- An identifier is never kept. What is kept is an HMAC of it, beside the
-- issuer that vouched for it, under a key drawn for this realm alone and sealed
-- in its keyring: an identity presented again is found by the same digest, and
-- a table read on its own names nobody.
CREATE TABLE realm_wallet_identity
(
    tenant           text        NOT NULL,
    realm_id         text        NOT NULL,
    -- The credential asked for, as one DCQL credential query.
    credential_query jsonb       NOT NULL,
    -- The issuer that vouches for identities, one the realm names.
    issuer           text        NOT NULL,
    -- The claim that identifies, as a path of member names.
    identifier_path  jsonb       NOT NULL,
    -- The HMAC key, drawn once and sealed under the realm's keyring.
    digest_key       bytea       NOT NULL,
    updated_by       text        NOT NULL,
    updated_at       timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_wallet_identity_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT wallet_identity_query_bounded
        CHECK (octet_length(credential_query::text) <= 8192),
    CONSTRAINT wallet_identity_issuer_bounded CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    CONSTRAINT wallet_identity_path_is_a_list CHECK (jsonb_typeof(identifier_path) = 'array')
);

ALTER TABLE realm_wallet_identity ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_wallet_identity FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_wallet_identity_isolation ON realm_wallet_identity
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_wallet_identity TO saffui_app;

-- The identities a realm's accounts linked. One identity answers for one
-- account, and an account holds one identity per issuer.
CREATE TABLE wallet_identities
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    user_id    text        NOT NULL,
    issuer     text        NOT NULL,
    -- The HMAC of the identifier, in lowercase hex.
    digest     text        NOT NULL,
    linked_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, issuer, digest),
    CONSTRAINT wallet_identity_one_per_issuer UNIQUE (tenant, realm_id, user_id, issuer),
    CONSTRAINT wallet_identities_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT wallet_identity_digest_written CHECK (digest ~ '^[0-9a-f]{64}$')
);

ALTER TABLE wallet_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE wallet_identities FORCE ROW LEVEL SECURITY;
CREATE POLICY wallet_identities_isolation ON wallet_identities
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON wallet_identities TO saffui_app;

-- A presentation asked for a login rather than by an administrator: what it is
-- for, the login it serves and the person that login names, so its answer is
-- read by that login alone.
ALTER TABLE presentation_requests
    ADD COLUMN purpose       text,
    ADD COLUMN login_session text,
    ADD COLUMN user_id       text,
    ADD CONSTRAINT presentation_purpose_known
        CHECK (purpose IS NULL OR purpose IN ('link', 'factor')),
    ADD CONSTRAINT presentation_purpose_bound
        CHECK ((purpose IS NULL) = (login_session IS NULL)
           AND (purpose IS NULL) = (user_id IS NULL));

-- The ceremony that links one: an application may ask the person for it, and a
-- realm may require it of somebody.
ALTER TYPE required_action ADD VALUE IF NOT EXISTS 'link-wallet-identity';
