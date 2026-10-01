-- How a realm presents itself to the wallets it asks for presentations: by
-- its did:web, or by an access certificate under the x509_hash prefix that
-- HAIP 1.0 requires, with what the European profile (ETSI TS 119 472-2) adds
-- to a request: the dataset the realm's registrar holds, and its registration
-- certificate.
CREATE TABLE realm_verifier_settings
(
    tenant                    text        NOT NULL,
    realm_id                  text        NOT NULL,
    -- `did-web`, or `x509-hash` while a certificate is in service.
    identity                  text        NOT NULL DEFAULT 'did-web',
    -- What the registrar holds of the realm, sent in `verifier_info`.
    registrar_dataset         jsonb,
    -- The registration certificate, a JWS in compact serialization.
    registration_certificate  text,
    updated_by                text        NOT NULL,
    updated_at                timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_verifier_settings_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT verifier_identity_known CHECK (identity IN ('did-web', 'x509-hash')),
    CONSTRAINT verifier_dataset_an_object
        CHECK (jsonb_typeof(registrar_dataset) = 'object'
           AND octet_length(registrar_dataset::text) <= 16384),
    CONSTRAINT verifier_registration_bounded
        CHECK (char_length(registration_certificate) BETWEEN 1 AND 16384)
);

-- The keys a realm's requests are signed with under its certificate. A key
-- is drawn with the request an authority certifies it from, and signs nothing
-- until its certificate is taken: then it serves, and the key it replaces is
-- dropped. It is in no key set the realm publishes, and no token is signed
-- with it.
CREATE TABLE realm_verifier_keys
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    -- The RFC 7638 thumbprint of the public key.
    kid             text        NOT NULL,
    -- The private half, sealed under the realm's keyring.
    sealed_key      bytea       NOT NULL,
    sealed_version  integer     NOT NULL,
    public_jwk      jsonb       NOT NULL,
    -- The subject the certificate request names, and the request, PEM.
    subject         jsonb       NOT NULL,
    request_pem     text        NOT NULL,
    -- `awaiting` its certificate, or `serving` under it.
    state           text        NOT NULL DEFAULT 'awaiting',
    -- The certificate and its issuers, DER, leaf first, the anchor left out.
    chain           bytea[],
    -- The base64url SHA-256 of the leaf, which `x509_hash` names it by.
    leaf_hash       text,
    not_before      timestamptz,
    not_after       timestamptz,
    certified_at    timestamptz,
    created_by      text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, kid),
    CONSTRAINT realm_verifier_keys_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT verifier_key_kid_written CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT verifier_key_state_known CHECK (state IN ('awaiting', 'serving')),
    CONSTRAINT verifier_key_certified_whole
        CHECK ((state = 'awaiting') = (chain IS NULL)
           AND (chain IS NULL) = (leaf_hash IS NULL)
           AND (leaf_hash IS NULL) = (not_before IS NULL)
           AND (not_before IS NULL) = (not_after IS NULL)
           AND (not_after IS NULL) = (certified_at IS NULL)),
    CONSTRAINT verifier_key_chain_bounded CHECK (cardinality(chain) BETWEEN 1 AND 9),
    CONSTRAINT verifier_key_hash_written CHECK (leaf_hash ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT verifier_key_request_bounded
        CHECK (octet_length(request_pem) <= 8192 AND octet_length(subject::text) <= 4096)
);

-- One key in service and one awaiting its certificate, at most, per realm.
CREATE UNIQUE INDEX realm_verifier_keys_one_serving
    ON realm_verifier_keys (tenant, realm_id) WHERE state = 'serving';
CREATE UNIQUE INDEX realm_verifier_keys_one_awaiting
    ON realm_verifier_keys (tenant, realm_id) WHERE state = 'awaiting';

-- The client identifier a request was asked under, so that an answer is held
-- to it after the realm changed how it presents itself. Absent on requests
-- asked before, which were all asked under the realm's did:web.
ALTER TABLE presentation_requests
    ADD COLUMN client_id text,
    ADD CONSTRAINT presentation_client_id_bounded
        CHECK (char_length(client_id) BETWEEN 1 AND 2048);

ALTER TABLE realm_verifier_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_verifier_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_verifier_settings_isolation ON realm_verifier_settings
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE realm_verifier_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_verifier_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_verifier_keys_isolation ON realm_verifier_keys
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_verifier_settings TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON realm_verifier_keys TO saffui_app;
