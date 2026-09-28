-- The credential issuers a realm names, with the keys read from each.
--
-- The keys are read when an administrator names the issuer, or asks for them
-- again, under the egress policy. A presentation is verified against what is
-- kept here and never sends this server out to ask.
CREATE TABLE realm_credential_issuers
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    issuer_id   text        NOT NULL,
    name        text        NOT NULL,
    -- The issuer as its credentials name it: an https address or a did:web.
    issuer      text        NOT NULL,
    -- Public keys as JWKs, each with the kid a credential names it by.
    keys        jsonb       NOT NULL,
    -- Where the keys were read, and when.
    read_from   text        NOT NULL,
    read_at     timestamptz NOT NULL,
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, issuer_id),
    CONSTRAINT realm_credential_issuers_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT credential_issuer_named_once UNIQUE (tenant, realm_id, issuer),
    CONSTRAINT credential_issuer_name_bounded CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT credential_issuer_bounded CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    CONSTRAINT credential_issuer_keys_listed
        CHECK (jsonb_typeof(keys) = 'array' AND jsonb_array_length(keys) BETWEEN 1 AND 20),
    CONSTRAINT credential_issuer_keys_bounded CHECK (octet_length(keys::text) <= 65536)
);

ALTER TABLE realm_credential_issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_credential_issuers FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_credential_issuers_isolation ON realm_credential_issuers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_credential_issuers TO saffui_app;
