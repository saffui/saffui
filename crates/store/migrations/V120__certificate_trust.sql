-- How a realm trusts an issuer it names: by the keys its metadata publishes,
-- or by the certificates the authorities it deposited issue for it. One way
-- per issuer, so a credential naming it is verified the way the realm chose
-- and never another a presenter picks (SD-JWT VC §10.2).
ALTER TABLE realm_credential_issuers
    ADD COLUMN trusted_by text NOT NULL DEFAULT 'metadata',
    -- The types an issuer trusted by certificate issues, as vct values.
    ADD COLUMN credential_types jsonb,
    ALTER COLUMN read_from DROP NOT NULL,
    ALTER COLUMN read_at DROP NOT NULL,
    DROP CONSTRAINT credential_issuer_keys_listed,
    ADD CONSTRAINT credential_issuer_trust_known
        CHECK (trusted_by IN ('metadata', 'certificate')),
    ADD CONSTRAINT credential_issuer_keys_listed
        CHECK (jsonb_typeof(keys) = 'array' AND jsonb_array_length(keys) <= 20),
    ADD CONSTRAINT credential_issuer_trusted_whole
        CHECK (CASE trusted_by
                   WHEN 'metadata' THEN jsonb_array_length(keys) >= 1
                                    AND read_from IS NOT NULL AND read_at IS NOT NULL
                                    AND credential_types IS NULL
                   ELSE jsonb_array_length(keys) = 0
                    AND read_from IS NULL AND read_at IS NULL
                    AND credential_types IS NOT NULL
                    AND jsonb_typeof(credential_types) = 'array'
                    AND jsonb_array_length(credential_types) BETWEEN 1 AND 20
               END),
    ADD CONSTRAINT credential_issuer_types_bounded
        CHECK (octet_length(credential_types::text) <= 8192);

-- The authorities an issuer trusted by certificate is trusted through. An
-- authority some issuer is trusted through is not withdrawn from under it.
CREATE TABLE realm_credential_issuer_anchors
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    issuer_id   text        NOT NULL,
    anchor_id   text        NOT NULL,

    PRIMARY KEY (tenant, realm_id, issuer_id, anchor_id),
    CONSTRAINT credential_issuer_anchors_issuer FOREIGN KEY (tenant, realm_id, issuer_id)
        REFERENCES realm_credential_issuers (tenant, realm_id, issuer_id) ON DELETE CASCADE,
    CONSTRAINT credential_issuer_anchors_anchor FOREIGN KEY (tenant, realm_id, anchor_id)
        REFERENCES realm_trust_anchors (tenant, realm_id, anchor_id) ON DELETE RESTRICT
);

-- The certificate revocation lists the chains of a realm's credentials name,
-- as a scheduled pass last read them.
--
-- As for status lists, a presentation reads only what is kept here: a list
-- nobody has read is written down by the first certificate naming it, which
-- is refused until the pass has read the list. A list is kept for the
-- authority whose certificates it covers, taken from the chain that named it,
-- and read under that authority's name and key alone.
CREATE TABLE certificate_revocation_lists
(
    tenant            text        NOT NULL,
    realm_id          text        NOT NULL,
    issuer_id         text        NOT NULL,
    -- The list's address, as certificates name it.
    uri               text        NOT NULL,
    -- SHA-256 of the authority's certificate, lowercase hex, and the
    -- certificate, DER.
    authority_digest  text        NOT NULL,
    authority         bytea       NOT NULL,
    -- When the authority issued what is kept, so an older list is not kept.
    issued_at         timestamptz,
    -- When what is kept was read, and until when it may be relied on.
    read_at           timestamptz,
    usable_until      timestamptz,
    -- When the pass reads the list next.
    due_at            timestamptz NOT NULL,
    -- Why the last reading was not kept, in the realm's words.
    failure           text,
    -- When a certificate last named the list, to a day.
    cited_at          timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, issuer_id, uri, authority_digest),
    CONSTRAINT certificate_revocation_lists_issuer FOREIGN KEY (tenant, realm_id, issuer_id)
        REFERENCES realm_credential_issuers (tenant, realm_id, issuer_id) ON DELETE CASCADE,
    CONSTRAINT revocation_list_uri_bounded CHECK (char_length(uri) BETWEEN 1 AND 2048),
    CONSTRAINT revocation_list_authority_named CHECK (authority_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT revocation_list_authority_bounded
        CHECK (octet_length(authority) BETWEEN 1 AND 16384),
    CONSTRAINT revocation_list_read_whole
        CHECK ((issued_at IS NULL) = (read_at IS NULL)
           AND (read_at IS NULL) = (usable_until IS NULL)),
    CONSTRAINT revocation_list_failure_bounded CHECK (char_length(failure) <= 200)
);

CREATE INDEX certificate_revocation_lists_due
    ON certificate_revocation_lists (tenant, realm_id, due_at);

-- The serials a list kept revokes: one row each, so a presentation looks one
-- up rather than reading the list.
CREATE TABLE certificate_revocations
(
    tenant            text        NOT NULL,
    realm_id          text        NOT NULL,
    issuer_id         text        NOT NULL,
    uri               text        NOT NULL,
    authority_digest  text        NOT NULL,
    -- The serial's magnitude, big-endian.
    serial            bytea       NOT NULL,

    PRIMARY KEY (tenant, realm_id, issuer_id, uri, authority_digest, serial),
    CONSTRAINT certificate_revocations_list
        FOREIGN KEY (tenant, realm_id, issuer_id, uri, authority_digest)
        REFERENCES certificate_revocation_lists (tenant, realm_id, issuer_id, uri, authority_digest)
        ON DELETE CASCADE,
    CONSTRAINT certificate_revocation_serial_bounded CHECK (octet_length(serial) <= 20)
);

ALTER TABLE realm_credential_issuer_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_credential_issuer_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_credential_issuer_anchors_isolation ON realm_credential_issuer_anchors
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE certificate_revocation_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_revocation_lists FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_revocation_lists_isolation ON certificate_revocation_lists
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE certificate_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY certificate_revocations_isolation ON certificate_revocations
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_credential_issuer_anchors TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_revocation_lists TO saffui_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON certificate_revocations TO saffui_app;
