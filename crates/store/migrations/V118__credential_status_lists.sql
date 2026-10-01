-- The status lists the credentials a realm verifies cite, as a scheduled pass
-- last read them.
--
-- A presentation reads what is kept here and never sends this server out to
-- ask: a list nobody has read yet is written down by the first credential
-- citing it, which is refused until the pass has read the list. A list is read
-- under the keys of the issuer whose credentials cite it, and goes with it.
CREATE TABLE credential_status_lists
(
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    issuer_id     text        NOT NULL,
    -- The list's address, as credentials cite it.
    uri           text        NOT NULL,
    -- `token` for an IETF Token Status List, `bitstring` for a W3C Bitstring
    -- Status List: how the list is read, and which way its bits run.
    format        text        NOT NULL,
    -- The statuses as the list holds them once expanded, null until read.
    statuses      bytea,
    -- Bits per status of a token list.
    bits          smallint,
    -- The purposes a bitstring list serves.
    purposes      text[],
    -- When the issuer wrote what is kept, so an older writing is not kept.
    issued_at     timestamptz,
    -- When what is kept was read, and until when it may be relied on.
    read_at       timestamptz,
    usable_until  timestamptz,
    -- When the pass reads the list next.
    due_at        timestamptz NOT NULL,
    -- Why the last reading was not kept, in the realm's words.
    failure       text,
    -- When a credential last cited the list, to a day.
    cited_at      timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, issuer_id, uri, format),
    CONSTRAINT credential_status_lists_issuer FOREIGN KEY (tenant, realm_id, issuer_id)
        REFERENCES realm_credential_issuers (tenant, realm_id, issuer_id) ON DELETE CASCADE,
    CONSTRAINT status_list_format_known CHECK (format IN ('token', 'bitstring')),
    CONSTRAINT status_list_uri_bounded CHECK (char_length(uri) BETWEEN 1 AND 2048),
    CONSTRAINT status_list_statuses_bounded
        CHECK (octet_length(statuses) BETWEEN 1 AND 4194304),
    CONSTRAINT status_list_bits_of_a_token
        CHECK (bits IS NULL OR (format = 'token' AND bits IN (1, 2, 4, 8))),
    CONSTRAINT status_list_purposes_of_a_bitstring
        CHECK (purposes IS NULL
           OR (format = 'bitstring' AND cardinality(purposes) BETWEEN 1 AND 8)),
    CONSTRAINT status_list_read_whole
        CHECK ((statuses IS NULL) = (read_at IS NULL)
           AND (read_at IS NULL) = (usable_until IS NULL)
           AND (statuses IS NULL
                OR ((format = 'token') = (bits IS NOT NULL)
                    AND (format = 'bitstring') = (purposes IS NOT NULL)))),
    CONSTRAINT status_list_failure_bounded CHECK (char_length(failure) <= 200)
);

-- Kept uncompressed, so reading one status reads the one chunk holding it.
ALTER TABLE credential_status_lists ALTER COLUMN statuses SET STORAGE EXTERNAL;

CREATE INDEX credential_status_lists_due ON credential_status_lists (tenant, realm_id, due_at);

ALTER TABLE credential_status_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_status_lists FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_status_lists_isolation ON credential_status_lists
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON credential_status_lists TO saffui_app;
