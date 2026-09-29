-- The JSON-LD contexts a realm pins, beside the ones the server holds built in.
--
-- A context is read when an administrator pins it, or asks for it again, under
-- the egress policy, and kept as it was read with the digest of what was read.
-- A presentation is read under what is kept here and never sends this server
-- out to ask.
CREATE TABLE realm_jsonld_contexts
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    context_id  text        NOT NULL,
    -- The context as documents name it.
    url         text        NOT NULL,
    -- The context document, byte for byte as it was read.
    document    text        NOT NULL,
    -- The SHA-256 of the document, in lowercase hex.
    digest      text        NOT NULL,
    read_at     timestamptz NOT NULL,
    created_by  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, context_id),
    CONSTRAINT realm_jsonld_contexts_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT jsonld_context_pinned_once UNIQUE (tenant, realm_id, url),
    CONSTRAINT jsonld_context_url_bounded CHECK (char_length(url) BETWEEN 1 AND 2048),
    CONSTRAINT jsonld_context_document_bounded
        CHECK (octet_length(document) BETWEEN 1 AND 65536),
    CONSTRAINT jsonld_context_digest_written CHECK (digest ~ '^[0-9a-f]{64}$')
);

ALTER TABLE realm_jsonld_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_jsonld_contexts FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_jsonld_contexts_isolation ON realm_jsonld_contexts
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_jsonld_contexts TO saffui_app;
