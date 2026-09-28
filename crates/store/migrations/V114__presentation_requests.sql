-- The presentations a realm asked a wallet for, each until it is answered or
-- runs out.
--
-- A request is answered once: the first answer moves it out of pending, and a
-- second finds nothing left to answer. Nothing a person disclosed is kept: the
-- outcome names the issuer, the credential type and the claims shown, never
-- their values.
CREATE TABLE presentation_requests
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    -- Also the request's state.
    request_id      text        NOT NULL,
    -- What the presentation's key binding must carry.
    nonce           text        NOT NULL,
    -- The key the answer is encrypted to, drawn for this request alone, named
    -- by the identifier the encrypted answer carries.
    response_kid    text        NOT NULL,
    response_key    bytea       NOT NULL,
    -- The query as asked, DCQL.
    query           jsonb       NOT NULL,
    -- The request as signed, served at its address while it is pending.
    request_object  text        NOT NULL,
    status          text        NOT NULL DEFAULT 'pending',
    -- What the answer came to, and why, in the realm's words.
    outcome         jsonb,
    expires_at      timestamptz NOT NULL,
    answered_at     timestamptz,
    created_by      text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, request_id),
    CONSTRAINT presentation_requests_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT presentation_response_key_once UNIQUE (tenant, realm_id, response_kid),
    CONSTRAINT presentation_status_known
        CHECK (status IN ('pending', 'verified', 'refused', 'failed')),
    CONSTRAINT presentation_settled_when_answered
        CHECK ((status = 'pending') = (answered_at IS NULL)),
    CONSTRAINT presentation_query_bounded CHECK (octet_length(query::text) <= 16384),
    CONSTRAINT presentation_request_bounded CHECK (octet_length(request_object) <= 65536),
    CONSTRAINT presentation_outcome_bounded CHECK (octet_length(outcome::text) <= 16384)
);

ALTER TABLE presentation_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE presentation_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY presentation_requests_isolation ON presentation_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON presentation_requests TO saffui_app;
