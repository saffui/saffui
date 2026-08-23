-- An authorization request a client pushed here before sending the browser,
-- RFC 9126. The reference travels in a URL, so the row is keyed by its digest
-- and never by the reference itself: a leaked table hands out nothing usable.
CREATE TABLE pushed_requests
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    handle_hash text        NOT NULL,
    client_id   text        NOT NULL,
    parameters  jsonb       NOT NULL,

    pushed_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    -- §4: one use. Marked rather than deleted, so a second presentation is
    -- told apart from a reference that never was.
    redeemed_at timestamptz,

    PRIMARY KEY (tenant, realm_id, handle_hash),
    CONSTRAINT pushed_requests_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT pushed_parameters_are_a_map CHECK (jsonb_typeof(parameters) = 'object'),
    CONSTRAINT a_pushed_request_expires_after_it_arrives CHECK (expires_at > pushed_at)
);

CREATE INDEX pushed_requests_by_expiry ON pushed_requests (tenant, realm_id, expires_at);

ALTER TABLE pushed_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pushed_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY pushed_request_isolation ON pushed_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON pushed_requests TO saffui_app;
