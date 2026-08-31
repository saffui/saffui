-- A decoupled sign-in in flight: opened by an authenticated client, decided
-- by the person on their own device, collected once at the token endpoint.
-- The request id travels as a bearer secret and only its digest lands here.
CREATE TYPE backchannel_state AS ENUM ('pending', 'approved', 'denied');

CREATE TABLE backchannel_requests
(
    tenant          text              NOT NULL,
    realm_id        text              NOT NULL,
    request_digest  bytea             NOT NULL,
    client_id       text              NOT NULL,
    -- Null is a ghost: an unknown hint answered normally, approvable by
    -- nobody, so which names exist stays unsaid.
    user_id         text,
    scope           text              NOT NULL,
    binding_message text,
    state           backchannel_state NOT NULL DEFAULT 'pending',
    interval_secs   integer           NOT NULL,
    last_polled_at  timestamptz,
    approved_at     timestamptz,
    expires_at      timestamptz       NOT NULL,
    created_at      timestamptz       NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, request_digest),
    CONSTRAINT backchannel_requests_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT request_digest_is_a_digest CHECK (octet_length(request_digest) = 32)
);

CREATE INDEX backchannel_requests_by_expiry ON backchannel_requests (expires_at);
CREATE INDEX backchannel_requests_by_user ON backchannel_requests (tenant, realm_id, user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON backchannel_requests TO saffui_app;

ALTER TABLE backchannel_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE backchannel_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY backchannel_requests_by_realm ON backchannel_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
