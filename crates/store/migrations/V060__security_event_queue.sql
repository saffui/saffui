-- Security Event Tokens waiting for a receiver that collects rather than
-- listens, RFC 8936: minted when the happening is delivered, held until the
-- receiver acknowledges them, and swept when their own expiry passes.
CREATE TABLE security_event_queue
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    receiver_id text        NOT NULL,
    jti         text        NOT NULL,
    set_body    text        NOT NULL,
    queued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, receiver_id, jti),
    CONSTRAINT security_event_queue_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

CREATE INDEX security_event_queue_by_receiver
    ON security_event_queue (tenant, realm_id, receiver_id, queued_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON security_event_queue TO saffui_app;

ALTER TABLE security_event_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_event_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY security_event_queue_by_realm ON security_event_queue
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
