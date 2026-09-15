-- A notice owed to a person when how they sign in changes. Drawn from the outbox
-- but settled on its own, so a connector that keeps failing never sends it twice.
CREATE TABLE security_notices
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    event_id        bigint      NOT NULL,
    user_id         text        NOT NULL,
    kind            text        NOT NULL,
    occurred_at     timestamptz NOT NULL,
    state           text        NOT NULL DEFAULT 'pending',
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, event_id),
    -- One notice for one change: an administrator taking a sheet of codes away
    -- writes an event per code, all stamped with the same transaction's instant.
    CONSTRAINT security_notice_once UNIQUE (tenant, realm_id, user_id, kind, occurred_at),
    CONSTRAINT security_notices_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT security_notice_state CHECK (state IN ('pending', 'sent', 'skipped', 'dead'))
);

CREATE INDEX security_notices_by_due ON security_notices (state, next_attempt_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON security_notices TO saffui_app;

ALTER TABLE security_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_notices FORCE ROW LEVEL SECURITY;
CREATE POLICY security_notices_by_realm ON security_notices
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

-- Absent sends the notices: a realm switches them off, never on.
ALTER TABLE realms ADD COLUMN security_notices_enabled boolean;
