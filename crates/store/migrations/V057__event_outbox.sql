-- What happened to people, kept until every outbound connector has been
-- told: written in the same transaction as the change itself, so a change
-- and its telling cannot disagree.
CREATE TYPE outbox_state AS ENUM ('pending', 'delivered', 'dead');

CREATE TABLE event_outbox
(
    tenant          text         NOT NULL,
    realm_id        text         NOT NULL,
    event_id        bigint       GENERATED ALWAYS AS IDENTITY,
    kind            text         NOT NULL,
    user_id         text         NOT NULL,
    payload         jsonb        NOT NULL,
    state           outbox_state NOT NULL DEFAULT 'pending',
    attempts        integer      NOT NULL DEFAULT 0,
    next_attempt_at timestamptz  NOT NULL DEFAULT now(),
    occurred_at     timestamptz  NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, event_id),
    CONSTRAINT event_outbox_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

CREATE INDEX event_outbox_by_due ON event_outbox (state, next_attempt_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON event_outbox TO saffui_app;

ALTER TABLE event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY event_outbox_by_realm ON event_outbox
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
