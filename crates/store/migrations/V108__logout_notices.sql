-- The logout notices a login owes its clients when it ends without the browser
-- logging out: an administrator closing it or every login of the realm, a
-- password changed or reset, a person switched off, an application's access
-- taken back.
--
-- Written in the transaction that ends the login, while it can still say who
-- took part, and sent by the outbox pass, which tries again on its own schedule
-- rather than holding anybody's request open. One per login and client: a
-- login ends once.
CREATE TABLE logout_notices
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    session_id      text        NOT NULL,
    client_id       text        NOT NULL,
    user_id         text        NOT NULL,
    owed_at         timestamptz NOT NULL DEFAULT now(),
    state           text        NOT NULL DEFAULT 'pending',
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, session_id, client_id),
    -- A person erased takes their notices with them, as every other row of
    -- theirs goes.
    CONSTRAINT logout_notices_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT logout_notice_state CHECK (state IN ('pending', 'sent', 'skipped', 'dead'))
);

CREATE INDEX logout_notices_by_due ON logout_notices (state, next_attempt_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON logout_notices TO saffui_app;

ALTER TABLE logout_notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE logout_notices FORCE ROW LEVEL SECURITY;
CREATE POLICY logout_notices_by_realm ON logout_notices
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
