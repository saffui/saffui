-- Asking for access instead of taking it: a request names who would hold
-- what and why, and someone other than its author decides it. The grant
-- itself is issued by the governed path, never here.
CREATE TABLE access_requests
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    request_id     text        NOT NULL,
    user_id        text        NOT NULL,
    role_id        text        NOT NULL,
    reason         text        NOT NULL,
    -- The end the grant will carry if granted; absent grants for good.
    expires_at     timestamptz,
    state          text        NOT NULL DEFAULT 'pending',
    asked_by       text        NOT NULL,
    decided_by     text,
    decided_at     timestamptz,
    decided_reason text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    version        integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, request_id),
    CONSTRAINT access_requests_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT access_requests_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    -- Four eyes at the schema: a decided request carries a decider, and
    -- the decider is not the asker. Withdrawal is the asker's own act and
    -- is not a decision.
    CONSTRAINT access_requests_four_eyes CHECK (
        state NOT IN ('granted', 'denied')
        OR (decided_by IS NOT NULL AND decided_by <> asked_by)
    )
);

GRANT SELECT, INSERT, UPDATE, DELETE ON access_requests TO saffui_app;

ALTER TABLE access_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY access_requests_by_realm ON access_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
