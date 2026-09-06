-- The realm's inbound USSD gateway: the secret its callbacks present.
--
-- Inbound and not outbound, so it is not a column on realm_sms: the two
-- gateways are often different companies, and the secret here authenticates
-- THEM to US. A callback that can name any phone number must prove who is
-- calling, or anyone who finds the URL approves sign-ins on behalf of
-- whoever they name.
CREATE TABLE realm_ussd
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    sealed_secret  bytea       NOT NULL,
    sealed_version integer     NOT NULL,

    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_ussd_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

ALTER TABLE realm_ussd ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_ussd FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_ussd_isolation ON realm_ussd
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_ussd TO saffui_app;

-- What a USSD screen showed, anchored to the gateway's own session id: the
-- answer "1" decides the request the person was actually shown, not
-- whichever is oldest by the time the answer arrives.
CREATE TABLE ussd_sessions
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    session_id text        NOT NULL,
    user_id    text        NOT NULL,
    -- The backchannel request the screen named, by its digest.
    anchored   bytea       NOT NULL,
    expires_at timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, session_id),
    CONSTRAINT ussd_sessions_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

ALTER TABLE ussd_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ussd_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY ussd_sessions_isolation ON ussd_sessions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON ussd_sessions TO saffui_app;
