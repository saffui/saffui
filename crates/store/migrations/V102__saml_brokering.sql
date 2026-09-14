-- What a SAML identity provider is asked, and what it names a login by. Kept
-- apart from the OAuth login states, whose verifier and nonce SAML has no use
-- for.

-- One authentication request in flight: the identifier the response must
-- answer, spent exactly once, by the browser login that sent it.
CREATE TABLE saml_login_requests
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    request_id     text        NOT NULL,
    provider_alias text        NOT NULL,
    auth_session   text        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, request_id)
);

ALTER TABLE saml_login_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_login_requests FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON saml_login_requests TO saffui_app;
CREATE POLICY saml_login_requests_by_realm ON saml_login_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

-- One logout request this realm sent, spent by the provider's answer.
CREATE TABLE saml_logout_requests
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    request_id     text        NOT NULL,
    provider_alias text        NOT NULL,
    -- Where the browser goes once the provider answered; absent when the
    -- logout named no place.
    resume_to      text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, request_id)
);

ALTER TABLE saml_logout_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_logout_requests FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON saml_logout_requests TO saffui_app;
CREATE POLICY saml_logout_requests_by_realm ON saml_logout_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

-- What an identity provider named a local login by, so a logout from either
-- side finds the other. It lives and ends with the login.
CREATE TABLE saml_broker_sessions
(
    tenant            text        NOT NULL,
    realm_id          text        NOT NULL,
    session_id        text        NOT NULL,
    provider_alias    text        NOT NULL,
    name_id           text        NOT NULL,
    name_id_format    text,
    name_qualifier    text,
    sp_name_qualifier text,
    session_index     text,
    created_at        timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, session_id),
    CONSTRAINT saml_broker_sessions_session FOREIGN KEY (tenant, realm_id, session_id)
        REFERENCES user_sessions (tenant, realm_id, session_id) ON DELETE CASCADE,
    CONSTRAINT saml_broker_session_name_not_blank CHECK (btrim(name_id) <> '')
);

-- A logout from the provider names the person, not the login.
CREATE INDEX saml_broker_sessions_by_name
    ON saml_broker_sessions (tenant, realm_id, provider_alias, name_id);

ALTER TABLE saml_broker_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE saml_broker_sessions FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON saml_broker_sessions TO saffui_app;
CREATE POLICY saml_broker_sessions_by_realm ON saml_broker_sessions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
