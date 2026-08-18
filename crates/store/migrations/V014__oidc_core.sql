-- What /authorize mints, what /token spends, and what a realm refuses to honour.

-- An authorization code, identified by the hash of the code and never by the
-- code.
--
-- The raw value goes to the client and is not kept, so reading this table
-- yields nothing that can be redeemed. Everything /token must re-check at
-- redemption is bound here rather than looked up again: the client, the exact
-- redirect_uri it was issued against, the challenge, and what the login
-- reached. Re-deriving any of that at redemption would attest to a request
-- that no longer exists.
CREATE TABLE oidc_auth_codes
(
    tenant                text        NOT NULL,
    realm_id              text        NOT NULL,
    code_hash             text        NOT NULL,
    client_id             text        NOT NULL,
    user_id               text        NOT NULL,
    session_id            text        NOT NULL,
    redirect_uri          text        NOT NULL,
    scope                 text        NOT NULL,
    nonce                 text,
    code_challenge        text,
    code_challenge_method text,
    auth_time             bigint      NOT NULL,
    acr                   text,
    org_id                text,

    issued_at             timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, code_hash),
    CONSTRAINT oidc_auth_codes_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT oidc_auth_codes_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT oidc_auth_codes_session FOREIGN KEY (tenant, realm_id, session_id)
        REFERENCES user_sessions (tenant, realm_id, session_id) ON DELETE CASCADE,
    CONSTRAINT oidc_auth_codes_org FOREIGN KEY (tenant, realm_id, org_id)
        REFERENCES organizations (tenant, realm_id, org_id) ON DELETE SET NULL,
    -- A challenge and the method that reads it travel together: one without the
    -- other is a check nobody can perform.
    CONSTRAINT a_challenge_names_its_method
        CHECK ((code_challenge IS NULL) = (code_challenge_method IS NULL)),
    CONSTRAINT a_code_expires_after_it_is_issued CHECK (expires_at > issued_at),
    CONSTRAINT code_hash_not_blank CHECK (btrim(code_hash) <> '')
);

CREATE INDEX oidc_auth_codes_by_expiry ON oidc_auth_codes (tenant, realm_id, expires_at);

-- Tokens a realm will not honour, whatever they say about themselves.
--
-- Keyed by the identifier a presented token carries, because that is the
-- question asked on every request: is this one refused. An expiry that can be
-- compared is what lets the list be swept rather than grow forever, since a
-- token nobody can present again need not be remembered.
CREATE TABLE revoked_tokens
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    token_id   text        NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now(),
    -- When the token would have stopped being accepted anyway.
    expires_at timestamptz NOT NULL,
    -- Why, for whoever asks later.
    reason     text        NOT NULL DEFAULT '',

    PRIMARY KEY (tenant, realm_id, token_id),
    CONSTRAINT revoked_tokens_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT token_id_not_blank CHECK (btrim(token_id) <> '')
);

CREATE INDEX revoked_tokens_by_expiry ON revoked_tokens (tenant, realm_id, expires_at);

-- The assertions a client has already used to authenticate.
--
-- The key is the protection: a client authenticating with a signed assertion
-- may use each identifier once, and a second insertion of the same one is
-- refused by the database rather than by a check somebody has to remember.
CREATE TABLE client_assertion_jtis
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    client_id  text        NOT NULL,
    jti_hash   text        NOT NULL,
    seen_at    timestamptz NOT NULL DEFAULT now(),
    -- The assertion's own expiry: past it, replay is refused by the signature
    -- check and this row has nothing left to prevent.
    expires_at timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, client_id, jti_hash),
    CONSTRAINT client_assertion_jtis_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT jti_hash_not_blank CHECK (btrim(jti_hash) <> '')
);

CREATE INDEX client_assertion_jtis_by_expiry
    ON client_assertion_jtis (tenant, realm_id, expires_at);

ALTER TABLE oidc_auth_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_auth_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_auth_code_isolation ON oidc_auth_codes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY revoked_token_isolation ON revoked_tokens
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE client_assertion_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_assertion_jtis FORCE ROW LEVEL SECURITY;
CREATE POLICY client_assertion_jti_isolation ON client_assertion_jtis
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON oidc_auth_codes, revoked_tokens, client_assertion_jtis TO saffui_app;
