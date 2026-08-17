-- What a login leaves behind, and the short lived things it hands out.

CREATE TYPE user_session_state AS ENUM (
    'logged-in', 'logged-out', 'logging-out', 'logging-out-unconfirmed'
);

CREATE TABLE user_sessions
(
    tenant                text               NOT NULL,
    realm_id              text               NOT NULL,
    session_id            text               NOT NULL,
    user_id               text               NOT NULL,
    login_username        text               NOT NULL,

    broker_session_id     text,
    broker_user_id        text,
    auth_method           text,
    ip_address            text,

    started_at            bigint             NOT NULL,
    -- When the user last actually authenticated, which is not when the session
    -- began. One started at nine and re-authenticated at noon is three hours
    -- old while its authentication is minutes old, and the question a client
    -- asks is about the second. Absent on a session written before this was
    -- tracked, never zero, which would read as an authentication at the epoch.
    auth_time             bigint,
    -- The level actually reached. Absent means unknown, not zero: without it a
    -- step up cannot be recognised as having happened, and the second factor
    -- runs again on every request that asks for a level.
    loa                   integer,

    expiration            bigint,
    -- Always present. An absent state has to be read as something, and every
    -- reading of "no state" is a guess about whether the user is still logged
    -- in.
    state                 user_session_state NOT NULL,
    remember_me           boolean,
    last_session_refresh  bigint,
    is_offline            boolean,
    notes                 jsonb,

    PRIMARY KEY (tenant, realm_id, session_id),
    CONSTRAINT user_sessions_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT session_id_not_blank CHECK (btrim(session_id) <> '')
);

CREATE INDEX user_sessions_by_user ON user_sessions (tenant, realm_id, user_id);
CREATE INDEX user_sessions_by_expiry ON user_sessions (expiration);

CREATE TABLE client_sessions
(
    tenant                             text        NOT NULL,
    realm_id                           text        NOT NULL,
    session_id                         text        NOT NULL,
    user_session_id                    text        NOT NULL,
    user_id                            text        NOT NULL,
    client_id                          text        NOT NULL,

    auth_method                        text,
    redirect_uri                       text,
    started_at                         bigint      NOT NULL,
    expiration                         bigint,
    notes                              jsonb,

    -- A bearer credential, and never rendered by the model that carries it.
    current_refresh_token              text,
    -- How many times the current token has been presented. Detecting replay is
    -- what this is for, so it counts rather than flagging: a flag says a token
    -- was reused and a count says how far the reuse went.
    current_refresh_token_use_count    integer     NOT NULL DEFAULT 0,
    offline                            boolean,

    PRIMARY KEY (tenant, realm_id, session_id),
    -- A client session dies with the login it belongs to. Left behind, it is a
    -- refresh token outliving the session that authorised it.
    CONSTRAINT client_sessions_user_session FOREIGN KEY (tenant, realm_id, user_session_id)
        REFERENCES user_sessions (tenant, realm_id, session_id) ON DELETE CASCADE,
    CONSTRAINT client_sessions_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE
);

CREATE INDEX client_sessions_by_user_session
    ON client_sessions (tenant, realm_id, user_session_id);

-- The single use, short lived things a login hands out: the code in a message,
-- the link in a mail, a reset token.
--
-- Only the digest is stored. The value itself travels in a message or a URL and
-- lands in inboxes, browser history and proxy logs, so reading this table yields
-- nothing that can be presented.
--
-- One row per user and purpose. Asking for a second replaces the first, which
-- bounds how many are live at once and means a link that was requested twice
-- only honours the newer. That is deliberate: the alternative is a mailbox full
-- of working links.
CREATE TABLE one_time_tokens
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    user_id      text        NOT NULL,
    purpose      text        NOT NULL,
    token_hash   bytea       NOT NULL,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id, purpose),
    CONSTRAINT one_time_tokens_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT purpose_not_blank CHECK (btrim(purpose) <> ''),
    CONSTRAINT token_hash_is_a_digest CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX one_time_tokens_by_expiry ON one_time_tokens (expires_at);

ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY user_session_isolation ON user_sessions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE client_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY client_session_isolation ON client_sessions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE one_time_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE one_time_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY one_time_token_isolation ON one_time_tokens
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON user_sessions, client_sessions, one_time_tokens TO saffui_app;
