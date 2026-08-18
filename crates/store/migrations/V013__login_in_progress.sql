-- A login while it is still happening, what it has failed at, and the
-- authenticators a user enrolled.

-- Recovery codes are secrets a user holds, so they belong beside the other
-- ones. Passkeys do not: they carry a binary identifier, a counter and a
-- serialised credential, and folding them in here would mean a second home for
-- the same fact plus a secret column that is not a secret.
ALTER TYPE credential_type ADD VALUE IF NOT EXISTS 'recovery-code';

-- A login in progress.
--
-- Typed columns and a bounded note map, not an opaque document. A blob whose
-- only schema is a struct in one process is a schema nothing else can read, and
-- the row outlives the process that wrote it by design.
CREATE TABLE auth_sessions
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    session_id   text        NOT NULL,
    -- Whose authorization request this is answering.
    client_id    text        NOT NULL,
    -- The flow being run, and where it currently stands.
    flow_id      text        NOT NULL,
    execution_id text,
    -- Set once a step has said who this is. Null until then, which is not the
    -- same as anonymous: it is the state a flow is in before it has asked.
    user_id      text,
    redirect_uri text        NOT NULL,

    started_at   timestamptz NOT NULL DEFAULT now(),
    -- A login in progress is rubbish the moment it stops progressing, and
    -- nothing else here has a reason to keep it.
    expires_at   timestamptz NOT NULL,

    -- What the steps have to say to each other. Bounded, because an unbounded
    -- map is a place for one step to stash a token and another to find it.
    notes        jsonb       NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (tenant, realm_id, session_id),
    CONSTRAINT auth_sessions_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE,
    CONSTRAINT auth_sessions_flow FOREIGN KEY (tenant, realm_id, flow_id)
        REFERENCES authentication_flows (tenant, realm_id, flow_id) ON DELETE CASCADE,
    CONSTRAINT auth_sessions_execution FOREIGN KEY (tenant, realm_id, execution_id)
        REFERENCES authentication_executions (tenant, realm_id, execution_id)
        ON DELETE SET NULL,
    CONSTRAINT auth_sessions_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT notes_are_a_map CHECK (jsonb_typeof(notes) = 'object'),
    CONSTRAINT notes_are_bounded CHECK (octet_length(notes::text) <= 4096),
    CONSTRAINT a_login_expires_after_it_starts CHECK (expires_at > started_at),
    CONSTRAINT auth_session_id_not_blank CHECK (btrim(session_id) <> '')
);

CREATE INDEX auth_sessions_by_expiry ON auth_sessions (tenant, realm_id, expires_at);

-- What a realm has counted against one user.
--
-- One row per user, because a lockout is per user: keyed that way rather than
-- by a surrogate, so counting twice is impossible rather than merely unlikely.
CREATE TABLE user_login_failures
(
    tenant                  text        NOT NULL,
    realm_id                text        NOT NULL,
    user_id                 text        NOT NULL,
    num_failures            bigint      NOT NULL DEFAULT 0,
    -- Logins before this instant are refused. Zero means no lockout, which is
    -- the state a cleared record is in.
    failed_login_not_before bigint      NOT NULL DEFAULT 0,
    last_failure            bigint      NOT NULL DEFAULT 0,
    -- The last address seen, not every address. Keeping them all turns a
    -- counter into a log nobody bounded.
    last_ip_failure         text,
    updated_at              timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id),
    CONSTRAINT user_login_failures_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT failures_do_not_go_negative CHECK (num_failures >= 0)
);

-- The authenticators a user enrolled.
--
-- Its own table rather than a credential row: the identifier is binary and part
-- of the identity, the counter is read and written on every use, and the stored
-- credential is a public key rather than a secret.
CREATE TABLE webauthn_credentials
(
    tenant        text        NOT NULL,
    realm_id      text        NOT NULL,
    -- The raw identifier the authenticator returns, which is what a login
    -- presents and what an allow list names.
    credential_id bytea       NOT NULL,
    user_id       text        NOT NULL,
    -- What the user calls it, since a person with three keys needs to know
    -- which one they are revoking.
    label         text        NOT NULL DEFAULT '',
    -- The serialised credential: public key, transports, flags.
    passkey       jsonb       NOT NULL,
    -- The authenticator's own counter. A value that does not advance is how a
    -- cloned authenticator announces itself.
    sign_count    bigint      NOT NULL DEFAULT 0,
    enrolled_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,

    PRIMARY KEY (tenant, realm_id, credential_id),
    CONSTRAINT webauthn_credentials_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT credential_id_is_not_empty CHECK (octet_length(credential_id) > 0),
    CONSTRAINT sign_count_does_not_go_negative CHECK (sign_count >= 0)
);

CREATE INDEX webauthn_credentials_by_user ON webauthn_credentials (tenant, realm_id, user_id);

ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY auth_session_isolation ON auth_sessions
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE user_login_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_login_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY user_login_failure_isolation ON user_login_failures
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY webauthn_credential_isolation ON webauthn_credentials
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON auth_sessions, user_login_failures, webauthn_credentials TO saffui_app;
