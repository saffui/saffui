-- What a user authenticates with.
--
-- Scoped by tenant and realm together, like everything a realm holds, and keyed
-- within its realm rather than globally: an identifier that is unique across the
-- deployment reports whether one exists in a realm the caller cannot read.

CREATE TYPE credential_type AS ENUM (
    'password', 'password-history', 'secret', 'totp', 'hotp'
);

CREATE TYPE otp_algorithm AS ENUM ('SHA1', 'SHA256', 'SHA512');

CREATE TABLE user_credentials
(
    tenant           text            NOT NULL,
    realm_id         text            NOT NULL,
    credential_id    text            NOT NULL,
    user_id          text            NOT NULL,
    credential_type  credential_type NOT NULL,
    user_label       text,

    -- What verifies the credential: a password record, or a shared secret.
    -- Never rendered by the model that carries it.
    secret           text            NOT NULL,

    -- The parameters an OTP credential is verified under, for the two types
    -- that have them. One flat value, so a time based credential cannot come
    -- back holding a counter.
    otp              jsonb,

    -- An ordering rank, tried lowest first when a user holds several of one
    -- type. Whole numbers on purpose: reordering spaces them in steps, and a
    -- scale here buys nothing while costing every reader a conversion.
    priority         bigint          NOT NULL DEFAULT 0,

    created_by       text,
    created_at       timestamptz     NOT NULL DEFAULT now(),
    updated_by       text,
    updated_at       timestamptz,
    version          integer         NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, credential_id),
    CONSTRAINT user_credentials_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT credential_id_not_blank CHECK (btrim(credential_id) <> ''),
    -- The two OTP types carry their parameters and the others do not. A time
    -- based credential with none cannot produce a code, and a password with some
    -- describes a way of checking it that nothing implements.
    CONSTRAINT otp_parameters_match_the_type CHECK (
        (credential_type IN ('totp', 'hotp')) = (otp IS NOT NULL)
    )
);

CREATE INDEX user_credentials_by_user
    ON user_credentials (tenant, realm_id, user_id, credential_type, priority);

ALTER TABLE user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_credentials FORCE ROW LEVEL SECURITY;

CREATE POLICY user_credential_isolation ON user_credentials
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON user_credentials TO saffui_app;
