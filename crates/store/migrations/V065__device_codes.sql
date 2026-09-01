-- RFC 8628: a sign-in for something with no browser worth typing in. The
-- device holds a long secret and polls with it; the person types a short
-- code somewhere comfortable and signs in there. Only the long secret's
-- digest lands here, and the short code lives exactly as long as the row.
CREATE TYPE device_code_state AS ENUM ('pending', 'approved', 'denied');

CREATE TABLE oidc_device_codes
(
    tenant         text              NOT NULL,
    realm_id       text              NOT NULL,
    device_digest  bytea             NOT NULL,
    -- Normalized: uppercase, no separators. Short-lived and rate-limited at
    -- the door, which is what makes its size honest.
    user_code      text              NOT NULL,
    client_id      text              NOT NULL,
    scope          text              NOT NULL,
    state          device_code_state NOT NULL DEFAULT 'pending',
    -- Written at approval, by the login that approved it: who, which login,
    -- when they authenticated, and what the flow attested. The token the
    -- poll redeems speaks these, so they are frozen here like a code's.
    user_id        text,
    session_id     text,
    auth_time      bigint,
    acr            text,
    org_id         text,
    org_name       text,
    interval_secs  integer           NOT NULL,
    last_polled_at timestamptz,
    approved_at    timestamptz,
    expires_at     timestamptz       NOT NULL,
    created_at     timestamptz       NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, device_digest),
    CONSTRAINT oidc_device_codes_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT device_digest_is_a_digest CHECK (octet_length(device_digest) = 32),
    CONSTRAINT one_user_code_at_a_time UNIQUE (tenant, realm_id, user_code)
);

CREATE INDEX oidc_device_codes_by_expiry ON oidc_device_codes (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON oidc_device_codes TO saffui_app;

ALTER TABLE oidc_device_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_device_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_device_codes_by_realm ON oidc_device_codes
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
