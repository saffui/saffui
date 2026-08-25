CREATE TABLE user_consents
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    user_id    text        NOT NULL,
    client_id  text        NOT NULL,
    -- What was agreed to, not what was asked for. A later request that asks
    -- for more is a question this row does not answer.
    scopes     text[]      NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id, client_id),
    CONSTRAINT user_consents_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT user_consents_client FOREIGN KEY (tenant, realm_id, client_id)
        REFERENCES clients (tenant, realm_id, client_id) ON DELETE CASCADE
);

ALTER TABLE user_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_consents FORCE ROW LEVEL SECURITY;
CREATE POLICY user_consents_isolation ON user_consents
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON user_consents TO saffui_app;
