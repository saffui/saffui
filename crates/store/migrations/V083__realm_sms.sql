-- How a realm sends SMS.
--
-- Per realm and not per deployment: no gateway covers the continent, so two
-- realms serving two countries route through two providers, each under its
-- own sender name and its own token.
CREATE TABLE realm_sms
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    -- Where the gateway listens for a message to carry.
    url            text        NOT NULL,
    -- The sender name or number messages go out under.
    sender         text        NOT NULL,
    -- Sealed under the realm's own key, like every other secret this schema
    -- holds. The generation is kept beside it so a rotation can find what is
    -- still sealed under the old one.
    sealed_token   bytea,
    sealed_version integer,

    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_sms_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT sms_url_is_http CHECK (url LIKE 'http://%' OR url LIKE 'https://%'),
    CONSTRAINT sms_sender_not_blank CHECK (btrim(sender) <> ''),
    CONSTRAINT sms_token_is_whole CHECK (
        (sealed_token IS NULL AND sealed_version IS NULL)
        OR (sealed_token IS NOT NULL AND sealed_version IS NOT NULL)
    )
);

ALTER TABLE realm_sms ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_sms FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_sms_isolation ON realm_sms
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_sms TO saffui_app;
