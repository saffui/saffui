-- How a realm sends its codes over WhatsApp, which way each attempt went, and
-- which way a person asked their codes to come.
--
-- One network, so the settings are Meta's own: the id of the business number,
-- a system user's token, and the authentication template with the languages
-- it was approved in. Such a template carries a code and nothing else, so a
-- link still goes by SMS.
CREATE TABLE realm_whatsapp
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    -- The id Meta gives the business number, not the number itself.
    phone_number_id text        NOT NULL,
    -- The approved template, and the languages it was approved in, spelled
    -- the way Meta spells them.
    template        text        NOT NULL,
    languages       text[]      NOT NULL,
    -- Sealed under the realm's own key. Meta wants it on every call, so there
    -- is no row without one.
    sealed_token    bytea       NOT NULL,
    sealed_version  integer     NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_whatsapp_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT whatsapp_number_id_is_digits CHECK (phone_number_id ~ '^[0-9]{1,32}$'),
    CONSTRAINT whatsapp_template_is_named CHECK (
        template ~ '^[a-z0-9_]+$' AND length(template) <= 512
    ),
    CONSTRAINT whatsapp_speaks_a_language CHECK (cardinality(languages) > 0)
);

ALTER TABLE realm_whatsapp ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_whatsapp FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_whatsapp_isolation ON realm_whatsapp
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_whatsapp TO saffui_app;

-- Empty on the attempts made before there was a choice. A code may now try
-- WhatsApp and then SMS, and each attempt keeps its own receipt.
ALTER TABLE message_deliveries
    ADD COLUMN channel text
        CONSTRAINT delivery_channel_is_known CHECK (channel IN ('mail', 'sms', 'whatsapp'));

-- A phone without WhatsApp is known only once its holder says so: Meta takes
-- a message for a number it cannot reach and fails it later, where nothing
-- here listens. Kept with the account, so erasing the person erases it.
CREATE TABLE code_channels
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    user_id    text        NOT NULL,
    -- The number the choice was made for. Once the account holds another,
    -- the choice says nothing about it.
    recipient  text        NOT NULL,
    channel    text        NOT NULL,
    chosen_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, user_id),
    CONSTRAINT code_channels_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT code_channel_is_known CHECK (channel IN ('sms', 'whatsapp'))
);

ALTER TABLE code_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE code_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY code_channels_isolation ON code_channels
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON code_channels TO saffui_app;
