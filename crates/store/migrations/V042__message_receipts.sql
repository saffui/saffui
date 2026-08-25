-- Whether a message this server produced actually went out.
--
-- A person who says the link never arrived leaves nothing behind today but a
-- log line, which may be gone. This says whether the server tried, and what
-- the far end said when it did not work.
CREATE TABLE message_deliveries
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    delivery_id  text        NOT NULL,
    user_id      text        NOT NULL,
    -- What the message was for, spelled as the token purpose is.
    purpose      text        NOT NULL,
    -- Where it went. Not the body: that holds the link, and a table anybody
    -- with read access could sign in from is not a receipt.
    recipient    text        NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT now(),
    delivered    boolean     NOT NULL,
    -- What the far end said, when it said something. Bounded, because an SMTP
    -- server that answers with a page of text should not fill a column.
    detail       text,

    PRIMARY KEY (tenant, realm_id, delivery_id),
    CONSTRAINT message_deliveries_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT delivery_purpose_not_blank CHECK (btrim(purpose) <> ''),
    CONSTRAINT delivery_detail_is_bounded CHECK (detail IS NULL OR length(detail) <= 500)
);

CREATE INDEX message_deliveries_by_person
    ON message_deliveries (tenant, realm_id, user_id, attempted_at DESC);

ALTER TABLE message_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE message_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY message_deliveries_isolation ON message_deliveries
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, DELETE ON message_deliveries TO saffui_app;
