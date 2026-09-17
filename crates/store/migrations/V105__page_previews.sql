-- A draft of a realm's page wording, kept just long enough to look at.
--
-- Written by an administrator and read by the browser they open it in, which
-- carries no bearer of its own. What makes that safe is not the identifier
-- being hard to guess: it is that the page rendered from one of these cannot
-- submit anything. A login page that cannot post cannot collect a password,
-- so a leaked draft is a picture and not a door.
CREATE TABLE page_previews
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    preview_id text        NOT NULL,
    -- The same shape the realm keeps its saved wording in, weighed against the
    -- keys a page actually reads before it is written.
    overrides  jsonb       NOT NULL,
    expires_at timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, preview_id)
);

CREATE INDEX page_previews_by_expiry ON page_previews (expires_at);

GRANT SELECT, INSERT, DELETE ON page_previews TO saffui_app;

ALTER TABLE page_previews ENABLE ROW LEVEL SECURITY;
ALTER TABLE page_previews FORCE ROW LEVEL SECURITY;
CREATE POLICY page_previews_by_realm ON page_previews
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
