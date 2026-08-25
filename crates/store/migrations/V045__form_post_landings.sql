-- A response waiting for the browser that will post it.
--
-- A browser running the sign-in script reads the answer as JSON, and a response
-- posted to the client is the one thing it cannot carry out itself: the sign-in
-- page may only post to this server, which is what its `form-action` says. The
-- page that may post to the client is served on the ticket held here.
CREATE TABLE form_post_landings
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    -- Hashed, never the ticket itself: this row is read to answer whoever
    -- presents one, and a readable ticket is a readable authorization code.
    ticket_hash  text        NOT NULL,
    redirect_uri text        NOT NULL,
    -- The response as the request asked for it, names and values.
    parameters   jsonb       NOT NULL,
    expires_at   timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, ticket_hash)
);

CREATE INDEX form_post_landings_expiry ON form_post_landings (expires_at);

ALTER TABLE form_post_landings ENABLE ROW LEVEL SECURITY;
ALTER TABLE form_post_landings FORCE ROW LEVEL SECURITY;
CREATE POLICY form_post_landings_isolation ON form_post_landings
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON form_post_landings TO saffui_app;
