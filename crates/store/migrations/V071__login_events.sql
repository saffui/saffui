-- The sign-in log a realm may switch on: who signed in, who failed to, who
-- signed out, with the provenance the login itself saw. Recording is gated
-- by the realm's events_enabled switch, and rows age out by the sweeper, so
-- an enabled log is a window and never an archive.
CREATE TABLE login_events
(
    tenant      text   NOT NULL,
    realm_id    text   NOT NULL,
    id          bigint GENERATED ALWAYS AS IDENTITY,
    recorded_at bigint NOT NULL,
    -- signed_in | sign_in_failed | signed_out
    kind        text   NOT NULL,
    user_id     text,
    client_id   text,
    session_id  text,
    ip          text,
    user_agent  text,
    detail      jsonb,

    PRIMARY KEY (tenant, realm_id, id),
    CONSTRAINT login_events_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

CREATE INDEX login_events_by_when ON login_events (tenant, realm_id, recorded_at DESC);
CREATE INDEX login_events_by_age ON login_events (recorded_at);

GRANT SELECT, INSERT, DELETE ON login_events TO saffui_app;

ALTER TABLE login_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_events FORCE ROW LEVEL SECURITY;
CREATE POLICY login_events_by_realm ON login_events
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
