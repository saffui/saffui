-- Whether the client asked the person to consent again, and the session the
-- request waits in for their answer. That session is written once.
ALTER TABLE authorization_requests
    ADD COLUMN consent_prompted boolean NOT NULL DEFAULT false,
    ADD COLUMN consent_session_id uuid;
ALTER TABLE authorization_requests ALTER COLUMN consent_prompted DROP DEFAULT;
GRANT UPDATE (consent_session_id) ON authorization_requests TO saffui_app;
