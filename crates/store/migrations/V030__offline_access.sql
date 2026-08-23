-- How long a grant that outlives its login may keep renewing. Separate from the
-- refresh lifespan, which an online client renews away before it ever reaches.
ALTER TABLE realms ADD COLUMN offline_session_lifespan integer;
ALTER TABLE realms ADD CONSTRAINT offline_session_lifespan_is_a_duration
    CHECK (offline_session_lifespan IS NULL OR offline_session_lifespan > 0);

-- The sweep must not take a login whose offline grant is still alive: the
-- client sessions cascade from it, so removing the row removes the grant.
CREATE INDEX client_sessions_offline ON client_sessions (tenant, realm_id, user_session_id)
    WHERE offline;
