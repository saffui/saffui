-- One client session per login and client. Two rows for one pair make "the
-- session's current refresh token" ambiguous, so renewing with the newer token
-- can find the older row and read a legitimate renewal as a replay.
CREATE UNIQUE INDEX client_sessions_one_per_client
    ON client_sessions (tenant, realm_id, user_session_id, client_id);
