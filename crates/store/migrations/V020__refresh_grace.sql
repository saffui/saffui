-- The token a rotation replaced, and when. Without it a client that fired two
-- refreshes at once, or retried after a lost response, is indistinguishable from
-- an attacker replaying a stolen token, and reuse detection destroys its session.
ALTER TABLE client_sessions
    ADD COLUMN previous_refresh_token text,
    ADD COLUMN previous_rotated_at    timestamptz;
