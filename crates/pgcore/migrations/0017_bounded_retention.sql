-- Retention removes in short batches, each found by an index: a pass never
-- holds a lock for the time of a whole table. Sessions that expired go,
-- and their refresh tokens with them.

CREATE INDEX authorization_requests_expiry ON authorization_requests (expires_at);
CREATE INDEX authorization_codes_expiry ON authorization_codes (expires_at);
CREATE INDEX refresh_tokens_expiry ON refresh_tokens (expires_at);
CREATE INDEX sessions_expiry ON sessions (expires_at);
CREATE INDEX login_failures_bucket ON login_failures (bucket_start);

GRANT DELETE ON refresh_tokens, sessions TO saffui_maintenance;
