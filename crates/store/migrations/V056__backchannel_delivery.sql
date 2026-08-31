-- Ping delivery: the client is told when the person has decided, at the
-- endpoint it registered, bearing the token it handed in. The request id is
-- sealed rather than kept clear, since the ping must speak it back.
ALTER TABLE backchannel_requests
    ADD COLUMN delivery           text  NOT NULL DEFAULT 'poll',
    ADD COLUMN notification_token text,
    ADD COLUMN sealed_request     bytea;
