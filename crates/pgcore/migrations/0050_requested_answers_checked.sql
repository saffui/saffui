-- The requests written before the rules of what they ask are checked under
-- a lock that blocks no write.
ALTER TABLE authorization_requests VALIDATE CONSTRAINT authorization_requests_response_type_known;
ALTER TABLE authorization_requests VALIDATE CONSTRAINT authorization_requests_response_mode_known;
ALTER TABLE authorization_requests VALIDATE CONSTRAINT authorization_requests_challenge_for_a_code;
