-- A security key proves the person in place of a code: `pop`, the holding of
-- a key, since nothing attests the key is hardware.

ALTER TABLE sessions DROP CONSTRAINT sessions_methods_known;
ALTER TABLE sessions ADD CONSTRAINT sessions_methods_known
    CHECK (methods <@ ARRAY['pwd', 'otp', 'pop'] AND cardinality(methods) >= 1);

-- The challenge the keys of a person were given for a pending request: what
-- judges the answer, and what the page hands to the browser. Written with
-- the first factor, never before it.
ALTER TABLE authorization_requests ADD COLUMN key_proof_state bytea;
ALTER TABLE authorization_requests ADD COLUMN key_proof_options jsonb;
ALTER TABLE authorization_requests ADD CONSTRAINT authorization_requests_key_proof_whole
    CHECK (
        (key_proof_state IS NULL) = (key_proof_options IS NULL)
        AND (key_proof_state IS NULL OR first_factor_person_id IS NOT NULL)
    );
GRANT UPDATE (key_proof_state, key_proof_options) ON authorization_requests TO saffui_app;
