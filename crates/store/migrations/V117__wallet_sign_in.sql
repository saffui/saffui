-- A person signing in with their wallet, on the device they sign in from. The
-- request names nobody until its answer does, and the code the wallet carries
-- back to the browser is kept as its digest, and spent once.
ALTER TABLE presentation_requests
    DROP CONSTRAINT presentation_purpose_known,
    DROP CONSTRAINT presentation_purpose_bound,
    ADD COLUMN response_code_digest text,
    ADD COLUMN redeemed_at          timestamptz,
    ADD CONSTRAINT presentation_purpose_known
        CHECK (purpose IS NULL OR purpose IN ('link', 'factor', 'sign-in')),
    ADD CONSTRAINT presentation_purpose_bound
        CHECK ((purpose IS NULL) = (login_session IS NULL)
           AND (user_id IS NULL) = (purpose IS NULL OR purpose = 'sign-in')),
    ADD CONSTRAINT presentation_response_code_for_sign_in
        CHECK (response_code_digest IS NULL
           OR (purpose = 'sign-in' AND response_code_digest ~ '^[0-9a-f]{64}$')),
    ADD CONSTRAINT presentation_redeemed_by_code
        CHECK (redeemed_at IS NULL OR response_code_digest IS NOT NULL);
