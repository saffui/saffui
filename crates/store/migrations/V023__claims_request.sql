-- What a client asked for by name, OIDC Core §5.5, carried from the request to
-- the tokens it produces. On the code until it is redeemed; on the client
-- session after, where the userinfo endpoint and every renewal read it.
ALTER TABLE oidc_auth_codes
    ADD COLUMN claims jsonb,
    ADD CONSTRAINT claims_are_a_map CHECK (claims IS NULL OR jsonb_typeof(claims) = 'object');
ALTER TABLE client_sessions
    ADD COLUMN requested_claims jsonb,
    ADD CONSTRAINT requested_claims_are_a_map
        CHECK (requested_claims IS NULL OR jsonb_typeof(requested_claims) = 'object');
