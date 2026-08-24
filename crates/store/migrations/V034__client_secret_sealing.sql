-- Where a secret this deployment must read back is kept.

-- `client_secret_jwt` recomputes an HMAC over the secret, so it needs the
-- secret back. A hash cannot give it back, so a client registered for that
-- method keeps the secret sealed under the realm's key instead. Never both:
-- one storage form per client, chosen by how it authenticates.
ALTER TABLE clients
    ADD COLUMN sealed_secret  bytea,
    ADD COLUMN sealed_version integer;

ALTER TABLE clients
    ADD CONSTRAINT sealed_secret_is_whole
        CHECK ((sealed_secret IS NULL) = (sealed_version IS NULL));

-- Which algorithm this client's assertions must be signed with, when it
-- registered one. §9 lets a client name it; absent, any in the catalogue.
ALTER TABLE clients ADD COLUMN token_endpoint_auth_signing_alg text;
