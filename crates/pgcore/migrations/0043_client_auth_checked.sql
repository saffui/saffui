-- The clients written before the rules of how they prove themselves are
-- checked under a lock that blocks no write.
ALTER TABLE clients VALIDATE CONSTRAINT clients_proof_fits_method;
ALTER TABLE clients VALIDATE CONSTRAINT clients_assertion_algorithm_fits_method;
ALTER TABLE clients VALIDATE CONSTRAINT clients_jwks_bounded;
