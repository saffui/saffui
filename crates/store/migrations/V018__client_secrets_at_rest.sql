-- What a client authenticates with, no longer readable from the table. Hashed
-- rather than sealed: a sealed secret is recoverable by whoever holds both the
-- table and the wrapping key, which is usually one place.
ALTER TABLE clients ADD COLUMN secret_hash text;

-- `registration_token` gets no column here. Nothing mints one, so a hash of it
-- would be a column nobody fills, and the plaintext one beside it is dead the
-- same way.

-- `secret` stays while N and N+1 run together. Rows convert as they
-- authenticate; dropping it is a later migration.
