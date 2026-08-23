-- The keys a client signs with, as the JWKS it registered. Inline and never a
-- URI: fetching one a caller names is a request this server makes on their
-- behalf, to wherever they point it.
ALTER TABLE clients ADD COLUMN jwks jsonb;
