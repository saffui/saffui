-- RFC 9449 section 10.1: an authorization request may name, ahead of time,
-- the thumbprint of the key its token request will prove. The code carries
-- it the way it carries the PKCE challenge, and the token endpoint measures
-- the proof against it.
ALTER TABLE oidc_auth_codes ADD COLUMN dpop_jkt TEXT;
