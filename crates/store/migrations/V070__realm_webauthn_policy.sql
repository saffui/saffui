-- How this realm presents itself to a browser's key ceremony. NULL keeps
-- the built behaviour: the origin's host as the shown name, no subdomains.
ALTER TABLE realms ADD COLUMN webauthn_policy jsonb;
