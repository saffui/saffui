-- The organization's human name, frozen beside org_id when the code is
-- minted, so the claims a redemption stamps do not re-read a row that may
-- have been renamed or removed in between.
ALTER TABLE oidc_auth_codes
    ADD COLUMN org_name text;
