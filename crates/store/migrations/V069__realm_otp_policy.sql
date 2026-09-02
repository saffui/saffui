-- What a newly enrolled authenticator app is set up with, and how much
-- clock drift a login tolerates. NULL keeps the built defaults.
ALTER TABLE realms ADD COLUMN otp_policy jsonb;
