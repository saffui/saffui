-- The login a one-time token was minted for.
--
-- A sign-in link that any browser could follow is one an attacker sends to a
-- person so that their own half-finished login is the one that completes. Bound
-- here, the link only finishes the login it was asked for.
ALTER TABLE one_time_tokens ADD COLUMN bound_to text;
