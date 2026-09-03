-- CIBA pacing, the realm's to tune: how long a backchannel request lives,
-- and how often the client may poll. NULL keeps the built defaults.
ALTER TABLE realms ADD COLUMN ciba_expiry integer;
ALTER TABLE realms ADD COLUMN ciba_interval integer;
