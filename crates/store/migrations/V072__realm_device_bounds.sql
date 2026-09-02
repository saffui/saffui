-- RFC 8628 pacing, the realm's to tune: how long a device code lives, and
-- how often the device may poll. NULL keeps the built defaults.
ALTER TABLE realms ADD COLUMN device_code_lifespan integer;
ALTER TABLE realms ADD COLUMN device_poll_interval integer;
