-- One key signs per realm, per use and per algorithm. Discovery §3 requires
-- RS256 of every provider, and a realm that also signs with ES256 needs both
-- active at once; two keys of one algorithm would still leave a rotation
-- unobservable, so that stays refused.
DROP INDEX one_active_key_per_use;
CREATE UNIQUE INDEX one_active_key_per_algorithm
    ON realm_signing_keys (tenant, realm_id, key_use, algorithm) WHERE status = 'active';
