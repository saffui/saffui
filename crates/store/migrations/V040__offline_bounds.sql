ALTER TABLE realms
    -- Zero means none, which is what a sliding window alone gives: a device
    -- renewing daily holds its grant forever.
    ADD COLUMN offline_session_max_lifespan integer NOT NULL DEFAULT 0,
    -- Each grant is a credential that outlives the browser it was made in, and
    -- nothing here ever counted them.
    ADD COLUMN max_offline_grants           integer NOT NULL DEFAULT 0;

ALTER TABLE realms
    ADD CONSTRAINT offline_bounds_are_not_negative CHECK (
        offline_session_max_lifespan >= 0 AND max_offline_grants >= 0
    );

CREATE INDEX client_sessions_offline_by_age
    ON client_sessions (tenant, realm_id, user_id, started_at)
    WHERE offline;
