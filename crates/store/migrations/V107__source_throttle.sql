-- Failed attempts counted per address, and per address and typed name, on
-- every door that verifies a password. On in a stock realm, unlike the
-- lockout per person: a count per address shuts nobody out but that address.
ALTER TABLE realms ADD COLUMN source_throttled boolean NOT NULL DEFAULT true;
ALTER TABLE realms ADD COLUMN source_max_failures integer NOT NULL DEFAULT 100;
ALTER TABLE realms ADD COLUMN source_name_max_failures integer NOT NULL DEFAULT 10;
ALTER TABLE realms ADD COLUMN source_window_seconds integer NOT NULL DEFAULT 900;
ALTER TABLE realms ADD CONSTRAINT source_throttle_bounds CHECK (
    source_max_failures BETWEEN 1 AND 100000
    AND source_name_max_failures BETWEEN 1 AND 10000
    AND source_window_seconds BETWEEN 60 AND 86400
);

-- One address's failures, a minute at a time. `named` is empty for the
-- address's own count, and otherwise the digest of the name typed with it:
-- a name box sometimes receives a password, so no name is kept as typed.
CREATE TABLE source_failures
(
    tenant   text    NOT NULL,
    realm_id text    NOT NULL,
    source   text    NOT NULL,
    named    text    NOT NULL,
    minute   bigint  NOT NULL,
    failures integer NOT NULL DEFAULT 0,

    PRIMARY KEY (tenant, realm_id, source, named, minute),
    CONSTRAINT source_failures_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

ALTER TABLE source_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY source_failures_isolation ON source_failures
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON source_failures TO saffui_app;
