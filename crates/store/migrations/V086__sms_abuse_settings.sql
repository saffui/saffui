-- The realm's own brakes on texting, replacing the built constants where
-- set: how many texts a day, how many to one number in one hour, and which
-- number ranges are never texted at all. NULL keeps the built default.
ALTER TABLE realms ADD COLUMN sms_daily_cap integer;
ALTER TABLE realms ADD COLUMN sms_per_number_cap integer;
ALTER TABLE realms ADD COLUMN sms_blocked_prefixes text[];
-- The realm's rewording of its texts: kind, then tongue, then the one body.
ALTER TABLE realms ADD COLUMN sms_templates jsonb;

-- What went to one number in one hour, counted where the code is minted:
-- a number is a destination somebody else pays to receive at, and a burst
-- at one number is the shape artificially inflated traffic takes.
CREATE TABLE sms_velocity
(
    tenant    text        NOT NULL,
    realm_id  text        NOT NULL,
    recipient text        NOT NULL,
    hour      timestamptz NOT NULL,
    sent      integer     NOT NULL DEFAULT 0,

    PRIMARY KEY (tenant, realm_id, recipient, hour),
    CONSTRAINT sms_velocity_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

ALTER TABLE sms_velocity ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_velocity FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_velocity_isolation ON sms_velocity
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON sms_velocity TO saffui_app;
