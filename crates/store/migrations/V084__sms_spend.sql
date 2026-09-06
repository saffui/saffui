-- What a realm spent on texts today.
--
-- One row per realm per day, counted where the code is minted: an OTP send
-- is a billable action an attacker can trigger, so the day's total is the
-- realm's brake, and a counter kept in memory would forget it at restart.
CREATE TABLE sms_spend
(
    tenant   text    NOT NULL,
    realm_id text    NOT NULL,
    day      date    NOT NULL,
    sent     integer NOT NULL DEFAULT 0,

    PRIMARY KEY (tenant, realm_id, day),
    CONSTRAINT sms_spend_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE
);

ALTER TABLE sms_spend ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_spend FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_spend_isolation ON sms_spend
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON sms_spend TO saffui_app;
