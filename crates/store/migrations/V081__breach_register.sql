-- One recorded breach per row: the register a notification clock hangs on.
-- The jurisdiction rides beside the record because the filing draft is
-- shaped for it; the model itself settles notify_by at discovery.
CREATE TABLE breaches
(
    breach_id         text   NOT NULL PRIMARY KEY,
    tenant            text   NOT NULL,
    realm_id          text   NOT NULL,
    description       text   NOT NULL,
    data_categories   text[] NOT NULL DEFAULT '{}',
    subjects_affected bigint,
    severity          text   NOT NULL,
    status            text   NOT NULL,
    jurisdiction      text   NOT NULL,
    occurred_at       bigint,
    discovered_at     bigint NOT NULL,
    notify_by         bigint,
    notified_at       bigint,
    notified_to       text,
    filed_by          text
);

CREATE INDEX breaches_by_clock ON breaches (tenant, realm_id, notify_by);

ALTER TABLE breaches ENABLE ROW LEVEL SECURITY;
ALTER TABLE breaches FORCE ROW LEVEL SECURITY;
CREATE POLICY breach_isolation ON breaches
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON breaches TO saffui_app;
