-- One lodged data-subject request per row: the register the response
-- windows are counted against. The stage and what closed it are separate
-- columns so a refusal always carries its reason and a fulfilment its
-- outcome, never a bare closed flag.
CREATE TABLE subject_requests
(
    request_id         text   NOT NULL PRIMARY KEY,
    tenant             text   NOT NULL,
    realm_id           text   NOT NULL,
    -- The account the identifier resolved to, when one did. A request may
    -- be lodged against an address no account answers to, and the register
    -- answers the same either way.
    user_id            text,
    subject_identifier text   NOT NULL,
    kind               text   NOT NULL,
    stage              text   NOT NULL,
    outcome            text,
    reason             text,
    jurisdiction       text   NOT NULL,
    received_at        bigint NOT NULL,
    due_at             bigint NOT NULL,
    verified_at        bigint,
    closed_at          bigint
);

CREATE INDEX subject_requests_by_due ON subject_requests (tenant, realm_id, due_at);

ALTER TABLE subject_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY subject_request_isolation ON subject_requests
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON subject_requests TO saffui_app;
