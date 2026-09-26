-- How a realm asks a carrier, over CAMARA, whether the SIM behind a number
-- changed lately, before a code goes to that number.
--
-- CAMARA holds a SIM change to be personal data, so every check runs on a
-- token for that one number: a backchannel request naming it, answered at the
-- carrier's token endpoint, then the check itself. The realm proves itself to
-- the carrier with a key of its own, never with a shared secret.
CREATE TABLE realm_sim_swap
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    client_id       text        NOT NULL,
    -- The carrier's backchannel authentication and token endpoints, and the
    -- SIM Swap API's check operation, each named in full.
    authorize_url   text        NOT NULL,
    token_url       text        NOT NULL,
    check_url       text        NOT NULL,
    -- How far back a change counts, in hours, within what the API accepts.
    max_age_hours   integer     NOT NULL DEFAULT 72,
    -- What a code does when the carrier gives no answer.
    when_unanswered text        NOT NULL DEFAULT 'send',
    -- The key the realm signs its client assertions with, sealed under the
    -- realm's own key; the public half is what the carrier was given.
    kid             text        NOT NULL,
    sealed_key      bytea       NOT NULL,
    sealed_version  integer     NOT NULL,
    public_jwk      jsonb       NOT NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_sim_swap_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT sim_swap_client_named CHECK (btrim(client_id) <> ''),
    CONSTRAINT sim_swap_urls_are_http CHECK (
        (authorize_url LIKE 'https://%' OR authorize_url LIKE 'http://%')
        AND (token_url LIKE 'https://%' OR token_url LIKE 'http://%')
        AND (check_url LIKE 'https://%' OR check_url LIKE 'http://%')
    ),
    CONSTRAINT sim_swap_age_in_range CHECK (max_age_hours BETWEEN 1 AND 2400),
    CONSTRAINT sim_swap_unanswered_known CHECK (when_unanswered IN ('send', 'hold'))
);

ALTER TABLE realm_sim_swap ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_sim_swap FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_sim_swap_isolation ON realm_sim_swap
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_sim_swap TO saffui_app;
