-- What a door has already seen and must not act on twice. One row per
-- remembered value, aged out by the sweep with everything else that expires.
CREATE TABLE replay_guard
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    purpose    text        NOT NULL,
    value_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, purpose, value_hash),
    CONSTRAINT replay_guard_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT purpose_not_blank CHECK (btrim(purpose) <> ''),
    CONSTRAINT value_hash_is_a_digest CHECK (octet_length(value_hash) = 32)
);

CREATE INDEX replay_guard_by_expiry ON replay_guard (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON replay_guard TO saffui_app;

ALTER TABLE replay_guard ENABLE ROW LEVEL SECURITY;
ALTER TABLE replay_guard FORCE ROW LEVEL SECURITY;
CREATE POLICY replay_guard_by_realm ON replay_guard
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
