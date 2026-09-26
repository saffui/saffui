-- The authorities a realm trusts, deposited by its administrators.
--
-- A credential a wallet presents is trusted through the chain in its token,
-- walked up to one of these. What an authority is trusted for is part of the
-- row: an authority deposited for the issuers of credentials vouches for
-- nothing else, so a wallet provider's root can never stand in for one.
CREATE TABLE realm_trust_anchors
(
    tenant          text        NOT NULL,
    realm_id        text        NOT NULL,
    anchor_id       text        NOT NULL,
    role            text        NOT NULL,
    -- The certificate as deposited, DER.
    certificate     bytea       NOT NULL,
    -- SHA-256 of the DER, lowercase hex: one deposit per certificate and role.
    fingerprint     text        NOT NULL,
    -- The subject, as this build renders a distinguished name.
    subject         text        NOT NULL,
    -- The subject key identifier, base64url, where the certificate states one.
    key_identifier  text,
    not_after       timestamptz NOT NULL,
    created_by      text        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, anchor_id),
    CONSTRAINT realm_trust_anchors_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT trust_anchor_deposited_once UNIQUE (tenant, realm_id, role, fingerprint),
    CONSTRAINT trust_anchor_role_known CHECK (role IN ('credential-issuer')),
    CONSTRAINT trust_anchor_certificate_bounded
        CHECK (octet_length(certificate) BETWEEN 1 AND 16384),
    CONSTRAINT trust_anchor_fingerprint_shape CHECK (fingerprint ~ '^[0-9a-f]{64}$')
);

ALTER TABLE realm_trust_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_trust_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_trust_anchors_isolation ON realm_trust_anchors
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, DELETE ON realm_trust_anchors TO saffui_app;
