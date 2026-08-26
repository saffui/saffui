-- The proofs a caller has already spent.
--
-- A DPoP proof carries an identifier its holder drew, and RFC 9449 §11.1 asks
-- that one be accepted once: a proof read off the wire and sent again is the
-- replay the binding exists to stop. Kept only as long as a proof may still be
-- presented, which is the window `iat` is judged in and nothing more.
CREATE TABLE dpop_proofs
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    -- Hashed, like every other identifier a caller chose: the row only has to
    -- answer whether one was seen.
    proof_hash text        NOT NULL,
    expires_at timestamptz NOT NULL,

    PRIMARY KEY (tenant, realm_id, proof_hash)
);

CREATE INDEX dpop_proofs_expiry ON dpop_proofs (expires_at);

ALTER TABLE dpop_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE dpop_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY dpop_proofs_isolation ON dpop_proofs
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON dpop_proofs TO saffui_app;
