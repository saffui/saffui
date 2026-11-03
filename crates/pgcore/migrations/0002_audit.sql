-- The audit chain: one per realm. An event is linked to the one before by a
-- hash, and one function is the only writer. Whether two appends can fork a
-- chain is decided here, by a row lock, never by which node is the leader.

-- Both read the stored bytes of an envelope. They are declared immutable so
-- that the columns below can be generated from them: the bytes are UTF-8 by
-- construction and every instant is written with its offset.
CREATE FUNCTION saffui_read_envelope(envelope bytea) RETURNS jsonb
    LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT convert_from(envelope, 'UTF8')::jsonb $$;

CREATE FUNCTION saffui_read_instant(written text) RETURNS timestamptz
    LANGUAGE sql IMMUTABLE STRICT
    AS $$ SELECT written::timestamptz $$;

CREATE TABLE audit_chain_heads (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    seq bigint NOT NULL,
    hash bytea NOT NULL,
    PRIMARY KEY (tenant_id, realm_id),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

CREATE TABLE audit_events (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    seq bigint NOT NULL,
    prev_hash bytea NOT NULL,
    hash bytea NOT NULL,
    -- The bytes that were hashed, kept as they were hashed. The columns
    -- queries filter on are generated from them, so they cannot drift.
    envelope bytea NOT NULL,
    event_id uuid NOT NULL
        GENERATED ALWAYS AS ((saffui_read_envelope(envelope) ->> 'id')::uuid) STORED,
    kind text NOT NULL
        GENERATED ALWAYS AS (saffui_read_envelope(envelope) ->> 'kind') STORED,
    occurred_at timestamptz NOT NULL
        GENERATED ALWAYS AS (saffui_read_instant(saffui_read_envelope(envelope) ->> 'ts')) STORED,
    PRIMARY KEY (tenant_id, realm_id, seq),
    FOREIGN KEY (tenant_id, realm_id) REFERENCES realms
);

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_chain_heads_scope ON audit_chain_heads
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_scope ON audit_events
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- The only writer. It runs as the owner of the tables, who is bound by the
-- policies above like anyone: it appends to the chain of the scope and to
-- no other.
CREATE FUNCTION saffui_append_audit_event(p_envelope bytea)
    RETURNS TABLE (new_seq bigint, new_hash bytea)
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, public, pg_temp
    AS $$
DECLARE
    v_tenant uuid := public.saffui_current_tenant();
    v_realm uuid := public.saffui_current_realm();
    v_read jsonb := public.saffui_read_envelope(p_envelope);
    v_previous bytea;
    v_seq bigint;
    v_hash bytea;
BEGIN
    IF v_tenant IS NULL OR v_realm IS NULL THEN
        RAISE EXCEPTION 'an audit event needs a scope' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF (v_read ->> 'tenant_id')::uuid IS DISTINCT FROM v_tenant
        OR (v_read ->> 'realm_id')::uuid IS DISTINCT FROM v_realm THEN
        RAISE EXCEPTION 'an audit event names another scope' USING ERRCODE = 'insufficient_privilege';
    END IF;

    INSERT INTO public.audit_chain_heads (tenant_id, realm_id, seq, hash)
    VALUES (v_tenant, v_realm, 0, decode(repeat('00', 32), 'hex'))
    ON CONFLICT DO NOTHING;

    -- The row lock is the whole guarantee: a second append waits here until
    -- the first has committed, then links to what the first wrote.
    SELECT h.seq, h.hash INTO v_seq, v_previous
    FROM public.audit_chain_heads h
    WHERE h.tenant_id = v_tenant AND h.realm_id = v_realm
    FOR UPDATE;

    v_seq := v_seq + 1;
    v_hash := sha256(v_previous || int8send(v_seq) || p_envelope);

    INSERT INTO public.audit_events (tenant_id, realm_id, seq, prev_hash, hash, envelope)
    VALUES (v_tenant, v_realm, v_seq, v_previous, v_hash, p_envelope);

    UPDATE public.audit_chain_heads h
    SET seq = v_seq, hash = v_hash
    WHERE h.tenant_id = v_tenant AND h.realm_id = v_realm;

    RETURN QUERY SELECT v_seq, v_hash;
END
$$;

REVOKE ALL ON FUNCTION saffui_append_audit_event(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION saffui_append_audit_event(bytea) TO saffui_app;
GRANT EXECUTE ON FUNCTION saffui_read_envelope(bytea), saffui_read_instant(text)
    TO saffui_app, saffui_maintenance;

-- The serving role reads the chain and writes it through the function only.
GRANT SELECT ON audit_chain_heads, audit_events TO saffui_app, saffui_maintenance;

-- The functions of 0001 that run as the owner look in the temporary schema
-- last, as the one above does: a table a session creates there never stands
-- in for one of public.
ALTER FUNCTION saffui_mirror_realm() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION saffui_locate_realm(text) SET search_path = pg_catalog, public, pg_temp;

-- No store changes a realm yet: the serving role writes none.
REVOKE UPDATE ON realms FROM saffui_app;
