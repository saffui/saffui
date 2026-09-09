-- What outlives a realm.
--
-- A realm's own chain is keyed to the realm and cascades with it, so the one
-- entry an auditor most wants after a deletion is the one entry that cannot
-- survive it. Everything else in this schema is keyed to a realm; `tenants`
-- was the only table above them, and nothing recorded a realm coming or going.
--
-- This chain is the tenant's. It records what happens *to* realms rather than
-- inside them, and it is deliberately narrow: a birth, a death, an import.
-- Anything a realm can record for itself belongs in the realm's own chain,
-- where the people who administer that realm can read it.
--
-- The application may append and may not read. A tenant-wide reader would let
-- an administrator of one realm learn which realms neighbour it, which is
-- exactly the enumeration the admin plane refuses by answering a foreign realm
-- and a missing one identically. Reading this is the operator's, from the host,
-- with the owner's credentials.

CREATE TABLE tenant_chain_heads
(
    tenant     text        NOT NULL,
    seq        bigint      NOT NULL DEFAULT 0,
    head_hash  bytea       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant),
    CONSTRAINT tenant_chain_heads_tenant FOREIGN KEY (tenant)
        REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    CONSTRAINT tenant_head_hash_is_a_sha256 CHECK (octet_length(head_hash) = 32),
    CONSTRAINT tenant_seq_does_not_go_backwards CHECK (seq >= 0)
);

CREATE TABLE tenant_events
(
    tenant      text        NOT NULL,
    seq         bigint      NOT NULL,

    envelope    jsonb       NOT NULL,
    prev_hash   bytea       NOT NULL,
    hash        bytea       NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),

    kind        text        GENERATED ALWAYS AS (envelope ->> 'kind') STORED,
    actor       text        GENERATED ALWAYS AS (envelope ->> 'actor') STORED,
    -- The realm the entry is about, which is the whole point of the table: it
    -- is a name, not a reference, because the row it named is gone.
    realm       text        GENERATED ALWAYS AS (envelope ->> 'realm') STORED,
    occurred_at timestamptz GENERATED ALWAYS AS
                    (to_timestamp((envelope ->> 'occurred_at')::double precision)) STORED,

    PRIMARY KEY (tenant, seq),
    CONSTRAINT tenant_events_tenant FOREIGN KEY (tenant)
        REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    CONSTRAINT tenant_hash_is_a_sha256 CHECK (octet_length(hash) = 32),
    CONSTRAINT tenant_prev_hash_is_a_sha256 CHECK (octet_length(prev_hash) = 32),
    CONSTRAINT tenant_seq_is_positive CHECK (seq > 0),
    CONSTRAINT a_tenant_entry_says_what_it_is CHECK (
        envelope ? 'kind' AND envelope ? 'occurred_at' AND envelope ? 'realm')
);

CREATE INDEX tenant_events_by_time ON tenant_events (tenant, occurred_at DESC);
CREATE INDEX tenant_events_by_realm ON tenant_events (tenant, realm, seq DESC);

-- The only writer, and it starts the chain rather than refusing when none
-- exists. A realm's chain is started by the realm's own provisioning; a
-- tenant's has no such moment, and the first realm to come or go is as good a
-- one as any.
CREATE OR REPLACE FUNCTION tenant_append(entry jsonb)
    RETURNS TABLE (seq bigint, hash bytea)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    current_tenant text := current_setting('saffui.current_tenant', true);
    head           tenant_chain_heads%ROWTYPE;
    next_seq       bigint;
    next_hash      bytea;
BEGIN
    IF current_tenant IS NULL THEN
        RAISE EXCEPTION 'no tenant is in scope';
    END IF;

    INSERT INTO tenant_chain_heads (tenant, head_hash)
        VALUES (current_tenant, sha256(convert_to(current_tenant, 'UTF8')))
        ON CONFLICT (tenant) DO NOTHING;

    SELECT * INTO head FROM tenant_chain_heads
        WHERE tenant = current_tenant
        FOR UPDATE;

    next_seq := head.seq + 1;
    next_hash := sha256(head.head_hash || int8send(next_seq) || convert_to(entry::text, 'UTF8'));

    INSERT INTO tenant_events (tenant, seq, envelope, prev_hash, hash)
        VALUES (current_tenant, next_seq, entry, head.head_hash, next_hash);

    UPDATE tenant_chain_heads
        SET seq = next_seq, head_hash = next_hash, updated_at = now()
        WHERE tenant = current_tenant;

    seq := next_seq;
    hash := next_hash;
    RETURN NEXT;
END
$$;

ALTER FUNCTION tenant_append(jsonb) OWNER TO saffui_resolver;
REVOKE ALL ON FUNCTION tenant_append(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_append(jsonb) TO saffui_app;
GRANT SELECT, INSERT, UPDATE ON tenant_chain_heads TO saffui_resolver;
GRANT INSERT ON tenant_events TO saffui_resolver;

ALTER TABLE tenant_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_chain_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_chain_head_isolation ON tenant_chain_heads
    USING      (tenant = current_setting('saffui.current_tenant', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true));

ALTER TABLE tenant_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_event_isolation ON tenant_events
    USING      (tenant = current_setting('saffui.current_tenant', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true));

-- No SELECT for saffui_app, on either table. That absence is the design: the
-- served plane writes what happened to a realm and cannot read what happened
-- to its neighbours.
