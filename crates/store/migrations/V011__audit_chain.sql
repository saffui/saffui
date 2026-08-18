-- The record an auditor is shown, and what makes it worth showing.
--
-- Every entry names the hash of the one before it, so the entries form a chain:
-- changing any one of them changes its hash, which breaks every entry after it.
-- What that buys is narrow and worth stating. It does not stop someone with
-- write access from rewriting the whole chain from a point onwards. It stops
-- them from rewriting one entry and leaving the rest, and combined with an
-- anchor published somewhere they do not control, it bounds how far back a
-- rewrite can reach without being visible.

-- Where each realm's chain currently ends.
--
-- Its own table rather than a query over the entries, because it is the
-- serialisation point: an append takes this row for update, and a second append
-- waits rather than reading the same tail and forking the chain.
--
-- An advisory lock would not do. It is not replicated, so a promoted replica
-- can hand the same lock to a second writer, and two writers on one chain is
-- the failure this table exists to prevent.
CREATE TABLE audit_chain_heads
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    -- The sequence number of the last entry, zero before the first.
    seq        bigint      NOT NULL DEFAULT 0,
    -- The hash of the last entry, or the genesis value before the first.
    head_hash  bytea       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT audit_chain_heads_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT head_hash_is_a_sha256 CHECK (octet_length(head_hash) = 32),
    CONSTRAINT seq_does_not_go_backwards CHECK (seq >= 0)
);

CREATE TABLE audit_events
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    -- Dense and per realm. A gap is not an ordering detail, it is an entry
    -- somebody removed.
    seq         bigint      NOT NULL,

    -- What happened, as the bytes that were hashed. Stored as jsonb so it can
    -- be read, and hashed as its canonical text so two readers agree.
    envelope    jsonb       NOT NULL,
    prev_hash   bytea       NOT NULL,
    hash        bytea       NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),

    -- Queryable columns are generated from the envelope rather than written
    -- beside it. Written beside it, they are a second copy of the truth that no
    -- constraint keeps in step, and an entry could then say one thing to a
    -- reader and another to the chain.
    kind        text        GENERATED ALWAYS AS (envelope ->> 'kind') STORED,
    actor       text        GENERATED ALWAYS AS (envelope ->> 'actor') STORED,
    occurred_at timestamptz GENERATED ALWAYS AS
                    (to_timestamp((envelope ->> 'occurred_at')::double precision)) STORED,

    PRIMARY KEY (tenant, realm_id, seq),
    CONSTRAINT audit_events_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT audit_hash_is_a_sha256 CHECK (octet_length(hash) = 32),
    CONSTRAINT audit_prev_hash_is_a_sha256 CHECK (octet_length(prev_hash) = 32),
    CONSTRAINT audit_seq_is_positive CHECK (seq > 0),
    -- The kind is part of what is hashed, so an entry without one is an entry
    -- whose chain position says nothing about what it records.
    CONSTRAINT an_entry_says_what_it_is CHECK (envelope ? 'kind' AND envelope ? 'occurred_at')
);

CREATE INDEX audit_events_by_time ON audit_events (tenant, realm_id, occurred_at DESC);
CREATE INDEX audit_events_by_kind ON audit_events (tenant, realm_id, kind, seq DESC);

-- A head published where whoever holds write access does not decide.
--
-- The chain proves internal consistency. It cannot prove that the whole of it
-- was not rewritten, and this is what bounds that: an entry at or before an
-- anchored sequence cannot be changed without contradicting something already
-- published elsewhere.
CREATE TABLE audit_anchors
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    seq        bigint      NOT NULL,
    head_hash  bytea       NOT NULL,
    -- Where it was published, and what came back.
    witness    text        NOT NULL,
    receipt    text        NOT NULL,
    anchored_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, seq),
    CONSTRAINT audit_anchors_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT anchor_hash_is_a_sha256 CHECK (octet_length(head_hash) = 32),
    CONSTRAINT anchor_witness_not_blank CHECK (btrim(witness) <> '')
);

-- The only writer.
--
-- The application is granted execute on this and no insert on the entries, so
-- an entry cannot be written except through the code that links it. The
-- function runs as its owner for that reason, and pins its search path because
-- it does.
--
-- The preimage is the previous hash, then the sequence as eight big endian
-- bytes, then the canonical text of the envelope. The sequence is inside the
-- hash so an entry cannot be moved to another position and still verify.
CREATE OR REPLACE FUNCTION audit_append(entry jsonb)
    RETURNS TABLE (seq bigint, hash bytea)
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, public
AS $$
DECLARE
    current_tenant text := current_setting('saffui.current_tenant', true);
    current_realm  text := current_setting('saffui.current_realm', true);
    head           audit_chain_heads%ROWTYPE;
    next_seq       bigint;
    next_hash      bytea;
BEGIN
    IF current_tenant IS NULL OR current_realm IS NULL THEN
        RAISE EXCEPTION 'no realm is in scope';
    END IF;

    -- Taken for update, which is what serialises two appends. The second waits
    -- here, reads the row the first wrote, and chains onto it.
    SELECT * INTO head FROM audit_chain_heads
        WHERE tenant = current_tenant AND realm_id = current_realm
        FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'the realm has no chain';
    END IF;

    next_seq := head.seq + 1;
    next_hash := sha256(head.head_hash || int8send(next_seq) || convert_to(entry::text, 'UTF8'));

    INSERT INTO audit_events (tenant, realm_id, seq, envelope, prev_hash, hash)
        VALUES (current_tenant, current_realm, next_seq, entry, head.head_hash, next_hash);

    UPDATE audit_chain_heads
        SET seq = next_seq, head_hash = next_hash, updated_at = now()
        WHERE tenant = current_tenant AND realm_id = current_realm;

    seq := next_seq;
    hash := next_hash;
    RETURN NEXT;
END
$$;

ALTER FUNCTION audit_append(jsonb) OWNER TO saffui_resolver;
REVOKE ALL ON FUNCTION audit_append(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_append(jsonb) TO saffui_app;
GRANT SELECT, INSERT, UPDATE ON audit_chain_heads TO saffui_resolver;
GRANT INSERT ON audit_events TO saffui_resolver;

ALTER TABLE audit_chain_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_chain_head_isolation ON audit_chain_heads
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_isolation ON audit_events
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_anchor_isolation ON audit_anchors
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

-- The application reads the chain and anchors it. It does not write entries:
-- that is the function's, and only the function's.
GRANT SELECT ON audit_events TO saffui_app;
GRANT SELECT, INSERT ON audit_chain_heads TO saffui_app;
GRANT SELECT, INSERT ON audit_anchors TO saffui_app;
