-- Decisions found by the trace they were made in, the way the journal already
-- is (V088): what joins a decision to the writes and requests around it.
CREATE INDEX authz_decisions_by_trace ON authz_decisions (tenant, realm_id, trace_id)
    WHERE trace_id IS NOT NULL;
