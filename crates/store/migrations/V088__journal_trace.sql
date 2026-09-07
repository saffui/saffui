-- The trace a request rode, projected out of the hashed envelope the same
-- way kind and actor already are: a forensic row becomes joinable to the
-- distributed trace without touching what the chain hashes. Rows written
-- by requests that carried no trace project NULL and keep their shape.
ALTER TABLE audit_events
    ADD COLUMN trace_id text GENERATED ALWAYS AS (envelope ->> 'trace_id') STORED;

-- Partial: the lookup is always "this one trace", and rows without one
-- would only widen the index.
CREATE INDEX audit_events_by_trace ON audit_events (tenant, realm_id, trace_id)
    WHERE trace_id IS NOT NULL;
