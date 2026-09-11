-- A distributed source's fetch token, sealed under the realm's key: released
-- to the relying parties entitled to the claim is not readable by whoever
-- reads the table.
ALTER TABLE user_claim_sources
    ADD COLUMN sealed_token   bytea,
    ADD COLUMN sealed_version integer;

ALTER TABLE user_claim_sources
    ADD CONSTRAINT claim_source_token_is_whole
        CHECK ((sealed_token IS NULL) = (sealed_version IS NULL));

-- `endpoint_token` stays while N and N+1 run together: nothing writes it any
-- more, and a row written before is still released from it. Dropping it is a
-- later migration.
