-- A key of a realm signs until another of its algorithm takes its place.
-- Retired, it verifies what it signed until an administrator removes it, and
-- nothing else changes it. A key made before signs, as it did. The rules bind
-- every row written from now on, and the next migration checks those already
-- there. Each migration of the keys blocks writes to one table that was
-- served before it: the clients come in the next.
ALTER TABLE signing_keys ADD COLUMN status text NOT NULL DEFAULT 'active';
ALTER TABLE signing_keys ALTER COLUMN status DROP DEFAULT;
ALTER TABLE signing_keys
    ADD CONSTRAINT signing_keys_status_known CHECK (status IN ('active', 'retired')) NOT VALID,
    DROP CONSTRAINT signing_keys_algorithm_check,
    ADD CONSTRAINT signing_keys_algorithm_check
        CHECK (algorithm IN ('ES256', 'ES384', 'RS256', 'PS256', 'EdDSA')) NOT VALID;

-- One key of an algorithm signs, whatever two rotations do at once.
CREATE UNIQUE INDEX signing_keys_one_active ON signing_keys (tenant_id, realm_id, algorithm)
    WHERE status = 'active';

-- The serving role retires an active key and removes a retired one, and
-- nothing more: the private half, the identifier and the algorithm of a key
-- stay as they were written.
GRANT UPDATE (status), DELETE ON signing_keys TO saffui_app;
CREATE POLICY signing_keys_retire_only ON signing_keys AS RESTRICTIVE FOR UPDATE TO saffui_app
    USING (status = 'active')
    WITH CHECK (status = 'retired');
CREATE POLICY signing_keys_remove_retired ON signing_keys AS RESTRICTIVE FOR DELETE TO saffui_app
    USING (status = 'retired');

-- Two rotations of a realm take turns under the lock of its data key. A row
-- lock asks for the right to update one column. Row security keeps that
-- column where it is: no update can move the row.
GRANT UPDATE (realm_id) ON realm_data_keys TO saffui_app;
