-- Where a realm's data encryption key lives, wrapped.
--
-- The key that encrypts a realm's reversible secrets is itself encrypted, by a
-- key the deployment holds and this database never sees. What is stored here is
-- the wrapped form, one row per generation.
--
-- The stored key is deliberately not derived from the wrapping key. Deriving it
-- would tie the two together in three ways that all cost more than the row this
-- table saves: rotating the outer key would mean re-encrypting every ciphertext
-- rather than rewriting one row per realm, destroying one realm's key would be
-- impossible without destroying every realm's, and the outer key could not stay
-- inside a token that never exports it.

-- A generation is the one that new writes use, or one that only still opens
-- what it sealed.
CREATE TYPE dek_status AS ENUM ('active', 'retired');

CREATE TABLE realm_deks
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    -- Stamped into the header of every blob this generation seals, which is how
    -- a retired generation keeps opening its own ciphertext.
    version     integer     NOT NULL,
    wrapped_dek bytea       NOT NULL,
    -- Which wrapping key this row is wrapped under, so a rewrap can find the
    -- rows a retired one still holds without unwrapping anything.
    kek_id      text        NOT NULL,
    status      dek_status  NOT NULL DEFAULT 'active',

    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Set when the generation stopped taking writes, and only then. A retired
    -- generation with no time says nothing about when its ciphertext was last
    -- written, and an active one with a time is a row that disagrees with
    -- itself.
    retired_at  timestamptz,

    PRIMARY KEY (tenant, realm_id, version),
    CONSTRAINT realm_deks_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT a_retired_generation_says_when
        CHECK ((status = 'retired') = (retired_at IS NOT NULL)),
    CONSTRAINT dek_version_is_positive CHECK (version > 0),
    CONSTRAINT wrapped_dek_is_not_empty CHECK (octet_length(wrapped_dek) > 0)
);

-- At most one generation takes writes.
--
-- Two active generations would have writes sealed under whichever the reader
-- found first, and the other's ciphertext would then be opened by a key nobody
-- reaches for.
CREATE UNIQUE INDEX one_active_generation_per_realm
    ON realm_deks (tenant, realm_id) WHERE status = 'active';

-- Rotating the wrapping key sweeps every realm, so this one is not scoped to a
-- realm the way the rest of the schema is.
CREATE INDEX realm_deks_by_kek ON realm_deks (kek_id);

ALTER TABLE realm_deks ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_deks FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_dek_isolation ON realm_deks
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_deks TO saffui_app;
