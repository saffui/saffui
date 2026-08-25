ALTER TABLE realms
    -- Counted over the clients registration created, never over the realm: an
    -- administrator writes clients down after the endpoint has stopped
    -- answering, and a realm filled from outside never locks its owner out.
    -- Null is no ceiling.
    ADD COLUMN registration_max_clients        integer,
    -- A client that registered itself was vetted by nobody, so the person it
    -- asks for is the one who decides. On, because the endpoint that creates
    -- these clients is open to whoever can reach it.
    ADD COLUMN registration_requires_consent   boolean NOT NULL DEFAULT true,
    -- Addresses and prefixes, `10.0.0.7` or `10.0.0.0/8`. Empty is every
    -- caller: what opened the endpoint at all is the policy above.
    ADD COLUMN registration_trusted_hosts      text[]  NOT NULL DEFAULT '{}';

-- The ceiling is counted over this. What keeps two registrations at one below
-- the ceiling from both passing the count is the lock the counting is taken
-- under, not the index.
CREATE INDEX clients_created_by ON clients (tenant, realm_id, created_by);
