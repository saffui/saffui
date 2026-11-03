-- What a client may do on the administration plane of its realm: a closed
-- list, held here too for a write that does not come through the product.
-- A client made before this migration is granted nothing.

ALTER TABLE clients
    ADD COLUMN capabilities text[] NOT NULL DEFAULT '{}'
        CONSTRAINT clients_capabilities_known
        CHECK (capabilities <@ ARRAY['realm:read', 'client:read', 'client:write', 'audit:read']);
