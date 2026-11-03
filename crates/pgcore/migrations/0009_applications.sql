-- Applications: clients that send people through the authorization
-- endpoint, and say where they may be sent back. A public application runs
-- where no secret can be kept: it has none, and no digest.

ALTER TABLE clients
    ADD COLUMN allows_authorization_code boolean NOT NULL DEFAULT false,
    ADD COLUMN redirect_uris text[] NOT NULL DEFAULT '{}',
    ALTER COLUMN secret_digest DROP NOT NULL;
ALTER TABLE clients
    ALTER COLUMN allows_authorization_code DROP DEFAULT,
    ALTER COLUMN redirect_uris DROP DEFAULT;

ALTER TABLE clients
    -- Sent back only where it registered, and only if it registered somewhere.
    ADD CONSTRAINT clients_redirect_uris_for_applications
        CHECK (allows_authorization_code = (cardinality(redirect_uris) > 0)),
    -- A client without a secret proves nothing about itself: it gets no
    -- token as itself.
    ADD CONSTRAINT clients_secret_for_services
        CHECK (secret_digest IS NOT NULL OR NOT allows_client_credentials),
    -- A capability is held by a client that acts as itself. An application
    -- gets tokens in the name of people: granted one, it would lend it to
    -- every person of the realm.
    ADD CONSTRAINT clients_capabilities_for_services
        CHECK (NOT allows_authorization_code OR capabilities = '{}');
