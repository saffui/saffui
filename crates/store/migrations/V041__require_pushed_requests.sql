ALTER TABLE realms
    -- RFC 9126 §5, for every client at once. Discovery states it, so a client
    -- reading the metadata knows before it tries.
    ADD COLUMN require_pushed_authorization_requests boolean NOT NULL DEFAULT false;

ALTER TABLE clients
    -- Absent follows the realm. A client that pushes cannot have its request
    -- read off a browser's history or a proxy's log.
    ADD COLUMN require_pushed_authorization_requests boolean;
