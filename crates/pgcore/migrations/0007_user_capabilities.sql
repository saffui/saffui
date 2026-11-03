-- Two capabilities more, for the people of the realm. The list stays
-- closed: a name it does not hold is refused by the database too.

ALTER TABLE clients
    DROP CONSTRAINT clients_capabilities_known,
    ADD CONSTRAINT clients_capabilities_known CHECK (
        capabilities <@ ARRAY[
            'realm:read', 'client:read', 'client:write', 'audit:read', 'user:read', 'user:write'
        ]
    );
