-- The keys written before the rules of their status and algorithm are
-- checked under a lock that blocks no write.
ALTER TABLE signing_keys VALIDATE CONSTRAINT signing_keys_status_known;
ALTER TABLE signing_keys VALIDATE CONSTRAINT signing_keys_algorithm_check;

-- The algorithm of the identity tokens of a client. None: the default of the
-- realm, which every realm has a key of. A client may be granted the keys of
-- its realm. The rules bind every row written from now on, and the next
-- migration checks those already there.
ALTER TABLE clients ADD COLUMN id_token_signed_response_alg text;
ALTER TABLE clients
    ADD CONSTRAINT clients_id_token_algorithm_known CHECK (
        id_token_signed_response_alg IN ('ES256', 'ES384', 'RS256', 'PS256', 'EdDSA')
    ) NOT VALID,
    DROP CONSTRAINT clients_capabilities_known,
    ADD CONSTRAINT clients_capabilities_known CHECK (
        capabilities <@ ARRAY[
            'realm:read', 'client:read', 'client:write', 'audit:read', 'user:read', 'user:write',
            'role:read', 'role:write', 'policy:read', 'policy:write', 'key:read', 'key:write'
        ]
    ) NOT VALID;

-- What an operator grants a client from the command line, which runs as the
-- serving role. The schema holds the list of what may be granted.
GRANT UPDATE (capabilities) ON clients TO saffui_app;
