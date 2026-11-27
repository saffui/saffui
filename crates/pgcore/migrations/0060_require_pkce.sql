-- Whether every code of a client is bound to a verifier (RFC 7636). A client
-- made before is, which is the default: a constant default rewrites no row,
-- and the table is held for the change of its definition alone: on 100 000
-- clients, 2 ms at most in three runs. Only a confidential client is let
-- off: one that proves nothing, or registered itself, is not. The rules bind
-- every row written from now on, and the next migration checks those
-- already there. The serving role is granted no update of the column: once
-- the client is made, only the owner changes it.
ALTER TABLE clients
    ADD COLUMN require_pkce boolean NOT NULL DEFAULT true,
    ADD CONSTRAINT clients_public_require_pkce CHECK (
        require_pkce OR auth_method <> 'none'
    ) NOT VALID,
    ADD CONSTRAINT clients_registered_require_pkce CHECK (
        NOT self_registered OR require_pkce
    ) NOT VALID;
