-- What a client may ask the authorization endpoint to hand back: each a set
-- of `code`, `id_token` and `token`, written in one order. A client made
-- before asks for a code and nothing else, which is the default: a constant
-- the catalog keeps, so no row is rewritten and the table is held for the
-- change of its definition alone: on 100 000 clients, 2 ms at most in three
-- runs. A client that registered itself asks for nothing else, whatever
-- writes it. The rules bind every row written from now on, and the next
-- migration checks those already there.
ALTER TABLE clients
    ADD COLUMN response_types text[] NOT NULL DEFAULT '{code}',
    ADD CONSTRAINT clients_response_types_known CHECK (
        cardinality(response_types) BETWEEN 1 AND 6
        AND response_types <@ ARRAY[
            'code', 'id_token', 'id_token token', 'code id_token', 'code token',
            'code id_token token'
        ]
    ) NOT VALID,
    ADD CONSTRAINT clients_registered_ask_a_code CHECK (
        NOT self_registered OR response_types = '{code}'
    ) NOT VALID;
