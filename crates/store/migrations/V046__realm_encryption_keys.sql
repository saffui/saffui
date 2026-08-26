-- A realm may now hold a key to be encrypted to, so the catalogue V010 left
-- for the work that reads one is written here.
--
-- Asymmetric only, and the same list the client side registers against: the
-- key is published for anyone to encrypt to, so a shared-secret family has
-- nothing here to use.
ALTER TABLE realm_signing_keys
    DROP CONSTRAINT the_algorithm_matches_the_use;

ALTER TABLE realm_signing_keys
    ADD CONSTRAINT the_algorithm_matches_the_use CHECK (
        CASE key_use
            WHEN 'sig' THEN algorithm IN (
                'RS256', 'RS384', 'RS512',
                'PS256', 'PS384', 'PS512',
                'ES256', 'ES384', 'ES512',
                'EdDSA'
            )
            ELSE algorithm IN (
                'RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512',
                'ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'
            )
        END
    );
