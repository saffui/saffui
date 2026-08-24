-- What a client may register about itself, and whether a realm lets it.
-- OpenID Connect Dynamic Client Registration 1.0 §2 and RFC 7591 §2.

-- Off unless a realm says otherwise: an endpoint that creates clients for
-- whoever asks is not something a deployment should get by not deciding.
ALTER TABLE realms
    ADD COLUMN client_registration text NOT NULL DEFAULT 'disabled',
    -- RFC 7591 §3, hashed as every other bearer credential here is.
    ADD COLUMN registration_secret text;

ALTER TABLE realms
    ADD CONSTRAINT client_registration_is_a_policy
        CHECK (client_registration IN ('disabled', 'open', 'protected')),
    -- A realm asking for a token it does not hold refuses every caller, which
    -- reads as broken rather than as closed.
    ADD CONSTRAINT protected_registration_holds_a_secret
        CHECK (client_registration <> 'protected' OR registration_secret IS NOT NULL);

-- §3.2.1 answers a registration with every value it kept, so what is not kept
-- cannot be answered with.
ALTER TABLE clients
    ADD COLUMN client_uri             text,
    ADD COLUMN logo_uri               text,
    ADD COLUMN policy_uri             text,
    ADD COLUMN tos_uri                text,
    ADD COLUMN contacts               text[],
    ADD COLUMN application_type       text,
    ADD COLUMN jwks_uri               text,
    -- The sets registered, which bound what the authorization endpoint will
    -- answer. Absent for a client an administrator made, and read as no bound.
    ADD COLUMN response_types         text[],
    ADD COLUMN default_max_age        integer,
    ADD COLUMN default_acr_values     text[],
    ADD COLUMN initiate_login_uri     text,
    -- Registering is not being created: an administrator's client has no
    -- registration.
    ADD COLUMN registered_at          timestamptz;

ALTER TABLE clients
    ADD CONSTRAINT application_type_is_known
        CHECK (application_type IS NULL OR application_type IN ('web', 'native')),
    ADD CONSTRAINT keys_are_published_one_way
        CHECK (jwks IS NULL OR jwks_uri IS NULL),
    ADD CONSTRAINT default_max_age_is_a_duration
        CHECK (default_max_age IS NULL OR default_max_age >= 0);

-- A client's name is what a person is shown, and §2 lets two clients register
-- the same one. The identifier is `client_id`, which is the key.
ALTER TABLE clients DROP CONSTRAINT clients_name_unique_per_realm;
