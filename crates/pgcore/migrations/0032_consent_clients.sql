-- Whether a client asks each person before it gets a code in their name.
-- A client made before asks nobody, as it did. Only a client that signs
-- people in has anyone to ask: the rule binds every row written from now
-- on, and the next migration checks those already there.
ALTER TABLE clients ADD COLUMN requires_consent boolean NOT NULL DEFAULT false;
ALTER TABLE clients ALTER COLUMN requires_consent DROP DEFAULT;
ALTER TABLE clients
    ADD CONSTRAINT clients_consent_for_applications
        CHECK (allows_authorization_code OR NOT requires_consent) NOT VALID;

-- A consent goes with its client.
ALTER TABLE consents
    ADD FOREIGN KEY (tenant_id, realm_id, client_id)
        REFERENCES clients (tenant_id, realm_id, client_id) ON DELETE CASCADE;
