-- Where an application may send a person after they sign out. Compared by
-- exact equality, as the addresses a person is sent back to after signing
-- in. Only an application that signs people in has anyone to send there.

ALTER TABLE clients ADD COLUMN post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';
ALTER TABLE clients ALTER COLUMN post_logout_redirect_uris DROP DEFAULT;

ALTER TABLE clients
    ADD CONSTRAINT clients_post_logout_for_applications
        CHECK (allows_authorization_code OR cardinality(post_logout_redirect_uris) = 0);
