-- Where a client is loaded in a frame when a session it served ends. A
-- client made before has none: a column with no default rewrites no row.
-- The table is held under ACCESS EXCLUSIVE from the first statement to the
-- commit, every read of a client waiting, `/token` included: on 100 000
-- clients, 3.3 ms at most in three runs, the trigger made again included.
-- Only an application that signs people in has a session to be told of. The
-- rule binds every row written from now on, and the next migration checks
-- those already there.
ALTER TABLE clients
    ADD COLUMN frontchannel_logout_uri text,
    ADD CONSTRAINT clients_frontchannel_for_applications
        CHECK (allows_authorization_code OR frontchannel_logout_uri IS NULL) NOT VALID;

-- A client that registered itself rewrites it, as what else it says of itself.
GRANT UPDATE (frontchannel_logout_uri) ON clients TO saffui_app;

-- The trigger names the columns it guards, and a list of columns is not
-- changed in place: it is made again, under the lock the column took.
DROP TRIGGER clients_rewritten_when_registered ON clients;
CREATE TRIGGER clients_rewritten_when_registered BEFORE UPDATE OF
    name, scopes, redirect_uris, post_logout_redirect_uris, id_token_signed_response_alg,
    auth_signing_alg, jwks, frontchannel_logout_uri ON clients
    FOR EACH ROW EXECUTE FUNCTION saffui_rewrite_registered_clients_only();
