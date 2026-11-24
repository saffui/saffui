-- Whether a client registered itself: written when it is made, and by no
-- statement after. A client made before was made by an administrator.
ALTER TABLE clients ADD COLUMN self_registered boolean NOT NULL DEFAULT false;
ALTER TABLE clients ALTER COLUMN self_registered DROP DEFAULT;
-- The key a registration names its client by, with how the client was
-- made: unique as the identifier alone is. This migration holds the table
-- under ACCESS EXCLUSIVE from its first statement to its commit: while the
-- index of this key is built, every read of a client waits, `/token`
-- included, and not only the writes.
ALTER TABLE clients
    ADD CONSTRAINT clients_registered_key UNIQUE (tenant_id, realm_id, client_id, self_registered);

-- The registration of a client through the protocol, by the digest of the
-- token that manages it, replaced at each use. Ended, it loses its token
-- and stays, its client disabled, until retention removes both: a realm
-- counts every client a registration made until then. Its key holds that
-- a client an administrator made has none.
CREATE TABLE client_registrations (
    tenant_id uuid NOT NULL,
    realm_id uuid NOT NULL,
    client_id text NOT NULL,
    self_registered boolean NOT NULL DEFAULT true CHECK (self_registered),
    token_digest bytea CHECK (octet_length(token_digest) = 32),
    registered_at timestamptz NOT NULL,
    ended_at timestamptz,
    PRIMARY KEY (tenant_id, realm_id, client_id),
    CONSTRAINT client_registrations_token_while_live
        CHECK ((token_digest IS NULL) = (ended_at IS NOT NULL)),
    FOREIGN KEY (tenant_id, realm_id, client_id, self_registered)
        REFERENCES clients (tenant_id, realm_id, client_id, self_registered) ON DELETE CASCADE
);
-- The registrations of a realm in its last day, counted against its budget.
CREATE INDEX client_registrations_recent
    ON client_registrations (tenant_id, realm_id, registered_at);
-- The registrations that ended, found by retention across realms.
CREATE INDEX client_registrations_ended ON client_registrations (ended_at)
    WHERE ended_at IS NOT NULL;

ALTER TABLE client_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_registrations FORCE ROW LEVEL SECURITY;
CREATE POLICY client_registrations_scope ON client_registrations
    USING (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm())
    WITH CHECK (tenant_id = saffui_current_tenant() AND realm_id = saffui_current_realm());

-- The token of a registration is replaced by the next, and taken away when
-- it ends. Nothing that serves removes one.
GRANT SELECT, INSERT, UPDATE (token_digest, ended_at) ON client_registrations TO saffui_app;
GRANT SELECT ON client_registrations TO saffui_maintenance;

-- A registered client rewrites what it says of itself, and the end of its
-- registration disables it. Its identifier, its method, its secret, its
-- grants and whether it asks each person stay as they were written.
GRANT UPDATE (
    name, scopes, redirect_uris, post_logout_redirect_uris, id_token_signed_response_alg,
    auth_signing_alg, jwks, enabled
) ON clients TO saffui_app;

-- The functions below run as whoever writes and read no table; their path
-- is their own. A client turned off stays off: the end of a registration
-- is final, and nothing that serves turns a client back on.
CREATE FUNCTION saffui_keep_client_disabled() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
BEGIN
    IF OLD.enabled OR NOT NEW.enabled THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a client turned off stays off'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER clients_stay_disabled BEFORE UPDATE OF enabled ON clients
    FOR EACH ROW EXECUTE FUNCTION saffui_keep_client_disabled();
REVOKE ALL ON FUNCTION saffui_keep_client_disabled() FROM PUBLIC;

-- What a client says of itself is rewritten for a client that registered
-- itself only: one an administrator made keeps what it was made with,
-- whatever statement the serving role runs.
CREATE FUNCTION saffui_rewrite_registered_clients_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
BEGIN
    IF OLD.self_registered THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'a client an administrator made keeps what it says of itself'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER clients_rewritten_when_registered BEFORE UPDATE OF
    name, scopes, redirect_uris, post_logout_redirect_uris, id_token_signed_response_alg,
    auth_signing_alg, jwks ON clients
    FOR EACH ROW EXECUTE FUNCTION saffui_rewrite_registered_clients_only();
REVOKE ALL ON FUNCTION saffui_rewrite_registered_clients_only() FROM PUBLIC;

-- Retention removes a client thirty days after its registration ended,
-- with the registration: what else hangs on the client goes by its keys.
-- Its role is bound by no row security: it removes a client that
-- registered itself and was turned off, and no other.
CREATE FUNCTION saffui_remove_ended_clients_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
BEGIN
    IF OLD.self_registered AND NOT OLD.enabled THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'only a client whose registration ended is removed'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER clients_removed_when_ended BEFORE DELETE ON clients
    FOR EACH ROW EXECUTE FUNCTION saffui_remove_ended_clients_only();
REVOKE ALL ON FUNCTION saffui_remove_ended_clients_only() FROM PUBLIC;

-- Nor a registration that lasts: its client would stay on, out of the
-- bound of its realm, with nothing left that ends it.
CREATE FUNCTION saffui_remove_ended_registrations_only() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public, pg_temp
    AS $$
BEGIN
    IF OLD.ended_at IS NOT NULL THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'only a registration that ended is removed'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER client_registrations_removed_when_ended BEFORE DELETE ON client_registrations
    FOR EACH ROW EXECUTE FUNCTION saffui_remove_ended_registrations_only();
REVOKE ALL ON FUNCTION saffui_remove_ended_registrations_only() FROM PUBLIC;
GRANT SELECT, DELETE ON clients, client_registrations TO saffui_retention;

-- One capability more: the settings of the realm and the tokens that let
-- clients register. The list stays closed. The rule binds every row
-- written from now on, and the next migration checks those already there.
ALTER TABLE clients
    DROP CONSTRAINT clients_capabilities_known,
    ADD CONSTRAINT clients_capabilities_known CHECK (
        capabilities <@ ARRAY[
            'realm:read', 'client:read', 'client:write', 'audit:read', 'user:read', 'user:write',
            'role:read', 'role:write', 'policy:read', 'policy:write', 'key:read', 'key:write',
            'realm:write'
        ]
    ) NOT VALID;
