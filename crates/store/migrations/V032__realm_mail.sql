-- How a realm sends mail.
--
-- Per realm and not per deployment: two realms on one server send from two
-- domains, and a single set of credentials would put one realm's name on the
-- other's messages.
CREATE TABLE realm_mail
(
    tenant           text        NOT NULL,
    realm_id         text        NOT NULL,
    host             text        NOT NULL,
    port             integer     NOT NULL,
    -- The address messages come from, and the name shown beside it.
    from_address     text        NOT NULL,
    from_name        text        NOT NULL DEFAULT '',
    reply_to         text,
    -- How the connection is protected. Implicit wraps the socket from the
    -- first byte; STARTTLS upgrades a plain one and is refused if the server
    -- will not. Neither is optional: a server that offers no TLS is one this
    -- deployment will not hand a password to.
    implicit_tls     boolean     NOT NULL DEFAULT false,
    username         text,
    -- Sealed under the realm's own key, like every other secret this schema
    -- holds. The generation is kept beside it so a rotation can find what is
    -- still sealed under the old one.
    sealed_password  bytea,
    sealed_version   integer,

    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT realm_mail_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT mail_host_not_blank CHECK (btrim(host) <> ''),
    CONSTRAINT mail_port_is_a_port CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT mail_from_looks_like_an_address CHECK (from_address LIKE '_%@_%'),
    -- A username with no password, or a password with no username, is half a
    -- credential and would fail at the first send rather than here.
    CONSTRAINT mail_credentials_are_whole CHECK (
        (username IS NULL AND sealed_password IS NULL AND sealed_version IS NULL)
        OR (username IS NOT NULL AND sealed_password IS NOT NULL AND sealed_version IS NOT NULL)
    )
);

ALTER TABLE realm_mail ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_mail FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_mail_isolation ON realm_mail
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_mail TO saffui_app;
