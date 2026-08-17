-- Organizations: a soft tenant inside a realm.
--
-- An organization shares its realm's issuer, keys, clients and user pool, and
-- isolates who belongs, how they log in and who administers them. It is not a
-- second tenancy: nothing here is a boundary the way (tenant, realm_id) is, and
-- the row level security below is the realm's, not the organization's.

-- How a user came to belong to one.
CREATE TYPE org_membership AS ENUM ('managed', 'unmanaged');

CREATE TABLE organizations
(
    tenant       text        NOT NULL,
    realm_id     text        NOT NULL,
    org_id       text        NOT NULL,
    -- The slug the login link is built from.
    name         text        NOT NULL,
    display_name text        NOT NULL,
    description  text        NOT NULL DEFAULT '',
    enabled      boolean     NOT NULL DEFAULT true,
    -- Where a login through the organization's link lands afterwards.
    redirect_url text,
    attributes   jsonb,

    created_by   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_by   text,
    updated_at   timestamptz,
    version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, org_id),
    CONSTRAINT organizations_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT organization_name_unique_per_realm UNIQUE (tenant, realm_id, name),
    CONSTRAINT org_id_not_blank CHECK (btrim(org_id) <> ''),
    CONSTRAINT organization_name_not_blank CHECK (btrim(name) <> '')
);

-- The mail domains that route a login to an organization.
--
-- Keyed by the domain within the realm rather than by the organization, because
-- discovery reads it the other way round: an address arrives and one row must
-- answer. Two organizations claiming the same domain would make that answer a
-- matter of which row was found first, so the key refuses the second claim.
--
-- The claim is per realm and not wider on purpose. A domain unique across the
-- deployment would have one tenant's claim refused by another tenant's, which
-- reports the existence of a customer that tenant cannot otherwise see.
CREATE TABLE organization_domains
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    domain      text        NOT NULL,
    org_id      text        NOT NULL,
    -- A claim is in exactly one of two states, and each carries its own datum:
    -- pending carries the challenge to publish, proven carries the instant it
    -- was proven. The check below is what makes them exclusive.
    --
    -- Neither is a flag beside a payload. A boolean could say proven with no
    -- time, and a challenge that outlived the proof is a second way to pass a
    -- check that has already been passed.
    challenge   text,
    verified_at timestamptz,

    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, domain),
    CONSTRAINT organization_domains_org FOREIGN KEY (tenant, realm_id, org_id)
        REFERENCES organizations (tenant, realm_id, org_id) ON DELETE CASCADE,
    CONSTRAINT domain_not_blank CHECK (btrim(domain) <> ''),
    CONSTRAINT a_claim_is_pending_or_proven CHECK ((challenge IS NULL) <> (verified_at IS NULL)),
    CONSTRAINT domain_is_lowercase CHECK (domain = lower(domain))
);

CREATE TABLE organization_members
(
    tenant          text           NOT NULL,
    realm_id        text           NOT NULL,
    org_id          text           NOT NULL,
    user_id         text           NOT NULL,
    membership_type org_membership NOT NULL,
    joined_at       timestamptz    NOT NULL DEFAULT now(),

    created_by      text,
    created_at      timestamptz    NOT NULL DEFAULT now(),
    updated_by      text,
    updated_at      timestamptz,
    version         integer        NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, org_id, user_id),
    CONSTRAINT organization_members_org FOREIGN KEY (tenant, realm_id, org_id)
        REFERENCES organizations (tenant, realm_id, org_id) ON DELETE CASCADE,
    CONSTRAINT organization_members_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE
);

-- Roles a member holds inside one organization.
--
-- The role is the realm's; what the organization scopes is who holds it and
-- where. Keyed by everything it joins, so the grant is idempotent and cannot
-- reach a role of another realm.
CREATE TABLE organization_members_roles
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    org_id     text        NOT NULL,
    user_id    text        NOT NULL,
    role_id    text        NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, org_id, user_id, role_id),
    CONSTRAINT organization_members_roles_member
        FOREIGN KEY (tenant, realm_id, org_id, user_id)
        REFERENCES organization_members (tenant, realm_id, org_id, user_id)
        ON DELETE CASCADE,
    CONSTRAINT organization_members_roles_role FOREIGN KEY (tenant, realm_id, role_id)
        REFERENCES roles (tenant, realm_id, role_id) ON DELETE CASCADE
);

CREATE INDEX organization_domains_by_org
    ON organization_domains (tenant, realm_id, org_id);
CREATE INDEX organization_members_by_user
    ON organization_members (tenant, realm_id, user_id);
CREATE INDEX organization_members_roles_by_role
    ON organization_members_roles (tenant, realm_id, role_id);

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_isolation ON organizations
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE organization_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_domains FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_domain_isolation ON organization_domains
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_member_isolation ON organization_members
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE organization_members_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_members_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_member_role_isolation ON organization_members_roles
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON organizations, organization_domains, organization_members,
       organization_members_roles TO saffui_app;
