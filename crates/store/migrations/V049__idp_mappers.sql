-- A rule turning what an upstream provider asserted into something local:
-- an attribute written onto the arriving user, or a role granted to them.
CREATE TABLE idp_mappers
(
    tenant         text        NOT NULL,
    realm_id       text        NOT NULL,
    mapper_id      text        NOT NULL,
    provider_alias text        NOT NULL,
    name           text        NOT NULL,
    -- Which rule. The catalogue lives in the build; the plane refuses names
    -- outside it rather than recording rules nothing runs.
    mapper_type    text        NOT NULL,
    configs        jsonb,

    created_by     text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     text,
    updated_at     timestamptz,
    version        integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, mapper_id),
    -- A mapper belongs to one provider, and goes when it goes: a rule
    -- reading claims nobody will ever present again decides nothing.
    CONSTRAINT idp_mappers_provider FOREIGN KEY (tenant, realm_id, provider_alias)
        REFERENCES identity_providers (tenant, realm_id, provider_id) ON DELETE CASCADE,
    CONSTRAINT idp_mapper_type_not_blank CHECK (btrim(mapper_type) <> '')
);

GRANT SELECT, INSERT, UPDATE, DELETE ON idp_mappers TO saffui_app;

ALTER TABLE idp_mappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE idp_mappers FORCE ROW LEVEL SECURITY;
CREATE POLICY idp_mappers_by_realm ON idp_mappers
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
