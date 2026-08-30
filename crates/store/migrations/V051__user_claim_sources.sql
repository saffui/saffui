-- What another provider asserts about a person, carried rather than
-- restated: a signed document from its issuer, or the address and the
-- token a relying party fetches it with (OIDC Core 5.6.2). This realm
-- never speaks these claims in its own voice; it says who does.
CREATE TYPE claim_source_kind AS ENUM ('jwt', 'endpoint');

CREATE TABLE user_claim_sources
(
    tenant      text        NOT NULL,
    realm_id    text        NOT NULL,
    user_id     text        NOT NULL,
    source_id   text        NOT NULL,
    -- The claim names the source answers for.
    claims      text[]      NOT NULL,
    -- 'jwt' carries the signed document itself; 'endpoint' points at it.
    kind        claim_source_kind NOT NULL,
    jwt         text,
    endpoint    text,
    -- Handed to the relying party so it can fetch; released by design,
    -- so stored as what it is rather than sealed.
    endpoint_token text,

    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  text,
    updated_at  timestamptz,
    version     integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    PRIMARY KEY (tenant, realm_id, source_id),
    CONSTRAINT user_claim_sources_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    CONSTRAINT claim_source_names_something CHECK (cardinality(claims) > 0)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_claim_sources TO saffui_app;

ALTER TABLE user_claim_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_claim_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY user_claim_sources_by_realm ON user_claim_sources
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
