-- What one realm has said about the capabilities it is allowed to move.
--
-- A row is a wish, not a state. What the realm actually runs is the process's
-- set narrowed by these, resolved in `commons::feature`: the process is the
-- ceiling and a realm moves under it. That is why nothing here records
-- "enabled" as a fact about the deployment; a realm asking for a capability
-- the node was started without still does not have it.
--
-- Absent is not the same as off. A realm with no row runs whatever the process
-- runs, which is what makes upgrading into this table change nothing anywhere.
CREATE TABLE realm_features
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    -- The slug as `commons::feature` spells it. Unvalidated here on purpose:
    -- the registry is a build's, and a database outliving a build must be
    -- readable by the one that follows. An unknown slug is refused at the
    -- door and ignored on resolution, never silently obeyed.
    slug       text        NOT NULL,
    enabled    boolean     NOT NULL,

    changed_by text        NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, slug),
    CONSTRAINT realm_features_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT realm_feature_slug_is_a_slug CHECK (slug ~ '^[a-z][a-z0-9-]{0,63}$')
);

GRANT SELECT, INSERT, UPDATE, DELETE ON realm_features TO saffui_app;

ALTER TABLE realm_features ENABLE ROW LEVEL SECURITY;
ALTER TABLE realm_features FORCE ROW LEVEL SECURITY;
CREATE POLICY realm_features_by_realm ON realm_features
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));
