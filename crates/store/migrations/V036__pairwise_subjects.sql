-- A different subject identifier per client sector, OIDC Core §8.

ALTER TABLE clients
    ADD COLUMN subject_type          text,
    ADD COLUMN sector_identifier_uri text;

ALTER TABLE clients
    ADD CONSTRAINT subject_type_is_known
        CHECK (subject_type IS NULL OR subject_type IN ('public', 'pairwise'));

-- Drawn rather than derived. A derived identifier is only as private as the
-- salt behind it, and a salt that leaks turns every identifier this realm ever
-- issued back into the account it stands for.
CREATE TABLE pairwise_subjects
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    sector     text        NOT NULL,
    user_id    text        NOT NULL,
    sub        text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant, realm_id, sector, user_id),
    CONSTRAINT pairwise_subjects_user FOREIGN KEY (tenant, realm_id, user_id)
        REFERENCES users (tenant, realm_id, user_id) ON DELETE CASCADE,
    -- One account behind each identifier, so reading one back is unambiguous.
    CONSTRAINT pairwise_subject_is_unique UNIQUE (tenant, realm_id, sub),
    CONSTRAINT pairwise_sector_not_blank CHECK (btrim(sector) <> ''),
    CONSTRAINT pairwise_sub_not_blank CHECK (btrim(sub) <> '')
);

ALTER TABLE pairwise_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE pairwise_subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY pairwise_subjects_isolation ON pairwise_subjects
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE ON pairwise_subjects TO saffui_app;
