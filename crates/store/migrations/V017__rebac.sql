-- Who is related to what, and the schema that says which relations exist.
--
-- The other engine. A policy decides from facts about a subject; this decides
-- by walking edges from an object back to one, and the two never fold into each
-- other: they are reached by a total dispatch on what is being asked about, so
-- neither can overrule the other by accident.

-- The relationship schema of a realm, as written and as compiled.
--
-- Both halves are stored. The source is what an administrator edits and the
-- compiled form is what the walk reads, and recompiling on import would make an
-- imported realm decide by something nobody exported. Keeping both means the
-- two can be compared, which is the only way to notice that they disagree.
CREATE TABLE rebac_schemas
(
    tenant     text        NOT NULL,
    realm_id   text        NOT NULL,
    -- What the compiled column's shape is, so a build meeting a form it does
    -- not know refuses instead of reading it as one it does.
    format     integer     NOT NULL,
    -- Which revision of this realm's schema this is, as an export carries it.
    -- Distinct from the audit column below, which counts writes to the row.
    revision   integer     NOT NULL DEFAULT 1 CHECK (revision > 0),
    source     text        NOT NULL,
    compiled   jsonb       NOT NULL,

    created_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_by text,
    updated_at timestamptz,
    version    integer     NOT NULL DEFAULT 1 CHECK (version > 0),

    -- One schema per realm of a tenant. The tenant is in the key, which is not
    -- a formality: keyed on the realm alone, two tenants that both call a realm
    -- `main` share one row, and whichever writes last decides for both.
    PRIMARY KEY (tenant, realm_id),
    CONSTRAINT rebac_schemas_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT a_compiled_schema_is_a_document CHECK (jsonb_typeof(compiled) = 'object'),
    -- Bounded on the way in. The source reaches a parser that recurses on
    -- nested groups, so its size is the first thing that has to stop being
    -- whatever a caller sent.
    CONSTRAINT a_schema_source_is_bounded CHECK (octet_length(source) <= 65536),
    CONSTRAINT a_compiled_schema_is_bounded CHECK (octet_length(compiled::text) <= 262144),
    CONSTRAINT a_schema_format_is_known CHECK (format > 0)
);

-- One edge: this subject stands in this relation to this object.
--
-- A subject is either something with an identifier, or everything that stands
-- in some relation to another object, which is what `subject_relation` names.
-- The empty string is the first, because a relation named there would make the
-- row mean the second, and a nullable column would make the difference depend
-- on whether a writer remembered.
CREATE TABLE rebac_tuples
(
    tenant           text        NOT NULL,
    realm_id         text        NOT NULL,
    object_type      text        NOT NULL,
    object_id        text        NOT NULL,
    relation         text        NOT NULL,
    subject_type     text        NOT NULL,
    subject_id       text        NOT NULL,
    -- Empty for a subject named directly. Otherwise the relation on the subject
    -- whose holders this edge stands for.
    subject_relation text        NOT NULL DEFAULT '',

    created_by       text,
    created_at       timestamptz NOT NULL DEFAULT now(),

    -- The tenant leads the key, and every index below. The reference keeps the
    -- tenant as a column and leaves it out of both, so two tenants sharing a
    -- realm name share their edges.
    PRIMARY KEY (tenant, realm_id, object_type, object_id, relation,
                 subject_type, subject_id, subject_relation),
    CONSTRAINT rebac_tuples_realm FOREIGN KEY (tenant, realm_id)
        REFERENCES realms (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT rebac_tuples_schema FOREIGN KEY (tenant, realm_id)
        REFERENCES rebac_schemas (tenant, realm_id) ON DELETE CASCADE,
    CONSTRAINT an_object_type_is_named CHECK (btrim(object_type) <> ''),
    CONSTRAINT an_object_is_named CHECK (btrim(object_id) <> ''),
    CONSTRAINT a_relation_is_named CHECK (btrim(relation) <> ''),
    CONSTRAINT a_subject_type_is_named CHECK (btrim(subject_type) <> ''),
    CONSTRAINT a_subject_is_named CHECK (btrim(subject_id) <> '')
);

-- What the walk asks: the subjects standing in one relation to one object.
CREATE INDEX rebac_tuples_by_object
    ON rebac_tuples (tenant, realm_id, object_type, object_id, relation);
-- And the reverse, for listing what one subject reaches. Written now because a
-- walk that has to answer it without an index answers it by reading the table.
CREATE INDEX rebac_tuples_by_subject
    ON rebac_tuples (tenant, realm_id, subject_type, subject_id, relation);

ALTER TABLE rebac_schemas ENABLE ROW LEVEL SECURITY;
ALTER TABLE rebac_schemas FORCE ROW LEVEL SECURITY;
CREATE POLICY rebac_schema_isolation ON rebac_schemas
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

ALTER TABLE rebac_tuples ENABLE ROW LEVEL SECURITY;
ALTER TABLE rebac_tuples FORCE ROW LEVEL SECURITY;
CREATE POLICY rebac_tuple_isolation ON rebac_tuples
    USING      (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true))
    WITH CHECK (tenant = current_setting('saffui.current_tenant', true)
            AND realm_id = current_setting('saffui.current_realm', true));

GRANT SELECT, INSERT, UPDATE, DELETE
    ON rebac_schemas, rebac_tuples TO saffui_app;
