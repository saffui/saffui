-- A group may sit under another, and then names a narrower slice of it:
-- its members also stand in every group above it.
ALTER TABLE groups ADD COLUMN parent_id text;
ALTER TABLE groups ADD CONSTRAINT groups_parent
    FOREIGN KEY (tenant, realm_id, parent_id)
    REFERENCES groups (tenant, realm_id, group_id);
ALTER TABLE groups ADD CONSTRAINT group_not_own_parent
    CHECK (parent_id IS DISTINCT FROM group_id);
