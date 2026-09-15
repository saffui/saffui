-- The address a changed one moved away from, where its notice goes, and the
-- provider a link names.
ALTER TABLE security_notices
    ADD COLUMN recipient      text,
    ADD COLUMN provider_alias text;
