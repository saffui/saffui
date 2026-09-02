-- The words the realm's mail speaks, kind by kind and tongue by tongue,
-- laid over the built defaults. NULL speaks the build.
ALTER TABLE realms ADD COLUMN mail_templates jsonb;
