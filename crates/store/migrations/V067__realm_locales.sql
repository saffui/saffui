-- Which of the built tongues this realm offers, and which answers when the
-- browser says nothing. NULL offers every built tongue; NULL default takes
-- the build's first.
ALTER TABLE realms ADD COLUMN supported_locales jsonb;
ALTER TABLE realms ADD COLUMN default_locale text;
