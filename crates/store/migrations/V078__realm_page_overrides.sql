-- What a realm says over the hosted pages' own words: per tongue, per key.
-- NULL says nothing; the build's strings answer as they always did.
ALTER TABLE realms ADD COLUMN page_overrides jsonb;
