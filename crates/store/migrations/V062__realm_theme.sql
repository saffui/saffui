-- The realm's look, as token overrides the hosted pages read. A realm with
-- nothing here gets the default the stylesheet itself spells.
ALTER TABLE realms ADD COLUMN theme jsonb;
