-- A realm's mark, kept beside its theme and read only by the door that serves
-- it: never in the column list a realm load reads, so no request pays for it.
--
-- The type is stored rather than sniffed again on the way out, because what is
-- served has to be what was weighed on the way in. Raster only is enforced at
-- the door, not here: a check constraint over bytes would be a second, weaker
-- copy of a rule that already lives in one place.
ALTER TABLE realms ADD COLUMN logo bytea;
ALTER TABLE realms ADD COLUMN logo_type text;

-- Both or neither. A mark with no type could not be served, and a type with no
-- mark is a row remembering something nobody kept.
ALTER TABLE realms ADD CONSTRAINT realm_logo_whole
    CHECK ((logo IS NULL) = (logo_type IS NULL));
