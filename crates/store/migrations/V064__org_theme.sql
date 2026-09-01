-- An organization may dress the hosted pages its members sign in on, the
-- same fifteen tokens a realm may set, worn after the realm's own.
ALTER TABLE organizations
    ADD COLUMN theme jsonb;
