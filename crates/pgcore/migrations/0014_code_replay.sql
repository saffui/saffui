-- A code is spent by marking it, no longer by deleting it. An exchange that
-- comes after finds it spent, and takes back what the first one obtained
-- (RFC 6749, section 4.1.2). The refresh tokens the first exchange started
-- are its family; a code marked as presented again before the first
-- exchange finished binds none, and that exchange issues nothing.
ALTER TABLE authorization_codes
    ADD COLUMN spent_at timestamptz,
    ADD COLUMN family uuid,
    ADD COLUMN replayed_at timestamptz;

GRANT UPDATE (spent_at, family, replayed_at) ON authorization_codes TO saffui_app;
REVOKE DELETE ON authorization_codes FROM saffui_app;
