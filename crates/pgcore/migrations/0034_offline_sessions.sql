-- A session lives in a browser, behind its cookie, or offline: there it
-- lives for the one grant of a client the person allowed to act while they
-- are away, and no cookie proves it, so it holds no secret. A session opened
-- before lived in a browser, and holds one. The rules bind every row written
-- from now on, and the next migration checks those already there.
ALTER TABLE sessions ADD COLUMN kind text NOT NULL DEFAULT 'browser';
ALTER TABLE sessions ALTER COLUMN kind DROP DEFAULT;
ALTER TABLE sessions
    ADD CONSTRAINT sessions_kind_known CHECK (kind IN ('browser', 'offline')) NOT VALID,
    ADD CONSTRAINT sessions_kind_secret
        CHECK ((kind = 'offline') = (octet_length(secret_digest) = 0)) NOT VALID;
