-- What a realm does about a password being guessed at.
--
-- The table and the counter have existed since V013; nothing ever wrote to
-- them, because nothing said when a count becomes a lockout.

ALTER TABLE realms
    -- Off by default: a lockout is a way to deny a person their own account.
    ADD COLUMN brute_force_protected boolean NOT NULL DEFAULT false,
    ADD COLUMN max_login_failures    integer NOT NULL DEFAULT 10,
    -- Each failure past the threshold adds another window, up to the ceiling.
    ADD COLUMN lockout_seconds       integer NOT NULL DEFAULT 60,
    ADD COLUMN max_lockout_seconds   integer NOT NULL DEFAULT 900,
    -- A quiet spell forgets the count, or somebody who mistypes twice a year
    -- is locked out on the tenth year.
    ADD COLUMN failure_reset_seconds integer NOT NULL DEFAULT 900;

ALTER TABLE realms
    ADD CONSTRAINT lockout_thresholds_are_positive CHECK (
        max_login_failures > 0
        AND lockout_seconds > 0
        AND failure_reset_seconds > 0
        AND max_lockout_seconds >= lockout_seconds
    );
