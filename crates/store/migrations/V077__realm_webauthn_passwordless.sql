-- Whether this realm signs people in by passkey alone, no name asked first.
-- NULL reads as off; the mechanics of the ceremony stay the build's.
ALTER TABLE realms ADD COLUMN webauthn_passwordless boolean;
