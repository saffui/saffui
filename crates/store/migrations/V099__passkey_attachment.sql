-- Where the browser reported a key lives, kept so a signal about the key can
-- say whether it is built into a device or carried to one. Absent for keys
-- enrolled before, and for browsers that do not say.
CREATE TYPE authenticator_attachment AS ENUM ('platform', 'cross-platform');

ALTER TABLE webauthn_credentials
    ADD COLUMN attachment authenticator_attachment;
