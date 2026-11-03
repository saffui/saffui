-- What proved who the person is, named as a token names it (RFC 8176): the
-- password, a one-time code, the holding of a key. A session opened before
-- was opened by the password: nothing else existed.
ALTER TABLE sessions ADD COLUMN methods text[] NOT NULL DEFAULT '{pwd}';
ALTER TABLE sessions ALTER COLUMN methods DROP DEFAULT;
ALTER TABLE sessions ADD CONSTRAINT sessions_methods_known
    CHECK (methods <@ ARRAY['pwd', 'otp', 'pop'] AND cardinality(methods) >= 1);
