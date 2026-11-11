-- The sessions written before the rules of their kind are checked under a
-- lock that blocks no write: the scan of the table keeps nobody waiting.
ALTER TABLE sessions VALIDATE CONSTRAINT sessions_kind_known;
ALTER TABLE sessions VALIDATE CONSTRAINT sessions_kind_secret;
