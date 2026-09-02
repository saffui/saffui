-- How long a signed-in session keeps renewing, and how old it may get.
-- Sliding window NULL means the compiled default; ceiling 0 means the
-- sliding window alone bounds it, which is what every realm did until now.
ALTER TABLE realms ADD COLUMN refresh_token_lifespan integer;
ALTER TABLE realms ADD COLUMN session_max_lifespan integer NOT NULL DEFAULT 0;
