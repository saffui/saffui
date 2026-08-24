-- What a relying party's iframe compares against to see whether this login is
-- still the one it was told about, OIDC Session Management 1.0 §4.2.
--
-- Drawn per login and kept, so a second client asking is told a value derived
-- from the same one. Never the session identifier: the value reaches script in
-- the browser, and an identifier that reaches script is one a page can use.
ALTER TABLE user_sessions ADD COLUMN browser_state text;
