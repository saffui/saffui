-- Which top-level flow answers /authorize when the client binds none.
-- NULL keeps the built default, the flow aliased "browser".
ALTER TABLE realms ADD COLUMN browser_flow text;
