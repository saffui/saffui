-- What a login said about where it came from.
--
-- The address is kept as text and not as inet: what a deployment behind a
-- proxy records is whatever that proxy wrote, and a column that refuses to
-- hold it would refuse the login rather than the value.
--
-- The agent is the header verbatim, capped. Parsing it into a browser is a
-- heuristic that ages, and one frozen into a column ages in the rows too;
-- whatever reads this can parse a better answer out of the same string later.
ALTER TABLE user_sessions ADD COLUMN user_agent text;
ALTER TABLE user_sessions ADD CONSTRAINT user_agent_is_not_storage
    CHECK (user_agent IS NULL OR length(user_agent) <= 512);
