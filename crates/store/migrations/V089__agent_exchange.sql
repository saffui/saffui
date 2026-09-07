-- Whether this realm mints capability tokens for agents. Absent is off:
-- an agent surface nobody turned on is an agent surface nobody audits,
-- so each realm opts in by hand, from the console or the CLI.
ALTER TABLE realms
    ADD COLUMN agent_exchange_enabled boolean;
