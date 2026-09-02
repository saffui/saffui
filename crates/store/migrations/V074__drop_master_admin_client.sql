-- A column from the first schema that nothing ever read or set to anything:
-- this deployment's console is named by configuration, not by a realm row.
ALTER TABLE realms DROP COLUMN master_admin_client;
