-- The clients written before the rules of their algorithm and capabilities
-- are checked under a lock that blocks no write.
ALTER TABLE clients VALIDATE CONSTRAINT clients_id_token_algorithm_known;
ALTER TABLE clients VALIDATE CONSTRAINT clients_capabilities_known;
