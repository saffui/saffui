-- The clients written before the new list of capabilities are checked
-- under a lock that blocks no write.
ALTER TABLE clients VALIDATE CONSTRAINT clients_capabilities_known;

-- The live tokens of one client, as the end of its registration revokes
-- every family it holds. The index is built under a lock that holds the
-- refresh of tokens until it is done.
CREATE INDEX refresh_tokens_live_client ON refresh_tokens (tenant_id, realm_id, client_id)
    WHERE revoked_at IS NULL;
