-- Reverse lookups used before removing client scopes and protocol mappers.

CREATE INDEX clients_protocol_mappers_by_mapper
    ON clients_protocol_mappers (tenant, realm_id, mapper_id, client_id);

CREATE INDEX policies_client_scopes_by_scope
    ON policies_client_scopes
       (tenant, realm_id, client_scope_id, server_id, policy_id);
