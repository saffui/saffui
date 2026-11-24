-- The consents of one client, as a change of its registration withdraws
-- them all, and as retention removes the client: without it, each reads
-- every consent of its realm. The index is built under a lock that holds
-- the consents until it is done.
CREATE INDEX consents_client ON consents (tenant_id, realm_id, client_id);
