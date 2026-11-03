-- Retention runs under a role of its own. It reads and removes what
-- expired in five tables, and does nothing else: the maintenance role,
-- which writes tenants and realms, no longer purges.

GRANT SELECT, DELETE ON authorization_requests, authorization_codes, refresh_tokens, sessions,
    login_failures TO saffui_retention;
REVOKE DELETE ON authorization_requests, authorization_codes, refresh_tokens, sessions,
    login_failures FROM saffui_maintenance;
