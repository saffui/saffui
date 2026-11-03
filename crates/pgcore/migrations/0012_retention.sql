-- Retention removes, across realms and under the maintenance role, the
-- requests and codes that expired and the counters no window reads.

GRANT DELETE ON authorization_requests, authorization_codes, login_failures TO saffui_maintenance;
