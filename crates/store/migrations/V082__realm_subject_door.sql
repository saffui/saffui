-- The realm's own privacy door: which law's clock a self-lodged subject
-- request runs on, and the realm's response window where that law fixes
-- none or its controller answers faster. NULL keeps the door closed.
CREATE TYPE dsar_jurisdiction AS ENUM
    ('ke', 'ng', 'za', 'gh', 'tg', 'bj', 'ci', 'bf', 'ga', 'cm', 'eu', 'other');
ALTER TABLE realms ADD COLUMN dsar_jurisdiction dsar_jurisdiction;
ALTER TABLE realms ADD COLUMN dsar_response_days integer;
