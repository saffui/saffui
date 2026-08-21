-- A redeemed code stays, marked, instead of vanishing. RFC 6749 §4.1.2 asks that
-- a code presented twice not only be refused but revoke what its first use
-- bought, and a row that is gone cannot say what it bought.
ALTER TABLE oidc_auth_codes
    ADD COLUMN redeemed_at      timestamptz,
    ADD COLUMN issued_token_ids text[]      NOT NULL DEFAULT '{}';
