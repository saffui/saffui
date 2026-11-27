-- The requests written before the rule of their challenge are checked under
-- a lock that blocks no write, before the codes are locked: on 20 000
-- requests and 20 000 codes, the scan took 4 ms at most in three runs. A code
-- is then bound to no challenge when its request was: the column changes in
-- its definition alone, no row is read, and the codes were held under 1 ms.
ALTER TABLE authorization_requests VALIDATE CONSTRAINT authorization_requests_challenge_only_for_a_code;
ALTER TABLE authorization_codes ALTER COLUMN code_challenge DROP NOT NULL;
