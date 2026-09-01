-- Time-bound access, and predicates with more than one term. A rule may
-- carry a composed expression; a grant may be written by hand, without a
-- rule, with an end the engine enforces.
ALTER TABLE birthright_rules ADD COLUMN when_expr text;
ALTER TABLE governed_grants ALTER COLUMN rule_id DROP NOT NULL;
ALTER TABLE governed_grants ADD COLUMN expires_at timestamptz;
ALTER TABLE governed_grants ADD COLUMN granted_by text;
