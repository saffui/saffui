-- A user who has lost their second factor needs a way back that is not the
-- support desk. The credential type has existed since V013; what was missing
-- is the instruction that asks somebody to draw a set.
ALTER TYPE required_action ADD VALUE IF NOT EXISTS 'configure-recovery-codes';
