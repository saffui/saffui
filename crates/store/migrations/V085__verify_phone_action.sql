-- A phone-first realm needs to tell a person to prove their number the way
-- it tells them to prove an address. The columns have existed since V002;
-- what was missing is the instruction.
ALTER TYPE required_action ADD VALUE IF NOT EXISTS 'verify-phone';
