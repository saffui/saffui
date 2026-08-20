-- The step an OTP code was accepted at. RFC 6238 §5.2 refuses a code presented
-- twice, and without somewhere to record which one was consumed, intercepting a
-- single code buys the whole acceptance window to reuse it.
ALTER TABLE user_credentials ADD COLUMN otp_last_step bigint;
