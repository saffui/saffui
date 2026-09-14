-- The authenticator model a key named at enrolment and the attestation format
-- it answered with, kept so a key's model can be judged later. Absent for keys
-- enrolled before, and where a key names its model with zeros.
ALTER TABLE webauthn_credentials
    ADD COLUMN aaguid uuid,
    ADD COLUMN attestation_format text;
