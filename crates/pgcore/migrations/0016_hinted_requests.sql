-- The person an identity token hint named. Whoever else signs in for such
-- a request gets no code: the client is told a sign-in is needed (OpenID
-- Connect Core 1.0, section 3.1.2.1). The table grants hold for the column.
ALTER TABLE authorization_requests ADD COLUMN expected_person uuid;
