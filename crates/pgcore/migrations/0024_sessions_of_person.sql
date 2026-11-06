-- The sessions of a person are found together: setting up a factor ends
-- those the password alone opened, in one statement.
CREATE INDEX sessions_of_person ON sessions (tenant_id, realm_id, person_id);
