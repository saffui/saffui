-- A request whose person proved their password, and owes a code, keeps who
-- they are: the code that comes next is asked of this person and no other.
-- No session exists until both are proven.
ALTER TABLE authorization_requests ADD COLUMN first_factor_person_id uuid;
GRANT UPDATE (first_factor_person_id) ON authorization_requests TO saffui_app;

-- A session a code opened says so.
ALTER TABLE sessions DROP CONSTRAINT sessions_methods_known;
ALTER TABLE sessions ADD CONSTRAINT sessions_methods_known
    CHECK (methods <@ ARRAY['pwd', 'otp'] AND cardinality(methods) >= 1);
