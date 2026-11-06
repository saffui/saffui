-- A request whose person proved their password, and owes a code, keeps who
-- they are: the code that comes next is asked of this person and no other.
-- No session exists until both are proven.
ALTER TABLE authorization_requests ADD COLUMN first_factor_person_id uuid;
GRANT UPDATE (first_factor_person_id) ON authorization_requests TO saffui_app;
