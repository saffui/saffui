-- When this client's published key set was last read, OIDC Core §10.1.1. A
-- client that rotates its keys publishes the new ones where it said it would,
-- and a set read once and kept forever stops verifying the day it does.
ALTER TABLE clients ADD COLUMN jwks_fetched_at timestamptz;

-- One way was a rule about registering, not about storing: a client that
-- publishes its keys has them read and kept here, and the stamp above is what
-- says which of the two this column holds. Registration still refuses both.
ALTER TABLE clients DROP CONSTRAINT keys_are_published_one_way;
