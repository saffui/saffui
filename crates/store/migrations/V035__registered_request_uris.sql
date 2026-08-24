-- Where a client hosts the request objects this server will fetch, OIDC Core
-- §6.2. Pre-registration is required rather than optional: an authorization
-- endpoint that fetches whatever URL a request names is a way to make this
-- server issue requests on somebody else's behalf.
ALTER TABLE clients ADD COLUMN request_uris text[];
