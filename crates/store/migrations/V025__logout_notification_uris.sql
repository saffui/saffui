-- Where a client is told a login ended: OpenID Connect Back-Channel Logout 1.0
-- posts a logout token there, Front-Channel Logout 1.0 loads it in the browser.
-- Either may insist on being told which session, §2.2 of each.
ALTER TABLE clients
    ADD COLUMN backchannel_logout_uri              text,
    ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false,
    ADD COLUMN frontchannel_logout_uri             text,
    ADD COLUMN frontchannel_logout_session_required boolean NOT NULL DEFAULT false;
