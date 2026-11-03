-- A name proven by its password, or a browser that signed in with it, is
-- no longer counted against: its counters are forgotten, row and all.

GRANT DELETE ON login_failures TO saffui_app;
