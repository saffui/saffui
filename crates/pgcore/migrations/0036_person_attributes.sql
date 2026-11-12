-- What an administrator writes of a person beyond their name and address:
-- mappers say it in tokens, and policies read part of it. A person made
-- before has none. Its bounds are measured once, by the binary that writes
-- it: Postgres writes a document longer than its compact form, and a second
-- measure here would refuse what the first admitted. Its shape binds every
-- row written from now on, and the next migration checks those already there.
ALTER TABLE persons ADD COLUMN attributes jsonb NOT NULL DEFAULT '{}';
ALTER TABLE persons
    ADD CONSTRAINT persons_attributes_object CHECK (jsonb_typeof(attributes) = 'object') NOT VALID;

-- The first statement that changes a person: its attributes, and nothing else.
GRANT UPDATE (attributes) ON persons TO saffui_app;
