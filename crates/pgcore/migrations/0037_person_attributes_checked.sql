-- The people written before the shape of their attributes was set are
-- checked under a lock that blocks no write.
ALTER TABLE persons VALIDATE CONSTRAINT persons_attributes_object;
