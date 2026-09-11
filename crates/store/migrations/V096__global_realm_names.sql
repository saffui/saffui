-- Issuers and token realm ids are resolved before a tenant is known. Refuse an
-- upgrade that would otherwise choose one tenant's realm for another tenant.
DO $$
DECLARE
    collision text;
BEGIN
    SELECT name INTO collision
      FROM realms
     GROUP BY name
    HAVING count(*) > 1
     LIMIT 1;
    IF collision IS NOT NULL THEN
        RAISE EXCEPTION 'realm name "%" belongs to more than one tenant', collision;
    END IF;

    SELECT realm_id INTO collision
      FROM realms
     GROUP BY realm_id
    HAVING count(*) > 1
     LIMIT 1;
    IF collision IS NOT NULL THEN
        RAISE EXCEPTION 'realm id "%" belongs to more than one tenant', collision;
    END IF;
END
$$;

ALTER TABLE realms ADD CONSTRAINT realm_name_unique UNIQUE (name);
ALTER TABLE realms ADD CONSTRAINT realm_id_unique UNIQUE (realm_id);
ALTER TABLE realms DROP CONSTRAINT realm_name_unique_per_tenant;
DROP INDEX realms_by_name;
