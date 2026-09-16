DO $$ DECLARE tab text; count_rows bigint; BEGIN
  FOREACH tab IN ARRAY ARRAY['usage_daily','integrations','reports'] LOOP
    EXECUTE format('SELECT count(*) FROM platform.%I',tab) INTO count_rows;
    IF count_rows > 0 THEN RAISE EXCEPTION 'Nonempty table platform.%: preserve data and roll back application',tab; END IF;
  END LOOP;
END $$;
DROP TABLE platform.reports,platform.integrations,platform.usage_daily,platform.tenant_operating_limits;
