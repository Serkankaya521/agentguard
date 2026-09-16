DO $$ DECLARE tab text; n bigint; BEGIN
  FOREACH tab IN ARRAY ARRAY['oidc_mappings','report_schedules'] LOOP
    EXECUTE format('SELECT count(*) FROM platform.%I',tab) INTO n;
    IF n>0 THEN RAISE EXCEPTION 'Nonempty table platform.%: preserve data and roll back application',tab; END IF;
  END LOOP;
END $$;
DROP TABLE platform.report_schedules,platform.oidc_mappings;
