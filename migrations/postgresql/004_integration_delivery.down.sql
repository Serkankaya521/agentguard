DO $$ BEGIN
  IF EXISTS (SELECT FROM platform.integration_deliveries LIMIT 1) THEN
    RAISE EXCEPTION 'Nonempty table platform.integration_deliveries: preserve data and roll back application';
  END IF;
END $$;
DROP TABLE platform.integration_deliveries;
