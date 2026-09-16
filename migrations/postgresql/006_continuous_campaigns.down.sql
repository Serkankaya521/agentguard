DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM platform.campaigns) THEN
   RAISE EXCEPTION 'refusing to remove nonempty campaign data';
 END IF;
END $$;
DROP TABLE platform.regression_cases,platform.campaign_candidates,platform.campaign_runs,platform.campaigns;
