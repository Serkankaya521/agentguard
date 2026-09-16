"""Security worker for durable response-aware campaigns."""
import os
from dashboard.campaign_engine import CampaignConfig,run_campaign_sync
from jobs.campaigns import CampaignExecutor,RegressionExecutor
from object_store import S3ObjectStore
from platform_main import register,main as worker_main

def runner(row,api_key=None,seed_prompt=None):
    population=min(20,row['request_budget'])
    generations=max(1,min(10,row['request_budget']//population,row['mutation_budget']//population))
    cfg=CampaignConfig(target_name=row['name'],seed_prompt=seed_prompt or row['seed_prompt'],objective_keywords=tuple(row['objective_markers']),population_size=population,generations=generations,model_name=str(row['target_config'].get('model','')),api_base=str(row['target_config'].get('api_base','')),request_delay_s=float(row['target_config'].get('request_delay_s',0)))
    return run_campaign_sync(cfg,api_key=api_key)

def main():
    store=S3ObjectStore(endpoint_url=os.environ['EVIDENCE_S3_ENDPOINT'],bucket=os.environ['EVIDENCE_S3_BUCKET'],region=os.environ.get('EVIDENCE_S3_REGION','us-east-1'))
    register('red_team.execute',CampaignExecutor(os.environ['CONTROL_DATABASE_URL'],store,runner))
    register('regression.execute',RegressionExecutor(os.environ['CONTROL_DATABASE_URL'],runner))
    worker_main(include_defaults=False)
if __name__=='__main__':main()
