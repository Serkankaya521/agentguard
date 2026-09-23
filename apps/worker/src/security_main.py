"""Security worker for durable response-aware campaigns.

Every campaign runs under the operator's Rules of Engagement (execution.live_target):
the target origin and the secrets it uses must be assigned to the tenant, and each
live request passes the kill switch and the safety budget.
"""
import os
from dashboard.campaign_engine import CampaignConfig,run_campaign_sync
from execution.kill_switch import KillSwitch
from execution.distributed_kill_switch import DistributedKillSwitch
from execution.live_target import (GuardedEvaluator,RoEConfig,ScopedSecretResolver,
                                   authorize_campaign,build_roe,finalize,target_origin)
from execution.safety_budget import SafetyBudget
from jobs.campaigns import CampaignExecutor,EnvironmentSecretResolver,RegressionExecutor
from object_store import S3ObjectStore
from platform_main import register,main as worker_main

def build_deep_analysis():
    from corpus_promotion import CorpusPromotionPolicy
    from repository import GraphRepository
    from jobs.deep_analysis import DeepAnalysisJob
    from memory.episodic import EpisodicMemory
    from risk_profiles import RiskProfilePublisher
    return DeepAnalysisJob(episodic=EpisodicMemory(),graph_repo=GraphRepository(),
        risk_publisher=RiskProfilePublisher(),corpus_policy=CorpusPromotionPolicy())

def make_runner(roe_config,kill_switch):
    def runner(row,api_key=None,seed_prompt=None):
        tenant_roe=roe_config.for_tenant(row['tenant_id'])
        model=str(row['target_config'].get('model',''))
        live=not model.startswith('mock-')
        authorize_campaign(row,tenant_roe,live=live)  # raises before any target traffic
        budget=SafetyBudget(build_roe(row,tenant_roe))
        target=target_origin(row['target_config']['api_base']) if live else None
        guards=[]
        def guard(evaluate):
            guards.append(GuardedEvaluator(evaluate,target=target,budget=budget,
                                           kill_switch=kill_switch,tenant_id=str(row['tenant_id'])))
            return guards[-1]
        population=min(20,row['request_budget'])
        generations=max(1,min(10,row['request_budget']//population,row['mutation_budget']//population))
        cfg=CampaignConfig(target_name=row['name'],seed_prompt=seed_prompt or row['seed_prompt'],objective_keywords=tuple(row['objective_markers']),population_size=population,generations=generations,model_name=model,api_base=str(row['target_config'].get('api_base','')),request_delay_s=float(row['target_config'].get('request_delay_s',0)))
        return finalize(run_campaign_sync(cfg,api_key=api_key,wrap_evaluator=guard),guards[0])
    return runner

def build_kill_switch():
    # Distributed switch across instances when a shared store is configured; the
    # in-process switch is a single-worker fallback for local/offline runs.
    url=os.environ.get('REDIS_URL')
    if not url:
        return KillSwitch()
    from redis import Redis
    return DistributedKillSwitch(Redis.from_url(url,socket_timeout=0.5,
                                                socket_connect_timeout=0.5,health_check_interval=30))

def main():
    roe=RoEConfig.from_env(os.environ)
    runner=make_runner(roe,build_kill_switch())
    secrets=ScopedSecretResolver(roe,EnvironmentSecretResolver())
    store=S3ObjectStore(endpoint_url=os.environ['EVIDENCE_S3_ENDPOINT'],bucket=os.environ['EVIDENCE_S3_BUCKET'],region=os.environ.get('EVIDENCE_S3_REGION','us-east-1'))
    register('red_team.execute',CampaignExecutor(os.environ['CONTROL_DATABASE_URL'],store,runner,
        secret_resolver=secrets,deep_analysis=build_deep_analysis()))
    register('regression.execute',RegressionExecutor(os.environ['CONTROL_DATABASE_URL'],runner,secret_resolver=secrets))
    worker_main(include_defaults=False)
if __name__=='__main__':main()
