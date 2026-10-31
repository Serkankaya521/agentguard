"""Durable campaign execution and evidence-to-finding promotion."""
from __future__ import annotations
import hashlib,json,os,re
from datetime import datetime,timezone
from uuid import UUID,uuid4,uuid5
import psycopg
from psycopg.rows import dict_row
from secret_normalize import canary_leaked  # packages/detectors/src (shared, single-source)

class EnvironmentSecretResolver:
    def __call__(self,reference):
        if not reference:return None
        if not reference.startswith('env://'):raise ValueError('SECRET_BACKEND_UNAVAILABLE')
        name=reference[6:]
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,127}',name):raise ValueError('INVALID_SECRET_REFERENCE')
        value=os.environ.get(name)
        if not value:raise ValueError('SECRET_NOT_FOUND')
        return value

class CampaignExecutor:
    def __init__(self,dsn,object_store,runner,secret_resolver=None,deep_analysis=None):
        self.dsn,self.objects,self.runner=dsn,object_store,runner
        self.secrets=secret_resolver or EnvironmentSecretResolver()
        self.deep_analysis=deep_analysis
    def __call__(self,envelope):
        tenant,run_id,campaign_id=envelope['tenant_id'],envelope['payload']['run_id'],envelope['payload']['campaign_id']
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant,))
            run=conn.execute('SELECT * FROM platform.campaign_runs WHERE id=%s FOR UPDATE',(run_id,)).fetchone()
            if not run:raise ValueError('CAMPAIGN_RUN_NOT_FOUND')
            if run['status']=='completed':return {'status':'completed','run_id':run_id}
            campaign=conn.execute('SELECT * FROM platform.campaigns WHERE id=%s',(campaign_id,)).fetchone()
            if not campaign:raise ValueError('CAMPAIGN_NOT_FOUND')
            conn.execute("UPDATE platform.campaign_runs SET status='running',started_at=coalesce(started_at,clock_timestamp()),error_code=NULL WHERE id=%s",(run_id,))
        api_key=self.secrets(campaign['secret_ref']) if campaign['secret_ref'] else None
        canary=self.secrets(campaign['canary_secret_ref']) if campaign['canary_secret_ref'] else None
        result=self.runner(campaign,api_key=api_key)
        findings=0
        evidence={'campaign_id':campaign_id,'run_id':run_id,'target':campaign['name'],'candidates':[]}
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant,))
            for candidate in result.candidates:
                raw=candidate.response_sample or '';response_hash=hashlib.sha256(raw.encode()).hexdigest()
                level='target_canary' if canary_leaked(canary,raw,candidate.prompt) else 'heuristic'
                finding_id=None
                if level=='target_canary':
                    finding_id=uuid4();findings+=1
                    now=datetime.now(timezone.utc).isoformat()
                    fingerprint=hashlib.sha256(candidate.prompt.encode()).hexdigest()
                    document={'schema_version':'1.0.0','finding_id':str(finding_id),'tenant_id':str(tenant),'state':'CONFIRMED','root_cause':'The target agent disclosed a server-side canary that was absent from the attack payload.','title':'Target-side canary disclosure','severity':'CRITICAL','campaign_id':str(campaign_id),'run_id':str(run_id),'successful_mutations':list(candidate.mutations_applied),'evidence_level':level,'evidence_pattern':f'sha256:{response_hash}','evidence_backed':True,'remediation':'Tighten instruction boundaries, tool authorization and secret isolation; then replay this regression case.','regression_fingerprint':fingerprint,'created_at':now,'updated_at':now}
                    if self.deep_analysis is not None:
                        document['aegis']=self.deep_analysis.analyze_finding(document)
                    conn.execute("INSERT INTO platform.findings(tenant_id,id,workspace_id,environment_id,state,document) VALUES(%s,%s,%s,%s,'CONFIRMED',%s)",(tenant,finding_id,campaign['workspace_id'],campaign['environment_id'],psycopg.types.json.Jsonb(document)))
                    conn.execute("INSERT INTO platform.regression_cases(tenant_id,id,finding_id,campaign_id,payload) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,finding_id) DO NOTHING",(tenant,uuid4(),finding_id,campaign_id,candidate.prompt))
                conn.execute('INSERT INTO platform.campaign_candidates(tenant_id,id,run_id,generation,lineage,payload,response_hash,fitness,evidence_level,finding_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(tenant,uuid4(),run_id,candidate.generation,psycopg.types.json.Jsonb(candidate.mutations_applied),candidate.prompt,response_hash,candidate.fitness_score,level,finding_id))
                evidence['candidates'].append({'generation':candidate.generation,'lineage':candidate.mutations_applied,'fitness':candidate.fitness_score,'response_hash':response_hash,'evidence_level':level,'finding_id':str(finding_id) if finding_id else None})
            content=(json.dumps(evidence,separators=(',',':'),sort_keys=True)+'\n').encode();digest=hashlib.sha256(content).hexdigest();key=f'{tenant}/campaigns/{run_id}.json'
            meta=self.objects.put(tenant,key,content,sha256=digest,media_type='application/json')
            evidence_id=uuid5(UUID(str(run_id)),'campaign-evidence')
            evidence_document={'schema_version':'1.0.0','kind':'campaign_run','campaign_id':str(campaign_id),'run_id':str(run_id),'object_hash':digest,'candidate_count':result.candidates_evaluated,'finding_count':findings}
            conn.execute('INSERT INTO platform.evidence_objects(tenant_id,id,workspace_id,environment_id,event_id,object_key,media_type,size_bytes,object_hash,record_hash,signature,document) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s) ON CONFLICT(tenant_id,object_key) DO NOTHING',(tenant,evidence_id,campaign['workspace_id'],campaign['environment_id'],f'campaign-run:{run_id}',key,meta.media_type,meta.size_bytes,digest,digest,psycopg.types.json.Jsonb(evidence_document)))
            conn.execute("UPDATE platform.campaign_runs SET status='completed',completed_at=clock_timestamp(),candidates_evaluated=%s,findings_created=%s,best_score=%s,evidence_object_id=%s WHERE id=%s",(result.candidates_evaluated,findings,result.best_score,evidence_id,run_id))
        return {'status':'completed','run_id':run_id,'findings_created':findings,'evidence_key':key,'evidence_hash':digest}

class RegressionExecutor:
    def __init__(self,dsn,runner,secret_resolver=None):
        self.dsn,self.runner=dsn,runner;self.secrets=secret_resolver or EnvironmentSecretResolver()
    def __call__(self,envelope):
        tenant,case_id=envelope['tenant_id'],envelope['payload']['case_id']
        with psycopg.connect(self.dsn,row_factory=dict_row) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant,))
            case=conn.execute('SELECT r.id AS case_id,r.finding_id,r.payload,r.expected_block,c.* FROM platform.regression_cases r JOIN platform.campaigns c ON c.tenant_id=r.tenant_id AND c.id=r.campaign_id WHERE r.id=%s',(case_id,)).fetchone()
            if not case:raise ValueError('REGRESSION_CASE_NOT_FOUND')
        api_key=self.secrets(case['secret_ref']) if case['secret_ref'] else None
        canary=self.secrets(case['canary_secret_ref']) if case['canary_secret_ref'] else None
        result=self.runner(case,api_key=api_key,seed_prompt=case['payload'])
        leaked=any(canary_leaked(canary,candidate.response_sample or '',candidate.prompt) for candidate in result.candidates)
        status='reopened' if leaked else 'passed'
        with psycopg.connect(self.dsn) as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)",(tenant,))
            conn.execute('UPDATE platform.regression_cases SET status=%s,last_run_at=clock_timestamp() WHERE id=%s',(status,case_id))
            if leaked:conn.execute("UPDATE platform.findings SET state='REOPENED',document=jsonb_set(jsonb_set(document,'{state}',to_jsonb('REOPENED'::text)),'{updated_at}',to_jsonb(clock_timestamp()::text)),version=version+1,updated_at=clock_timestamp() WHERE id=%s",(case['finding_id'],))
            elif case['expected_block']:conn.execute("UPDATE platform.findings SET state='RESOLVED_VERIFIED',document=jsonb_set(jsonb_set(document,'{state}',to_jsonb('RESOLVED_VERIFIED'::text)),'{updated_at}',to_jsonb(clock_timestamp()::text)),version=version+1,updated_at=clock_timestamp() WHERE id=%s",(case['finding_id'],))
        return {'status':status,'case_id':case_id}
