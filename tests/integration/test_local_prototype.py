from types import SimpleNamespace

import pytest

from dashboard.local_runtime import LocalSettings,PrototypeRuntime


def test_local_runtime_is_tenant_scoped_bounded_and_idempotent():
    runtime=PrototypeRuntime(LocalSettings(queue_capacity=10,cache_capacity=10))
    result=SimpleNamespace(campaign_id='c1',target='app.test',executed=2,refused=0,
        killed=False,budget_exhausted=False,unauthorized=False,observations=({'candidate_id':'x'},))
    artifact=runtime.capture_campaign(result)
    assert artifact['key'].startswith('agentguard-lab/')
    assert runtime.cache.get('agentguard-lab','last_campaign')['executed']==2
    assert runtime.analytics.summary('agentguard-lab')==[{'kind':'red_team.completed','events':1}]
    with pytest.raises(ValueError):runtime.objects.get('other-tenant',artifact['key'])
    with pytest.raises(RuntimeError):
        for index in range(11):runtime.events.publish('agentguard-lab',{'event_id':f'e{index}'})


def test_local_runtime_rejects_non_prototype_profile():
    with pytest.raises(ValueError):LocalSettings(profile='production')


def test_dashboard_renders_without_external_services():
    from pathlib import Path
    from streamlit.testing.v1 import AppTest
    root=Path(__file__).resolve().parents[2]
    app=AppTest.from_file(str(root/'dashboard/app.py')).run(timeout=15)
    assert not app.exception
    assert any('AgentGuard Security Operations' in item.value for item in app.markdown)
    twin_button=next(button for button in app.button if button.label=='Run defense twin')
    app=twin_button.click().run(timeout=15)
    assert not app.exception
    assert any(metric.label=='Defenses held' and metric.value=='12/12' for metric in app.metric)

def test_p3_failure_drill_passes_without_external_services():
    from benchmarks.platform_failure_drill import run
    result=run();assert result['passed'];assert all(result['checks'].values())
