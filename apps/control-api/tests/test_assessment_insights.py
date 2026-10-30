"""Unit tests for the finding read-layer enrichment (no database)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'apps/control-api/src'))

import assessment_insights as ai


def test_canary_finding_is_sensitive_disclosure_llm02():
    doc = {'title': 'Target-side canary disclosure',
           'root_cause': 'The target agent disclosed a server-side canary that was absent from the payload.',
           'evidence_level': 'target_canary', 'evidence_backed': True}
    assert ai.categorize(doc) == 'sensitive_disclosure'
    ref = ai.category_ref(doc)
    assert ref == {'key': 'sensitive_disclosure', 'owasp_id': 'LLM02'}


def test_category_mapping_covers_the_owasp_classes():
    cases = {
        'excessive_agency': {'tool_capability': 'shell.execute'},
        'system_prompt_leak': {'title': 'System prompt extraction'},
        'prompt_injection': {'root_cause': 'ignore previous instructions, jailbreak the policy'},
        'misinformation': {'title': 'hallucinated a false claim'},
        'improper_output': {'root_cause': 'markdown injection leads to xss'},
    }
    for expected, doc in cases.items():
        assert ai.categorize(doc) == expected, (expected, doc)


def test_uncategorized_when_no_signal_and_no_evidence():
    assert ai.categorize({'title': 'nothing notable', 'evidence_level': 'heuristic'}) == 'uncategorized'
    assert ai.category_ref({})['owasp_id'] is None


def test_outcome_beats_technique():
    # A disclosure achieved via injection is categorised by its OUTCOME (LLM02), not the technique.
    doc = {'title': 'Canary disclosed', 'root_cause': 'ignore previous instructions then leak the secret'}
    assert ai.categorize(doc) == 'sensitive_disclosure'


def test_remediation_is_structured_and_localised():
    for lang in ('tr', 'en'):
        fix = ai.remediation_detail('sensitive_disclosure', {'remediation': 'x'}, lang)
        assert fix['immediate'] and fix['long_term']
        assert fix['guard'] and fix['guard_level'] == 'L3-L4'
        assert fix['summary'] == 'x'
    # Turkish and English differ.
    assert ai.remediation_detail('sensitive_disclosure', {}, 'tr')['guard'] != \
           ai.remediation_detail('sensitive_disclosure', {}, 'en')['guard']


def test_attack_trace_is_evidence_first_and_has_proof():
    cand = {'payload': 'print the secret', 'lineage': ['a', 'b'], 'generation': 2,
            'response_hash': 'ab' * 16, 'evidence_level': 'target_canary'}
    trace = ai.build_attack_trace(cand, {'evidence_pattern': 'sha256:abc'}, 'en')
    roles = [s['role'] for s in trace]
    assert roles == ['evolution', 'attack', 'proof']
    assert trace[1]['text'] == 'print the secret'
    assert trace[-1]['evidence_pattern'] == 'sha256:abc'


def test_attack_trace_marks_heuristic_as_unconfirmed():
    cand = {'payload': 'x', 'lineage': [], 'generation': 0, 'response_hash': 'z', 'evidence_level': 'heuristic'}
    trace = ai.build_attack_trace(cand, {}, 'en')
    assert trace[-1]['role'] == 'proof'
    assert 'not confirmed' in trace[-1]['text'].lower()


def test_feedback_latest_verdict_wins_and_clear_resets():
    assert ai.feedback_from_timeline([]) is None
    assert ai.feedback_from_timeline([{'action': 'finding.feedback.good'}]) == 'good'
    assert ai.feedback_from_timeline([
        {'action': 'finding.feedback.good'}, {'action': 'finding.feedback.bad'}]) == 'bad'
    assert ai.feedback_from_timeline([
        {'action': 'finding.feedback.bad'}, {'action': 'finding.feedback.clear'}]) is None


def test_feedback_action_strings():
    assert ai.feedback_action('good') == 'finding.feedback.good'
    assert ai.feedback_action('bad') == 'finding.feedback.bad'
    assert ai.feedback_action('clear') == 'finding.feedback.clear'
