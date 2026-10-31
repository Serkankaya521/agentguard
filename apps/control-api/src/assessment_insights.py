"""Read-layer enrichment for findings: category, OWASP LLM Top 10 mapping,
structured remediation, attack reconstruction and analyst feedback.

Nothing here changes the stored finding document or the shared finding schema.
It derives presentation facts deterministically from fields the engine already
writes, so a finding categorises the same way every time it is read. Raw target
responses are never stored (privacy), so the attack reconstruction shows the
tenant's own attack input plus the deterministic proof, never a model transcript.
"""
from __future__ import annotations

from typing import Literal

Lang = Literal['tr', 'en']

# --- Attack categories, each mapped to exactly one OWASP LLM Top 10 (2025) class ---
# Ordered: categorisation walks this list and takes the first outcome that matches,
# so more specific outcomes (disclosure, agency) are tested before technique-only
# signals (injection). Categorise by the OUTCOME, not the technique used.
CATEGORIES: dict[str, dict] = {
    'sensitive_disclosure': {
        'owasp': 'LLM02',
        'label': {'tr': 'Hassas bilgi ifşası', 'en': 'Sensitive information disclosure'},
        'owasp_title': {'tr': 'Hassas Bilgi İfşası', 'en': 'Sensitive Information Disclosure'},
        'markers': ('canary', 'secret', 'credential', 'api key', 'api-key', 'apikey',
                    'password', 'private key', 'access key', 'token leak', 'disclos',
                    'exfil', 'pii', 'sensitive data', 'data leak', 'leaked'),
    },
    'system_prompt_leak': {
        'owasp': 'LLM07',
        'label': {'tr': 'Sistem komutu sızıntısı', 'en': 'System prompt leakage'},
        'owasp_title': {'tr': 'Sistem Komutu Sızıntısı', 'en': 'System Prompt Leakage'},
        'markers': ('system prompt', 'system instruction', 'prompt extraction',
                    'prompt leak', 'reveal your instructions', 'initial instructions'),
    },
    'excessive_agency': {
        'owasp': 'LLM06',
        'label': {'tr': 'Aşırı yetki', 'en': 'Excessive agency'},
        'owasp_title': {'tr': 'Aşırı Yetki', 'en': 'Excessive Agency'},
        'markers': ('unauthorized', 'unauthorised', 'tool call', 'tool invocation',
                    'invoked tool', 'executed action', 'privilege', 'agency',
                    'performed an action', 'destructive action'),
    },
    'prompt_injection': {
        'owasp': 'LLM01',
        'label': {'tr': 'Komut enjeksiyonu', 'en': 'Prompt injection'},
        'owasp_title': {'tr': 'Komut Enjeksiyonu', 'en': 'Prompt Injection'},
        'markers': ('prompt injection', 'instruction override', 'ignore previous',
                    'ignore all previous', 'jailbreak', 'bypass', 'override your',
                    'disregard the above'),
    },
    'improper_output': {
        'owasp': 'LLM05',
        'label': {'tr': 'Hatalı çıktı işleme', 'en': 'Improper output handling'},
        'owasp_title': {'tr': 'Hatalı Çıktı İşleme', 'en': 'Improper Output Handling'},
        'markers': ('improper output', 'markdown injection', 'html injection',
                    'xss', 'script injection', 'unescaped'),
    },
    'misinformation': {
        'owasp': 'LLM09',
        'label': {'tr': 'Yanlış bilgi', 'en': 'Misinformation'},
        'owasp_title': {'tr': 'Yanlış Bilgi', 'en': 'Misinformation'},
        'markers': ('hallucinat', 'misinformation', 'fabricat', 'false claim',
                    'made up', 'unsupported claim'),
    },
    'uncategorized': {
        'owasp': None,
        'label': {'tr': 'Sınıflandırılmamış', 'en': 'Uncategorized'},
        'owasp_title': {'tr': 'Genel', 'en': 'General'},
        'markers': (),
    },
}

_ORDER = ['excessive_agency', 'system_prompt_leak', 'sensitive_disclosure',
          'prompt_injection', 'improper_output', 'misinformation']

OWASP_REFERENCE = 'https://genai.owasp.org/llm-top-10/'


def categorize(document: dict) -> str:
    """Deterministically pick a category key from fields the engine already writes."""
    if not document:
        return 'uncategorized'
    # A tool/capability field is strong evidence of an agency outcome.
    if document.get('tool_capability'):
        return 'excessive_agency'
    parts = [str(document.get(field, '')) for field in
             ('title', 'root_cause', 'remediation', 'evidence_level')]
    mutations = document.get('successful_mutations') or []
    if isinstance(mutations, list):
        parts.extend(str(m) for m in mutations)
    haystack = ' '.join(parts).lower()
    for key in _ORDER:
        if any(marker in haystack for marker in CATEGORIES[key]['markers']):
            return key
    # An evidence-backed finding with no textual signal is still a real disclosure.
    if document.get('evidence_backed') or document.get('evidence_level') in ('target_canary', 'tool_observation'):
        return 'sensitive_disclosure'
    return 'uncategorized'


def category_facts(category_key: str, lang: Lang = 'en') -> dict:
    cat = CATEGORIES.get(category_key, CATEGORIES['uncategorized'])
    return {
        'key': category_key,
        'label': cat['label'][lang],
        'owasp_id': cat['owasp'],
        'owasp_title': cat['owasp_title'][lang],
        'owasp_url': OWASP_REFERENCE,
    }


def category_ref(document: dict) -> dict:
    """Language-neutral category reference for a finding: key + OWASP id.

    The console renders the human label from its own i18n so categories read the
    same as the rest of the UI; the PDF uses the language-aware helpers above.
    """
    key = categorize(document or {})
    return {'key': key, 'owasp_id': CATEGORIES[key]['owasp']}


def enrich_finding(document: dict, lang: Lang = 'en') -> dict:
    """Category + OWASP facts for a single finding, language-aware."""
    return category_facts(categorize(document or {}), lang)


# --- Structured remediation: immediate vs long-term, plus the guard that blocks it ---
# `guard` names the runtime output/input guard layer that would stop this class at
# runtime, with a defense depth level (L1 cheapest rule .. L4 strongest), matching
# the "find then block" architecture.
REMEDIATION: dict[str, dict] = {
    'sensitive_disclosure': {
        'immediate': {
            'tr': ['Sistem komutuna sırların ve iç verilerin asla paylaşılmayacağına dair açık sınır ekleyin.',
                   'Gizli değerleri (anahtar, parola, canary) ajanın erişebildiği bağlamdan çıkarın.'],
            'en': ['Add an explicit boundary to the system prompt forbidding disclosure of secrets and internal data.',
                   'Remove secret values (keys, passwords, canaries) from the context the agent can read.'],
        },
        'long_term': {
            'tr': ['Sır yönetimini ajandan ayırın; sırlar yalnızca sunucu tarafında, ajanın göremeyeceği yerde dursun.',
                   'Çıkış tarafında sır/sızıntı yakalayan koruma katmanını devreye alın.'],
            'en': ['Isolate secret management from the agent; secrets stay server-side, out of the agent\'s view.',
                   'Deploy the output-side secret-leak guard layer.'],
        },
        'guard': {'tr': 'Çıkış sır sızıntısı koruması', 'en': 'Output secret-leak guard'}, 'guard_level': 'L3-L4',
    },
    'system_prompt_leak': {
        'immediate': {
            'tr': ['Sistem komutunu talep eden girişleri reddedin; komut içeriğini tekrar etmemesini açıkça belirtin.'],
            'en': ['Refuse inputs that request the system prompt; explicitly instruct the agent not to repeat its instructions.'],
        },
        'long_term': {
            'tr': ['Hassas talimatları model komutundan çıkarıp sunucu tarafı politikasına taşıyın.',
                   'Giriş tarafında komut-çıkarma denemelerini yakalayan filtreyi ekleyin.'],
            'en': ['Move sensitive instructions out of the model prompt into server-side policy.',
                   'Add an input filter that catches prompt-extraction attempts.'],
        },
        'guard': {'tr': 'Giriş komut-sızıntısı filtresi', 'en': 'Input prompt-leak filter'}, 'guard_level': 'L3',
    },
    'excessive_agency': {
        'immediate': {
            'tr': ['Araç/aksiyon çağrılarını yalnızca izin verilenlerle (allowlist) sınırlayın.',
                   'Yüksek etkili işlemler için onay (approval) zorunlu kılın.'],
            'en': ['Restrict tool/action calls to an allowlist of permitted capabilities.',
                   'Require approval for high-impact actions.'],
        },
        'long_term': {
            'tr': ['Yetkiyi yetenek kaydından (capability registry) verin, araç adından değil.',
                   'Araç çağrılarını argüman şemasıyla ve politikayla kapıda denetleyin.'],
            'en': ['Grant authority from the capability registry, not tool-name inference.',
                   'Gate tool calls at runtime with argument-schema and policy checks.'],
        },
        'guard': {'tr': 'Araç çağrısı kapısı', 'en': 'Tool-call gating'}, 'guard_level': 'L4',
    },
    'prompt_injection': {
        'immediate': {
            'tr': ['Kullanıcı girdisini güvenilir talimattan ayırın; girdiyi komut olarak yorumlamayın.'],
            'en': ['Separate user input from trusted instructions; do not treat input as commands.'],
        },
        'long_term': {
            'tr': ['Giriş tarafına enjeksiyon/jailbreak sınıflandırıcısı ekleyin.',
                   'Riskli girişlerde onay veya adım-yükseltme (step-up) uygulayın.'],
            'en': ['Add an injection/jailbreak classifier on the input side.',
                   'Apply approval or step-up on risky inputs.'],
        },
        'guard': {'tr': 'Giriş enjeksiyon filtresi', 'en': 'Input injection filter'}, 'guard_level': 'L3-L4',
    },
    'improper_output': {
        'immediate': {
            'tr': ['Ajan çıktısını tüketen tarafta kaçış/temizleme (sanitize) uygulayın.'],
            'en': ['Escape/sanitize agent output where it is consumed.'],
        },
        'long_term': {
            'tr': ['Çıktıyı yapılandırılmış ve doğrulanmış biçime zorlayın; serbest HTML/markdown render etmeyin.'],
            'en': ['Force output into a structured, validated form; do not render free HTML/markdown.'],
        },
        'guard': {'tr': 'Çıkış içerik temizleme', 'en': 'Output sanitisation'}, 'guard_level': 'L2-L3',
    },
    'misinformation': {
        'immediate': {
            'tr': ['Doğrulanabilir alanlarda kaynak/dayanak zorunlu kılın; emin olunmayan cevabı işaretleyin.'],
            'en': ['Require sources/grounding in verifiable domains; flag low-confidence answers.'],
        },
        'long_term': {
            'tr': ['Kritik alanlarda cevabı güvenilir kaynağa karşı doğrulayan bir kontrol ekleyin.'],
            'en': ['Add a check that verifies answers against a trusted source in critical domains.'],
        },
        'guard': {'tr': 'Çıktı dayanak kontrolü', 'en': 'Output grounding check'}, 'guard_level': 'L3',
    },
    'uncategorized': {
        'immediate': {
            'tr': ['Talimat sınırlarını, araç yetkisini ve sır izolasyonunu gözden geçirin.'],
            'en': ['Review instruction boundaries, tool authorisation and secret isolation.'],
        },
        'long_term': {
            'tr': ['Bulguyu bir saldırı sınıfına göre sınıflandırıp uygun koruma katmanını eşleyin.'],
            'en': ['Classify the finding into an attack class and map the matching guard layer.'],
        },
        'guard': {'tr': 'Genel koruma', 'en': 'General guard'}, 'guard_level': '—',
    },
}


def remediation_detail(category_key: str, document: dict | None, lang: Lang = 'en') -> dict:
    """Structured fix guidance. The stored free-text remediation is kept as the summary."""
    spec = REMEDIATION.get(category_key, REMEDIATION['uncategorized'])
    summary = ''
    if document:
        summary = str(document.get('remediation', '') or '')
    return {
        'summary': summary,
        'immediate': list(spec['immediate'][lang]),
        'long_term': list(spec['long_term'][lang]),
        'guard': spec['guard'][lang],
        'guard_level': spec['guard_level'],
    }


def build_attack_trace(candidate: dict | None, document: dict | None, lang: Lang = 'en') -> list[dict]:
    """A faithful, evidence-first reconstruction of the confirmed attack.

    Raw target responses are never stored, so this shows the tenant's own attack
    input and the deterministic proof (planted marker present in the response yet
    absent from the input → confirmed), not a fabricated model transcript.
    """
    if not candidate:
        return []
    tr = lang == 'tr'
    steps: list[dict] = []
    lineage = candidate.get('lineage') or []
    generation = candidate.get('generation')
    if isinstance(lineage, list) and len(lineage) > 1:
        steps.append({
            'role': 'evolution',
            'label': 'Evrim' if tr else 'Evolution',
            'text': (f'Saldırı {len(lineage)} kuşak boyunca evrildi (kuşak {generation}).'
                     if tr else
                     f'The attack evolved across {len(lineage)} generations (generation {generation}).'),
        })
    steps.append({
        'role': 'attack',
        'label': 'Saldırı girdisi' if tr else 'Attack input',
        'text': str(candidate.get('payload', '')),
    })
    level = candidate.get('evidence_level')
    pattern = (document or {}).get('evidence_pattern') or (
        f"sha256:{candidate.get('response_hash')}" if candidate.get('response_hash') else '')
    if level in ('target_canary', 'tool_observation'):
        proof = ('Ekilen canary değeri, saldırı girdisinde olmadığı halde hedefin cevabında belirdi '
                 '→ kesin sızıntı (olasılıksal yargı değil).'
                 if tr else
                 'The planted canary appeared in the target response though it was absent from the '
                 'attack input → confirmed leak (not a probabilistic judgement).')
        if level == 'tool_observation':
            proof = ('Hedefin bir araç çağrısı gözlemlendi ve beklenen sınırın dışına çıktı → kesin kanıt.'
                     if tr else
                     'A tool invocation by the target was observed crossing the expected boundary → deterministic proof.')
        steps.append({
            'role': 'proof',
            'label': 'Kesin kanıt' if tr else 'Deterministic proof',
            'text': proof,
            'evidence_pattern': pattern,
        })
    else:
        steps.append({
            'role': 'proof',
            'label': 'Kanıt' if tr else 'Evidence',
            'text': ('Sezgisel sinyal — doğrulanmış kanıt değil; yalnızca inceleme için.'
                     if tr else
                     'Heuristic signal — not confirmed evidence; for review only.'),
            'evidence_pattern': pattern,
        })
    return steps


# --- Analyst feedback, stored append-only as audit actions on the finding ---
FEEDBACK_GOOD = 'finding.feedback.good'
FEEDBACK_BAD = 'finding.feedback.bad'
FEEDBACK_CLEAR = 'finding.feedback.clear'
FEEDBACK_ACTIONS = {FEEDBACK_GOOD: 'good', FEEDBACK_BAD: 'bad', FEEDBACK_CLEAR: None}


def feedback_action(verdict: str) -> str:
    """Map an analyst verdict to its audit action string."""
    return {'good': FEEDBACK_GOOD, 'bad': FEEDBACK_BAD, 'clear': FEEDBACK_CLEAR}[verdict]


def feedback_from_timeline(timeline: list[dict]) -> str | None:
    """Latest analyst verdict ('good'|'bad') from the finding's audit chain, or None."""
    verdict: str | None = None
    for entry in timeline:  # timeline is ordered oldest→newest by audit id
        action = entry.get('action')
        if action in FEEDBACK_ACTIONS:
            verdict = FEEDBACK_ACTIONS[action]
    return verdict
