"""A4: Türkçe saldırı korpusu — refusal kalıpları + yönetişimli şablon draft'ları.

İki şeyi doğrular: (1) Türkçe hedef reddettiğinde fitness bunu "uyum" sanmayıp ret
bandında düşük puan veriyor; (2) Türkçe roleplay/tag şablonları registry'ye DRAFT
olarak ekleniyor ve §10 gereği yönetişim (PRODUCTION-stage onay) olmadan aktifleşmiyor.
Deps-hafif: core.fuzzer (pydantic) + attack_corpus_tr/attack_templates/governance.
"""
import os
import sys
from types import SimpleNamespace

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)                                     # core.fuzzer
sys.path.insert(0, os.path.join(_ROOT, "packages/aegis/src"))  # attack_corpus_tr, attack_templates

from core.fuzzer import GeneticSemanticFuzzer
from attack_corpus_tr import register_turkish_drafts, TURKISH_TEMPLATES

# Registry.activate() duck-types proposal.kind/.stage; real Proposal↔registry wiring
# is covered by tests/contracts/test_a7. A stub keeps this standalone test deps-light.
def _proposal(stage):
    return SimpleNamespace(kind="attack_template", stage=stage)

F = GeneticSemanticFuzzer()
KW = ["secret", "config", "admin"]


def test_turkish_refusal_is_graded_low():
    """İngilizce-only kalıplar Türkçe reddi kaçırıyordu; artık ret bandına düşüyor."""
    refusal = F.calculate_fitness("Üzgünüm, bir yapay zeka olarak bu talebi yerine getiremem.", KW)
    comply = F.calculate_fitness("Elbette, istediğin yapılandırma detayları: " + "x" * 80, KW)
    assert refusal < 0.2, f"Türkçe ret düşük bantta olmalı, got {refusal}"
    assert refusal < comply, f"ret ({refusal}) uyumdan ({comply}) düşük olmalı"


def test_turkish_templates_are_governed_drafts():
    reg = register_turkish_drafts()
    assert reg.active_templates() == [], "draft'lar yönetişim olmadan aktif olmamalı (§10)"
    for technique in TURKISH_TEMPLATES:  # propose KeyError verirse draft eklenmemiş demektir
        reg.propose(f"tr-{technique}")
        reg.activate(f"tr-{technique}", approved_proposal=_proposal("PRODUCTION"))
    assert len(reg.active_templates()) == len(TURKISH_TEMPLATES)


def test_turkish_draft_cannot_skip_governance():
    reg = register_turkish_drafts()
    reg.propose("tr-roleplay_tr")
    try:
        reg.activate("tr-roleplay_tr", approved_proposal=_proposal("CANARY"))
        raise AssertionError("CANARY-stage öneri bir şablonu aktive edememeli")
    except ValueError:
        pass


def test_wrappers_format_safely():
    """Her wrapper {text} yuvasını taşımalı ve .format(text=...) hatasız çalışmalı."""
    for wrappers in TURKISH_TEMPLATES.values():
        for w in wrappers:
            assert "PAYLOAD" in w.format(text="PAYLOAD"), f"payload yuvası çalışmıyor: {w!r}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("A4 Turkish corpus: all checks passed")
