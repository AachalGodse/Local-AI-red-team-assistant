"""Tests for the MITRE ATT&CK mapping. Run without Ollama or tools."""
import pytest

from ghostops.methodology import mitre
from ghostops.models import ActivityLog, Credential, Engagement, Finding

pytestmark = pytest.mark.skipif(
    not mitre.available(),
    reason="ATT&CK map not present on disk (AV quarantine? run on Kali)",
)


def test_for_tool_and_payload_lookups():
    assert "T1110" in {t.id for t in mitre.for_tool("hydra")}
    assert "T1190" in {t.id for t in mitre.for_tool("sqlmap")}
    assert "T1505.003" in {t.id for t in mitre.for_payload("webshell")}
    assert mitre.for_tool("does-not-exist") == []


def test_all_techniques_nonempty_and_well_formed():
    allt = mitre.all_techniques()
    assert len(allt) >= 10
    for section, key, tech in allt:
        assert section in ("tools", "payloads")
        assert tech.id and tech.tactic and tech.name


def test_observed_from_engagement_with_provenance():
    e = Engagement(id="x", scope=["10.0.0.1"])
    e.findings.append(Finding(title="ver", source="nmap", host="10.0.0.1"))
    e.findings.append(Finding(title="sqli", source="sqlmap", host="10.0.0.1"))
    e.credentials.append(Credential(service="ssh", source="hydra",
                                    host="10.0.0.1"))
    e.activity.append(ActivityLog(timestamp="t", kind="payload",
                                  summary="generated webshell/php", detail="PHP"))
    obs = mitre.observed(e)
    ids = {t.id for t, _ in obs}
    assert {"T1046", "T1190", "T1110", "T1505.003"}.issubset(ids)

    prov = {t.id: p for t, p in obs}
    assert "nmap" in prov["T1046"]
    assert any("webshell" in x for x in prov["T1505.003"])


def test_observed_sorted_by_tactic_order():
    e = Engagement(id="x")
    e.findings.append(Finding(title="a", source="nmap"))       # Discovery/Recon
    e.findings.append(Finding(title="b", source="sqlmap"))     # Initial Access
    e.credentials.append(Credential(service="ssh", source="hydra"))
    obs = mitre.observed(e)
    ranks = [mitre._tactic_rank(t.tactic) for t, _ in obs]
    assert ranks == sorted(ranks)


def test_observed_empty_when_nothing_done():
    assert mitre.observed(Engagement(id="y")) == []


def test_report_includes_attack_section():
    from ghostops.report.generator import render_markdown
    e = Engagement(id="z", name="t", scope=["10.0.0.1"], created_at="2026-01-01")
    e.findings.append(Finding(title="ver", source="nmap", host="10.0.0.1",
                             port=22))
    md = render_markdown(e)
    assert "MITRE ATT&CK Techniques" in md
    assert "T1046" in md
