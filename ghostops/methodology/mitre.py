"""GhostOps action -> MITRE ATT&CK technique mapping.

Curated (knowledge/mitre.yaml), so the report cites real technique IDs rather
than model-invented ones. `observed()` walks an engagement's structured data
(finding/credential sources, payload activity) and returns the deduped set of
techniques actually exercised, with provenance. Pure - no rich/console.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

_PATH = Path(__file__).resolve().parent.parent / "knowledge" / "mitre.yaml"


@dataclass(frozen=True)
class Technique:
    tactic: str
    id: str
    name: str


def available() -> bool:
    return _PATH.is_file()


@lru_cache(maxsize=1)
def _raw() -> dict:
    if not _PATH.is_file():
        return {}
    return yaml.safe_load(_PATH.read_text(encoding="utf-8")) or {}


def _techs(section: str, key: str) -> list[Technique]:
    entries = (_raw().get(section, {}) or {}).get(key, []) or []
    return [Technique(e.get("tactic", ""), e.get("id", ""), e.get("name", ""))
            for e in entries]


def for_tool(name: str) -> list[Technique]:
    return _techs("tools", (name or "").lower().strip())


def for_payload(category: str) -> list[Technique]:
    return _techs("payloads", (category or "").lower().strip())


def all_techniques() -> list[tuple[str, str, Technique]]:
    """Every mapping as (section, key, Technique) - for the static catalog view."""
    out: list[tuple[str, str, Technique]] = []
    raw = _raw()
    for section in ("tools", "payloads"):
        for key in raw.get(section, {}) or {}:
            for t in _techs(section, key):
                out.append((section, key, t))
    return out


# ATT&CK tactic order (for stable, kill-chain-like sorting of output).
_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]


def _tactic_rank(tactic: str) -> int:
    return _TACTIC_ORDER.index(tactic) if tactic in _TACTIC_ORDER else 99


def observed(engagement) -> list[tuple[Technique, list[str]]]:
    """Techniques actually exercised in an engagement, with provenance.

    Sources: finding.source and credential.source (the tools that produced
    results) and payload-kind activity entries ("generated <category>/<key>").
    Returns [(Technique, [provenance, ...])] sorted by ATT&CK tactic order.
    """
    acc: dict[str, tuple[Technique, set[str]]] = {}

    def add(t: Technique, prov: str) -> None:
        if not t.id:
            return
        if t.id not in acc:
            acc[t.id] = (t, set())
        acc[t.id][1].add(prov)

    sources: set[str] = set()
    for f in engagement.findings:
        if f.source:
            sources.add(f.source)
    for c in engagement.credentials:
        if c.source:
            sources.add(c.source)
    for src in sources:
        for t in for_tool(src):
            add(t, src)

    for a in engagement.activity:
        if a.kind == "payload" and a.summary.startswith("generated "):
            ref = a.summary.split(" ", 1)[1].split()[0]   # e.g. revshell/python3
            category = ref.split("/")[0]
            for t in for_payload(category):
                add(t, f"payload:{category}")

    return sorted(
        ((t, sorted(prov)) for t, prov in acc.values()),
        key=lambda item: (_tactic_rank(item[0].tactic), item[0].id),
    )
