"""Service enumeration checklists - loader, service matching, and suggestions.

Curated methodology (knowledge/checklists.yaml), not model-generated, so `next`
and `checklist` give concrete, correct steps rather than whatever a weak local
model might invent. Kept free of rich/console so it stays unit-testable; the
orchestrator/CLI render the dataclasses this returns.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

_PATH = Path(__file__).resolve().parent.parent / "knowledge" / "checklists.yaml"


@dataclass
class Check:
    task: str
    tool: str = ""
    cmd: str = ""
    why: str = ""
    noise: str = ""


@dataclass
class Checklist:
    key: str
    name: str
    ports: list[int] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    phase: str = "enumeration"
    checks: list[Check] = field(default_factory=list)


def available() -> bool:
    return _PATH.is_file()


@lru_cache(maxsize=1)
def _raw() -> dict:
    if not _PATH.is_file():
        return {}
    return yaml.safe_load(_PATH.read_text(encoding="utf-8")) or {}


@lru_cache(maxsize=1)
def _all() -> dict[str, Checklist]:
    out: dict[str, Checklist] = {}
    for key, meta in _raw().items():
        out[key] = Checklist(
            key=key,
            name=meta.get("name", key),
            ports=list(meta.get("ports", []) or []),
            names=[n.lower() for n in (meta.get("names", []) or [])],
            phase=meta.get("phase", "enumeration"),
            checks=[
                Check(
                    task=c.get("task", ""),
                    tool=c.get("tool", ""),
                    cmd=c.get("cmd", ""),
                    why=c.get("why", ""),
                    noise=c.get("noise", ""),
                )
                for c in (meta.get("checks", []) or [])
            ],
        )
    return out


def services() -> list[str]:
    return list(_all().keys())


def get(key: str) -> Checklist | None:
    return _all().get(key.lower())


def match(name: str = "", port: int | None = None) -> Checklist | None:
    """Find the checklist for a discovered service.

    Match by nmap service name first (most reliable), then fall back to the
    port number. A direct key hit (e.g. 'http') also works.
    """
    name = (name or "").lower().strip()
    lists = _all()
    if name in lists:
        return lists[name]
    if name:
        for cl in lists.values():
            if name in cl.names:
                return cl
    if port is not None:
        for cl in lists.values():
            if port in cl.ports:
                return cl
    return None


def render_cmd(cmd: str, host: str = "", port: int | str = "") -> str:
    """Fill {host}/{port} by literal replacement (templates hold other braces)."""
    out = cmd
    if host:
        out = out.replace("{host}", str(host))
    if port != "" and port is not None:
        out = out.replace("{port}", str(port))
    return out
