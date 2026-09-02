"""Payload generator - renders curated templates from the knowledge base.

Design (mirrors searchsploit_tool.py's grounding principle): payloads come from
a reviewed YAML catalog, NOT from the LLM. GhostOps_Plan.md lists "LLMs
fabricate wrong exploit syntax" as a core gap; asking the model to write a
reverse shell would reintroduce it. So we curate, and the model's only job is
to help pick an entry - never to author the bytes.

Substitution is literal string replacement (not str.format), because several
templates legitimately contain '{' / '}' (PowerShell's ${...}, awk blocks).
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

_KB_DIR = Path(__file__).resolve().parent.parent / "knowledge"
# Two on-disk forms are accepted, in priority order:
#   payloads.b64   base64 of the YAML text - carries no plaintext signatures,
#                  so it survives host AV (Windows Defender quarantines the
#                  plaintext form on sight). Preferred where present.
#   payloads.yaml  plaintext - fine on Kali/WSL where the tool actually runs.
_CATALOG_B64 = _KB_DIR / "payloads.b64"
_CATALOG_YAML = _KB_DIR / "payloads.yaml"

# Placeholders a caller may fill. Order doesn't matter - each is replaced
# independently and only where it actually appears in a template.
_PLACEHOLDERS = ("lhost", "lport", "shell", "param")

DEFAULTS = {"shell": "/bin/bash", "param": "cmd"}

# Sensible default payload per category, used when a category is requested with
# connection args but no explicit name.
DEFAULT_PAYLOAD = {
    "revshell": "bash",
    "bindshell": "nc-mkfifo",
    "webshell": "php",
    "listener": "nc",
    "tty": "python-pty",
    "privesc": "linux-enum",
}


class PayloadError(ValueError):
    """Raised for an unknown category/name or a missing required placeholder."""


@dataclass
class Payload:
    category: str
    key: str
    name: str
    lang: str
    runner: str
    noise: str
    requires: str
    opsec: str
    body: str            # rendered, ready to use

    @property
    def ref(self) -> str:
        return f"{self.category}/{self.key}"


@lru_cache(maxsize=1)
def _catalog() -> dict:
    if _CATALOG_B64.is_file():
        raw = base64.b64decode(_CATALOG_B64.read_text(encoding="ascii"))
        return yaml.safe_load(raw.decode("utf-8")) or {}
    if _CATALOG_YAML.is_file():
        return yaml.safe_load(_CATALOG_YAML.read_text(encoding="utf-8")) or {}
    raise PayloadError(
        "payload catalog not found. Expected "
        f"{_CATALOG_B64.name} or {_CATALOG_YAML.name} in {_KB_DIR}. "
        "On a host with antivirus (e.g. Windows Defender) the plaintext "
        "catalog is quarantined on sight - ship the base64 form, or add an "
        "AV exclusion for the project directory."
    )


def catalog_available() -> bool:
    """True if a usable catalog is present on disk."""
    return _CATALOG_B64.is_file() or _CATALOG_YAML.is_file()


def categories() -> list[str]:
    return list(_catalog().keys())


def list_payloads(category: str | None = None) -> list[Payload]:
    """Every payload (unrendered body) in a category, or in all categories."""
    cat = _catalog()
    cats = [category] if category else list(cat)
    out: list[Payload] = []
    for c in cats:
        entries = cat.get(c) or {}
        for key, meta in entries.items():
            out.append(_to_payload(c, key, meta, meta.get("template", "")))
    return out


def _to_payload(category: str, key: str, meta: dict, body: str) -> Payload:
    return Payload(
        category=category,
        key=key,
        name=meta.get("name", key),
        lang=meta.get("lang", "text"),
        runner=meta.get("runner", "none"),
        noise=meta.get("noise", "medium"),
        requires=meta.get("requires", ""),
        opsec=meta.get("opsec", ""),
        body=body,
    )


def _render_template(template: str, values: dict) -> str:
    out = template
    for name in _PLACEHOLDERS:
        token = "{" + name + "}"
        if token in out:
            val = values.get(name)
            if val is None or str(val) == "":
                raise PayloadError(f"this payload needs a value for '{name}'")
            out = out.replace(token, str(val))
    return out


def generate(
    category: str,
    key: str,
    *,
    lhost: str = "",
    lport: str | int = "",
    shell: str = DEFAULTS["shell"],
    param: str = DEFAULTS["param"],
    encode: bool = False,
) -> Payload:
    """Render one payload. Raises PayloadError on unknown ref or missing arg."""
    cat = _catalog()
    if category not in cat:
        raise PayloadError(
            f"unknown category {category!r}; choose from: {', '.join(cat)}"
        )
    entries = cat[category] or {}
    if key not in entries:
        raise PayloadError(
            f"unknown payload {category}/{key}; options: {', '.join(entries)}"
        )
    meta = entries[key]
    values = {"lhost": lhost, "lport": lport, "shell": shell, "param": param}
    body = _render_template(meta.get("template", ""), values)

    if encode:
        body = _encode(body, meta.get("runner", "none"))

    return _to_payload(category, key, meta, body)


def _encode(body: str, runner: str) -> str:
    """Wrap a rendered payload as a copy-paste base64 one-liner.

    - sh:         echo <b64> | base64 -d | sh     (raw bytes are UTF-8)
    - powershell: powershell -Enc <b64>           (UTF-16LE, per -EncodedCommand)
    - none:       not applicable (listeners, source snippets, enum blocks)
    """
    if runner == "sh":
        b64 = base64.b64encode(body.encode("utf-8")).decode("ascii")
        return f"echo {b64} | base64 -d | sh"
    if runner == "powershell":
        b64 = base64.b64encode(body.encode("utf-16-le")).decode("ascii")
        return f"powershell -NoP -NonI -W Hidden -Enc {b64}"
    raise PayloadError(
        f"--encode is only supported for sh/powershell payloads, not {runner!r}"
    )
