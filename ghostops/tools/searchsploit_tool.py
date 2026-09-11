"""Searchsploit wrapper — query the LOCAL ExploitDB.

This directly attacks the "LLM hallucinates CVEs / exploit paths" gap: exploit
discovery is grounded in real ExploitDB data (via `searchsploit --json`), not
the model's memory. Results are stored as INFO findings (candidate exploits to
verify), not confirmed vulnerabilities.
"""
from __future__ import annotations

import json
import re

from ghostops.models import Finding, Severity
from ghostops.tools.base_tool import BaseTool, ToolResult

# Characters searchsploit has any use for. Everything else becomes a space -
# we normalize rather than reject, because the queries that matter come from
# nmap version banners full of ';', '(' and ','.
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9 ._\-/+]")

# nmap appends its extras after the first of these.
_BANNER_BREAK = re.compile(r"[;(\[,]")

# '2.4.7', '6.6.1p1', '1.14.0', '10.0' - starts with a digit.
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z._\-]*$")

_MAX_TOKENS = 6
_MAX_QUERY = 200


def normalize_query(raw: str) -> str:
    """Reduce whatever we were handed to a short, argv-safe product+version.

    'OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 Ubuntu Linux; protocol 2.0'
        -> 'OpenSSH 6.6.1p1'
    'Apache httpd 2.4.7 ((Ubuntu))'
        -> 'Apache httpd 2.4.7'

    A whole banner matches nothing in ExploitDB; product + version matches
    plenty. Every token is stripped of leading '-' so a query can never turn
    into a searchsploit FLAG - searchsploit folds a '-'-prefixed positional
    into its own option parsing, where -u triggers a package update and -m
    mirrors a file. That protection is the reason this sanitizes instead of
    simply allowing more characters through.
    """
    text = _BANNER_BREAK.split(str(raw or ""), 1)[0]
    text = _UNSAFE_CHARS.sub(" ", text)

    out: list[str] = []
    for token in text.split():
        token = token.lstrip("-")
        if not token:
            continue
        out.append(token)
        # Stop once we have a product AND a version; keep going for a
        # version-less banner like 'Postfix smtpd'.
        if len(out) > 1 and _VERSION_RE.match(token):
            break
        if len(out) >= _MAX_TOKENS:
            break
    return " ".join(out)[:_MAX_QUERY].strip()


class SearchsploitTool(BaseTool):
    name = "searchsploit"
    binary = "searchsploit"
    description = (
        "Search the local ExploitDB for known exploits by product/version or "
        "keyword. Grounds exploit discovery in real data (no invented CVEs). "
        "Args: query (required, e.g. 'OpenSSH 8.2' or 'Apache 2.4.41')."
    )
    args_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string",
                      "description": "product/version/keyword to search"},
        },
        "required": ["query"],
    }

    def validate_args(self, args: dict) -> tuple[bool, str]:
        ok, msg = super().validate_args(args)
        if not ok:
            return ok, msg
        raw = str(args.get("query", ""))
        if len(raw) > 4000:
            return False, "query is implausibly long"
        # Reject only what cannot be searched at all. A version banner is
        # normalized, never refused - a step the menu offers must be runnable.
        if not normalize_query(raw):
            return False, f"nothing searchable in query: {raw!r}"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        q = normalize_query(args.get("query", ""))
        tokens = [t for t in q.split() if not t.startswith("-")]
        return [self.binary, "--json", *tokens]

    def parse(self, result: ToolResult) -> None:
        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            result.summary = "searchsploit: no parseable results"
            return
        query = data.get("SEARCH", "")
        exploits = data.get("RESULTS_EXPLOIT", []) or []
        for ex in exploits[:20]:
            title = ex.get("Title", "").strip()
            edb = str(ex.get("EDB-ID", "")).strip()
            path = ex.get("Path", "").strip()
            refs = [f"EDB-{edb}"] if edb else []
            result.findings.append(Finding(
                title=f"Candidate exploit: {title}",
                severity=Severity.INFO,
                source="searchsploit",
                references=refs,
                description=f"ExploitDB path: {path}",
            ))
        result.summary = (
            f"searchsploit: {len(exploits)} result(s)"
            + (f" for '{query}'." if query else ".")
        )
