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

_QUERY_RE = re.compile(r"^[A-Za-z0-9 ._\-/+]+$")


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
        q = str(args.get("query", "")).strip()
        if not q or len(q) > 200:
            return False, "query must be 1-200 characters"
        if not _QUERY_RE.match(q):
            return False, f"query has unsupported characters: {q!r}"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        q = str(args["query"]).strip()
        return [self.binary, "--json", *q.split()]

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
