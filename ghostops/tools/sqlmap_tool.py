"""SQLMap wrapper — automated SQL-injection testing on a discovered URL.

Runs non-interactively (--batch) and parses the summary for injection points
and the back-end DBMS. This is a NOISY/aggressive tool — it always passes
through the orchestrator's confirmation gate and scope guard (host taken from
the URL).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ghostops.models import Finding, Severity
from ghostops.tools.base_tool import BaseTool, ToolResult

_PARAM_RE = re.compile(r"^Parameter:\s*(.+?)\s*\((GET|POST|COOKIE|HEADER)\)")
_DBMS_RE = re.compile(r"back-end DBMS:\s*(.+)", re.IGNORECASE)
_NOT_INJECTABLE = "do not appear to be injectable"
_INJECTABLE_HINT = "sqlmap identified the following injection point"


class SqlmapTool(BaseTool):
    name = "sqlmap"
    binary = "sqlmap"
    intrusive = True
    description = (
        "Automated SQL-injection tester for web URLs. Detects injectable "
        "parameters and fingerprints the DBMS. NOISY. Args: url (required, "
        "e.g. http://host/page.php?id=1), data (optional POST body), level "
        "(1-5), risk (1-3)."
    )
    args_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "target URL with a parameter, e.g. ...?id=1"},
            "data": {"type": "string", "description": "POST data string"},
            "level": {"type": "integer", "description": "1-5 (default 1)"},
            "risk": {"type": "integer", "description": "1-3 (default 1)"},
        },
        "required": ["url"],
    }

    def scope_target(self, args: dict) -> str:
        try:
            return urlparse(str(args.get("url", ""))).hostname or ""
        except Exception:
            return ""

    def validate_args(self, args: dict) -> tuple[bool, str]:
        ok, msg = super().validate_args(args)
        if not ok:
            return ok, msg
        url = str(args.get("url", "")).strip()
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return False, f"url must be http(s)://..., got {url!r}"
        for key in ("level", "risk"):
            v = args.get(key)
            if v is not None and str(v) not in ("1", "2", "3", "4", "5"):
                if key == "risk" and str(v) in ("1", "2", "3"):
                    continue
                return False, f"{key} must be an integer in range"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        url = str(args["url"]).strip()
        level = str(args.get("level") or 1)
        risk = str(args.get("risk") or 1)
        cmd = [self.binary, "-u", url, "--batch",
               "--level", level, "--risk", risk, "--random-agent"]
        data = str(args.get("data", "")).strip()
        if data:
            cmd += ["--data", data]
        return cmd

    def parse(self, result: ToolResult) -> None:
        out = result.stdout
        host = ""
        try:
            host = urlparse(result.command[result.command.index("-u") + 1]).hostname or ""
        except (ValueError, IndexError):
            pass

        dbms = ""
        params: list[str] = []
        for line in out.splitlines():
            line = line.strip()
            pm = _PARAM_RE.match(line)
            if pm:
                params.append(f"{pm.group(1)} ({pm.group(2)})")
            dm = _DBMS_RE.search(line)
            if dm:
                dbms = dm.group(1).strip()

        injectable = bool(params) or (_INJECTABLE_HINT in out)
        if injectable:
            for p in (params or ["(parameter)"]):
                result.findings.append(Finding(
                    title=f"SQL injection in {p}",
                    severity=Severity.HIGH,
                    host=host,
                    description=f"sqlmap confirmed SQL injection. "
                                f"DBMS: {dbms or 'unknown'}.",
                    source="sqlmap",
                    references=["CWE-89"],
                ))
            result.summary = (
                f"sqlmap: INJECTABLE — {len(params) or 1} point(s), "
                f"DBMS={dbms or 'unknown'}."
            )
        elif _NOT_INJECTABLE in out:
            result.summary = "sqlmap: no injectable parameters found."
        else:
            result.summary = "sqlmap: run complete (no clear verdict parsed)."
