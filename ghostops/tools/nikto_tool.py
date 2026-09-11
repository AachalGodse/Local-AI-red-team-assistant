"""Nikto wrapper — web server vulnerability scanner.

Runs non-interactively against a URL and parses nikto's '+ ' report lines into
structured findings. NOISY/intrusive: always gated by the orchestrator's confirm
prompt + scope guard (host taken from the URL). subprocess runs a list argv (no
shell), and the URL is validated, so there is no injection surface.

Findings are tagged INFO ('observed'), never inflated - nikto is
false-positive-prone, so severity judgement is left to the operator, and the
model never invents or re-rates them.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ghostops.models import Finding, Severity
from ghostops.tools.base_tool import BaseTool, ToolResult

_REF_RE = re.compile(r"(?:CVE-\d{4}-\d{4,7}|OSVDB-\d+)", re.IGNORECASE)
# '+ ' lines that are bookkeeping/banner, not findings:
_SKIP_PREFIXES = (
    "target ip", "target hostname", "target port", "start time", "end time",
    "host(s) tested",
)
_SUMMARY_RE = re.compile(r"^\d+\s+requests?:", re.IGNORECASE)


class NiktoTool(BaseTool):
    name = "nikto"
    binary = "nikto"
    intrusive = True
    description = (
        "Web server vulnerability scanner. Flags dangerous files, outdated "
        "software, and misconfigurations on an HTTP(S) service. NOISY. "
        "Args: url (required, e.g. http://10.0.0.5:8080)."
    )
    args_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "target URL, e.g. http://10.0.0.5:8080"},
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
            return False, f"url must be http(s)://host[:port], got {url!r}"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        url = str(args["url"]).strip()
        # list argv, no shell -> no injection. -nointeractive/-ask no keep it
        # from prompting or phoning home mid-scan.
        return [self.binary, "-h", url, "-nointeractive", "-ask", "no"]

    def parse(self, result: ToolResult) -> None:
        host = ""
        try:
            host = urlparse(
                result.command[result.command.index("-h") + 1]).hostname or ""
        except (ValueError, IndexError):
            pass

        found = 0
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            item = line[2:].strip()
            low = item.lower()
            if not item or low.startswith(_SKIP_PREFIXES) or _SUMMARY_RE.match(low):
                continue
            refs = [r.upper() for r in _REF_RE.findall(item)]
            result.findings.append(Finding(
                title=f"nikto: {item[:120]}",
                severity=Severity.INFO,        # observed - never inflated
                host=host,
                description=item,
                source="nikto",
                references=refs,
            ))
            found += 1
        result.summary = f"nikto: {found} item(s) reported on {host or 'target'}."
