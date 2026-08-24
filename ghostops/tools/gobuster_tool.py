"""Gobuster wrapper — directory/content brute-forcing over HTTP(S).

Execute -> parse discovered paths -> findings. The scope guard checks the
hostname extracted from the URL, so gobuster can never be pointed at an
out-of-scope host.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ghostops.models import Finding, Severity
from ghostops.tools.base_tool import BaseTool, ToolResult

# gobuster -q lines look like:  /admin (Status: 301) [Size: 312]
_LINE_RE = re.compile(
    r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?"
)
_EXT_RE = re.compile(r"^[A-Za-z0-9,]+$")


class GobusterTool(BaseTool):
    name = "gobuster"
    binary = "gobuster"
    description = (
        "Directory/content brute-forcer for web servers. Finds hidden paths "
        "and files. Args: url (required, e.g. http://10.0.0.5:8080), wordlist "
        "(optional), extensions (optional, e.g. 'php,txt')."
    )
    args_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string",
                    "description": "target URL, e.g. http://10.0.0.5:8080"},
            "wordlist": {"type": "string", "description": "path to a wordlist"},
            "extensions": {"type": "string",
                           "description": "comma list, e.g. php,html"},
        },
        "required": ["url"],
    }

    def __init__(self, timeout: int = 600, default_args: str = "",
                 wordlist: str = ""):
        super().__init__(timeout, default_args)
        self.wordlist = wordlist
        self._host = ""

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
        wl = str(args.get("wordlist") or self.wordlist).strip()
        if not wl:
            return False, "no wordlist configured (set tools.gobuster.wordlist)"
        ext = str(args.get("extensions", "")).strip()
        if ext and not _EXT_RE.match(ext):
            return False, f"invalid extensions token: {ext!r}"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        url = str(args["url"]).strip()
        self._host = urlparse(url).hostname or ""
        wl = str(args.get("wordlist") or self.wordlist).strip()
        cmd = [self.binary, "dir", "-u", url, "-w", wl, "-q", "--no-color"]
        ext = str(args.get("extensions", "")).strip()
        if ext:
            cmd += ["-x", ext]
        return cmd

    def parse(self, result: ToolResult) -> None:
        found = 0
        for line in result.stdout.splitlines():
            m = _LINE_RE.match(line.strip())
            if not m:
                continue
            path, status, size = m.group(1), m.group(2), m.group(3)
            found += 1
            result.findings.append(Finding(
                title=f"path {path} (HTTP {status})",
                severity=Severity.INFO,
                host=self._host,
                description=f"gobuster found {path} "
                            f"status={status} size={size or '?'}",
                source="gobuster",
            ))
        result.summary = f"gobuster: {found} path(s) found."
