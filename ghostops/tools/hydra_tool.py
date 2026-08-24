"""Hydra wrapper — online password brute-forcing against a login service.

Parses hydra's success lines into Credential objects. VERY NOISY — always
gated by confirmation + scope guard (target host). Supports simple services
(ssh, ftp, etc.) where the syntax is `hydra -l user -P list host service`.
"""
from __future__ import annotations

import re

from ghostops.models import Credential, Finding, Severity
from ghostops.tools.base_tool import BaseTool, ToolResult

# [22][ssh] host: 10.0.0.5   login: root   password: toor
_HIT_RE = re.compile(
    r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)"
)
_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-]+$")
_SERVICES = {
    "ssh", "ftp", "telnet", "mysql", "postgres", "rdp", "smb",
    "vnc", "http-get", "https-get", "smtp", "pop3", "imap",
}


class HydraTool(BaseTool):
    name = "hydra"
    binary = "hydra"
    description = (
        "Online login brute-forcer. Tries username/password combos against a "
        "network service. VERY NOISY. Args: target (host, required), service "
        "(ssh|ftp|... required), username (single) OR userlist (file), "
        "password (single) OR passlist (file)."
    )
    args_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "host IP or name"},
            "service": {"type": "string", "description": "ssh, ftp, mysql, ..."},
            "username": {"type": "string", "description": "single username"},
            "userlist": {"type": "string", "description": "path to a userlist"},
            "password": {"type": "string", "description": "single password"},
            "passlist": {"type": "string", "description": "path to a passlist"},
        },
        "required": ["target", "service"],
    }

    def validate_args(self, args: dict) -> tuple[bool, str]:
        ok, msg = super().validate_args(args)
        if not ok:
            return ok, msg
        target = str(args.get("target", "")).strip()
        if not _HOST_RE.match(target):
            return False, f"invalid target: {target!r}"
        service = str(args.get("service", "")).strip().lower()
        if service not in _SERVICES:
            return False, (f"unsupported service {service!r}; "
                           f"supported: {', '.join(sorted(_SERVICES))}")
        if not (args.get("username") or args.get("userlist")):
            return False, "provide 'username' or 'userlist'"
        if not (args.get("password") or args.get("passlist")):
            return False, "provide 'password' or 'passlist'"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        target = str(args["target"]).strip()
        service = str(args["service"]).strip().lower()
        cmd = [self.binary]
        if args.get("username"):
            cmd += ["-l", str(args["username"]).strip()]
        else:
            cmd += ["-L", str(args["userlist"]).strip()]
        if args.get("password"):
            cmd += ["-p", str(args["password"]).strip()]
        else:
            cmd += ["-P", str(args["passlist"]).strip()]
        cmd += ["-t", "4", "-f", target, service]
        return cmd

    def parse(self, result: ToolResult) -> None:
        hits = 0
        for line in result.stdout.splitlines():
            m = _HIT_RE.search(line)
            if not m:
                continue
            hits += 1
            _, service, host, login, password = m.groups()
            result.credentials.append(Credential(
                service=service, host=host,
                username=login, secret=password, source="hydra",
            ))
            result.findings.append(Finding(
                title=f"Weak {service} credentials for '{login}'",
                severity=Severity.HIGH,
                host=host,
                description=f"hydra brute-forced a valid {service} login "
                            f"'{login}'.",
                source="hydra",
                references=["CWE-521"],
            ))
        result.summary = f"hydra: {hits} credential(s) recovered."
