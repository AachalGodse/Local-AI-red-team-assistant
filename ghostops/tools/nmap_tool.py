"""Nmap wrapper — the reference vertical slice.

Execute -> parse XML -> structured Host/Service objects -> findings + summary.

Safety: the command is assembled from *structured* args (a fixed set of scan
profiles + validated port/target strings), never from a raw flag string handed
over by the LLM. subprocess runs with a list argv (no shell), so there is no
shell-injection surface.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ghostops.models import Finding, Host, Service, Severity
from ghostops.tools.base_tool import BaseTool, ToolResult

# scan profiles -> the flags they map to. The LLM/user picks a profile name;
# it can never inject arbitrary flags.
PROFILES: dict[str, list[str]] = {
    "quick":   ["-sV", "-T4", "--top-ports", "100"],
    "default": ["-sC", "-sV", "-T4"],
    "full":    ["-sC", "-sV", "-T4", "-p-"],
    "udp":     ["-sU", "-T4", "--top-ports", "50"],
    "stealth": ["-sS", "-sV", "-T2"],   # slower / quieter
}

# A conservative host-token validator: IPs, CIDRs, hostnames. Rejects spaces,
# shell metacharacters, etc.
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:\-/]+$")
_PORTS_RE = re.compile(r"^[0-9,\-]+$")


class NmapTool(BaseTool):
    name = "nmap"
    binary = "nmap"
    description = (
        "Network port/service scanner. Discovers open ports, identifies "
        "services and versions, and fingerprints the OS. Use for recon and "
        "scanning. Args: target (required), profile "
        "(quick|default|full|udp|stealth), ports (optional, e.g. '80,443')."
    )
    args_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "IP, CIDR, or hostname"},
            "profile": {
                "type": "string",
                "enum": list(PROFILES.keys()),
                "description": "scan intensity/type",
            },
            "ports": {"type": "string", "description": "explicit ports, e.g. 22,80,443"},
        },
        "required": ["target"],
    }

    def validate_args(self, args: dict) -> tuple[bool, str]:
        ok, msg = super().validate_args(args)
        if not ok:
            return ok, msg
        target = str(args.get("target", "")).strip()
        if not _TARGET_RE.match(target):
            return False, f"invalid target token: {target!r}"
        ports = str(args.get("ports", "")).strip()
        if ports and not _PORTS_RE.match(ports):
            return False, f"invalid ports token: {ports!r}"
        profile = args.get("profile", "default")
        if profile and profile not in PROFILES:
            return False, f"unknown profile: {profile!r}"
        return True, ""

    def build_command(self, args: dict) -> list[str]:
        target = str(args["target"]).strip()
        profile = args.get("profile") or "default"
        flags = list(PROFILES.get(profile, PROFILES["default"]))
        ports = str(args.get("ports", "")).strip()
        cmd = [self.binary, *flags]
        if ports:
            # explicit ports override the profile's port selection
            cmd = [c for c in cmd if c not in ("-p-", "--top-ports")]
            # also drop a stray top-ports count
            cmd = [c for c in cmd if not c.isdigit()]
            cmd += ["-p", ports]
        cmd += ["-oX", "-", target]   # XML to stdout for robust parsing
        return cmd

    # ---------------------------------------------------------------- parse
    def parse(self, result: ToolResult) -> None:
        xml = result.stdout.strip()
        if not xml.startswith("<?xml") and "<nmaprun" not in xml:
            # nmap wrote human text (e.g. an error). Keep stderr/stdout as-is.
            result.summary = "nmap produced no XML output"
            return
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as exc:
            result.error = f"nmap XML parse error: {exc}"
            return

        hosts: list[Host] = []
        findings: list[Finding] = []
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") == "down":
                continue
            addr = ""
            hostname = ""
            for a in host_el.findall("address"):
                if a.get("addrtype") in ("ipv4", "ipv6"):
                    addr = a.get("addr", "")
            hn = host_el.find("hostnames/hostname")
            if hn is not None:
                hostname = hn.get("name", "")
            os_str = ""
            osmatch = host_el.find("os/osmatch")
            if osmatch is not None:
                os_str = osmatch.get("name", "")

            host = Host(ip=addr or hostname, hostname=hostname, os=os_str)
            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                svc_el = port_el.find("service")
                svc = Service(
                    port=int(port_el.get("portid", 0)),
                    proto=port_el.get("protocol", "tcp"),
                )
                if svc_el is not None:
                    svc.name = svc_el.get("name", "")
                    svc.product = svc_el.get("product", "")
                    svc.version = svc_el.get("version", "")
                    svc.extra = svc_el.get("extrainfo", "")
                host.services.append(svc)

                # cheap heuristic finding: version disclosure
                if svc.product or svc.version:
                    findings.append(Finding(
                        title=f"{svc.name or 'service'} version disclosed on {svc.port}",
                        severity=Severity.INFO,
                        host=host.ip,
                        port=svc.port,
                        description=f"{svc.banner}".strip(),
                        source="nmap",
                    ))
            hosts.append(host)

        result.hosts = hosts
        result.findings = findings
        open_ports = sum(len(h.services) for h in hosts)
        result.summary = (
            f"nmap: {len(hosts)} host(s) up, {open_ports} open port(s)."
        )
