"""GhostOps data models — the structured backbone of an engagement.

Everything else (memory store, "what do we know?" summary, and the final
report) is just a view over these types. Get this schema right and the rest
follows.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Phase(str, Enum):
    """The pentest kill chain. Ordered — index gives progression."""

    RECON = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post-exploitation"
    REPORTING = "reporting"

    @property
    def order(self) -> int:
        return list(Phase).index(self)

    def next(self) -> "Phase":
        phases = list(Phase)
        return phases[min(self.order + 1, len(phases) - 1)]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


@dataclass
class Service:
    """A single network service on a host."""

    port: int
    proto: str = "tcp"
    name: str = ""            # e.g. "http", "ssh"
    product: str = ""         # e.g. "Apache httpd"
    version: str = ""         # e.g. "2.4.41"
    state: str = "open"
    extra: str = ""           # banner / extrainfo

    @property
    def banner(self) -> str:
        bits = [b for b in (self.product, self.version, self.extra) if b]
        return " ".join(bits)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Host:
    """A discovered host and its services."""

    ip: str
    hostname: str = ""
    os: str = ""
    status: str = "up"
    services: list[Service] = field(default_factory=list)

    def get_service(self, port: int, proto: str = "tcp") -> Optional[Service]:
        for s in self.services:
            if s.port == port and s.proto == proto:
                return s
        return None

    def upsert_service(self, service: Service) -> None:
        existing = self.get_service(service.port, service.proto)
        if existing:
            self.services[self.services.index(existing)] = service
        else:
            self.services.append(service)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class Finding:
    """A vulnerability or notable observation."""

    title: str
    severity: Severity = Severity.INFO
    host: str = ""            # ip it relates to
    port: Optional[int] = None
    description: str = ""
    source: str = ""          # tool or reasoning that produced it
    references: list[str] = field(default_factory=list)  # CVEs, URLs, EDB-IDs

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Credential:
    """A discovered credential."""

    service: str              # e.g. "ssh", "mysql"
    host: str = ""
    username: str = ""
    secret: str = ""          # password or hash
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ActivityLog:
    """One action taken during the engagement (audit trail + report input)."""

    timestamp: str
    kind: str                 # "tool", "note", "phase", "llm"
    summary: str
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Engagement:
    """The full state of a single engagement. This is what gets persisted."""

    id: str
    name: str = ""
    scope: list[str] = field(default_factory=list)   # IPs / CIDRs / hostnames allowed
    phase: Phase = Phase.RECON
    created_at: str = ""
    stealth: bool = False
    model: str = "dolphin-mistral"

    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    activity: list[ActivityLog] = field(default_factory=list)

    # ---- host helpers ----
    def get_host(self, ip: str) -> Optional[Host]:
        for h in self.hosts:
            if h.ip == ip:
                return h
        return None

    def upsert_host(self, host: Host) -> Host:
        existing = self.get_host(host.ip)
        if existing:
            # merge services rather than clobber
            for svc in host.services:
                existing.upsert_service(svc)
            if host.hostname and not existing.hostname:
                existing.hostname = host.hostname
            if host.os and not existing.os:
                existing.os = host.os
            return existing
        self.hosts.append(host)
        return host

    def add_finding(self, finding: Finding) -> None:
        # de-dupe on (title, host, port)
        key = (finding.title, finding.host, finding.port)
        for f in self.findings:
            if (f.title, f.host, f.port) == key:
                return
        self.findings.append(finding)

    def add_credential(self, cred: Credential) -> None:
        key = (cred.service, cred.host, cred.username, cred.secret)
        for c in self.credentials:
            if (c.service, c.host, c.username, c.secret) == key:
                return
        self.credentials.append(cred)

    # ---- summary counts ----
    @property
    def total_ports(self) -> int:
        return sum(len(h.services) for h in self.hosts)

    def counts(self) -> dict:
        return {
            "hosts": len(self.hosts),
            "ports": self.total_ports,
            "findings": len(self.findings),
            "creds": len(self.credentials),
        }
