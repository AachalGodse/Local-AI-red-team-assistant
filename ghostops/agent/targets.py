"""Target normalization + type detection.

Turns whatever the operator typed (an IP, a hostname, or a full URL) into a
clean, typed Target and exposes:

  .host  - bare host/IP for nmap and other network tools (NEVER a scheme/path)
  .url   - the full URL for web tools (gobuster, nikto), or None
  .kind  - "ip" | "host" | "url"   .scheme / .port when known

normalize() does no network I/O, so it stays pure and unit-testable; .resolve()
(DNS) is available for callers that explicitly want an IP.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class Target:
    raw: str
    kind: str                # "ip" | "host" | "url"
    host: str                # bare host or IP - safe to hand to nmap
    url: str | None = None   # full URL for web tools, else None
    scheme: str = ""
    port: int | None = None

    @property
    def is_web(self) -> bool:
        return self.kind == "url"

    def resolve(self) -> str | None:
        """Best-effort DNS resolution of .host to an IP (network call)."""
        try:
            return socket.gethostbyname(self.host)
        except Exception:
            return None


# An engagement authorizes at most this many resolved addresses for one
# hostname. DNS decides what goes into scope, so the answer is bounded and the
# caller prints every address it adds - a poisoned resolver must not be able to
# quietly widen an engagement.
MAX_RESOLVED = 8


def resolve_all(host: str, limit: int = MAX_RESOLVED) -> list[str]:
    """Every address `host` resolves to (A and AAAA), best-effort.

    Returns [] on any failure - no exception escapes, because failing to
    resolve must degrade to a hostname-only scope rather than break `engage`.
    """
    host = (host or "").strip()
    if not host or _is_ip(host):
        return []
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    out: list[str] = []
    for info in infos:
        try:
            ip = info[4][0]
        except (IndexError, TypeError):
            continue
        if ip and ip not in out:
            out.append(ip)
        if len(out) >= limit:
            break
    return out


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _is_cidr(s: str) -> bool:
    if "/" not in s:
        return False
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def normalize(raw: str) -> Target:
    """Detect the target type and split into .host (nmap) / .url (web tools)."""
    raw = (raw or "").strip()

    # 1. explicit URL (scheme://...)
    if "://" in raw:
        p = urlparse(raw)
        return Target(raw=raw, kind="url", host=p.hostname or "", url=raw,
                      scheme=(p.scheme or "").lower(), port=p.port)

    # 2. CIDR range -> a network target for nmap (keep the slash for nmap)
    if _is_cidr(raw):
        return Target(raw=raw, kind="ip", host=raw)

    # 3. a path present but no scheme (e.g. "host/admin") -> assume http web
    if "/" in raw:
        url = "http://" + raw
        p = urlparse(url)
        return Target(raw=raw, kind="url", host=p.hostname or "", url=url,
                      scheme="http", port=p.port)

    # 4. bare IP
    if _is_ip(raw):
        return Target(raw=raw, kind="ip", host=raw)

    # 5. host:port (no scheme, no path)
    if ":" in raw:
        h, _, port_s = raw.partition(":")
        port = int(port_s) if port_s.isdigit() else None
        return Target(raw=raw, kind=("ip" if _is_ip(h) else "host"),
                      host=h, port=port)

    # 6. bare hostname
    return Target(raw=raw, kind="host", host=raw)
