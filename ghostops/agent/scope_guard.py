"""Scope enforcement — a hard, non-bypassable control.

A tool that executes real attacks MUST refuse targets outside the authorized
engagement scope. This protects the user (staying in-scope is a legal/ethical
requirement of any real pentest) and stops the LLM from ever firing at a
hallucinated or out-of-scope host.

Scope entries may be:
  * an IP address            -> "10.10.10.5"
  * a CIDR range             -> "10.10.10.0/24"
  * a hostname / domain      -> "example.com" (and subdomains via ".example.com")
  * "*"                      -> allow anything (explicit opt-out; discouraged)
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str


class ScopeGuard:
    def __init__(self, scope: list[str], enforce: bool = True):
        self.scope = [s.strip() for s in scope if s and s.strip()]
        self.enforce = enforce
        self._nets: list[ipaddress._BaseNetwork] = []
        self._names: list[str] = []
        self._wildcard = False
        for entry in self.scope:
            if entry == "*":
                self._wildcard = True
                continue
            net = self._as_network(entry)
            if net is not None:
                self._nets.append(net)
            else:
                self._names.append(entry.lower().lstrip("."))

    @staticmethod
    def _as_network(entry: str):
        """Parse a scope entry (or a target) as a network.

        A slash-less address is a single host, so the prefix length comes from
        its FAMILY - /32 for IPv4, /128 for IPv6. Hardcoding /32 turned a bare
        IPv6 address into a 2**96-address prefix, and, since targets are parsed
        here too, made a legitimate IPv6 /64 scope reject its own hosts.
        """
        try:
            if "/" in entry:
                return ipaddress.ip_network(entry, strict=False)
            addr = ipaddress.ip_address(entry)
            return ipaddress.ip_network(
                f"{entry}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            return None

    def check(self, target: str) -> ScopeDecision:
        """Decide whether `target` is in scope."""
        target = (target or "").strip()
        if not target:
            return ScopeDecision(False, "empty target")

        if not self.enforce:
            return ScopeDecision(True, "scope enforcement disabled")

        if self._wildcard:
            return ScopeDecision(True, "wildcard scope (*)")

        if not self.scope:
            return ScopeDecision(
                False,
                "no scope defined — declare targets when starting the engagement",
            )

        # IP / CIDR match
        target_net = self._as_network(target)
        if target_net is not None:
            for net in self._nets:
                if target_net.version == net.version and target_net.subnet_of(net):
                    return ScopeDecision(True, f"{target} within {net}")
            # An IP target that matched no network is out of scope.
            if not self._names:
                return ScopeDecision(False, f"{target} not in scope {self.scope}")

        # hostname match (exact or subdomain of an allowed domain)
        t = target.lower()
        for name in self._names:
            if t == name or t.endswith("." + name):
                return ScopeDecision(True, f"{target} matches {name}")

        return ScopeDecision(False, f"{target} not in scope {self.scope}")

    def __repr__(self) -> str:
        return f"ScopeGuard(scope={self.scope}, enforce={self.enforce})"
