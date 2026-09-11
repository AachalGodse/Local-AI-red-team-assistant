"""Regressions for the two bugs found in a live lab run against
scanme.nmap.org, plus the scope-widening one they exposed.

None of these touch the network: DNS is monkeypatched, and no tool is executed.
"""
import pytest

from ghostops.agent.next_steps import build_actions
from ghostops.agent.scope_guard import ScopeGuard
from ghostops.agent.targets import normalize, resolve_all
from ghostops.config import load_config
from ghostops.models import Engagement, Host, Service
from ghostops.tools.registry import build_registry
from ghostops.tools.searchsploit_tool import SearchsploitTool, normalize_query

REG = build_registry(load_config())

# The real banner nmap produced for scanme.nmap.org's SSH service.
SCANME_SSH = "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 Ubuntu Linux; protocol 2.0"


# ----------------------------------------------- BUG 1: searchsploit queries

@pytest.mark.parametrize("raw, expected", [
    (SCANME_SSH, "OpenSSH 6.6.1p1"),
    ("Apache httpd 2.4.7 ((Ubuntu))", "Apache httpd 2.4.7"),
    ("nginx 1.14.0 (Ubuntu)", "nginx 1.14.0"),
    ("Microsoft IIS httpd 10.0", "Microsoft IIS httpd 10.0"),
    ("OpenSSH 8.2", "OpenSSH 8.2"),
    ("Postfix smtpd", "Postfix smtpd"),          # no version -> keep it whole
    ("  vsftpd   3.0.3  ", "vsftpd 3.0.3"),
])
def test_version_banner_reduces_to_product_and_version(raw, expected):
    assert normalize_query(raw) == expected


def test_full_version_banner_is_accepted_not_rejected():
    """The lab failure: the menu offered this search, then refused to run it
    with 'query has unsupported characters'."""
    tool = SearchsploitTool()
    ok, msg = tool.validate_args({"query": SCANME_SSH})
    assert ok, msg
    assert tool.build_command({"query": SCANME_SSH}) == [
        "searchsploit", "--json", "OpenSSH", "6.6.1p1"]


def test_every_searchsploit_step_the_menu_offers_actually_validates():
    """The 'suggests what it can't run' class of bug, pinned: whatever
    build_actions emits must pass the tool's own validation."""
    e = Engagement(id="e", scope=["scanme.nmap.org"])
    h = Host(ip="45.33.32.156", hostname="scanme.nmap.org")
    h.services = [
        Service(port=22, name="ssh", product="OpenSSH", version="6.6.1p1",
                extra="Ubuntu 2ubuntu2.13 Ubuntu Linux; protocol 2.0"),
        Service(port=80, name="http", product="Apache httpd", version="2.4.7",
                extra="(Ubuntu)"),
        Service(port=25, name="smtp", product="Postfix smtpd", version=""),
    ]
    e.hosts = [h]

    steps = [a for a in build_actions(e, REG) if a.tool == "searchsploit"]
    assert steps, "no searchsploit steps were built"
    for a in steps:
        ok, msg = REG["searchsploit"].validate_args(a.args)
        assert ok, f"menu offered an unrunnable step: {a.label} -> {msg}"


@pytest.mark.parametrize("hostile", [
    "nginx -u 1.0",        # -u makes searchsploit run a package update
    "-m 12345",            # -m mirrors an exploit into the cwd
    "--json x",
    "-u",
    "-----",
])
def test_a_query_can_never_become_a_searchsploit_flag(hostile):
    """Loosening the validator must not reopen the argument-injection hole:
    searchsploit folds a '-'-prefixed positional into its own option parsing."""
    argv = SearchsploitTool().build_command({"query": hostile})
    assert argv[:2] == ["searchsploit", "--json"]
    assert not [t for t in argv[2:] if t.startswith("-")], argv


def test_build_command_strips_flags_independently_of_normalize(monkeypatch):
    """build_command's filter is the second layer: normalize_query already
    defuses leading hyphens, so this pins the filter on its own rather than
    trusting the layer above it."""
    import ghostops.tools.searchsploit_tool as sst
    monkeypatch.setattr(sst, "normalize_query", lambda raw: "-u nginx --json")
    argv = sst.SearchsploitTool().build_command({"query": "anything"})
    assert argv == ["searchsploit", "--json", "nginx"]


def test_an_unsearchable_query_is_still_refused():
    ok, _ = SearchsploitTool().validate_args({"query": "---  ;;; ((("})
    assert ok is False


# --------------------------------- BUG 2: resolved IP of an in-scope hostname

def _engage_scope(target, monkeypatch, addresses):
    """The scope start_engagement really builds - calls the production
    function, with DNS stubbed. Re-deriving the logic here would make these
    tests pass even with the fix reverted."""
    import ghostops.agent.orchestrator as orch
    monkeypatch.setattr(orch, "resolve_all", lambda h, limit=8: list(addresses))
    scope, resolved = orch._engagement_scope(normalize(target), target)
    return scope


def test_resolved_ip_of_an_in_scope_hostname_is_allowed(monkeypatch):
    """The lab failure: gobuster on the authorized host was BLOCKED because
    nmap keys findings by the resolved IP."""
    scope = _engage_scope("scanme.nmap.org", monkeypatch, ["45.33.32.156"])
    assert scope == ["scanme.nmap.org", "45.33.32.156"]

    g = ScopeGuard(scope)
    assert g.check("45.33.32.156").allowed is True
    assert g.check("scanme.nmap.org").allowed is True


def test_unrelated_addresses_still_block(monkeypatch):
    """The guard must not have been loosened in general."""
    scope = _engage_scope("scanme.nmap.org", monkeypatch, ["45.33.32.156"])
    g = ScopeGuard(scope)
    for outside in ("8.8.8.8", "45.33.32.157", "1.1.1.1", "example.com",
                    "evil.scanme.nmap.org.attacker.tld"):
        assert g.check(outside).allowed is False, outside


def test_dns_failure_degrades_to_hostname_only(monkeypatch):
    scope = _engage_scope("scanme.nmap.org", monkeypatch, [])
    assert scope == ["scanme.nmap.org"]
    assert ScopeGuard(scope).check("45.33.32.156").allowed is False


def test_an_ip_target_is_not_resolved(monkeypatch):
    scope = _engage_scope("10.0.0.5", monkeypatch, ["1.2.3.4"])
    assert scope == ["10.0.0.5"]


def test_resolve_all_never_raises_and_skips_literals():
    assert resolve_all("no-such-host.invalid.") == []
    assert resolve_all("") == []
    assert resolve_all("10.0.0.5") == []          # already an IP
    assert resolve_all("2001:db8::1") == []


def test_resolve_all_is_capped():
    many = [("f", "", "", "", (f"10.0.0.{i}", 0)) for i in range(40)]
    import socket as _s
    real = _s.getaddrinfo
    try:
        _s.getaddrinfo = lambda *a, **k: many
        assert len(resolve_all("example.test", limit=8)) == 8
    finally:
        _s.getaddrinfo = real


# ------------- the scope-widening bug that resolving AAAA records exposed

def test_a_bare_ipv6_scope_entry_authorizes_exactly_one_host():
    """_as_network hardcoded the IPv4 /32, so a bare IPv6 entry authorized
    2**96 addresses. Resolving hostnames puts AAAA records into scope
    automatically, which made this reachable by default."""
    g = ScopeGuard(["2600:3c01::f03c:91ff:fe18:bb2f"])
    assert g.check("2600:3c01::f03c:91ff:fe18:bb2f").allowed is True
    for outside in ("2600:3c01:dead:beef::1", "2600:3c01:ffff:ffff::9",
                    "2600:3c01::1", "2001:db8::1"):
        assert g.check(outside).allowed is False, outside


def test_an_ipv6_cidr_scope_still_covers_its_own_hosts():
    """The same hardcoded /32 made a legitimate /64 scope reject its hosts,
    because targets are parsed by the same function."""
    g = ScopeGuard(["2001:db8:1::/64"])
    assert g.check("2001:db8:1::5").allowed is True
    assert g.check("2001:db8:2::5").allowed is False


def test_ipv4_scope_behaviour_is_unchanged():
    assert ScopeGuard(["10.0.0.5"]).check("10.0.0.5").allowed is True
    assert ScopeGuard(["10.0.0.5"]).check("10.0.0.6").allowed is False
    assert ScopeGuard(["10.0.0.0/24"]).check("10.0.0.6").allowed is True
    assert ScopeGuard(["10.0.0.0/24"]).check("10.0.1.6").allowed is False


def test_mixed_family_scope_from_a_real_engagement():
    """What `engage scanme.nmap.org` now actually builds."""
    g = ScopeGuard(["scanme.nmap.org", "45.33.32.156",
                    "2600:3c01::f03c:91ff:fe18:bb2f"])
    assert g.check("45.33.32.156").allowed is True
    assert g.check("2600:3c01::f03c:91ff:fe18:bb2f").allowed is True
    assert g.check("scanme.nmap.org").allowed is True
    assert g.check("8.8.8.8").allowed is False
    assert g.check("2600:3c01:dead::1").allowed is False
