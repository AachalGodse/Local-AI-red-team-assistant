"""Smoke tests that run without Ollama or security tools installed."""
import os
import tempfile

from ghostops.agent.scope_guard import ScopeGuard
from ghostops.models import Engagement, Host, Service, Phase, Finding, Severity
from ghostops.memory.store import EngagementStore
from ghostops.tools.nmap_tool import NmapTool
from ghostops.report.generator import render_markdown


def test_scope_guard_ip_and_cidr():
    g = ScopeGuard(["10.10.10.0/24"], enforce=True)
    assert g.check("10.10.10.5").allowed
    assert not g.check("10.10.11.5").allowed
    assert not g.check("8.8.8.8").allowed


def test_scope_guard_hostname():
    g = ScopeGuard(["example.com"], enforce=True)
    assert g.check("example.com").allowed
    assert g.check("api.example.com").allowed
    assert not g.check("evil.com").allowed


def test_scope_guard_wildcard_and_disabled():
    assert ScopeGuard(["*"], enforce=True).check("1.2.3.4").allowed
    assert ScopeGuard([], enforce=False).check("1.2.3.4").allowed
    assert not ScopeGuard([], enforce=True).check("1.2.3.4").allowed


def test_nmap_build_command_profiles():
    t = NmapTool()
    cmd = t.build_command({"target": "10.0.0.5", "profile": "quick"})
    assert cmd[0] == "nmap" and "10.0.0.5" in cmd and "-oX" in cmd
    ok, _ = t.validate_args({"target": "10.0.0.5"})
    assert ok
    bad, _ = t.validate_args({"target": "10.0.0.5; rm -rf /"})
    assert not bad
    # a URL must never reach nmap - it's rejected up front
    url_bad, _ = t.validate_args({"target": "https://example.com/path"})
    assert not url_bad


def test_nmap_parse_xml():
    t = NmapTool()
    from ghostops.tools.base_tool import ToolResult
    xml = (
        '<?xml version="1.0"?><nmaprun><host>'
        '<status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22">'
        '<state state="open"/>'
        '<service name="ssh" product="OpenSSH" version="8.2p1"/>'
        '</port></ports></host></nmaprun>'
    )
    r = ToolResult(tool="nmap", command=["nmap"], stdout=xml)
    t.parse(r)
    assert len(r.hosts) == 1
    assert r.hosts[0].services[0].port == 22
    assert r.hosts[0].services[0].name == "ssh"


def test_store_roundtrip_and_report():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "eng.db")
        e = Engagement(id="eng-test", name="10.0.0.5",
                       scope=["10.0.0.5"], phase=Phase.SCANNING,
                       created_at="2026-01-01")
        h = Host(ip="10.0.0.5", hostname="box")
        h.services.append(Service(port=22, name="ssh",
                                  product="OpenSSH", version="8.2p1"))
        e.upsert_host(h)
        e.add_finding(Finding(title="ssh exposed", severity=Severity.LOW,
                              host="10.0.0.5", port=22, source="nmap"))
        e.add_web_target("https://10.0.0.5/app")
        store = EngagementStore(path)
        store.save(e)
        store.close()

        store2 = EngagementStore(path)
        loaded = store2.load()
        assert loaded is not None
        assert loaded.hosts[0].services[0].version == "8.2p1"
        assert loaded.findings[0].title == "ssh exposed"
        assert "https://10.0.0.5/app" in loaded.web_targets   # persisted

        md = render_markdown(loaded)
        assert "Penetration Test Report" in md
        assert "OpenSSH" in md
        store2.close()


def test_gobuster_command_scope_and_parse():
    from ghostops.tools.gobuster_tool import GobusterTool
    from ghostops.tools.base_tool import ToolResult
    t = GobusterTool(wordlist="/usr/share/wordlists/dirb/common.txt")
    # scope target is derived from the URL host
    assert t.scope_target({"url": "http://10.0.0.5:8080/"}) == "10.0.0.5"
    ok, _ = t.validate_args({"url": "http://10.0.0.5:8080"})
    assert ok
    bad, _ = t.validate_args({"url": "ftp://10.0.0.5"})
    assert not bad
    cmd = t.build_command({"url": "http://10.0.0.5:8080", "extensions": "php"})
    assert "dir" in cmd and "-u" in cmd and "-x" in cmd
    r = ToolResult(tool="gobuster", command=cmd,
                   stdout="/admin (Status: 301) [Size: 312]\n"
                          "/index.html (Status: 200) [Size: 10]\n")
    t.build_command({"url": "http://10.0.0.5:8080"})  # sets _host
    t.parse(r)
    assert len(r.findings) == 2
    assert "/admin" in r.findings[0].title


def test_searchsploit_query_validation_and_parse():
    import json
    from ghostops.tools.searchsploit_tool import SearchsploitTool
    from ghostops.tools.base_tool import ToolResult
    t = SearchsploitTool()
    ok, _ = t.validate_args({"query": "OpenSSH 8.2"})
    assert ok
    bad, _ = t.validate_args({"query": "OpenSSH; rm -rf /"})
    assert not bad
    payload = json.dumps({
        "SEARCH": "OpenSSH 8.2",
        "RESULTS_EXPLOIT": [
            {"Title": "OpenSSH 8.2 - Example", "EDB-ID": "12345",
             "Path": "/opt/exploitdb/exploits/linux/remote/12345.py"},
        ],
    })
    r = ToolResult(tool="searchsploit", command=["searchsploit"], stdout=payload)
    t.parse(r)
    assert len(r.findings) == 1
    assert "OpenSSH 8.2 - Example" in r.findings[0].title
    assert r.findings[0].references == ["EDB-12345"]


def test_sqlmap_command_scope_and_parse():
    from ghostops.tools.sqlmap_tool import SqlmapTool
    from ghostops.tools.base_tool import ToolResult
    t = SqlmapTool()
    assert t.scope_target({"url": "http://10.0.0.5/p.php?id=1"}) == "10.0.0.5"
    ok, _ = t.validate_args({"url": "http://10.0.0.5/p.php?id=1"})
    assert ok
    bad, _ = t.validate_args({"url": "not-a-url"})
    assert not bad
    cmd = t.build_command({"url": "http://10.0.0.5/p.php?id=1", "level": 2})
    assert "--batch" in cmd and "-u" in cmd and "--level" in cmd
    out = ("sqlmap identified the following injection point\n"
           "Parameter: id (GET)\n"
           "    Type: boolean-based blind\n"
           "back-end DBMS: MySQL >= 5.0\n")
    r = ToolResult(tool="sqlmap", command=cmd, stdout=out)
    t.parse(r)
    assert any("SQL injection in id" in f.title for f in r.findings)
    assert "INJECTABLE" in r.summary


def test_hydra_command_validation_and_parse():
    from ghostops.tools.hydra_tool import HydraTool
    from ghostops.tools.base_tool import ToolResult
    t = HydraTool()
    ok, _ = t.validate_args({"target": "10.0.0.5", "service": "ssh",
                             "username": "root", "passlist": "/tmp/p.txt"})
    assert ok
    bad, _ = t.validate_args({"target": "10.0.0.5", "service": "ssh"})
    assert not bad  # no creds provided
    bad2, _ = t.validate_args({"target": "10.0.0.5", "service": "nope",
                               "username": "root", "password": "x"})
    assert not bad2  # unsupported service
    cmd = t.build_command({"target": "10.0.0.5", "service": "ssh",
                           "username": "root", "passlist": "/tmp/p.txt"})
    assert cmd[:1] == ["hydra"] and "ssh" in cmd and "-P" in cmd
    out = "[22][ssh] host: 10.0.0.5   login: root   password: toor\n"
    r = ToolResult(tool="hydra", command=cmd, stdout=out)
    t.parse(r)
    assert len(r.credentials) == 1
    assert r.credentials[0].username == "root"
    assert r.credentials[0].secret == "toor"
    assert any("Weak ssh credentials" in f.title for f in r.findings)
