"""Tests for the nikto web-vuln scanner wrapper."""
from ghostops.config import load_config
from ghostops.models import Severity
from ghostops.tools.base_tool import ToolResult
from ghostops.tools.nikto_tool import NiktoTool
from ghostops.tools.registry import build_registry


def test_nikto_registered_as_sixth_tool():
    reg = build_registry(load_config())
    assert "nikto" in reg and isinstance(reg["nikto"], NiktoTool)
    assert set(reg) == {"nmap", "gobuster", "searchsploit", "sqlmap",
                        "hydra", "nikto"}


def test_validate_args_and_scope():
    t = NiktoTool()
    ok, _ = t.validate_args({"url": "http://10.0.0.5:8080"})
    assert ok
    bad, _ = t.validate_args({"url": "10.0.0.5; rm -rf /"})   # not http(s)
    assert not bad
    bad2, _ = t.validate_args({"url": "ftp://10.0.0.5"})
    assert not bad2
    assert t.scope_target({"url": "http://10.0.0.5:8080/x"}) == "10.0.0.5"


def test_build_command_is_list_argv_no_shell():
    cmd = NiktoTool().build_command({"url": "http://10.0.0.5"})
    assert cmd[0] == "nikto" and "-h" in cmd and "http://10.0.0.5" in cmd
    assert all(";" not in c and "|" not in c and "&" not in c for c in cmd)


def test_parse_real_output_into_findings():
    t = NiktoTool()
    out = (
        "- Nikto v2.5.0\n"
        "+ Target IP:          10.0.0.5\n"
        "+ Start Time:         2026-01-01\n"
        "+ Server: Apache/2.4.41\n"
        "+ /admin/: Admin login page/section found.\n"
        "+ OSVDB-3092: /test/: interesting dir. CVE-2021-1234\n"
        "+ 7 requests: 0 error(s) and 2 item(s) reported\n"
    )
    r = ToolResult(tool="nikto", command=["nikto", "-h", "http://10.0.0.5"],
                   stdout=out)
    t.parse(r)
    titles = [f.title for f in r.findings]
    assert any("Admin login" in x for x in titles)
    assert any("Server: Apache" in x for x in titles)
    # bookkeeping / summary lines are NOT findings
    assert not any("Target IP" in x for x in titles)
    assert not any("requests:" in x for x in titles)
    # honest tagging: all INFO, sourced to nikto; CVE ref captured
    assert all(f.severity == Severity.INFO and f.source == "nikto"
               for f in r.findings)
    assert any("CVE-2021-1234" in f.references for f in r.findings)


def test_missing_binary_is_graceful(monkeypatch):
    t = NiktoTool()
    monkeypatch.setattr(t, "is_available", lambda: False)
    res = t.run({"url": "http://10.0.0.5"})
    assert res.error and "not found" in res.error.lower()   # no crash
