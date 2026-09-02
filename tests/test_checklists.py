"""Tests for the curated service checklists. Run without Ollama or tools."""
import pytest

from ghostops.methodology import checklists as cl

pytestmark = pytest.mark.skipif(
    not cl.available(),
    reason="checklist catalog not present on disk (AV quarantine? run on Kali)",
)


def test_catalog_loads_core_services():
    svcs = set(cl.services())
    assert {"http", "https", "ssh", "smb", "ftp", "mysql"}.issubset(svcs)
    # every checklist has a name and at least one check
    for key in cl.services():
        c = cl.get(key)
        assert c is not None and c.name and c.checks


def test_get_is_case_insensitive():
    assert cl.get("SSH") is cl.get("ssh")
    assert cl.get("does-not-exist") is None


def test_match_by_service_name():
    c = cl.match(name="ssh")
    assert c is not None and c.key == "ssh"
    # nmap's SMB names route to the smb checklist
    assert cl.match(name="microsoft-ds").key == "smb"
    assert cl.match(name="netbios-ssn").key == "smb"


def test_match_by_port_when_name_unknown():
    assert cl.match(name="unknown-thing", port=445).key == "smb"
    assert cl.match(name="", port=3306).key == "mysql"
    assert cl.match(name="", port=443).key == "https"


def test_match_prefers_name_over_port():
    # name says ssh even though port is a decoy value
    assert cl.match(name="ssh", port=9999).key == "ssh"


def test_no_match_returns_none():
    assert cl.match(name="nope", port=65000) is None


def test_render_cmd_substitutes_host_and_port():
    c = cl.get("http")
    step = next(s for s in c.checks if "{host}" in s.cmd)
    out = cl.render_cmd(step.cmd, host="10.0.0.5", port=8080)
    assert "10.0.0.5" in out and "8080" in out
    assert "{host}" not in out and "{port}" not in out


def test_render_cmd_leaves_other_braces_alone():
    # nothing to substitute -> unchanged
    assert cl.render_cmd("echo {literal}", host="", port="") == "echo {literal}"
