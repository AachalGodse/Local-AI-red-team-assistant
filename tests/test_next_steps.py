"""Tests for the registry-driven next-steps menu."""
from ghostops.agent.next_steps import (
    Action, QUIT, build_actions, resolve_choice,
)
from ghostops.config import load_config
from ghostops.models import Engagement, Finding, Host, Service
from ghostops.tools.registry import build_registry

REG = build_registry(load_config())


def _eng():
    e = Engagement(id="e", scope=["10.0.0.5"])
    h = Host(ip="10.0.0.5")
    h.services = [
        Service(port=80, name="http", product="Apache httpd", version="2.4.41"),
        Service(port=22, name="ssh", product="OpenSSH", version="8.2p1"),
        Service(port=3306, name="mysql", product="MySQL", version="5.7.38"),
    ]
    e.hosts = [h]
    return e


def test_actions_only_use_registered_tools():
    acts = build_actions(_eng(), REG)
    assert acts
    for a in acts:
        assert a.tool in REG            # invented tools are impossible


def test_web_maps_to_gobuster_with_concrete_url():
    acts = build_actions(_eng(), REG)
    g = [a for a in acts if a.tool == "gobuster"]
    assert g and g[0].args["url"] == "http://10.0.0.5:80"


def test_mysql_maps_to_hydra_and_searchsploit_not_sqlmap():
    acts = build_actions(_eng(), REG)
    hyd = [a for a in acts if a.tool == "hydra" and a.args.get("service") == "mysql"]
    assert hyd and hyd[0].intrusive and hyd[0].args["target"] == "10.0.0.5"
    assert any(a.tool == "searchsploit" and "MySQL" in a.args["query"] for a in acts)
    assert not any(a.tool == "sqlmap" for a in acts)   # no param'd URL yet


def test_sqlmap_only_when_parameterised_url_in_memory():
    e = _eng()
    e.add_finding(Finding(title="path found", source="gobuster",
                          description="gobuster found http://10.0.0.5:80/item.php?id=1"))
    acts = build_actions(e, REG)
    sql = [a for a in acts if a.tool == "sqlmap"]
    assert sql and sql[0].args["url"] == "http://10.0.0.5:80/item.php?id=1"
    assert sql[0].intrusive


def test_hydra_action_prompts_for_credentials():
    hyd = next(a for a in build_actions(_eng(), REG) if a.tool == "hydra")
    names = [p[0] for p in hyd.prompts]
    assert "username" in names and "passlist" in names


def test_non_intrusive_actions_ordered_first():
    acts = build_actions(_eng(), REG)
    first_intrusive = next(i for i, a in enumerate(acts) if a.intrusive)
    assert all(not a.intrusive for a in acts[:first_intrusive])


def test_resolve_choice_valid_invalid_quit():
    acts = build_actions(_eng(), REG)
    assert resolve_choice(acts, "1") is acts[0]
    assert resolve_choice(acts, str(len(acts))) is acts[-1]
    assert resolve_choice(acts, "999") is None     # out of range -> no default
    assert resolve_choice(acts, "abc") is None      # garbage -> no default
    assert resolve_choice(acts, "q") == QUIT


# ---- integration: selection sits in front of the confirm gate ----

def _orch(tmp_path):
    from ghostops.agent.orchestrator import Orchestrator
    from ghostops.memory.store import EngagementStore
    e = Engagement(id="e", scope=["10.0.0.5"])
    h = Host(ip="10.0.0.5")
    h.services = [Service(port=22, name="ssh", product="OpenSSH", version="8.2p1")]
    e.hosts = [h]
    store = EngagementStore(str(tmp_path / "e.db"))
    return Orchestrator(load_config(), e, store)


def test_intrusive_pick_still_hits_confirm(tmp_path, monkeypatch):
    import ghostops.agent.orchestrator as orch
    o = _orch(tmp_path)
    hyd = next(a for a in build_actions(o.e, o.tools) if a.tool == "hydra")
    monkeypatch.setattr(o.tools["hydra"], "is_available", lambda: True)
    inputs = iter(["root", "/tmp/pw.txt"])           # answer the two prompts
    monkeypatch.setattr(orch.console, "input", lambda *a, **k: next(inputs))
    monkeypatch.setattr(orch.Confirm, "ask", lambda *a, **k: False)  # user: NO
    ran = {"called": False}
    monkeypatch.setattr(o.tools["hydra"], "run",
                        lambda *a, **k: ran.update(called=True))
    o._run_action(hyd)
    assert ran["called"] is False        # confirm gate held -> tool not run


def test_cancelling_input_prompt_returns_without_running(tmp_path, monkeypatch):
    import ghostops.agent.orchestrator as orch
    o = _orch(tmp_path)
    hyd = next(a for a in build_actions(o.e, o.tools) if a.tool == "hydra")
    monkeypatch.setattr(o.tools["hydra"], "is_available", lambda: True)
    monkeypatch.setattr(orch.console, "input", lambda *a, **k: "")   # cancel

    def boom(*a, **k):
        raise AssertionError("confirm/run reached after cancel")
    monkeypatch.setattr(orch.Confirm, "ask", boom)
    ran = {"called": False}
    monkeypatch.setattr(o.tools["hydra"], "run",
                        lambda *a, **k: ran.update(called=True))
    o._run_action(hyd)
    assert ran["called"] is False        # cancelled -> tool not run


# ---- web target routing (Step: IP/URL normalization + nikto) ----

def test_web_target_offers_gobuster_and_nikto():
    e = Engagement(id="e", scope=["10.0.0.5"])
    e.add_web_target("https://10.0.0.5/app")
    acts = build_actions(e, REG)
    tools = {a.tool for a in acts}
    assert "gobuster" in tools and "nikto" in tools
    nk = next(a for a in acts if a.tool == "nikto")
    assert nk.intrusive and nk.args["url"] == "https://10.0.0.5/app"


def test_nmap_empty_web_is_not_a_dead_end():
    # no hosts/services discovered, but a web target is recorded -> the menu
    # still offers the web path instead of dead-ending.
    e = Engagement(id="e", scope=["10.0.0.5"])
    e.add_web_target("http://10.0.0.5:8080/")
    acts = build_actions(e, REG)
    assert acts
    assert any(a.tool in ("gobuster", "nikto") for a in acts)


def test_nikto_menu_pick_still_hits_confirm(tmp_path, monkeypatch):
    import ghostops.agent.orchestrator as orch
    o = _orch(tmp_path)
    o.e.add_web_target("http://10.0.0.5/")
    nk = next(a for a in build_actions(o.e, o.tools) if a.tool == "nikto")
    monkeypatch.setattr(o.tools["nikto"], "is_available", lambda: True)
    monkeypatch.setattr(orch.Confirm, "ask", lambda *a, **k: False)   # user: NO
    ran = {"called": False}
    monkeypatch.setattr(o.tools["nikto"], "run",
                        lambda *a, **k: ran.update(called=True))
    o._run_action(nk)
    assert ran["called"] is False        # intrusive -> confirm gate held
