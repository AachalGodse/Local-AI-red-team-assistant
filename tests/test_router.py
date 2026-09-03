"""Router / model-config tests. Run without Ollama or any tools installed."""
from ghostops.config import DEFAULTS, load_config


def test_config_has_router_and_embed_models():
    # Router and embed models are both declared in the built-in defaults.
    assert DEFAULTS["llm"]["model"] == "dolphin-mistral"
    assert DEFAULTS["llm"]["embed_model"] == "nomic-embed-text"
    # And are reachable through the dotted lookup used everywhere.
    cfg = load_config()
    assert cfg.get("llm.model")
    assert cfg.get("llm.embed_model")


def test_llmclient_degrades_when_host_unreachable():
    # Point at a dead port: no server -> both checks are False, so the
    # orchestrator drops to the deterministic offline router.
    from ghostops.ai.llm_client import LLMClient
    c = LLMClient("dolphin-mistral", host="http://127.0.0.1:1")
    assert c.available() is False
    assert c.has_model() is False


def test_router_registry_never_exposes_payloads():
    # Design rule #1: the model routes only to real tools; payload generation
    # is NOT a routable tool, so the model can never be asked to make a payload.
    from ghostops.tools.registry import build_registry
    reg = build_registry(load_config())
    assert set(reg) == {"nmap", "gobuster", "searchsploit", "sqlmap", "hydra"}
    for payload_category in ("revshell", "webshell", "bindshell",
                             "listener", "tty", "privesc"):
        assert payload_category not in reg
