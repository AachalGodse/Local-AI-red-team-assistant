"""REPL routing: plain-English questions reach the grounded path, instructions
keep reaching the tool router, and nothing ever prints a silent blank.

No network, no Ollama, no ChromaDB: the LLM and the vector store are stubs, and
console output is captured so a blank is detectable rather than assumed.
"""
import io
import tempfile

import pytest
from rich.console import Console

import ghostops.agent.orchestrator as orch
from ghostops.agent import rag
from ghostops.agent.orchestrator import _looks_like_question
from ghostops.config import load_config
from ghostops.memory.store import EngagementStore
from ghostops.models import Engagement, Finding, Host, Service, Severity


class StubLLM:
    """Router that always answers 'respond', with configurable prose."""

    def __init__(self, message="Some advice.", chat_text="Some advice."):
        self.message = message
        self.chat_text = chat_text
        self.routed = []

    def available(self):
        return True

    def has_model(self, model=None):
        return True

    def chat_json(self, messages, **kw):
        self.routed.append(messages[-1]["content"])
        return {"action": "respond", "message": self.message}

    def chat(self, messages, **kw):
        return self.chat_text

    def embed(self, text, model=None):
        return [1.0]

    def embed_many(self, texts, model=None):
        return [[1.0] for _ in texts]


class StubVec:
    def __init__(self, ok=True, hits=()):
        self._ok = ok
        self._hits = list(hits)
        self.last_query_failed = False
        self.queried = []

    def available(self):
        return self._ok

    def count(self):
        return len(self._hits)

    def query(self, text, k=5, max_distance=None):
        self.queried.append(text)
        return list(self._hits)

    def add_findings(self, findings):
        return 0


HIT = {
    "document": "nikto: X-Frame-Options header missing 10.0.0.5:80 info nikto",
    "distance": 0.40,
    "metadata": {"title": "nikto: X-Frame-Options header missing",
                 "host": "10.0.0.5", "port": 80, "severity": "info",
                 "source": "nikto"},
}


def make(findings=True, vec_ok=True, hits=(HIT,), llm=None):
    e = Engagement(id="e", name="t", scope=["10.0.0.5"])
    h = Host(ip="10.0.0.5")
    h.services = [Service(port=80, name="http", product="Apache httpd",
                          version="2.4.7")]
    e.hosts = [h]
    if findings:
        e.add_finding(Finding(
            title="nikto: X-Frame-Options header missing", host="10.0.0.5",
            port=80, severity=Severity.INFO, source="nikto",
            description="missing header"))
    store = EngagementStore(tempfile.mktemp(suffix=".db"))
    o = orch.Orchestrator(load_config(), e, store)
    o.llm = llm or StubLLM()
    o._llm_ok = True
    o.vec = StubVec(ok=vec_ok, hits=hits)
    return o


def capture(o, text, monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr(orch, "console", Console(file=buf, width=100,
                                                 no_color=True))
    o.handle(text)
    return buf.getvalue().strip()


# ------------------------------------------------------- question detection

@pytest.mark.parametrize("text", [
    "what did nikto find?",
    "what did nikto find",
    "why is port 80 open",
    "how many hosts do we have",
    "where is the admin panel",
    "which services are exposed",
    "who owns this host",
    "is 10.0.0.5 vulnerable?",          # ambiguous word, but ends with '?'
    "can you summarise the findings?",
    "do we have credentials?",
])
def test_questions_are_recognised(text):
    assert _looks_like_question(text) is True


@pytest.mark.parametrize("text", [
    "do a full port sweep of the target",   # documented tool routing
    "does the scan",
    "is the web server",
    "scan port 80",
    "enumerate the web server",
    "run gobuster against the host",
    "whatever you think is best",           # not 'what'
    "",
    "   ",
])
def test_instructions_are_not_treated_as_questions(text):
    assert _looks_like_question(text) is False


# ----------------------------------------------------------- auto-routing

def test_a_bare_question_reaches_the_grounded_path(monkeypatch):
    o = make()
    seen = {}
    real = rag.answer

    def spy(*a, **k):
        seen["called"] = True
        return real(*a, **k)

    monkeypatch.setattr(orch.rag, "answer", spy)
    out = capture(o, "what did nikto find?", monkeypatch)

    assert seen.get("called") is True
    assert o.vec.queried == ["what did nikto find?"]
    assert o.llm.routed == []              # the tool router was NOT used
    assert out


def test_an_instruction_still_reaches_the_tool_router(monkeypatch):
    o = make()
    out = capture(o, "do a full port sweep of the target", monkeypatch)
    assert o.llm.routed == ["do a full port sweep of the target"]
    assert o.vec.queried == []             # grounded path NOT used
    assert out


def test_auto_routing_is_skipped_when_there_is_nothing_to_ground_on(monkeypatch):
    """`ghostops shell` and a fresh engagement must keep free-form chat."""
    o = make(findings=False)
    out = capture(o, "what did nikto find?", monkeypatch)
    assert o.vec.queried == []
    assert o.llm.routed == ["what did nikto find?"]
    assert out


def test_auto_routing_is_skipped_without_a_vector_store(monkeypatch):
    o = make(vec_ok=False)
    capture(o, "what did nikto find?", monkeypatch)
    assert o.llm.routed == ["what did nikto find?"]


def test_explicit_ask_is_grounded_even_with_no_findings(monkeypatch):
    """The `ask` command never falls back to the router."""
    o = make(findings=False, hits=())
    out = capture(o, "ask what did nikto find?", monkeypatch)
    assert o.llm.routed == []
    assert rag.NO_FINDINGS in out


def test_auto_routed_refusal_explains_the_scope(monkeypatch):
    o = make(hits=())
    out = capture(o, "what did nikto find?", monkeypatch)
    assert rag.NO_FINDINGS in out
    assert "general questions" in out


def test_auto_routed_question_does_not_fall_back_to_freeform(monkeypatch):
    """The hallucination hole the RAG work closed: an engagement question that
    finds nothing must NOT be answered from the model's own knowledge."""
    o = make(hits=(), llm=StubLLM(message="Port 445 is running SMBv1.",
                                  chat_text="Port 445 is running SMBv1."))
    out = capture(o, "what did nikto find?", monkeypatch)
    assert "SMBv1" not in out
    assert o.llm.routed == []


# --------------------------------------------------------- never a blank

def test_gibberish_prints_a_hint_not_an_empty_panel(monkeypatch):
    o = make(llm=StubLLM(message="", chat_text=""))
    out = capture(o, "asdkjhaskdjh", monkeypatch)
    assert out
    assert "unknown input" in out.lower()
    assert "help" in out.lower()


def test_an_empty_router_reply_never_renders_an_empty_panel(monkeypatch):
    """The original bug: a 302-character bordered box with nothing in it."""
    o = make(llm=StubLLM(message="   ", chat_text="\n  \n"))
    out = capture(o, "tell me something", monkeypatch)
    assert "unknown input" in out.lower()
    assert "GhostOps" not in out          # the empty panel title is gone


def test_router_output_is_escaped(monkeypatch):
    """Model prose is rendered text; a stray closing tag must not raise."""
    o = make(llm=StubLLM(message="watch out for [/red] in banners"))
    out = capture(o, "tell me something", monkeypatch)
    assert "[/red]" in out


@pytest.mark.parametrize("vec_ok, hits, llm_ready, expect", [
    (False, (),      True,  "chromadb"),          # no vector store
    (True,  (),      True,  rag.NO_FINDINGS),     # nothing retrieved
    (True,  (HIT,),  True,  None),                # a real answer
    (True,  (HIT,),  False, None),                # no model -> search table
])
def test_the_grounded_path_is_never_empty_in_any_mode(
        vec_ok, hits, llm_ready, expect, monkeypatch):
    """Every state of the grounded path must say SOMETHING: an answer,
    NO RELEVANT FINDINGS, or why it is unavailable - never silence."""
    o = make(vec_ok=vec_ok, hits=hits)
    o._llm_ok = llm_ready
    buf = io.StringIO()
    monkeypatch.setattr(orch, "console", Console(file=buf, width=100,
                                                 no_color=True))
    o._ask_question("what did nikto find?")
    out = buf.getvalue().strip()
    assert out, "grounded path produced no output at all"
    if expect:
        assert expect.lower() in out.lower()


def test_every_grounded_render_mode_produces_output(monkeypatch):
    """Same guarantee, driven straight through the renderer for each mode -
    including the two a stub store cannot easily reach."""
    o = make()
    for res in [
        rag.GroundedAnswer(rag.MODE_ANSWER, text="Apache 2.4.7 on port 80 [1].",
                           used=[HIT]),
        rag.GroundedAnswer(rag.MODE_NO_FINDINGS, text=rag.NO_FINDINGS),
        rag.GroundedAnswer(rag.MODE_SEARCH, used=[HIT], message="no model"),
        rag.GroundedAnswer(rag.MODE_UNAVAILABLE, message="needs ChromaDB"),
        rag.GroundedAnswer(rag.MODE_RETRIEVAL_FAILED, message="store down"),
        rag.GroundedAnswer(rag.MODE_BLOCKED, used=[HIT],
                           message="Answer withheld"),
        rag.GroundedAnswer(rag.MODE_ANSWER, text="", used=[HIT]),
    ]:
        buf = io.StringIO()
        monkeypatch.setattr(orch, "console", Console(file=buf, width=100,
                                                     no_color=True))
        o._render_grounded("q?", res)
        assert buf.getvalue().strip(), f"{res.mode} rendered nothing"
