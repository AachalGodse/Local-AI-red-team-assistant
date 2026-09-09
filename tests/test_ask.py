"""Tests for grounded answering (`ask`) - the RAG path over findings.

Deliberately needs neither ChromaDB nor Ollama: the answer core in
`ghostops.agent.rag` takes the vector store and the LLM as collaborators, so
the grounding rules are tested with fakes and never skip. That matters - these
are the tests that assert the model cannot invent findings.
"""
import io

import pytest

from ghostops.agent import rag
from ghostops.memory.vector_store import _collection_name
from ghostops.models import Finding, Severity


def hit(title, document, distance, host="10.0.0.5", port=80,
        severity="info", source="nmap"):
    return {
        "document": document,
        "distance": distance,
        "metadata": {"title": title, "host": host, "port": port,
                     "severity": severity, "source": source},
    }


class FakeVec:
    """Stands in for VectorMemory. Records what it was asked."""

    def __init__(self, hits=(), ok=True, count=0):
        self._hits = list(hits)
        self._ok = ok
        self._count = count
        self.queries = []

    def available(self):
        return self._ok

    def count(self):
        return self._count

    def query(self, text, k=5, max_distance=None):
        self.queries.append((text, k))
        return list(self._hits)

    def add_findings(self, findings):
        self._count += len(findings)
        return len(findings)


class FakeLLM:
    """Records every message list it is handed, so tests can assert exactly
    what context the model did - and did not - receive."""

    def __init__(self, reply="Apache 2.4 on port 80 [1]."):
        self.reply = reply
        self.calls = []

    def chat(self, messages, **kw):
        self.calls.append(messages)
        return self.reply


NEAR_A = hit("Apache 2.4", "Apache 2.4 default page 10.0.0.5:80 info nmap", 0.42)
NEAR_B = hit("MySQL 5.7", "MySQL 5.7 exposed 10.0.0.5:3306 medium nmap", 0.50)
FAR = hit("Sourdough", "totally unrelated document about baking", 0.95)


# ---------------------------------------------------------------- retrieval

def test_retrieval_feeds_the_model_only_the_retrieved_findings():
    vec = FakeVec([NEAR_A, NEAR_B, FAR])
    llm = FakeLLM()
    res = rag.answer(vec, llm, "what did we find on the web servers?",
                     max_distance=0.62)

    assert res.mode == rag.MODE_ANSWER
    assert len(llm.calls) == 1
    system, context = llm.calls[0][0]["content"], llm.calls[0][1]["content"]

    # findings live in the USER turn, fenced as untrusted data...
    assert rag.BEGIN_MARK in context and rag.END_MARK in context
    assert NEAR_A["document"] in context
    assert NEAR_B["document"] in context
    assert "[1]" in context and "[2]" in context
    # ...the out-of-range hit did not reach the model at all
    assert FAR["document"] not in context
    # ...the question is in the same turn, after the data
    assert "what did we find on the web servers?" in context
    assert context.index("QUESTION:") > context.index(rag.END_MARK)
    # ...and the rules are restated AFTER the untrusted block
    assert context.index("RULE 5") > context.index(rag.END_MARK)
    # the system turn holds the rules and NO attacker-reachable text
    assert "RULES" in system
    assert NEAR_A["document"] not in system


def test_context_carries_provenance_metadata():
    vec = FakeVec([NEAR_A])
    llm = FakeLLM()
    rag.answer(vec, llm, "web?", max_distance=None)
    context = llm.calls[0][1]["content"]
    assert "10.0.0.5:80" in context
    assert "nmap" in context


# ---------------------------------------------------------------- grounding

def test_nothing_relevant_reports_so_and_never_calls_the_model():
    """The strongest grounding guarantee: when retrieval finds nothing close
    enough, the model is not invoked at all, so it cannot fabricate."""
    vec = FakeVec([FAR])            # only a far-away hit
    llm = FakeLLM(reply="Port 445 is running SMBv1 and is vulnerable.")
    res = rag.answer(vec, llm, "what did we find on the mail server?",
                     max_distance=0.62)

    assert res.mode == rag.MODE_NO_FINDINGS
    assert res.text.startswith(rag.NO_FINDINGS)
    assert res.used == []
    assert llm.calls == []          # the model was NEVER given the question
    assert "445" not in res.text    # nothing invented leaked through


def test_empty_store_reports_no_relevant_findings():
    res = rag.answer(FakeVec([]), FakeLLM(), "anything?")
    assert res.mode == rag.MODE_NO_FINDINGS
    assert res.text.startswith(rag.NO_FINDINGS)


def test_model_refusal_is_surfaced_not_masked():
    """Retrieval returned something, but the model judged it irrelevant. That
    verdict must reach the operator intact and be flagged as un-answered."""
    vec = FakeVec([NEAR_A])
    llm = FakeLLM(reply="NO RELEVANT FINDINGS - only an Apache page is recorded.")
    res = rag.answer(vec, llm, "what did we find on the mail server?")

    assert res.mode == rag.MODE_ANSWER
    assert res.refused is True
    assert res.answered is False
    assert res.used == [NEAR_A]


def test_grounding_prompt_states_the_hard_rules():
    """The prompt is the guarantee when retrieval can't be - assert the rules
    that carry it are actually present."""
    from ghostops.ai.prompts import (GROUNDED_ANSWER_CONTEXT,
                                     GROUNDED_ANSWER_SYSTEM)
    p = GROUNDED_ANSWER_SYSTEM.lower()
    assert "only" in p                       # answer only from findings
    assert "no relevant findings" in p       # the refusal sentinel
    assert "partially" in p                  # partial-coverage rule
    assert "prose" in p                      # never reprint findings
    assert "premise" in p                    # no misattribution
    for banned in ("payload", "exploit code", "next steps"):
        assert banned in p                   # model still never emits actions

    # the untrusted-data framing, and the rule-precedence resolution
    assert "untrusted_findings" in p
    assert "data" in p and "never as instructions" in p
    assert "rule 5 beats rule 1" in p

    # the context template carries the block and restates the rules after it
    c = GROUNDED_ANSWER_CONTEXT.lower()
    assert "{findings}" in GROUNDED_ANSWER_CONTEXT
    assert "{question}" in GROUNDED_ANSWER_CONTEXT
    assert c.index("rule 5") > c.index("{end}")
    assert c.index("rule 4") > c.index("{end}")
    assert "beats rule 1" in c


# ---------------------------------------------------------------- fallbacks

def test_offline_falls_back_to_semantic_search():
    vec = FakeVec([NEAR_A, NEAR_B])
    llm = FakeLLM()
    res = rag.answer(vec, llm, "web servers?", llm_ready=False)

    assert res.mode == rag.MODE_SEARCH
    assert res.used == [NEAR_A, NEAR_B]      # search results still returned
    assert llm.calls == []
    assert "semantic search" in res.message.lower()


def test_model_error_falls_back_to_search_without_raising():
    class Boom:
        def chat(self, messages, **kw):
            raise RuntimeError("ollama down")

    res = rag.answer(FakeVec([NEAR_A]), Boom(), "web?")
    assert res.mode == rag.MODE_SEARCH
    assert res.used == [NEAR_A]
    assert "RuntimeError" in res.message


def test_missing_chromadb_is_graceful():
    res = rag.answer(FakeVec(ok=False), FakeLLM(), "anything?")
    assert res.mode == rag.MODE_UNAVAILABLE
    assert "chromadb" in res.message.lower()
    assert res.used == []


def test_missing_chromadb_via_real_vectormemory(monkeypatch, tmp_path):
    import ghostops.memory.vector_store as vs
    monkeypatch.setattr(vs, "chromadb_available", lambda: False)
    vm = vs.VectorMemory("eng", tmp_path / "e.chroma", lambda t: [1.0])
    res = rag.answer(vm, FakeLLM(), "anything?")
    assert res.mode == rag.MODE_UNAVAILABLE


# ------------------------------------------------------------- provenance

def test_provenance_is_exactly_what_the_model_was_given():
    vec = FakeVec([NEAR_A, NEAR_B, FAR])
    res = rag.answer(vec, FakeLLM(), "web?", max_distance=0.62)
    assert res.used == [NEAR_A, NEAR_B]
    assert all(h["metadata"]["title"] for h in res.used)


# --------------------------------------------------------- re-index (quiet)

def test_reindex_runs_once_and_only_when_needed():
    """Migration transparency: the backfill fires when the collection is
    behind SQLite, and stays silent once it has caught up."""
    findings = [Finding(title=f"f{i}", host="10.0.0.5") for i in range(3)]
    started = []

    vec = FakeVec(count=0)
    assert rag.ensure_indexed(vec, findings, on_start=started.append) == 3
    assert started == [3]                    # notified once, with the total
    assert rag.ensure_indexed(vec, findings, on_start=started.append) == 0
    assert started == [3]                    # already indexed -> silent


def test_reindex_is_silent_when_vector_store_is_absent():
    started = []
    n = rag.ensure_indexed(FakeVec(ok=False), [Finding(title="x")],
                           on_start=started.append)
    assert n == 0 and started == []


# ---------------------------------------------------- collection naming

def test_collection_name_is_chroma_legal():
    """ChromaDB requires 3-512 chars, starting AND ending alphanumeric. An id
    ending in a separator used to be rejected outright, and the error was
    swallowed into the misleading advice 'pip install chromadb'."""
    for eid in ["eng-audit", "eng-2026-09-04-", "eng.2026.", "_", "x" * 900,
                "eng 2026 09", "-"]:
        name = _collection_name(eid)
        assert 3 <= len(name) <= 512, (eid, name)
        assert name[0].isalnum() and name[-1].isalnum(), (eid, name)


def test_collection_name_is_stable_and_unique():
    assert _collection_name("eng-a") == _collection_name("eng-a")
    assert _collection_name("eng-a") != _collection_name("eng-b")
    # long ids that share a prefix must not collide after truncation
    a, b = "x" * 600 + "-alpha", "x" * 600 + "-beta"
    assert _collection_name(a) != _collection_name(b)


def test_batch_indexing_falls_back_when_batch_embedder_fails(tmp_path):
    """An older Ollama without /api/embed must still index, one at a time."""
    import ghostops.memory.vector_store as vs
    if not vs.chromadb_available():
        pytest.skip("chromadb not installed")

    def boom(_texts):
        raise RuntimeError("no /api/embed on this server")

    vm = vs.VectorMemory("eng-batch", tmp_path / "e.chroma",
                         embed_fn=lambda t: [1.0, 0.0],
                         embed_many_fn=boom)
    n = vm.add_findings([Finding(title="a", host="1.1.1.1", port=80),
                         Finding(title="b", host="1.1.1.1", port=22)])
    assert n == 2
    assert vm.count() == 2


# ------------------------------------------------- echoed-context stripping

ECHO_A = "[1] " + NEAR_A["document"] + "  (info, 10.0.0.5:80, nmap)"
ECHO_B = "[2] " + NEAR_B["document"] + "  (medium, 10.0.0.5:3306, nmap)"


def test_echoed_findings_are_stripped_from_the_answer():
    """Small local models reprint the numbered context before answering.
    Observed with dolphin-mistral; left in, it buries the real answer."""
    reply = ECHO_A + "\n" + ECHO_B + "\n\n[1] Apache 2.4 is on port 80."
    out = rag.strip_echoed_context(reply, [NEAR_A, NEAR_B])
    assert out == "[1] Apache 2.4 is on port 80."


def test_citation_followed_by_real_prose_is_kept():
    reply = "[1] We found an Apache 2.4 web server on port 80 of 10.0.0.5."
    assert rag.strip_echoed_context(reply, [NEAR_A]) == reply


def test_refusal_is_detected_even_behind_an_echoed_block():
    """The bug this guards: refused used a plain startswith, and an echoed
    context block meant the reply no longer started with the sentinel."""
    vec = FakeVec([NEAR_A])
    llm = FakeLLM(reply=ECHO_A + "\n\nNO RELEVANT FINDINGS for mail server.")
    res = rag.answer(vec, llm, "what did we find on the mail server?")
    assert res.refused is True
    assert res.answered is False
    assert res.text.startswith(rag.NO_FINDINGS)


def test_partial_coverage_still_counts_as_answered():
    """Rule 4's partial case: answer the covered part, flag the gap. That is
    an answer, not a refusal."""
    vec = FakeVec([NEAR_B])
    llm = FakeLLM(reply=ECHO_B + "\n\nThe database is MySQL 5.7 [1].\n\n"
                        "NO RELEVANT FINDINGS\n\nThe PHP version is not recorded.")
    res = rag.answer(vec, llm, "what database and what PHP version?")
    assert res.refused is False
    assert res.answered is True
    assert "MySQL 5.7" in res.text


def test_pure_echo_strips_to_empty():
    """The contract: a reply that is nothing but echoed findings contains no
    answer, and strip_echoed_context says so rather than hiding it."""
    assert rag.strip_echoed_context(ECHO_A, [NEAR_A]) == ""


def test_pure_echo_reply_degrades_instead_of_posing_as_an_answer():
    """Observed live with dolphin-mistral: it intermittently restates the
    context and produces nothing of its own. Rendering that as a
    'Grounded answer' would misrepresent what happened."""
    vec = FakeVec([NEAR_A, NEAR_B])
    llm = FakeLLM(reply=ECHO_A + "\n" + ECHO_B)
    res = rag.answer(vec, llm, "web servers?")
    assert res.mode == rag.MODE_SEARCH
    assert res.used == [NEAR_A, NEAR_B]
    assert "restated" in res.message.lower()


def test_answer_pins_low_temperature_and_caps_length():
    """An uncapped 7B on CPU spends minutes restating its context."""

    class RecordingLLM:
        def __init__(self):
            self.opts = None

        def chat(self, messages, **kw):
            self.opts = kw.get("options")
            return "ok [1]"

    llm = RecordingLLM()
    rag.answer(FakeVec([NEAR_A]), llm, "web?")
    assert llm.opts["temperature"] <= 0.3
    assert 0 < llm.opts["num_predict"] <= 512


# ------------------------------------- regressions found by adversarial review

class BrokenVec(FakeVec):
    """A store whose lookup ERRORED. VectorMemory.query() swallows the
    exception and returns [] - byte-identical to 'matched nothing'."""

    def __init__(self, stored=5):
        super().__init__([], ok=True, count=stored)
        self.last_query_failed = True


def test_failed_retrieval_is_not_reported_as_a_grounded_fact():
    """The worst bug in the first cut: an embed/store outage was announced as
    'NO RELEVANT FINDINGS - nothing in this engagement's memory is relevant',
    a false claim about the engagement, in the same voice as a real refusal."""
    llm = FakeLLM()
    res = rag.answer(BrokenVec(stored=5), llm, "what did we find?")

    assert res.mode == rag.MODE_RETRIEVAL_FAILED
    assert res.text == ""                       # it makes no claim at all
    assert rag.NO_FINDINGS not in res.message
    assert "not a statement that nothing was found" in res.message.lower()
    assert llm.calls == []


def test_healthy_empty_result_still_refuses_normally():
    vec = FakeVec([], ok=True, count=5)
    vec.last_query_failed = False
    res = rag.answer(vec, FakeLLM(), "sourdough?")
    assert res.mode == rag.MODE_NO_FINDINGS
    assert res.text.startswith(rag.NO_FINDINGS)


def test_empty_engagement_says_so_rather_than_not_close_enough():
    vec = FakeVec([], ok=True, count=0)
    vec.last_query_failed = False
    res = rag.answer(vec, FakeLLM(), "anything?")
    assert "no findings have been recorded" in res.text.lower()


def test_backfill_is_attempted_once_per_store_even_if_counts_never_converge():
    """count() can sit permanently below len(findings) - a failed embedding, a
    '|' inside a title. Unguarded, that re-embedded everything every question."""
    class NeverCatchesUp(FakeVec):
        def add_findings(self, findings):
            return 0                    # nothing ever lands

    findings = [Finding(title=f"f{i}", host="10.0.0.5") for i in range(4)]
    vec = NeverCatchesUp(count=0)
    starts = []
    rag.ensure_indexed(vec, findings, on_start=starts.append)
    rag.ensure_indexed(vec, findings, on_start=starts.append)
    rag.ensure_indexed(vec, findings, on_start=starts.append)
    assert starts == [4]                # exactly one attempt, not three


def test_config_numbers_tolerate_junk_instead_of_killing_the_repl():
    """rag.* tunes `ask` only; a typo must not stop an engagement opening."""
    from ghostops.agent.orchestrator import _cfg_num

    class Cfg:
        def __init__(self, v):
            self.v = v

        def get(self, key, default=None):
            return self.v

    assert _cfg_num(Cfg("abc"), "rag.top_k", 5, int) == 5
    assert _cfg_num(Cfg(None), "rag.top_k", 5, int) == 5
    assert _cfg_num(Cfg("7"), "rag.top_k", 5, int) == 7
    assert _cfg_num(Cfg(0.7), "rag.max_distance", 0.62, float) == 0.7


def test_install_hint_survives_rich_rendering():
    """rich parsed the '[rag]' in "pip install -e '.[rag]'" as a markup tag and
    swallowed it, printing "pip install -e '.'" - an install command that fixes
    nothing. rag.py stays console-free, so the renderer must escape it."""
    from rich.console import Console
    from rich.markup import escape

    res = rag.answer(FakeVec(ok=False), FakeLLM(), "q?")
    assert "[rag]" in res.message          # the core keeps plain text

    buf = io.StringIO()
    Console(file=buf, width=200, no_color=True).print(
        f"[yellow]{escape(res.message)}[/yellow]")
    assert "[rag]" in buf.getvalue()       # and the operator actually sees it


def test_unescaped_message_would_lose_the_hint():
    """Guards the fix: without escape(), the hint really does disappear."""
    from rich.console import Console

    buf = io.StringIO()
    Console(file=buf, width=200, no_color=True).print(
        "Install: pip install -e '.[rag]'")
    assert "[rag]" not in buf.getvalue()


def test_batch_indexing_chunks_under_the_chroma_cap(tmp_path):
    import ghostops.memory.vector_store as vs
    assert vs._MAX_UPSERT <= 5461

    calls = []

    class Col:
        def upsert(self, ids, **kw):
            calls.append(len(ids))

        def count(self):
            return sum(calls)

    vm = vs.VectorMemory.__new__(vs.VectorMemory)
    vm._ok = True
    vm._col = Col()
    vm.embed_fn = lambda t: [1.0]
    vm.embed_many_fn = lambda ts: [[1.0] for _ in ts]
    n = vm.add_findings([Finding(title=f"f{i}", host="1.1.1.1", port=i)
                         for i in range(vs._MAX_UPSERT + 25)])
    assert n == vs._MAX_UPSERT + 25
    assert len(calls) == 2 and max(calls) <= vs._MAX_UPSERT


def test_batch_upsert_failure_falls_back_per_finding(tmp_path):
    import ghostops.memory.vector_store as vs

    singles = []

    class Col:
        def upsert(self, ids, **kw):
            if len(ids) > 1:
                raise RuntimeError("batch rejected")
            singles.append(ids[0])

    vm = vs.VectorMemory.__new__(vs.VectorMemory)
    vm._ok = True
    vm._col = Col()
    vm.embed_fn = lambda t: [1.0]
    vm.embed_many_fn = lambda ts: [[1.0] for _ in ts]
    n = vm.add_findings([Finding(title="a", host="1.1.1.1", port=80),
                         Finding(title="b", host="1.1.1.1", port=22)])
    assert n == 2                       # nothing was lost to the batch error
    assert len(singles) == 2


def test_chat_timeout_is_configurable(monkeypatch):
    """A grounded answer on a CPU-only box was measured at 433s, past the old
    hardcoded 300s. Every tool timeout here is configurable; this one is now too."""
    from ghostops.ai import llm_client

    seen = {}

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "ok"}}

    def fake_post(url, **kw):
        seen["timeout"] = kw.get("timeout")
        return Resp()

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    c = llm_client.LLMClient(model="m", timeout=900)
    assert c.chat([{"role": "user", "content": "hi"}]) == "ok"
    assert seen["timeout"] == 900

    monkeypatch.setattr(llm_client.requests, "post", fake_post)
    llm_client.LLMClient(model="m").chat([{"role": "user", "content": "hi"}])
    assert seen["timeout"] == 300          # unchanged default
