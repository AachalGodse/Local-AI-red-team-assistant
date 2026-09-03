"""Tests for the optional semantic-memory (RAG) layer.

Uses a fake keyword embedder so no Ollama is needed. Tests that require the
optional `chromadb` package skip cleanly when it isn't installed.
"""
import pytest

from ghostops.memory.vector_store import (
    VectorMemory,
    chromadb_available,
    finding_text,
)
from ghostops.models import Finding, Severity

HAVE_CHROMA = chromadb_available()
needs_chroma = pytest.mark.skipif(not HAVE_CHROMA, reason="chromadb not installed")

# A deterministic stand-in for real embeddings: a 0/1 vector over a small
# vocabulary. Docs/queries that share keywords land near each other.
_VOCAB = ["http", "web", "server", "apache", "ssh", "shell", "openssh",
          "mysql", "database"]


def fake_embed(text: str) -> list[float]:
    t = text.lower()
    return [1.0 if w in t else 0.0 for w in _VOCAB]


def test_finding_text_includes_key_fields():
    txt = finding_text(Finding(
        title="SQLi in id", host="10.0.0.5", port=80, severity=Severity.HIGH,
        source="sqlmap", description="injectable parameter"))
    assert "SQLi in id" in txt
    assert "10.0.0.5:80" in txt
    assert "high" in txt


def test_vectormemory_disabled_without_chromadb(monkeypatch, tmp_path):
    # Force the "chromadb not installed" path: everything no-ops gracefully.
    import ghostops.memory.vector_store as vs
    monkeypatch.setattr(vs, "chromadb_available", lambda: False)
    vm = vs.VectorMemory("eng", tmp_path / "e.chroma", fake_embed)
    assert vm.available() is False
    assert vm.add_finding(Finding(title="x")) is False
    assert vm.query("anything") == []
    assert vm.count() == 0


@needs_chroma
def test_add_and_query_returns_relevant_finding(tmp_path):
    vm = VectorMemory("eng-test", tmp_path / "e.chroma", fake_embed)
    assert vm.available()
    vm.add_finding(Finding(title="Apache httpd", host="10.0.0.5", port=80,
                           source="nmap", description="http web server apache"))
    vm.add_finding(Finding(title="OpenSSH", host="10.0.0.6", port=22,
                           source="nmap", description="ssh secure shell openssh"))
    assert vm.count() == 2
    hits = vm.query("which web http server did we find", k=2)
    assert hits
    assert "Apache" in hits[0]["metadata"]["title"]
    assert hits[0]["metadata"]["host"] == "10.0.0.5"


@needs_chroma
def test_upsert_dedupes_on_same_finding(tmp_path):
    vm = VectorMemory("eng", tmp_path / "e.chroma", fake_embed)
    f = Finding(title="X", host="1.1.1.1", port=80, description="http web")
    vm.add_finding(f)
    vm.add_finding(f)
    assert vm.count() == 1


@needs_chroma
def test_embed_failure_is_graceful(tmp_path):
    def boom(_text):
        raise RuntimeError("ollama down")
    vm = VectorMemory("eng", tmp_path / "e.chroma", boom)
    assert vm.available() is True          # chromadb is fine...
    assert vm.add_finding(Finding(title="x")) is False   # ...embedding is not
    assert vm.query("q") == []
