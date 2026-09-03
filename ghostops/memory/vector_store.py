"""Semantic (vector) memory - an OPTIONAL layer over the SQLite store.

RAG here *augments* the structured SQLite memory (which stays the source of
truth); it never replaces it. ChromaDB is an optional dependency: if it isn't
installed, `available()` is False and GhostOps runs exactly as before - callers
just skip semantic features and show a clear message.

Embeddings are injected as a callable (text -> vector) so this module has no
hard dependency on Ollama and is unit-testable with a fake embedder.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from ghostops.models import Finding

EmbedFn = Callable[[str], list[float]]


def chromadb_available() -> bool:
    """True if the optional `chromadb` package is importable."""
    try:
        import chromadb  # noqa: F401
        return True
    except Exception:
        return False


def finding_text(f: Finding) -> str:
    """A compact, searchable one-line representation of a finding."""
    loc = f"{f.host}:{f.port}" if f.port else (f.host or "")
    bits = [f.title, loc, f.severity.value, f.source, f.description]
    return " ".join(b for b in bits if b)


def _finding_id(f: Finding) -> str:
    # Same identity as the SQLite/in-memory dedupe key -> upserts, never dupes.
    return f"{f.title}|{f.host}|{f.port}"


class VectorMemory:
    """A per-engagement Chroma collection. All ops are no-ops (returning
    False/[]) when ChromaDB is unavailable or embedding fails, so a vector
    problem can never break an engagement."""

    def __init__(self, engagement_id: str, path: str | Path, embed_fn: EmbedFn):
        self.engagement_id = engagement_id
        self.embed_fn = embed_fn
        self._ok = False
        self._col = None
        if not chromadb_available():
            return
        try:
            import chromadb
            try:
                from chromadb.config import Settings
                settings = Settings(anonymized_telemetry=False)
            except Exception:
                settings = None
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            self.client = (
                chromadb.PersistentClient(path=str(path), settings=settings)
                if settings is not None
                else chromadb.PersistentClient(path=str(path))
            )
            name = "eng_" + "".join(
                c if c.isalnum() else "_" for c in engagement_id
            )[:60]
            self._col = self.client.get_or_create_collection(name=name)
            self._ok = True
        except Exception:
            self._ok = False

    def available(self) -> bool:
        return self._ok

    def count(self) -> int:
        if not self._ok:
            return 0
        try:
            return self._col.count()
        except Exception:
            return 0

    def add_finding(self, f: Finding) -> bool:
        if not self._ok:
            return False
        text = finding_text(f)
        try:
            vec = self.embed_fn(text)
        except Exception:
            return False
        if not vec:
            return False
        try:
            self._col.upsert(
                ids=[_finding_id(f)],
                embeddings=[vec],
                documents=[text],
                metadatas=[{
                    "title": f.title,
                    "host": f.host or "",
                    "port": int(f.port) if f.port else 0,
                    "severity": f.severity.value,
                    "source": f.source or "",
                }],
            )
            return True
        except Exception:
            return False

    def add_findings(self, findings: list[Finding]) -> int:
        return sum(1 for f in findings if self.add_finding(f))

    def query(self, text: str, k: int = 5) -> list[dict]:
        """Return up to k relevant findings as
        [{document, metadata, distance}], most relevant first. Empty on any
        failure (unavailable, embed error, empty store)."""
        if not self._ok:
            return []
        try:
            vec = self.embed_fn(text)
            if not vec:
                return []
            res = self._col.query(query_embeddings=[vec], n_results=k)
        except Exception:
            return []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[None]])[0]
        out = []
        for doc, meta, dist in zip(docs, metas, dists):
            out.append({"document": doc, "metadata": meta or {},
                        "distance": dist})
        return out
