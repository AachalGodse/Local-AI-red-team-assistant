"""Semantic (vector) memory - an OPTIONAL layer over the SQLite store.

RAG here *augments* the structured SQLite memory (which stays the source of
truth); it never replaces it. ChromaDB is an optional dependency: if it isn't
installed, `available()` is False and GhostOps runs exactly as before - callers
just skip semantic features and show a clear message.

Embeddings are injected as callables (text -> vector) so this module has no
hard dependency on Ollama and is unit-testable with a fake embedder.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Optional

from ghostops.models import Finding

EmbedFn = Callable[[str], list[float]]
EmbedManyFn = Callable[[list[str]], list[list[float]]]

# Collections are queried in COSINE space: distances land in [0, 2] and are
# comparable across embedding models, so `rag.max_distance` keeps its meaning
# if the operator swaps nomic-embed-text for something else. Raw L2 distances
# are unbounded and model-specific, which makes any threshold unportable.
_SPACE = "cosine"

# Bumping this prefix changes every collection name, which makes the next
# ask/recall re-index from SQLite automatically. That is the migration path:
# no user action, no data loss (SQLite is the source of truth). The 'c' marks
# cosine space - collections written by the old L2 build are simply orphaned.
_NAME_PREFIX = "engc_"

# ChromaDB names: 3-512 chars, and must START and END alphanumeric.
_MAX_NAME = 512

# ChromaDB rejects an upsert larger than its max batch size (5461). Stay well
# under it and chunk, rather than losing the whole backfill to one exception.
_MAX_UPSERT = 4000


def _collection_name(engagement_id: str) -> str:
    """A ChromaDB-legal collection name for an engagement id.

    Guards the two ways a real id breaks the store: an id ending in a
    non-alphanumeric character (dot, dash, trailing separator) would produce a
    trailing '_' and be rejected outright, and a very long id would exceed the
    length cap. Both used to surface as a swallowed error and the misleading
    advice "pip install chromadb".
    """
    raw = str(engagement_id)
    safe = "".join(c if c.isalnum() else "_" for c in raw).strip("_")
    if not safe:
        safe = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]

    budget = _MAX_NAME - len(_NAME_PREFIX)
    if len(safe) > budget:
        # Truncation can collide; a digest of the FULL id keeps names unique.
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8]
        safe = safe[: budget - len(digest) - 1].rstrip("_") + "_" + digest

    name = (_NAME_PREFIX + safe).rstrip("_.-")
    return name if len(name) >= 3 else name + "00"


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


def _finding_meta(f: Finding) -> dict:
    return {
        "title": f.title,
        "host": f.host or "",
        "port": int(f.port) if f.port else 0,
        "severity": f.severity.value,
        "source": f.source or "",
    }


class VectorMemory:
    """A per-engagement Chroma collection. All ops are no-ops (returning
    False/[]) when ChromaDB is unavailable or embedding fails, so a vector
    problem can never break an engagement."""

    def __init__(self, engagement_id: str, path: str | Path, embed_fn: EmbedFn,
                 embed_many_fn: Optional[EmbedManyFn] = None):
        self.engagement_id = engagement_id
        self.embed_fn = embed_fn
        # Optional batch embedder. Backfilling a resumed engagement one HTTP
        # call at a time is the difference between ~8s and ~40s for 50
        # findings, so re-indexing stays a blink rather than a stall.
        self.embed_many_fn = embed_many_fn
        self._ok = False
        self._col = None
        self.last_query_failed = False
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
            self._col = self.client.get_or_create_collection(
                name=_collection_name(engagement_id),
                metadata={"hnsw:space": _SPACE},
            )
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
                metadatas=[_finding_meta(f)],
            )
            return True
        except Exception:
            return False

    def add_findings(self, findings: list[Finding]) -> int:
        """Index many findings, in ONE embedding call where the caller supplied
        a batch embedder. Falls back to one-at-a-time on any batch failure, so
        an older Ollama (no /api/embed) still works."""
        if not self._ok or not findings:
            return 0

        if self.embed_many_fn is not None:
            texts = [finding_text(f) for f in findings]
            vecs = None
            try:
                vecs = self.embed_many_fn(texts)
            except Exception:
                vecs = None
            if vecs is not None and len(vecs) == len(texts):
                # Dedupe by id: Chroma rejects a batch with repeated ids, and
                # the last write is the one we'd want anyway.
                seen: dict[str, tuple] = {}
                for f, text, vec in zip(findings, texts, vecs):
                    if vec:
                        seen[_finding_id(f)] = (text, vec, _finding_meta(f))
                if not seen:
                    return 0
                ids = list(seen.keys())
                written = 0
                # ChromaDB caps a single upsert (5461 at the time of writing).
                # An over-cap batch raises and, without chunking, silently
                # indexed nothing at all.
                for i in range(0, len(ids), _MAX_UPSERT):
                    chunk = ids[i:i + _MAX_UPSERT]
                    try:
                        self._col.upsert(
                            ids=chunk,
                            embeddings=[seen[k][1] for k in chunk],
                            documents=[seen[k][0] for k in chunk],
                            metadatas=[seen[k][2] for k in chunk],
                        )
                        written += len(chunk)
                    except Exception:
                        # Fall back to one at a time so a single bad row
                        # cannot discard everything around it.
                        by_id = {_finding_id(f): f for f in findings}
                        written += sum(
                            1 for k in chunk
                            if k in by_id and self.add_finding(by_id[k])
                        )
                return written

        return sum(1 for f in findings if self.add_finding(f))

    def query(self, text: str, k: int = 5,
              max_distance: Optional[float] = None) -> list[dict]:
        """Return up to k relevant findings as
        [{document, metadata, distance}], most relevant first. Empty on any
        failure (unavailable, embed error, empty store).

        NOTE: a similarity search always returns its nearest neighbours no
        matter how far away they are, so a non-empty result does NOT mean the
        findings are relevant. `max_distance` filters the obvious misses;
        judging real relevance is the grounding prompt's job (see agent/rag.py).
        """
        if not self._ok:
            self.last_query_failed = True
            return []
        self.last_query_failed = False
        try:
            vec = self.embed_fn(text)
            if not vec:
                self.last_query_failed = True
                return []
            res = self._col.query(query_embeddings=[vec], n_results=k)
        except Exception:
            # A failed lookup is NOT an empty engagement. Callers must be able
            # to tell them apart, or they report a store outage as the grounded
            # fact "nothing relevant was recorded".
            self.last_query_failed = True
            return []
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[None]])[0]
        out = []
        for doc, meta, dist in zip(docs, metas, dists):
            if (max_distance is not None and dist is not None
                    and dist > max_distance):
                continue
            out.append({"document": doc, "metadata": meta or {},
                        "distance": dist})
        return out
