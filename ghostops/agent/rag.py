"""Retrieval-augmented answering over engagement findings.

`recall` does semantic SEARCH: retrieve findings and show them in a table.
This module adds grounded ANSWERING: retrieve the relevant findings, hand ONLY
those to the model, and constrain it to answer from them alone.

THE THREAT MODEL. Finding text is NOT trusted input. Titles and descriptions
are built from scanner output - an nmap banner, a nikto line, a gobuster path -
and every one of those echoes bytes chosen by the scanned host. A hostile target
can therefore write text that lands inside the model's context. It has been
demonstrated doing exactly that: a crafted HTTP response header produced an
answer containing an attacker-supplied command with credentials, plus a
fabricated finding about a host that was never in the engagement.

Four independent layers defend the grounding guarantee, in order:

  1. Retrieval.    Hits beyond `max_distance` are dropped. If nothing survives
                   the model is NEVER CALLED - it cannot invent an answer to a
                   question it was never asked.
  2. Sanitisation. Finding text is flattened to a single line, control
                   characters are stripped, citation-shaped sequences are
                   defused so a hostile finding cannot mint a fake source, and
                   the block delimiters are removed so it cannot close the
                   quoted region early. Each document and the whole block are
                   length-capped, with `num_ctx` set, so an oversized finding
                   cannot push the rules out of the context window.
  3. The prompt.   Findings go in a delimited, explicitly-untrusted block in the
                   USER turn, and rules 3/4/5 are restated AFTER it, so the last
                   instruction the model reads is ours and not the attacker's.
  4. Output guard. `unsafe_answer()` re-checks the generated text for command
                   shapes and out-of-range citations. It does not trust the
                   prompt to have worked, and it is what makes layer 3 fail
                   safe rather than fail open.

KNOWN LIMITATION (accepted, deliberately not hardened further). These layers
strip the dangerous CONTENT - the command, the credential, the fabricated
citation - but a hostile finding can still influence how a refusal is WORDED.
Asked about a planted "remediation note", the model may reply that a finding
contains a verification command for some credentials, without reproducing
either. That is the designed behaviour of rule 5, and it is useful: the
operator learns that a scanned host planted something, which is exactly what
they need to know. Suppressing it would cost real information for little gain,
so an operator should read a refusal's phrasing as a report ABOUT untrusted
finding text, never as a statement of fact about the engagement. The Sources
table under every answer exists so that text can be inspected directly.

Kept free of rich/console (the convention stated in methodology/display.py and
payloads/display.py) so all of this is unit-testable without ChromaDB, without
Ollama, and without a REPL.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ghostops.ai.prompts import GROUNDED_ANSWER_CONTEXT, GROUNDED_ANSWER_SYSTEM

# Cosine distance in [0, 2]. Measured against nomic-embed-text on real
# engagement findings: on-topic questions land ~0.43-0.53, off-domain ones
# ~0.64+. 0.62 rejects clearly unrelated questions while leaving legitimate
# ones through. It is a coarse filter only - the prompt does the real work.
# Override per-install with `rag.max_distance` in config.yaml.
DEFAULT_MAX_DISTANCE = 0.62
DEFAULT_K = 5

# The exact refusal sentinel required by GROUNDED_ANSWER_SYSTEM rule 4.
# Machine-checkable, so "the model declined" is a visible, testable state
# rather than prose someone has to parse.
NO_FINDINGS = "NO RELEVANT FINDINGS"

# Delimiters for the untrusted region. Stripped from the data itself, so a
# hostile finding cannot close the block early and escape into instructions.
BEGIN_MARK = "<<<UNTRUSTED_FINDINGS>>>"
END_MARK = "<<<END_UNTRUSTED_FINDINGS>>>"

# Size caps. Without them a single oversized finding evicts the rule block from
# the context window, which silently removes every prompt-level defence.
MAX_DOC_CHARS = 400
MAX_BLOCK_CHARS = 3000

# Generation options. A grounding task wants the most probable continuation,
# not a creative one, and five sentences do not need an unbounded budget -
# uncapped, a 7B on CPU spends minutes restating its context. num_ctx is set
# explicitly so the window is a known quantity rather than a server default.
NUM_CTX = 4096
ANSWER_OPTIONS = {"temperature": 0.2, "num_predict": 220, "num_ctx": NUM_CTX}

# answer()'s outcomes.
MODE_ANSWER = "answer"            # model answered from retrieved findings
MODE_NO_FINDINGS = "no_findings"  # nothing relevant retrieved; model not called
MODE_SEARCH = "search"            # no model available -> semantic search only
MODE_UNAVAILABLE = "unavailable"  # no vector store at all
MODE_RETRIEVAL_FAILED = "retrieval_failed"   # the store errored; say so
MODE_BLOCKED = "blocked"          # output guard rejected the model's reply


@dataclass
class GroundedAnswer:
    """The result of a grounded question. `used` is the provenance: the exact
    findings the model was given, so the operator can verify every claim."""

    mode: str
    text: str = ""
    used: list[dict] = field(default_factory=list)
    message: str = ""
    dropped: int = 0              # hits omitted for size; never silently

    @property
    def refused(self) -> bool:
        """True when the model reported that the findings don't cover it."""
        return self.text.strip().upper().startswith(NO_FINDINGS)

    @property
    def answered(self) -> bool:
        return self.mode == MODE_ANSWER and not self.refused


# --------------------------------------------------------------- sanitising

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CITATION = re.compile(r"\[\s*(\d+)\s*\]")


def sanitize_document(text: str, limit: int = MAX_DOC_CHARS) -> str:
    """Make one finding safe to place inside the untrusted block.

    Flattens to a single line (a hostile finding cannot fake block structure),
    strips control characters, rewrites `[n]` to `(n)` so it cannot mint a
    citation the operator's Sources table does not contain, removes the block
    delimiters so it cannot close the quoted region, and caps the length.
    """
    t = _CTRL.sub(" ", str(text or ""))
    t = t.replace(BEGIN_MARK, "").replace(END_MARK, "")
    t = _CITATION.sub(r"(\1)", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > limit:
        t = t[: limit - 1].rstrip() + "…"
    return t


def format_findings(hits: list[dict]) -> str:
    """Render hits as the numbered list the prompt cites by index."""
    block, _, _ = build_block(hits)
    return block


def build_block(hits: list[dict]) -> tuple[str, list[dict], int]:
    """Build the untrusted findings block.

    Returns (block_text, hits_actually_included, dropped_count). Callers must
    report provenance from the SECOND value, never the input: if a hit was
    dropped for size, citation [3] in the answer must still line up with row 3
    of the operator's Sources table.
    """
    lines: list[str] = []
    kept: list[dict] = []
    total = 0
    for h in hits:
        meta = h.get("metadata") or {}
        where = sanitize_document(meta.get("host", "") or "", 64)
        if meta.get("port"):
            where = f"{where}:{sanitize_document(str(meta['port']), 12)}"
        bits = [sanitize_document(str(b), 32) for b in
                (meta.get("severity"), where, meta.get("source")) if b]
        suffix = f"  ({', '.join(bits)})" if bits else ""
        line = f"[{len(kept) + 1}] {sanitize_document(h.get('document', ''))}{suffix}"
        if total + len(line) > MAX_BLOCK_CHARS and kept:
            break
        lines.append(line)
        kept.append(h)
        total += len(line)
    return "\n".join(lines), kept, len(hits) - len(kept)


def build_messages(question: str, hits: list[dict]) -> tuple[list[dict], list[dict], int]:
    """The chat messages for a grounded answer.

    The findings live in the USER turn inside explicit untrusted delimiters,
    and rules 3/4/5 are restated after them - so whatever a hostile finding
    says, our instructions are the last thing the model reads.
    """
    block, kept, dropped = build_block(hits)
    messages = [
        {"role": "system", "content": GROUNDED_ANSWER_SYSTEM},
        {"role": "user", "content": GROUNDED_ANSWER_CONTEXT.format(
            begin=BEGIN_MARK, end=END_MARK, findings=block,
            question=sanitize_document(question, 500))},
    ]
    return messages, kept, dropped


# ------------------------------------------------------------ output guard

# Binaries an answer has no business emitting. Matched only when followed by
# something command-shaped (a flag, a UNC/URL target, user@host), so prose that
# merely NAMES a tool - "finding [1] was produced by nmap" - is not flagged.
_BINARIES = (
    r"nc|ncat|netcat|socat|bash|sh|zsh|dash|python3?|perl|ruby|php|curl|wget|"
    r"ssh|scp|sftp|telnet|ftp|smbclient|smbmap|mysql|psql|mongo|redis-cli|"
    r"rdesktop|xfreerdp|evil-winrm|crackmapexec|nxc|impacket-\w+|hydra|medusa|"
    r"john|hashcat|sqlmap|nmap|nikto|gobuster|ffuf|msfconsole|msfvenom|"
    r"powershell|pwsh|cmd|certutil|bitsadmin|rundll32|mshta|regsvr32|wmic|"
    r"schtasks|net|reg|chisel|ligolo|mimikatz|sudo|su|chmod|chown|useradd"
)

_UNSAFE_PATTERNS = [
    # a known binary followed by a flag, a UNC path, a URL, or user@host
    (re.compile(r"(?:^|[\s`;|&(\"'])(?:" + _BINARIES +
                r")\s+(?:-{1,2}[A-Za-z]|//\S|\S+://|\w+@\S)", re.I),
     "a shell command"),
    # command substitution / chaining / piping into a shell
    (re.compile(r"\$\(|`[^`\n]{3,}`|\|\s*(?:ba)?sh\b|&&\s*\S|;\s*(?:" +
                _BINARIES + r")\b", re.I),
     "shell command syntax"),
    # credential-bearing argument forms
    (re.compile(r"-[UuPp]\s*\S+%\S+|--password[= ]\S+|-p['\"]?\S{3,}", re.I),
     "a credential in command form"),
]


def _cited_indices(text: str) -> set[int]:
    out: set[int] = set()
    for group in re.findall(r"\[([0-9,\s]+)\]", text or ""):
        for n in re.findall(r"\d+", group):
            out.add(int(n))
    return out


def unsafe_answer(text: str, hits: list[dict]) -> Optional[str]:
    """Second line of defence, independent of the prompt.

    Returns a reason string if the model's reply must be withheld, else None.
    This exists because layer 3 is an instruction to a 7B model, and an
    instruction is not a control. Rule 5 beats rule 1: a command sitting inside
    a finding is not licence to reproduce it, so we check the OUTPUT rather
    than trusting that the model obeyed.
    """
    if not text:
        return None
    for pattern, reason in _UNSAFE_PATTERNS:
        if pattern.search(text):
            return reason
    n = len(hits)
    bogus = sorted(i for i in _cited_indices(text) if i < 1 or i > n)
    if bogus:
        return (f"a citation to finding {bogus[0]}, which does not exist "
                f"(only {n} were retrieved)")
    return None


# ------------------------------------------------------------------ helpers

_CITED_LINE = re.compile(r"^\[\d+\]\s*(.*)$")


def strip_echoed_context(text: str, hits: list[dict]) -> str:
    """Remove findings the model reprinted verbatim before answering.

    Small local models routinely replay the numbered context block first.
    Left in, it buries the actual answer and - worse - defeats refusal
    detection, because the reply no longer STARTS with the sentinel. Only
    lines that restate a supplied finding are dropped; a citation followed by
    the model's own prose ("[1] We found an Apache...") is kept.
    """
    if not text:
        return text
    docs = {sanitize_document(h.get("document") or "") for h in hits}
    docs.discard("")
    kept: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not kept and not stripped:
            continue                                    # leading blank lines
        m = _CITED_LINE.match(stripped)
        if m is not None:
            core = m.group(1).strip()
            echoed = any(
                core.startswith(d[:80]) or (len(core) >= 25 and d.startswith(core))
                for d in docs
            )
            if echoed:
                continue
        kept.append(line)
    # May legitimately return "": a reply that was nothing but echoed
    # findings contains no answer, and answer() degrades rather than dress
    # the echo up as one.
    return "\n".join(kept).strip()


def relevant(hits: list[dict], max_distance: Optional[float]) -> list[dict]:
    """Drop hits beyond the distance cutoff. A hit with no distance (a store
    that doesn't report one) is kept - we never silently discard evidence."""
    if max_distance is None:
        return list(hits)
    out = []
    for h in hits:
        d = h.get("distance")
        if d is None or d <= max_distance:
            out.append(h)
    return out


def ensure_indexed(vec: Any, findings: list,
                   on_start: Optional[Callable[[int], None]] = None) -> int:
    """Backfill the vector store from SQLite, which is the source of truth.

    Covers three cases with one check: findings recorded while ChromaDB was
    absent, an engagement resumed from disk, and a collection-name change (a
    new name starts empty, so everything re-indexes once). `on_start` fires
    only when work is actually needed, so callers can show a one-time notice
    without printing anything in the common no-op case.
    """
    if not findings or not vec.available():
        return 0
    if vec.count() >= len(findings):
        return 0
    # count() can sit permanently below len(findings) - an embedding that
    # failed, a title containing the '|' used in the vector id. Without this
    # guard that difference re-embeds the whole engagement on EVERY question.
    # One attempt per store instance; a new session retries.
    if getattr(vec, "_gh_backfill_attempted", False):
        return 0
    try:
        vec._gh_backfill_attempted = True
    except Exception:
        pass
    if on_start is not None:
        on_start(len(findings))
    return vec.add_findings(findings)


def _generate(llm: Any, question: str, hits: list[dict]) -> GroundedAnswer:
    """Shared generate-then-check step for `ask` and `recall`'s summary.

    Both paths put scanner-controlled text in front of a model, so both get the
    same delimiting, the same restated rules, and the same output guard.
    """
    messages, kept, dropped = build_messages(question, hits)
    try:
        raw = llm.chat(messages, options=dict(ANSWER_OPTIONS))
    except Exception as exc:
        return GroundedAnswer(
            MODE_SEARCH, used=kept, dropped=dropped,
            message=f"Answering failed ({type(exc).__name__}); showing "
                    f"semantic search results instead.",
        )

    # Strip echoed context BEFORE guarding. Echoed lines are verbatim finding
    # text that never reaches the operator (they are removed from the display,
    # and the same rows appear in the Sources table anyway), so judging them as
    # if the model had authored them only produces false positives - an echoed
    # citation index would read as a fabricated source.
    stripped = strip_echoed_context((raw or "").strip(), kept)
    if not stripped:
        return GroundedAnswer(
            MODE_SEARCH, used=kept, dropped=dropped,
            message="The model restated the findings instead of answering; "
                    "showing what was retrieved.",
        )

    reason = unsafe_answer(stripped, kept)
    if reason is not None:
        return GroundedAnswer(
            MODE_BLOCKED, used=kept, dropped=dropped,
            message=f"Answer withheld: the model produced {reason}. Finding "
                    f"text comes from the scanned host and can carry planted "
                    f"instructions, so the reply was not shown. The retrieved "
                    f"findings are below - read them directly.",
        )

    return GroundedAnswer(MODE_ANSWER, text=stripped, used=kept, dropped=dropped)


def summarize(llm: Any, question: str, hits: list[dict]) -> GroundedAnswer:
    """Grounded summary of already-retrieved hits, for `recall`.

    Exposed so the older recall path gets the same hardening as `ask` rather
    than keeping its own weaker inline prompt.
    """
    if not hits:
        return GroundedAnswer(MODE_NO_FINDINGS, text=NO_FINDINGS)
    return _generate(llm, question, hits)


def answer(vec: Any, llm: Any, question: str,
           k: int = DEFAULT_K,
           max_distance: Optional[float] = DEFAULT_MAX_DISTANCE,
           llm_ready: bool = True) -> GroundedAnswer:
    """Retrieve, then answer STRICTLY from what was retrieved.

    Never raises: every failure degrades to a mode the caller can render.
    """
    question = (question or "").strip()
    if not question:
        return GroundedAnswer(MODE_NO_FINDINGS, text=NO_FINDINGS,
                              message="ask a question")

    if not vec.available():
        return GroundedAnswer(
            MODE_UNAVAILABLE,
            message="Semantic memory needs ChromaDB. Install it: "
                    "pipx inject ghostops 'chromadb>=0.5'  "
                    "(or  pip install -e '.[rag]'  in a venv).",
        )

    raw_hits = vec.query(question, k=k)

    # A lookup that ERRORED returns [] exactly like a lookup that matched
    # nothing. Reporting the first as "nothing relevant is recorded" would be
    # a false statement about the engagement dressed as a grounded one.
    if getattr(vec, "last_query_failed", False):
        return GroundedAnswer(
            MODE_RETRIEVAL_FAILED,
            message="Semantic memory did not answer (the store or the embed "
                    "model is unavailable). No grounded answer attempted - "
                    "this is NOT a statement that nothing was found.",
        )

    hits = relevant(raw_hits, max_distance)

    # Nothing close enough: report it WITHOUT calling the model. The model
    # cannot invent a finding it was never asked about.
    if not hits:
        try:
            stored = vec.count()
        except Exception:
            stored = None
        if stored == 0:
            detail = "no findings have been recorded in this engagement yet."
        else:
            detail = ("nothing recorded in this engagement is close enough to "
                      "that question.")
        return GroundedAnswer(MODE_NO_FINDINGS, text=f"{NO_FINDINGS} - {detail}")

    # No model: fall back to search rather than dead-ending.
    if not llm_ready:
        return GroundedAnswer(
            MODE_SEARCH, used=hits,
            message="Answering needs the router model; showing semantic "
                    "search results instead.",
        )

    return _generate(llm, question, hits)
