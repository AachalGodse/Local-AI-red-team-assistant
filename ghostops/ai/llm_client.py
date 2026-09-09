"""Ollama client with graceful offline degradation.

If Ollama isn't reachable (common during Windows dev with no GPU), GhostOps
stays usable: manual tool commands still run; only AI reasoning is disabled.
`available()` lets callers detect the mode.
"""
from __future__ import annotations

import json
from typing import Any

import requests


class LLMClient:
    def __init__(self, model: str, host: str = "http://localhost:11434",
                 temperature: float = 0.4, timeout: int = 300):
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
        # Generation budget. A 7B on CPU answering a grounded question with the
        # full rule block can run well past the old hardcoded 300s; every tool
        # timeout here is configurable, so this one is too (`llm.timeout`).
        self.timeout = timeout
        self._available: bool | None = None

    # ------------------------------------------------------------ health
    def available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=2)
            self._available = r.status_code == 200
        except Exception:
            self._available = False
        return self._available

    def has_model(self, model: str | None = None) -> bool:
        """Is `model` (default: this client's router model) pulled in Ollama?"""
        want = (model or self.model).split(":")[0]
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            names = [m.get("name", "") for m in r.json().get("models", [])]
            return any(want in n for n in names)
        except Exception:
            return False

    # ------------------------------------------------------------ chat
    def chat(self, messages: list[dict], stream: bool = False,
             fmt: str | dict | None = None,
             options: dict | None = None) -> str:
        """Return the assistant message content. `fmt='json'` forces JSON.

        `options` overrides Ollama generation options (temperature,
        num_predict, ...). Grounded answering uses it to pin a low temperature
        and cap the reply length - an uncapped 7B on CPU will happily spend
        minutes restating its context.
        """
        opts: dict[str, Any] = {"temperature": self.temperature}
        if options:
            opts.update(options)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": opts,
        }
        if fmt:
            payload["format"] = fmt
        r = requests.post(f"{self.host}/api/chat", json=payload,
                          timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return data.get("message", {}).get("content", "")

    def chat_json(self, messages: list[dict]) -> dict:
        """Force a JSON object response and parse it (with a repair retry)."""
        raw = self.chat(messages, fmt="json")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            # one repair attempt: extract the first {...} block
            start, end = raw.find("{"), raw.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(raw[start:end + 1])
                except json.JSONDecodeError:
                    pass
            return {"action": "respond",
                    "message": raw or "(no response from model)"}

    # ------------------------------------------------------------ embeddings
    def embed(self, text: str, model: str | None = None) -> list[float]:
        """Return an embedding vector for `text` from Ollama's embed model.

        `model` defaults to this client's model; for RAG pass the configured
        embed model (e.g. nomic-embed-text). Raises on transport/HTTP error so
        callers can degrade gracefully.
        """
        payload = {"model": model or self.model, "prompt": text}
        r = requests.post(f"{self.host}/api/embeddings", json=payload, timeout=60)
        r.raise_for_status()
        return r.json().get("embedding", []) or []

    def embed_many(self, texts: list[str],
                   model: str | None = None) -> list[list[float]]:
        """Embed many texts in ONE request via Ollama's /api/embed.

        Backfilling a resumed engagement one HTTP call at a time is the
        difference between a blink and a stall (~8s vs ~40s for 50 findings).
        Falls back to per-text /api/embeddings on older servers that have no
        /api/embed, so nothing breaks on an older Ollama.

        Note: /api/embed returns unit-normalized vectors while /api/embeddings
        does not. The direction is identical, and cosine distance - which is
        what the vector store queries in - ignores magnitude, so the two are
        safely interchangeable here.
        """
        texts = list(texts)
        if not texts:
            return []
        try:
            r = requests.post(
                f"{self.host}/api/embed",
                json={"model": model or self.model, "input": texts},
                timeout=300,
            )
            r.raise_for_status()
            embs = r.json().get("embeddings") or []
            if len(embs) == len(texts):
                return embs
        except Exception:
            pass
        return [self.embed(t, model=model) for t in texts]
