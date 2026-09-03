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
                 temperature: float = 0.4):
        self.model = model
        self.host = host.rstrip("/")
        self.temperature = temperature
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
             fmt: str | dict | None = None) -> str:
        """Return the assistant message content. `fmt='json'` forces JSON."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        if fmt:
            payload["format"] = fmt
        r = requests.post(f"{self.host}/api/chat", json=payload, timeout=300)
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
