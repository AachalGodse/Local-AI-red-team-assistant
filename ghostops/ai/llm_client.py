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

    def has_model(self) -> bool:
        try:
            r = requests.get(f"{self.host}/api/tags", timeout=3)
            names = [m.get("name", "") for m in r.json().get("models", [])]
            return any(self.model.split(":")[0] in n for n in names)
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
