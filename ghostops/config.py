"""Configuration loading. Merges built-in defaults with optional YAML files."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "llm": {
        # Router / reasoning model. Does tool routing and next-step reasoning
        # ONLY - never payload generation. Swappable: change this one line to
        # use any Ollama model; if it's unreachable GhostOps falls back to the
        # deterministic offline router.
        "model": "dolphin-mistral",
        # Embedding model for semantic memory (RAG). Inert until that feature
        # is enabled; pulled with `ollama pull nomic-embed-text`.
        "embed_model": "nomic-embed-text",
        "host": "http://localhost:11434",
        "temperature": 0.4,
    },
    "engagements": {
        "dir": "./engagements",
    },
    "tools": {
        "nmap": {"default_args": "-sV -T4", "timeout": 600},
        "gobuster": {
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "timeout": 600,
        },
        "searchsploit": {"timeout": 120},
        "sqlmap": {"timeout": 900},
        "hydra": {"timeout": 900},
        "nikto": {"timeout": 900},
    },
    "safety": {
        "confirm_before_run": True,
        "enforce_scope": True,
    },
}

# Config file search order (first found is merged over defaults, later files
# override earlier keys).
_SEARCH_PATHS = [
    Path.home() / ".ghostops" / "config.yaml",
    Path.cwd() / "config.yaml",
]


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict[str, Any]):
        self._data = data

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def get(self, path: str, default: Any = None) -> Any:
        """Dotted lookup, e.g. cfg.get('llm.model')."""
        cur: Any = self._data
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return default
        return cur

    @property
    def data(self) -> dict:
        return self._data


def load_config(extra_path: str | os.PathLike | None = None) -> Config:
    data = copy.deepcopy(DEFAULTS)
    paths = list(_SEARCH_PATHS)
    if extra_path:
        paths.append(Path(extra_path))
    for p in paths:
        try:
            if p.is_file():
                with open(p, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f) or {}
                data = _deep_merge(data, loaded)
        except Exception:
            # A broken config file should never crash the tool; fall back.
            continue
    return Config(data)
