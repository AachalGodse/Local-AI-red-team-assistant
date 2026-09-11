"""Base class + result type for every tool wrapper.

The contract every tool implements:
  * name / description           -> shown to the LLM for routing
  * args_schema                  -> JSON schema; validates LLM-proposed args
  * is_available()               -> is the binary installed?
  * build_command(args)          -> the exact argv that will run (for preview)
  * run(args)                    -> execute + parse into a ToolResult
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field

from ghostops.models import Credential, Finding, Host


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    summary: str = ""
    error: str = ""
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return not self.error and self.returncode == 0

    @property
    def command_str(self) -> str:
        return " ".join(self.command)


class BaseTool:
    name: str = "base"
    description: str = ""
    # JSON-schema-ish description of accepted args; subclasses override.
    args_schema: dict = {"type": "object", "properties": {}, "required": []}
    binary: str = ""          # executable name to look up on PATH
    # Loud/attacking tools. The orchestrator ALWAYS prompts before running one,
    # even when safety.confirm_before_run is off - a config flag must not be
    # able to fire a brute-force silently. Keep in step with the intrusive
    # actions in agent/next_steps.py (tests/test_smoke.py asserts they agree).
    intrusive: bool = False

    def __init__(self, timeout: int = 600, default_args: str = ""):
        self.timeout = timeout
        self.default_args = default_args

    # ---- availability -------------------------------------------------
    def is_available(self) -> bool:
        return shutil.which(self.binary or self.name) is not None

    # ---- to be implemented by subclasses ------------------------------
    def build_command(self, args: dict) -> list[str]:
        raise NotImplementedError

    def parse(self, result: ToolResult) -> None:
        """Populate result.hosts / result.findings / result.summary in place."""
        return None

    def validate_args(self, args: dict) -> tuple[bool, str]:
        """Lightweight required-field check against args_schema."""
        for req in self.args_schema.get("required", []):
            if not args.get(req):
                return False, f"missing required arg: {req}"
        return True, ""

    def scope_target(self, args: dict) -> str:
        """The host the scope guard should check for this call.

        Default: the 'target' arg. Tools that address a host differently
        (e.g. gobuster via a URL) override this. Return "" for tools that
        don't hit a network target (e.g. searchsploit)."""
        return str(args.get("target", "")).strip()

    # ---- execution ----------------------------------------------------
    def run(self, args: dict, dry_run: bool = False) -> ToolResult:
        cmd = self.build_command(args)
        result = ToolResult(tool=self.name, command=cmd, dry_run=dry_run)

        if dry_run:
            result.summary = f"[dry-run] would execute: {result.command_str}"
            return result

        if not self.is_available():
            result.error = (
                f"'{self.binary or self.name}' not found on PATH. "
                f"Install it (e.g. sudo apt install {self.binary or self.name})."
            )
            return result

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            result.returncode = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr
        except subprocess.TimeoutExpired:
            result.error = f"timed out after {self.timeout}s"
        except FileNotFoundError:
            result.error = f"'{cmd[0]}' not found"
        except Exception as exc:  # pragma: no cover - defensive
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.duration = round(time.time() - start, 2)

        if not result.error:
            try:
                self.parse(result)
            except Exception as exc:
                result.error = f"parse error: {type(exc).__name__}: {exc}"
        return result
