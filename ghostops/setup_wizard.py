"""First-run setup wizard - checks tools, Ollama, and model availability."""
from __future__ import annotations

import shutil

from rich.console import Console
from rich.table import Table

from ghostops.config import load_config
from ghostops.ai.llm_client import LLMClient

console = Console()

REQUIRED_TOOLS = {
    "nmap": "Network/port scanner",
    "gobuster": "Directory brute-forcer",
    "ffuf": "Web fuzzer",
    "sqlmap": "SQL injection tool",
    "hydra": "Brute-force tool",
    "nikto": "Web vulnerability scanner",
    "searchsploit": "ExploitDB search",
    "john": "Password cracker",
    "curl": "HTTP client",
}


def run_setup() -> None:
    console.print("[bold red]GhostOps Setup[/bold red]\n")
    cfg = load_config()

    table = Table(title="Security Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Purpose")
    table.add_column("Status")
    missing = []
    for tool, desc in REQUIRED_TOOLS.items():
        found = shutil.which(tool) is not None
        table.add_row(tool, desc,
                      "[green]found[/green]" if found else "[red]missing[/red]")
        if not found:
            missing.append(tool)
    console.print(table)
    if missing:
        console.print(
            f"\n[yellow]Install missing tools (Kali/Debian):[/yellow]\n"
            f"  sudo apt install {' '.join(missing)}"
        )

    console.print("\n[bold]LLM (Ollama)[/bold]")
    llm = LLMClient(cfg.get("llm.model"), cfg.get("llm.host"))
    if llm.available():
        console.print(f"  [green]Ollama reachable[/green] at {llm.host}")
        if llm.has_model():
            console.print(f"  [green]Model ready:[/green] {llm.model}")
        else:
            console.print(f"  [yellow]Pull the model:[/yellow] "
                          f"ollama pull {llm.model}")
    else:
        console.print(f"  [red]Ollama not reachable[/red] at {llm.host}")
        console.print("  Install: https://ollama.com  then: "
                      "ollama pull dolphin-mistral")

    console.print("\n[green]Ready.[/green] Start with: "
                  "ghostops engage <target>")
