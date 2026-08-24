#!/usr/bin/env python3
"""GhostOps - Local AI Red Team Assistant. Global 'ghostops' CLI."""
from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ghostops import __version__

app = typer.Typer(
    name="ghostops",
    help="GhostOps - Local AI Red Team Assistant (authorized use only).",
    add_completion=True,
    no_args_is_help=True,
)
console = Console()


@app.command()
def engage(
    target: str = typer.Argument(..., help="Target IP, CIDR, or hostname"),
    model: str = typer.Option("dolphin-mistral", help="Ollama model to use"),
    stealth: bool = typer.Option(False, help="Enable OPSEC-safe (quieter) mode"),
):
    """Start a new engagement against a target."""
    from ghostops.agent.orchestrator import start_engagement
    start_engagement(target, model, stealth)


@app.command()
def shell(model: str = typer.Option("dolphin-mistral", help="Ollama model")):
    """Open free-form chat with the red team AI (scope = *)."""
    from ghostops.agent.orchestrator import start_shell
    start_shell(model)


@app.command()
def resume(
    engagement_id: str = typer.Argument("last", help="Engagement ID or 'last'"),
):
    """Resume a previous engagement."""
    from ghostops.agent.orchestrator import resume_engagement
    resume_engagement(engagement_id)


@app.command()
def report(
    engagement_id: str = typer.Argument("last", help="Engagement ID or 'last'"),
    output: str = typer.Option("report.md", "-o", help="Output file path"),
):
    """Generate a markdown pentest report from engagement data."""
    from ghostops.report.generator import generate_report
    generate_report(engagement_id, output)


@app.command()
def engagements():
    """List all saved engagements."""
    from ghostops.config import load_config
    from ghostops.memory.store import list_engagements
    cfg = load_config()
    items = list_engagements(cfg.get("engagements.dir", "./engagements"))
    if not items:
        console.print("[yellow]No engagements yet.[/yellow] "
                      "Start one: ghostops engage <target>")
        return
    t = Table(title="Engagements")
    t.add_column("ID", style="cyan")
    t.add_column("Name")
    t.add_column("Phase", style="magenta")
    t.add_column("Hosts", justify="right")
    t.add_column("Ports", justify="right")
    t.add_column("Findings", justify="right")
    t.add_column("Created")
    for it in sorted(items, key=lambda x: x["created_at"], reverse=True):
        t.add_row(it["id"], it["name"], it["phase"],
                  str(it["hosts"]), str(it["ports"]),
                  str(it["findings"]), it["created_at"])
    console.print(t)


@app.command()
def setup():
    """First-run setup - check tools, models, and config."""
    from ghostops.setup_wizard import run_setup
    run_setup()


@app.command()
def version():
    """Show the GhostOps version."""
    console.print(Panel(f"[bold red]GhostOps[/bold red] v{__version__}",
                        border_style="red"))


if __name__ == "__main__":
    app()
