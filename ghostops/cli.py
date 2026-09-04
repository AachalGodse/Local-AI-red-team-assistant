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
    no_args_is_help=False,   # the callback shows the welcome screen for no args
)
console = Console()


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    no_intro: bool = typer.Option(
        False, "--no-intro", help="Skip the first-run walkthrough."),
):
    """GhostOps - Local AI Red Team Assistant (authorized use only)."""
    from ghostops import onboarding
    # First-run walkthrough: interactive terminals only, once. Never fires in
    # piped / non-TTY use, so it can't block scripts or automation.
    if onboarding.should_show_walkthrough(no_intro):
        onboarding.first_run_walkthrough(console, ctx.invoked_subcommand)
        onboarding.mark_onboarded()
        if ctx.invoked_subcommand is None:
            raise typer.Exit()
        return
    # Bare `ghostops` (no subcommand) -> the friendly welcome screen.
    if ctx.invoked_subcommand is None:
        onboarding.welcome(console)
        raise typer.Exit()


@app.command()
def engage(
    target: str = typer.Argument(..., help="Target IP, CIDR, or hostname"),
    model: str = typer.Option(None, help="Ollama model (default: config llm.model)"),
    stealth: bool = typer.Option(False, help="Enable OPSEC-safe (quieter) mode"),
):
    """Start a new engagement against a target."""
    from ghostops.agent.orchestrator import start_engagement
    start_engagement(target, model, stealth)


@app.command()
def shell(
    model: str = typer.Option(None, help="Ollama model (default: config llm.model)"),
):
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
    output: str = typer.Option("report.md", "-o", "--output", help="Output file path"),
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
def generate(
    category: str = typer.Argument(
        None, help="revshell | bindshell | webshell | listener | tty | privesc"
    ),
    name: str = typer.Argument(None, help="specific payload key, e.g. 'python3'"),
    lhost: str = typer.Option("", "-l", "--lhost", help="listener/callback host"),
    lport: str = typer.Option("", "-p", "--lport", help="listener/callback port"),
    shell: str = typer.Option("/bin/bash", "--shell", help="shell to spawn"),
    param: str = typer.Option("cmd", "--param", help="web-shell request param"),
    encode: bool = typer.Option(False, "--encode", help="base64-wrap the payload"),
    list_only: bool = typer.Option(False, "--list", help="list payloads and exit"),
):
    """Generate a curated offensive payload (reverse shell, web shell, etc.)."""
    from ghostops.payloads.display import show_catalog, show_payload
    from ghostops.payloads.generator import (
        DEFAULT_PAYLOAD, PayloadError, catalog_available, categories, generate,
    )

    if not catalog_available():
        console.print(Panel(
            "[red]Payload catalog not found on disk.[/red]\n\n"
            "The plaintext catalog is quarantined on sight by host antivirus "
            "(e.g. Windows Defender). Fix by one of:\n"
            "  - ship the base64 form [cyan]payloads.b64[/cyan] "
            "(carries no signatures), or\n"
            "  - add an AV exclusion for the project directory, then restore "
            "[cyan]payloads.yaml[/cyan], or\n"
            "  - install/run GhostOps on Kali/WSL (no Defender).",
            border_style="red", title="Payloads",
        ))
        raise typer.Exit(1)

    if category is None:
        show_catalog(console)
        console.print("\n[dim]Categories:[/dim] " + ", ".join(categories()))
        console.print("[dim]e.g.[/dim] ghostops generate revshell python3 "
                      "-l 10.10.14.5 -p 4444")
        return
    if category not in categories():
        console.print(f"[red]Unknown category:[/red] {category}. "
                      f"Choose from: {', '.join(categories())}")
        raise typer.Exit(1)

    # No specific payload chosen: fall back to the category default only when
    # the user clearly wants one rendered (gave -l/-p); otherwise just list.
    if name is None:
        if list_only or not (lhost or lport):
            return show_catalog(console, category)
        name = DEFAULT_PAYLOAD.get(category)
        if name:
            console.print(f"[dim]no payload named; using default "
                          f"'{category}/{name}'[/dim]")
    if list_only:
        return show_catalog(console, category)

    try:
        p = generate(category, name, lhost=lhost, lport=lport,
                     shell=shell, param=param, encode=encode)
    except PayloadError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    show_payload(console, p)


@app.command()
def checklist(
    service: str = typer.Argument(
        None, help="service name, e.g. http, ssh, smb (omit to list all)"
    ),
):
    """Show the enumeration checklist for a service (curated methodology)."""
    from ghostops.methodology import checklists as cl
    from ghostops.methodology.display import show_checklist, show_index
    if not cl.available():
        console.print("[red]Checklist catalog not found on disk.[/red] "
                      "Run on Kali/WSL or restore knowledge/checklists.yaml.")
        raise typer.Exit(1)
    if service is None:
        return show_index(console)
    match = cl.get(service) or cl.match(service)
    if match is None:
        console.print(f"[red]No checklist for '{service}'.[/red]")
        show_index(console)
        raise typer.Exit(1)
    show_checklist(console, match)


@app.command()
def attack():
    """Show the GhostOps action -> MITRE ATT&CK technique mapping."""
    from rich.table import Table
    from ghostops.methodology import mitre
    if not mitre.available():
        console.print("[red]ATT&CK map not found on disk.[/red] "
                      "Run on Kali/WSL or restore knowledge/mitre.yaml.")
        raise typer.Exit(1)
    t = Table(title="GhostOps -> MITRE ATT&CK")
    t.add_column("Action", style="cyan")
    t.add_column("Tactic", style="magenta")
    t.add_column("ID", no_wrap=True)
    t.add_column("Technique")
    for section, key, tech in mitre.all_techniques():
        t.add_row(f"{section[:-1]}:{key}", tech.tactic, tech.id, tech.name)
    console.print(t)


@app.command()
def recall(
    question: str = typer.Argument(..., help="natural-language question"),
    engagement_id: str = typer.Argument("last", help="Engagement ID or 'last'"),
):
    """Semantic search over an engagement's findings (RAG). Needs ChromaDB + embed model."""
    from pathlib import Path
    from rich.table import Table
    from ghostops.ai.llm_client import LLMClient
    from ghostops.config import load_config
    from ghostops.memory.store import EngagementStore, list_engagements
    from ghostops.memory.vector_store import VectorMemory, chromadb_available

    cfg = load_config()
    eng_dir = cfg.get("engagements.dir", "./engagements")
    if not chromadb_available():
        console.print("[yellow]Semantic recall needs ChromaDB.[/yellow] "
                      "Install: [cyan]pip install chromadb[/cyan]")
        raise typer.Exit(1)
    if engagement_id == "last":
        items = list_engagements(eng_dir)
        if not items:
            console.print("[yellow]No engagements found.[/yellow]")
            raise typer.Exit(1)
        engagement_id = sorted(items, key=lambda x: x["created_at"])[-1]["id"]
    store = EngagementStore(f"{eng_dir}/{engagement_id}.db")
    e = store.load()
    if e is None:
        console.print(f"[red]Engagement not found:[/red] {engagement_id}")
        raise typer.Exit(1)

    host = cfg.get("llm.host", "http://localhost:11434")
    embed = cfg.get("llm.embed_model", "nomic-embed-text")
    llm = LLMClient(model=embed, host=host)
    if not (llm.available() and llm.has_model(embed)):
        console.print(f"[yellow]Embed model unavailable.[/yellow] "
                      f"Pull it: [cyan]ollama pull {embed}[/cyan]")
        raise typer.Exit(1)

    vec = VectorMemory(e.id, Path(f"{eng_dir}/{engagement_id}.chroma"),
                       embed_fn=lambda t: llm.embed(t, model=embed))
    if vec.count() < len(e.findings):
        vec.add_findings(e.findings)
    hits = vec.query(question, k=5)
    if not hits:
        console.print("[dim]No relevant findings recorded.[/dim]")
        return
    t = Table(title=f"Recall - {question}")
    t.add_column("#", style="cyan", justify="right")
    t.add_column("Finding", style="green")
    t.add_column("Where", style="dim")
    for i, h in enumerate(hits, 1):
        meta = h.get("metadata", {})
        where = (meta.get("host", "") or "")
        if meta.get("port"):
            where += f":{meta['port']}"
        t.add_row(str(i), meta.get("title") or (h.get("document") or "")[:70],
                  where)
    console.print(t)


@app.command()
def model():
    """Show which LLM is active and whether GhostOps will run in AI or offline mode."""
    from ghostops.ai.llm_client import LLMClient
    from ghostops.config import load_config
    cfg = load_config()
    host = cfg.get("llm.host", "http://localhost:11434")
    router = cfg.get("llm.model", "dolphin-mistral")
    embed = cfg.get("llm.embed_model", "nomic-embed-text")

    client = LLMClient(model=router, host=host)
    reachable = client.available()
    router_pulled = reachable and client.has_model()
    embed_pulled = reachable and LLMClient(model=embed, host=host).has_model()
    # AI routing needs the server up AND the router model pulled; otherwise the
    # deterministic offline router takes over.
    mode = ("[green]AI routing[/green]" if router_pulled
            else "[yellow]OFFLINE (deterministic router)[/yellow]")

    def yn(ok: bool) -> str:
        return "[green]yes[/green]" if ok else "[red]no[/red]"

    console.print(Panel(
        f"Host:          [cyan]{host}[/cyan]  (reachable: {yn(reachable)})\n"
        f"Router model:  [green]{router}[/green]  (pulled: {yn(router_pulled)})\n"
        f"Embed model:   [green]{embed}[/green]  (pulled: {yn(embed_pulled)})  "
        f"[dim]# for RAG[/dim]\n"
        f"Active mode:   {mode}",
        title="Active model", border_style="red",
    ))
    if not reachable:
        console.print("[dim]Start Ollama, or run offline - commands still "
                      "work. Install: https://ollama.com[/dim]")
    elif not router_pulled:
        console.print(f"[dim]Pull the router model:[/dim] ollama pull {router}")


@app.command()
def setup():
    """First-run setup - check tools, models, and config."""
    from ghostops.setup_wizard import run_setup
    run_setup()


@app.command("help")
def help_cmd():
    """Show the GhostOps welcome screen and command reference."""
    from ghostops import onboarding
    onboarding.welcome(console)


@app.command()
def version():
    """Show the GhostOps version."""
    console.print(Panel(f"[bold red]GhostOps[/bold red] v{__version__}",
                        border_style="red"))


if __name__ == "__main__":
    app()
