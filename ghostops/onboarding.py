"""First-run walkthrough + the `ghostops help` welcome screen.

Additive onboarding only: this wraps *around* command dispatch and never changes
what any command does. The first-run walkthrough shows once, only in an
interactive terminal, and hands off to the existing `ghostops setup` wizard -
it never reimplements onboarding config.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# The one-line authorized-use note shown in BOTH the walkthrough and help.
AUTHORIZED_USE = (
    "[red]Authorized use only.[/red] Only run GhostOps against systems you own "
    "or have [bold]explicit written permission[/bold] to test. You are "
    "responsible for staying in scope and within the law."
)


def _flag_path() -> Path:
    """Where the 'already onboarded' marker lives (beside the config).
    Wrapped in a function so tests can point it elsewhere."""
    return Path.home() / ".ghostops" / ".onboarded"


def is_first_run() -> bool:
    try:
        return not _flag_path().exists()
    except Exception:
        return False


def mark_onboarded() -> None:
    try:
        p = _flag_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch()
    except Exception:
        pass


def _interactive() -> bool:
    """True only when both stdin and stdout are a real terminal."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def should_show_walkthrough(no_intro: bool = False) -> bool:
    """Fire the walkthrough only on an interactive first run, unless skipped."""
    if no_intro or os.environ.get("GHOSTOPS_NO_INTRO"):
        return False
    return _interactive() and is_first_run()


def _rag_present() -> bool:
    try:
        from ghostops.memory.vector_store import chromadb_available
        return chromadb_available()
    except Exception:
        return False


def welcome(console: Console) -> None:
    """The `ghostops help` welcome / command reference. Safe to print anytime,
    including piped (it's static text, no prompts)."""
    console.print(Panel(
        "[bold red]GhostOps[/bold red] - a local, offline AI red-team copilot.\n"
        "It runs the security tools, remembers what it finds, follows the "
        "pentest kill chain, and writes the report - all on your machine, no "
        "cloud, no API keys.",
        border_style="red", title="What is GhostOps?",
    ))
    console.print(
        "\n[bold]The flow[/bold]  "
        "[cyan]engage[/cyan] a target -> [cyan]scan[/cyan] it -> "
        "[cyan]pick[/cyan] a next step from the menu -> "
        "[cyan]review[/cyan] findings -> generate the [cyan]report[/cyan]\n"
    )

    shell_cmds = [
        ("ghostops engage <target>", "start an engagement (scope locks to it)"),
        ("ghostops shell", "free-form chat with the AI (scope = *)"),
        ("ghostops resume last", "resume your most recent engagement"),
        ("ghostops report last -o report.md", "generate a Markdown report"),
        ("ghostops setup", "check tools, model, and config"),
        ("ghostops model", "show which LLM is active (AI vs offline)"),
        ("ghostops engagements", "list saved engagements"),
        ("ghostops help", "show this screen"),
    ]
    repl_cmds = [
        ("scan <target>", "run an nmap scan (in-scope only)"),
        ("next", "numbered menu of next steps - pick by number"),
        ("what do we know", "full engagement summary"),
    ]
    if _rag_present():
        repl_cmds.append(("recall <question>", "semantic search of findings (RAG)"))
    repl_cmds.append(("help / exit", "help, or leave the engagement"))

    st = Table(title="From your shell", show_header=False, box=None, pad_edge=False)
    st.add_column(style="green", no_wrap=True)
    st.add_column()
    for cmd, desc in shell_cmds:
        st.add_row(cmd, desc)
    console.print(st)

    rt = Table(title="Inside an engagement", show_header=False, box=None,
               pad_edge=False)
    rt.add_column(style="green", no_wrap=True)
    rt.add_column()
    for cmd, desc in repl_cmds:
        rt.add_row(cmd, desc)
    console.print(rt)

    console.print(Panel(AUTHORIZED_USE, border_style="red"))


def first_run_walkthrough(console: Console, invoked_subcommand: str | None) -> None:
    """Brief guided intro, shown once on an interactive first run. On a bare
    invocation (no subcommand) it offers to launch the existing setup wizard."""
    console.print(Panel(
        "[bold red]Welcome to GhostOps[/bold red] - your local, offline "
        "AI red-team copilot.\n\n"
        "It [bold]runs[/bold] security tools (nmap, gobuster, searchsploit, "
        "sqlmap, hydra), remembers everything discovered, follows the pentest "
        "kill chain, and writes a report - all on your machine.\n\n"
        "[bold]Recommended first steps[/bold]\n"
        "  1. [green]ghostops setup[/green] - check your tools + model\n"
        "  2. [green]ghostops engage <target>[/green] - start on an authorized "
        "target\n"
        "  3. inside: [green]scan <target>[/green], then pick a numbered next "
        "step\n\n"
        + AUTHORIZED_USE,
        border_style="red", title="First run",
    ))
    if invoked_subcommand is not None:
        return   # a command was given; don't prompt, just let it run
    try:
        from rich.prompt import Confirm
        if Confirm.ask("Run setup now to check your tools?", default=True):
            from ghostops.setup_wizard import run_setup
            run_setup()
        else:
            console.print("[dim]Skipped. Run 'ghostops setup' anytime, or "
                          "'ghostops help'.[/dim]")
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Skipped. Run 'ghostops setup' anytime.[/dim]")
