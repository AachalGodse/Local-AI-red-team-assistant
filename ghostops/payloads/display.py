"""Rich rendering for payloads. Kept out of generator.py so the generator has
no rich/console dependency and stays trivially unit-testable."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from ghostops.payloads.generator import Payload, list_payloads

_NOISE_COLOR = {"low": "green", "medium": "yellow", "high": "red"}


def show_payload(console: Console, p: Payload, *, stealth: bool = False) -> None:
    """Print a rendered payload: the code, plus requires/OPSEC context."""
    noise_col = _NOISE_COLOR.get(p.noise, "white")
    syntax = Syntax(p.body, p.lang, theme="ansi_dark",
                    word_wrap=True, background_color="default")
    console.print(Panel(
        syntax,
        title=f"[bold]{p.name}[/bold]  [dim]({p.ref})[/dim]",
        subtitle=f"noise: [{noise_col}]{p.noise}[/{noise_col}]",
        border_style=noise_col if stealth else "green",
    ))
    if p.requires:
        console.print(f"[dim]requires:[/dim] {p.requires}")
    if p.opsec:
        console.print(f"[{noise_col}]OPSEC:[/{noise_col}] {p.opsec}")


def show_catalog(console: Console, category: str | None = None) -> None:
    """List available payloads (name, noise, requirement) as a table."""
    payloads = list_payloads(category)
    if not payloads:
        console.print(f"[yellow]No payloads in category {category!r}.[/yellow]")
        return
    t = Table(title="Payloads" + (f" - {category}" if category else ""))
    t.add_column("Ref", style="cyan")
    t.add_column("Name")
    t.add_column("Noise")
    t.add_column("Requires", style="dim", no_wrap=False)
    for p in payloads:
        noise_col = _NOISE_COLOR.get(p.noise, "white")
        t.add_row(p.ref, p.name,
                  f"[{noise_col}]{p.noise}[/{noise_col}]", p.requires)
    console.print(t)
