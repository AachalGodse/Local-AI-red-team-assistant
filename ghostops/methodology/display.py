"""Rich rendering for service checklists. Separate from checklists.py so the
loader stays dependency-light and testable."""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ghostops.methodology.checklists import Checklist, render_cmd, services

_NOISE_COLOR = {"low": "green", "medium": "yellow", "high": "red"}


def show_checklist(console: Console, cl: Checklist, *, host: str = "",
                   port: int | str = "", stealth: bool = False) -> None:
    """Render one service's checklist, filling {host}/{port} where given."""
    where = ""
    if host:
        where = f"  [dim]{host}{(':' + str(port)) if port else ''}[/dim]"
    t = Table(title=None, show_lines=False, expand=True)
    t.add_column("#", style="cyan", justify="right", no_wrap=True)
    t.add_column("Step")
    t.add_column("Command", style="green", no_wrap=False)
    for i, c in enumerate(cl.checks, 1):
        if stealth and c.noise == "high":
            continue
        step = c.task
        bits = []
        if c.tool:
            bits.append(f"[magenta]{c.tool}[/magenta]")
        if c.noise:
            col = _NOISE_COLOR.get(c.noise, "white")
            bits.append(f"[{col}]{c.noise}[/{col}]")
        if bits:
            step += "  " + " ".join(bits)
        if c.why:
            step += f"\n[dim]{c.why}[/dim]"
        t.add_row(str(i), step, render_cmd(c.cmd, host, port) if c.cmd else "")
    console.print(Panel(
        t, title=f"[bold]{cl.name}[/bold] checklist  [dim]({cl.phase})[/dim]{where}",
        border_style="magenta",
    ))
    if stealth and any(c.noise == "high" for c in cl.checks):
        console.print("[dim]stealth: high-noise steps hidden.[/dim]")


def show_index(console: Console) -> None:
    """List the services the catalog has checklists for."""
    console.print(Panel(
        ", ".join(services()) or "(none)",
        title="Checklists available", border_style="magenta",
        subtitle="[dim]checklist <service>  |  checklist  (for discovered hosts)[/dim]",
    ))
