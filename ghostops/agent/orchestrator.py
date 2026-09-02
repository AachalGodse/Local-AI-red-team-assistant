"""The agent loop: intent -> tool -> parse -> memory -> briefing.

Design notes:
- LLM tool routing uses a strict JSON contract (see ai/prompts.ROUTER_SYSTEM).
- Every tool call passes through: arg validation -> scope guard -> operator
  confirmation -> execute. No tool ever runs against an out-of-scope target.
- If Ollama is unreachable, a regex offline router keeps core actions working,
  so the tool is fully testable without a model.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from ghostops.ai.llm_client import LLMClient
from ghostops.ai.prompts import PERSONA, ROUTER_SYSTEM, SUMMARIZE_SYSTEM
from ghostops.agent.scope_guard import ScopeGuard
from ghostops.config import Config, load_config
from ghostops.models import ActivityLog, Engagement, Phase
from ghostops.memory.store import EngagementStore
from ghostops.tools.base_tool import ToolResult
from ghostops.tools.registry import build_registry, tool_catalog

console = Console()

# Payload categories usable as bare REPL verbs (revshell, webshell, ...).
_PAYLOAD_CATEGORIES = frozenset(
    ("revshell", "bindshell", "webshell", "listener", "tty", "privesc")
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _new_id() -> str:
    return f"eng-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:4]}"


class Orchestrator:
    def __init__(self, cfg: Config, engagement: Engagement, store: EngagementStore):
        self.cfg = cfg
        self.e = engagement
        self.store = store
        self.tools = build_registry(cfg)
        self.llm = LLMClient(
            model=engagement.model,
            host=cfg.get("llm.host", "http://localhost:11434"),
            temperature=cfg.get("llm.temperature", 0.4),
        )
        self.guard = ScopeGuard(
            engagement.scope, enforce=cfg.get("safety.enforce_scope", True)
        )
        self.confirm_before_run = cfg.get("safety.confirm_before_run", True)
        self._llm_ok = self.llm.available()

    # ---------------------------------------------------------------- log
    def _log(self, kind: str, summary: str, detail: str = "") -> None:
        self.e.activity.append(ActivityLog(_now(), kind, summary, detail))

    def _persist(self) -> None:
        self.store.save(self.e)

    # ------------------------------------------------------------- banner
    def banner(self) -> None:
        mode = (
            "[green]AI mode[/green]"
            if self._llm_ok
            else "[yellow]OFFLINE (no Ollama) - commands only[/yellow]"
        )
        c = self.e.counts()
        console.print(Panel(
            f"[bold red]GhostOps[/bold red] - engagement [cyan]{self.e.id}[/cyan]\n"
            f"Scope:    [cyan]{', '.join(self.e.scope) or '(none)'}[/cyan]\n"
            f"Phase:    [magenta]{self.e.phase.value}[/magenta]\n"
            f"Model:    [green]{self.e.model}[/green]   {mode}\n"
            f"Findings: {c['hosts']} hosts | {c['ports']} ports | "
            f"{c['findings']} findings | {c['creds']} creds",
            title="Engagement", border_style="red",
        ))
        if not self._llm_ok:
            console.print(
                "[dim]Ollama not reachable. Use commands like "
                "'scan <target>', 'what do we know', 'help'. "
                "Start Ollama for full AI routing.[/dim]"
            )

    # -------------------------------------------------------------- input
    def run(self) -> None:
        self.banner()
        console.print("[dim]Type 'help' for commands, 'exit' to quit.[/dim]\n")
        while True:
            try:
                text = console.input(
                    "[bold red]ghostops[/bold red][white]>[/white] "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Saving and exiting.[/dim]")
                break
            if not text:
                continue
            if text.lower() in ("exit", "quit", ":q"):
                break
            try:
                self.handle(text)
            except Exception as exc:  # keep the REPL alive on any error
                console.print(f"[red]error:[/red] {type(exc).__name__}: {exc}")
            self._persist()
        self._persist()
        console.print(f"[green]Saved.[/green] Engagement: {self.store.path}")

    # ------------------------------------------------------------- router
    def handle(self, text: str) -> None:
        low = text.lower()

        # ---- built-in commands (work with or without the LLM) ----
        if low in ("help", "?", "/help"):
            return self._help()
        if low in ("tools", "/tools"):
            return self._show_tools()
        if low in ("what do we know", "whatweknow", "/know", "summary", "/summary"):
            return self._show_summary()
        if low in ("phase", "/phase"):
            return console.print(
                f"Current phase: [magenta]{self.e.phase.value}[/magenta]"
            )
        if low in ("next", "/next"):
            return self._suggest_next()
        if (low in ("checklist", "checklists", "/checklist")
                or low.startswith("checklist ")):
            return self._handle_checklist(text)
        if low.startswith("scan "):
            target = text[5:].strip()
            return self._execute_tool(
                "nmap", {"target": target, "profile": "default"}
            )
        if low.startswith("gobuster "):
            return self._execute_tool("gobuster", {"url": text[9:].strip()})
        if low.startswith("searchsploit ") or low.startswith("sploit "):
            return self._execute_tool(
                "searchsploit", {"query": text.split(" ", 1)[1].strip()}
            )
        if low.startswith("sqlmap "):
            return self._execute_tool("sqlmap", {"url": text[7:].strip()})
        if low.startswith("hydra "):
            parts = text.split()
            if len(parts) >= 5:
                return self._execute_tool("hydra", {
                    "target": parts[1], "service": parts[2],
                    "username": parts[3], "passlist": parts[4],
                })
            return console.print(
                "usage: hydra <target> <service> <username> <passlist>"
            )
        if low.startswith("scope"):
            return self._handle_scope(text)
        if low in ("payloads", "/payloads") or low.startswith("payloads "):
            return self._show_payloads(text)
        # payload categories are usable as bare verbs: "revshell python3 ..."
        first, _, rest = text.partition(" ")
        if first.lower() == "generate":
            first, _, rest = rest.strip().partition(" ")
        if first.lower() in _PAYLOAD_CATEGORIES:
            return self._handle_generate(first.lower(), rest.strip())

        # ---- LLM routing (or offline fallback) ----
        if self._llm_ok:
            return self._llm_route(text)
        return self._offline_route(text)

    # ---------------------------------------------------------- llm route
    def _llm_route(self, text: str) -> None:
        system = ROUTER_SYSTEM.format(
            tool_catalog=tool_catalog(self.tools),
            context=self._context_blob(),
        )
        try:
            decision = self.llm.chat_json([
                {"role": "system", "content": system},
                {"role": "user", "content": text},
            ])
        except Exception as exc:
            console.print(f"[yellow]LLM error, falling back:[/yellow] {exc}")
            return self._offline_route(text)

        action = decision.get("action")
        if action == "run_tool":
            tool = decision.get("tool", "")
            args = decision.get("args", {}) or {}
            reasoning = decision.get("reasoning", "")
            if reasoning:
                console.print(f"[dim]>> {reasoning}[/dim]")
            return self._execute_tool(tool, args)
        # default: respond
        msg = decision.get("message") or self._freeform(text)
        console.print(Panel(msg, border_style="blue", title="GhostOps"))
        self._log("llm", "advice", msg[:200])

    def _freeform(self, text: str) -> str:
        try:
            return self.llm.chat([
                {"role": "system",
                 "content": PERSONA + "\n\n" + self._context_blob()},
                {"role": "user", "content": text},
            ])
        except Exception as exc:
            return f"(LLM error: {exc})"

    # ------------------------------------------------------ offline route
    def _offline_route(self, text: str) -> None:
        low = text.lower()
        m = re.search(
            r"\b(scan|nmap|enumerate)\b.*?"
            r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?"
            r"|[a-z0-9.-]+\.[a-z]{2,})",
            low,
        )
        if m:
            return self._execute_tool(
                "nmap", {"target": m.group(2), "profile": "default"}
            )
        console.print(
            "[yellow]Offline mode:[/yellow] I can't reason without Ollama. "
            "Try 'scan <target>', 'what do we know', or 'help'."
        )

    # ------------------------------------------------------ execute tool
    def _execute_tool(self, name: str, args: dict) -> None:
        tool = self.tools.get(name)
        if tool is None:
            console.print(f"[red]Unknown tool:[/red] {name}")
            return

        ok, msg = tool.validate_args(args)
        if not ok:
            console.print(f"[red]Invalid args for {name}:[/red] {msg}")
            return

        # scope guard on the host this call targets (if any)
        target = tool.scope_target(args)
        if target:
            decision = self.guard.check(target)
            if not decision.allowed:
                console.print(Panel(
                    f"[red]BLOCKED - out of scope[/red]\n{decision.reason}\n\n"
                    f"Add it with: [cyan]scope add {target}[/cyan]",
                    border_style="red", title="Scope Guard",
                ))
                self._log("tool", f"BLOCKED {name} {target}", decision.reason)
                return

        cmd = tool.build_command(args)
        console.print(f"[dim]$[/dim] [white]{' '.join(cmd)}[/white]")

        if not tool.is_available():
            console.print(
                f"[yellow]{name} is not installed here.[/yellow] "
                f"Showing dry-run only. Install it on Kali/WSL to execute."
            )
            result = tool.run(args, dry_run=True)
            self._log("tool", f"dry-run {name} {target}", result.command_str)
            return

        if self.confirm_before_run:
            if not Confirm.ask("Execute this command?", default=True):
                console.print("[dim]skipped.[/dim]")
                return

        with console.status(f"[cyan]running {name}...[/cyan]"):
            result = tool.run(args)

        self._apply_result(result)

    # ------------------------------------------------------ apply result
    def _apply_result(self, result: ToolResult) -> None:
        if result.error:
            console.print(f"[red]{result.tool} failed:[/red] {result.error}")
            if result.stderr:
                console.print(f"[dim]{result.stderr.strip()[:400]}[/dim]")
            self._log("tool", f"{result.tool} error", result.error)
            return

        # merge structured data into engagement memory
        for h in result.hosts:
            self.e.upsert_host(h)
        for f in result.findings:
            self.e.add_finding(f)
        for cr in result.credentials:
            self.e.add_credential(cr)

        self._log(
            "tool", result.summary or f"{result.tool} ran",
            f"cmd: {result.command_str}\nrc={result.returncode} "
            f"dur={result.duration}s",
        )

        # phase progression: a productive scan moves us forward
        if result.hosts and self.e.phase.order < Phase.ENUMERATION.order:
            self.e.phase = Phase.ENUMERATION

        self._render_result(result)
        if self._llm_ok:
            self._brief(result)
        else:
            self._suggest_next()

    # ---------------------------------------------------------- rendering
    def _render_result(self, result: ToolResult) -> None:
        console.print(
            f"[green]done[/green] in {result.duration}s - {result.summary}"
        )
        if result.hosts:
            for h in result.hosts:
                title = f"{h.ip} {('(' + h.hostname + ')') if h.hostname else ''}"
                table = Table(title=title, show_lines=False)
                table.add_column("Port", style="cyan", justify="right")
                table.add_column("Proto")
                table.add_column("Service", style="green")
                table.add_column("Version")
                for s in sorted(h.services, key=lambda x: x.port):
                    table.add_row(str(s.port), s.proto, s.name, s.banner)
                console.print(table)

    def _brief(self, result: ToolResult) -> None:
        payload = {
            "tool": result.tool,
            "summary": result.summary,
            "hosts": [h.to_dict() for h in result.hosts],
        }
        try:
            text = self.llm.chat([
                {"role": "system",
                 "content": SUMMARIZE_SYSTEM + "\n\n" + self._context_blob()},
                {"role": "user", "content": str(payload)},
            ])
            console.print(Panel(text, border_style="blue", title="Briefing"))
        except Exception as exc:
            console.print(f"[dim]briefing unavailable: {exc}[/dim]")

    # ------------------------------------------------------------ summary
    def _show_summary(self) -> None:
        c = self.e.counts()
        console.print(Panel(
            f"[bold]Engagement {self.e.id}[/bold]\n"
            f"Phase: [magenta]{self.e.phase.value}[/magenta]  |  "
            f"Scope: {', '.join(self.e.scope) or '(none)'}",
            border_style="cyan", title="What We Know",
        ))
        if self.e.hosts:
            t = Table(title="Hosts & Services")
            t.add_column("Host", style="cyan")
            t.add_column("Port", justify="right")
            t.add_column("Service", style="green")
            t.add_column("Version")
            for h in self.e.hosts:
                if not h.services:
                    t.add_row(h.ip, "-", "-", "-")
                for s in sorted(h.services, key=lambda x: x.port):
                    t.add_row(h.ip, str(s.port), s.name, s.banner)
            console.print(t)
        if self.e.findings:
            ft = Table(title="Findings")
            ft.add_column("Sev")
            ft.add_column("Host", style="cyan")
            ft.add_column("Title")
            for f in sorted(self.e.findings, key=lambda x: -x.severity.rank):
                ft.add_row(
                    f.severity.value.upper(),
                    f"{f.host}:{f.port or ''}", f.title,
                )
            console.print(ft)
        if self.e.credentials:
            ct = Table(title="Credentials")
            ct.add_column("Service")
            ct.add_column("Host", style="cyan")
            ct.add_column("User")
            ct.add_column("Secret")
            for cr in self.e.credentials:
                ct.add_row(cr.service, cr.host, cr.username, cr.secret)
            console.print(ct)
        if not (self.e.hosts or self.e.findings):
            console.print("[dim]Nothing discovered yet. Try: scan <target>[/dim]")

    def _suggest_next(self) -> None:
        # Deterministic suggestions, driven by the curated service checklists:
        # for each discovered service, surface its top methodology step.
        from ghostops.methodology import checklists as cl
        tips: list[str] = []
        if cl.available():
            for h in self.e.hosts:
                for s in h.services:
                    match = cl.match(s.name, s.port)
                    if match is None or not match.checks:
                        continue
                    step = next((c for c in match.checks if c.cmd),
                                match.checks[0])
                    line = f"{h.ip}:{s.port} {match.name} - {step.task}"
                    if step.cmd:
                        line += "\n    " + cl.render_cmd(step.cmd, h.ip, s.port)
                    tips.append(line)
        if not tips:
            tips = (["Run an nmap scan to discover services: scan <target>"]
                    if not self.e.hosts else
                    ["No checklist matched the open services. "
                     "Browse methodology with 'checklist'."])
        console.print(Panel(
            "\n".join(f"- {t}" for t in dict.fromkeys(tips)),
            border_style="magenta", title="Suggested Next Steps",
        ))
        if self.e.hosts and cl.available():
            console.print("[dim]Full per-service steps: 'checklist'[/dim]")

    # ---------------------------------------------------------- checklists
    def _handle_checklist(self, text: str) -> None:
        from ghostops.methodology import checklists as cl
        from ghostops.methodology.display import show_checklist, show_index
        if not cl.available():
            console.print(
                "[yellow]Checklist catalog not on disk.[/yellow] "
                "(AV quarantine? run on Kali/WSL.)"
            )
            return
        parts = text.split()
        if len(parts) > 1:
            key = parts[1].lower()
            match = cl.get(key) or cl.match(key)
            if match is None:
                console.print(f"[red]No checklist for '{key}'.[/red]")
                return show_index(console)
            return show_checklist(console, match, stealth=self.e.stealth)
        # no argument: show checklists for what we've discovered, else the index
        shown = False
        for h in self.e.hosts:
            for s in h.services:
                match = cl.match(s.name, s.port)
                if match is not None:
                    show_checklist(console, match, host=h.ip, port=s.port,
                                   stealth=self.e.stealth)
                    shown = True
        if not shown:
            show_index(console)

    # -------------------------------------------------------------- scope
    def _handle_scope(self, text: str) -> None:
        parts = text.split()
        if len(parts) >= 3 and parts[1].lower() == "add":
            entry = parts[2]
            if entry not in self.e.scope:
                self.e.scope.append(entry)
                self.guard = ScopeGuard(
                    self.e.scope,
                    enforce=self.cfg.get("safety.enforce_scope", True),
                )
                console.print(f"[green]Added to scope:[/green] {entry}")
            return
        console.print(
            f"Scope: [cyan]{', '.join(self.e.scope) or '(none)'}[/cyan]  "
            f"([dim]scope add <ip/cidr/host>[/dim])"
        )

    # ----------------------------------------------------------- payloads
    def _payloads_ready(self) -> bool:
        from ghostops.payloads.generator import catalog_available
        if catalog_available():
            return True
        console.print(
            "[yellow]Payload catalog not on disk.[/yellow] It is quarantined "
            "by host AV (Defender) in plaintext form. Ship payloads.b64, add "
            "an AV exclusion, or run on Kali/WSL. See 'help'."
        )
        return False

    def _show_payloads(self, text: str) -> None:
        if not self._payloads_ready():
            return
        from ghostops.payloads.display import show_catalog
        parts = text.split()
        category = parts[1] if len(parts) > 1 else None
        show_catalog(console, category)

    def _handle_generate(self, category: str, args_text: str) -> None:
        if not self._payloads_ready():
            return
        from ghostops.payloads.display import show_payload
        from ghostops.payloads.generator import (
            DEFAULT_PAYLOAD, PayloadError, generate,
        )
        toks = args_text.split()
        encode = False
        if toks and toks[-1] in ("enc", "encode", "--encode"):
            encode, toks = True, toks[:-1]
        name = toks[0] if toks else DEFAULT_PAYLOAD.get(category)
        if not name:
            return self._show_payloads(f"payloads {category}")
        rest = toks[1:]

        lhost = lport = ""
        param = "cmd"
        if category == "revshell" and len(rest) >= 2:
            lhost, lport = rest[0], rest[1]
        elif category == "bindshell" and rest:
            lport = rest[0]
        elif category == "listener" and rest:
            lport = rest[0]
            if len(rest) > 1:
                lhost = rest[1]
        elif category == "webshell" and rest:
            param = rest[0]

        try:
            p = generate(category, name, lhost=lhost, lport=lport,
                         param=param, encode=encode)
        except PayloadError as exc:
            console.print(f"[red]{exc}[/red]")
            console.print(f"[dim]list options:[/dim] payloads {category}")
            return

        show_payload(console, p, stealth=self.e.stealth)
        if self.e.stealth and p.noise == "high":
            console.print(
                f"[red]stealth:[/red] {p.ref} is HIGH noise. "
                f"See 'payloads {category}' for quieter options."
            )
        self._log("payload",
                  f"generated {p.ref}" + (" (encoded)" if encode else ""),
                  p.name)

    # -------------------------------------------------------------- helps
    def _help(self) -> None:
        console.print(Panel(
            "[bold]Commands[/bold]\n"
            "  scan <target>         run an nmap scan\n"
            "  gobuster <url>        brute-force web directories\n"
            "  searchsploit <terms>  search ExploitDB for exploits\n"
            "  sqlmap <url>          test a URL for SQL injection\n"
            "  hydra <tgt> <svc> <user> <passlist>   brute-force a login\n"
            "  payloads [category]   browse the payload catalog\n"
            "  revshell <name> <lhost> <lport> [enc] reverse shell\n"
            "  webshell <name> [param]               web shell\n"
            "  listener <name> <lport>               attacker-side listener\n"
            "  tty / privesc <name>  post-exploitation helpers\n"
            "  checklist [service]   per-service enumeration methodology\n"
            "  what do we know       full engagement summary\n"
            "  next                  suggested next steps\n"
            "  scope / scope add X   view or extend scope\n"
            "  tools                 list tools + availability\n"
            "  phase                 show current kill-chain phase\n"
            "  help / exit\n\n"
            "[dim]In AI mode you can also speak naturally: "
            "\"scan the target with a full port sweep\".[/dim]",
            border_style="blue", title="GhostOps Help",
        ))

    def _show_tools(self) -> None:
        t = Table(title="Tools")
        t.add_column("Tool", style="cyan")
        t.add_column("Installed")
        t.add_column("Purpose")
        for name, tool in self.tools.items():
            t.add_row(
                name,
                "[green]yes[/green]" if tool.is_available() else "[red]no[/red]",
                tool.description.split(".")[0],
            )
        console.print(t)

    # ------------------------------------------------------------ context
    def _context_blob(self) -> str:
        c = self.e.counts()
        lines = [
            f"Phase: {self.e.phase.value}",
            f"Scope: {', '.join(self.e.scope) or '(none)'}",
            f"Discovered: {c['hosts']} hosts, {c['ports']} ports, "
            f"{c['findings']} findings, {c['creds']} creds",
        ]
        for h in self.e.hosts[:10]:
            ports = ", ".join(f"{s.port}/{s.name}" for s in h.services[:12])
            lines.append(f"  {h.ip}: {ports or 'no open ports yet'}")
        return "\n".join(lines)


# ------------------------------------------------------------- entrypoints
def _store_for(cfg: Config, engagement_id: str) -> EngagementStore:
    eng_dir = cfg.get("engagements.dir", "./engagements")
    return EngagementStore(f"{eng_dir}/{engagement_id}.db")


def start_engagement(target: str, model: str = "dolphin-mistral",
                     stealth: bool = False) -> None:
    cfg = load_config()
    eid = _new_id()
    e = Engagement(
        id=eid, name=target, scope=[target], phase=Phase.RECON,
        created_at=_now(), stealth=stealth,
        model=model or cfg.get("llm.model", "dolphin-mistral"),
    )
    store = _store_for(cfg, eid)
    store.save(e)
    Orchestrator(cfg, e, store).run()


def start_shell(model: str = "dolphin-mistral") -> None:
    """Free-form chat / scratch engagement (wildcard scope)."""
    cfg = load_config()
    eid = _new_id()
    e = Engagement(
        id=eid, name="shell", scope=["*"], phase=Phase.RECON,
        created_at=_now(),
        model=model or cfg.get("llm.model", "dolphin-mistral"),
    )
    store = _store_for(cfg, eid)
    store.save(e)
    console.print("[dim]Free chat mode (scope=*). Findings still saved.[/dim]")
    Orchestrator(cfg, e, store).run()


def resume_engagement(engagement_id: str = "last") -> None:
    from ghostops.memory.store import list_engagements
    cfg = load_config()
    eng_dir = cfg.get("engagements.dir", "./engagements")
    if engagement_id == "last":
        items = list_engagements(eng_dir)
        if not items:
            console.print("[yellow]No engagements found.[/yellow]")
            return
        engagement_id = sorted(items, key=lambda x: x["created_at"])[-1]["id"]
    store = _store_for(cfg, engagement_id)
    e = store.load()
    if e is None:
        console.print(f"[red]Engagement not found:[/red] {engagement_id}")
        return
    Orchestrator(cfg, e, store).run()
