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
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from ghostops.ai.llm_client import LLMClient
from ghostops.ai.prompts import PERSONA, RANK_SYSTEM, ROUTER_SYSTEM, SUMMARIZE_SYSTEM
from ghostops.agent import rag
from ghostops.agent.next_steps import Action, QUIT, build_actions, resolve_choice
from ghostops.agent.scope_guard import ScopeGuard
from ghostops.agent.targets import normalize
from ghostops.config import Config, load_config
from ghostops.models import ActivityLog, Engagement, Phase, Severity
from ghostops.memory.store import EngagementStore
from ghostops.memory.vector_store import VectorMemory
from ghostops.tools.base_tool import ToolResult
from ghostops.tools.registry import build_registry, tool_catalog

console = Console()

# Payload categories usable as bare REPL verbs (revshell, webshell, ...).
_PAYLOAD_CATEGORIES = frozenset(
    ("revshell", "bindshell", "webshell", "listener", "tty", "privesc")
)


def _cfg_num(cfg, key: str, default, cast):
    """Read a numeric config value, tolerating a missing, null or malformed
    one. `ask` tuning must never prevent an engagement from opening."""
    raw = cfg.get(key, default)
    if raw is None:
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        console.print(f"[yellow]config: {key}={raw!r} is not a number; "
                      f"using {default}.[/yellow]")
        return default


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
        self._llm_timeout = _cfg_num(cfg, "llm.timeout", 300, int)
        self.llm = LLMClient(
            model=engagement.model,
            host=cfg.get("llm.host", "http://localhost:11434"),
            temperature=cfg.get("llm.temperature", 0.4),
            timeout=self._llm_timeout,
        )
        self.guard = ScopeGuard(
            engagement.scope, enforce=cfg.get("safety.enforce_scope", True)
        )
        self.confirm_before_run = cfg.get("safety.confirm_before_run", True)
        # AI mode requires BOTH: Ollama reachable AND the router model pulled.
        # If the model is missing we drop cleanly into the deterministic offline
        # router instead of erroring on the first request.
        self._llm_ok = self.llm.available() and self.llm.has_model()

        # Optional semantic memory (RAG). Augments SQLite, never replaces it.
        # No-op if chromadb isn't installed or the embed model isn't pulled.
        self._embed_model = cfg.get("llm.embed_model", "nomic-embed-text")
        chroma_path = Path(str(self.store.path)).with_suffix(".chroma")
        self.vec = VectorMemory(
            engagement.id, chroma_path,
            embed_fn=lambda t: self.llm.embed(t, model=self._embed_model),
            embed_many_fn=lambda ts: self.llm.embed_many(
                ts, model=self._embed_model),
        )
        # Never let a typo in config.yaml stop an engagement from opening:
        # these tune `ask` only, so fall back to the defaults and say so.
        self._rag_k = _cfg_num(cfg, "rag.top_k", rag.DEFAULT_K, int)
        self._rag_max_distance = _cfg_num(
            cfg, "rag.max_distance", rag.DEFAULT_MAX_DISTANCE, float)

        # Current numbered next-steps menu (registry-built). Selecting a number
        # in the REPL runs the mapped action; empty until the first scan.
        self._menu: list[Action] = []

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
        stealth = "  [yellow]STEALTH[/yellow]" if self.e.stealth else ""
        console.print(Panel(
            f"[bold red]GhostOps[/bold red] - engagement [cyan]{self.e.id}[/cyan]\n"
            f"Scope:    [cyan]{', '.join(self.e.scope) or '(none)'}[/cyan]\n"
            f"Phase:    [magenta]{self.e.phase.value}[/magenta]{stealth}\n"
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

        # ---- next-steps menu selection ----
        # When a menu is showing, a bare number or 'q' is a menu pick. Anything
        # else (a real command) falls through to normal handling below.
        if self._menu and (low == "q" or low.isdigit()):
            choice = resolve_choice(self._menu, text)
            if choice == QUIT:
                self._menu = []
                return console.print("[dim]menu dismissed.[/dim]")
            if isinstance(choice, Action):
                return self._run_action(choice)
            console.print(f"[yellow]Invalid choice.[/yellow] "
                          f"Pick 1-{len(self._menu)} or 'q'.")
            return self._render_menu()

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
        if low in ("attack", "mitre", "att&ck", "/attack", "/mitre"):
            return self._show_attack()
        if (low.startswith("ask ") or low.startswith("/ask ")
                or low in ("ask", "/ask")):
            return self._ask(text)
        if low.startswith("recall ") or low in ("recall", "/recall"):
            return self._recall(text)
        if low.startswith("scan "):
            t = normalize(text[5:].strip())
            # A web URL: scan the HOST with nmap (never the URL), and record the
            # URL so the web tools (gobuster/nikto) are offered in the menu.
            if t.is_web and t.url:
                self.e.add_web_target(t.url)
                console.print(f"[dim]web target: {t.url} - scanning host "
                              f"{t.host}; web tools will appear in the menu.[/dim]")
            profile = "stealth" if self.e.stealth else "default"
            return self._execute_tool(
                "nmap", {"target": t.host, "profile": profile}
            )
        if low.startswith("gobuster "):
            return self._execute_tool("gobuster", {"url": text[9:].strip()})
        if low.startswith("nikto "):
            return self._execute_tool("nikto", {"url": text[6:].strip()})
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

        # phase progression, driven by what the tool actually produced.
        # Never moves backward (we take the furthest phase reached).
        target = self.e.phase
        if result.hosts:
            target = max(target, Phase.ENUMERATION, key=lambda p: p.order)
        if any(f.severity.rank >= Severity.HIGH.rank for f in result.findings):
            target = max(target, Phase.EXPLOITATION, key=lambda p: p.order)
        if result.credentials:
            target = max(target, Phase.POST_EXPLOITATION, key=lambda p: p.order)
        if target.order != self.e.phase.order:
            old = self.e.phase
            self.e.phase = target
            self._log("phase", f"{old.value} -> {target.value}", "auto-advance")
            console.print(f"[magenta]phase -> {target.value}[/magenta]")

        # mirror new findings into semantic memory (best-effort, never fatal)
        if result.findings and self.vec.available():
            self.vec.add_findings(result.findings)

        self._render_result(result)
        if self._llm_ok:
            self._brief(result)      # short findings summary (no tool names)
        self._suggest_next()         # build + (rank) + render the numbered menu

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

    # ----------------------------------------------------------- next menu
    def _suggest_next(self) -> None:
        """Rebuild the registry-driven next-steps menu and show it."""
        self._refresh_menu()
        if not self._menu:
            if not self.e.hosts:
                console.print("[dim]Nothing discovered yet. Try: scan <target>[/dim]")
            else:
                console.print("[dim]No runnable next steps for the open "
                              "services. Try 'checklist' for methodology.[/dim]")
            return
        self._render_menu()

    def _refresh_menu(self) -> None:
        # The menu is ALWAYS built from the real tool registry + memory. The
        # model may only reorder it (offline -> deterministic order).
        self._menu = build_actions(self.e, self.tools)
        if self._menu and self._llm_ok:
            self._menu = self._rank_menu(self._menu)

    def _rank_menu(self, menu: list[Action]) -> list[Action]:
        """Let the model reorder the candidates by relevance. It can only
        reorder the given numbers; invalid/missing ones are handled here, so it
        can never invent or drop a step."""
        listing = "\n".join(f"{i}. {a.label}" for i, a in enumerate(menu, 1))
        try:
            decision = self.llm.chat_json([
                {"role": "system",
                 "content": RANK_SYSTEM.format(context=self._context_blob())},
                {"role": "user", "content": listing},
            ])
        except Exception:
            return menu
        order = decision.get("order") or []
        seen: set[int] = set()
        ranked: list[Action] = []
        for n in order:
            if isinstance(n, int) and 1 <= n <= len(menu) and n not in seen:
                seen.add(n)
                ranked.append(menu[n - 1])
        for i, a in enumerate(menu, 1):        # append anything the model omitted
            if i not in seen:
                ranked.append(a)
        return ranked

    def _render_menu(self) -> None:
        if not self._menu:
            return
        lines = []
        for i, a in enumerate(self._menu, 1):
            tag = " [red](intrusive)[/red]" if a.intrusive else ""
            lines.append(f"  [cyan]\\[{i}][/cyan] {a.label}{tag}")
        console.print(Panel(
            "\n".join(lines), title="Next steps", border_style="magenta",
            subtitle="[dim]pick a number, or 'q' to skip[/dim]",
        ))

    def _run_action(self, action: Action) -> None:
        """Menu pick -> prompt for any required input -> confirm gate -> run.
        Selection sits in FRONT of _execute_tool; it never bypasses scope guard,
        the confirm gate, or arg validation."""
        args = dict(action.args)
        for arg, question in action.prompts:
            try:
                val = console.input(
                    f"[cyan]{question}[/cyan] [dim](blank or 'q' to cancel)[/dim]: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                val = ""
            if val == "" or val.lower() == "q":
                console.print("[dim]cancelled - back to menu.[/dim]")
                return self._render_menu()
            args[arg] = val
        self._execute_tool(action.tool, args)

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

    # ------------------------------------------------------------- attack
    def _show_attack(self) -> None:
        from ghostops.methodology import mitre
        if not mitre.available():
            console.print("[yellow]ATT&CK map not on disk.[/yellow] "
                          "(run on Kali/WSL)")
            return
        observed = mitre.observed(self.e)
        if not observed:
            console.print(Panel(
                "No ATT&CK techniques exercised yet. Run a tool or generate "
                "a payload, then check again.",
                border_style="magenta", title="MITRE ATT&CK",
            ))
            return
        t = Table(title="MITRE ATT&CK - techniques exercised")
        t.add_column("Tactic", style="magenta")
        t.add_column("ID", style="cyan", no_wrap=True)
        t.add_column("Technique")
        t.add_column("Via", style="dim")
        for tech, prov in observed:
            t.add_row(tech.tactic, tech.id, tech.name, ", ".join(prov))
        console.print(t)

    # ------------------------------------------------------------- recall
    def _recall(self, text: str) -> None:
        question = text.split(" ", 1)[1].strip() if " " in text else ""
        if not question:
            console.print("usage: recall <question>   "
                          "e.g. recall what did we find on the web servers")
            return
        # graceful degradation, each with the exact fix
        if not self.vec.available():
            console.print(
                "[yellow]Semantic recall needs ChromaDB.[/yellow] Install it: "
                "[cyan]pip install chromadb[/cyan]  (or  pip install -e '.[rag]')."
            )
            return
        if not (self.llm.available() and self.llm.has_model(self._embed_model)):
            console.print(
                f"[yellow]Embed model unavailable.[/yellow] Pull it: "
                f"[cyan]ollama pull {self._embed_model}[/cyan] (Ollama must run)."
            )
            return
        self._ensure_indexed()

        hits = self.vec.query(question, k=5)
        if not hits:
            console.print("[dim]Nothing relevant in memory yet. "
                          "Run some tools first.[/dim]")
            return
        t = Table(title=f"Recall - {question}")
        t.add_column("#", style="cyan", justify="right")
        t.add_column("Finding", style="green")
        t.add_column("Where", style="dim")
        for i, h in enumerate(hits, 1):
            meta = h.get("metadata", {})
            where = meta.get("host", "") or ""
            if meta.get("port"):
                where += f":{meta['port']}"
            title = meta.get("title") or (h.get("document") or "")[:70]
            t.add_row(str(i), title, where)
        console.print(t)
        # In AI mode, let the model summarize the retrieved findings. This is
        # reasoning over grounded data - it never generates payloads.
        if self._llm_ok:
            self._recall_summary(question, hits)

    def _ensure_indexed(self) -> None:
        """Bring semantic memory level with SQLite, which is the source of
        truth. Covers a resumed engagement, findings recorded while ChromaDB
        was absent, and a collection-name change (a new name starts empty, so
        everything re-indexes exactly once). Silent unless work is needed."""
        def notice(total: int) -> None:
            console.print(f"[dim]indexing {total} finding(s) into semantic "
                          f"memory (one-time)...[/dim]")

        with console.status("[dim]indexing semantic memory...[/dim]"):
            rag.ensure_indexed(self.vec, self.e.findings, on_start=notice)

    # ----------------------------------------------------------------- ask
    def _ask(self, text: str) -> None:
        """Grounded Q&A: retrieve findings, then answer STRICTLY from them.

        `recall` shows what matched; `ask` answers with it. The model only ever
        sees findings already stored by a real tool run - it cannot introduce a
        host, port, version or vulnerability of its own.
        """
        question = text.split(" ", 1)[1].strip() if " " in text else ""
        if not question:
            console.print("usage: ask <question>   "
                          "e.g. ask what did we find on the web servers")
            return

        if self.vec.available():
            if not (self.llm.available()
                    and self.llm.has_model(self._embed_model)):
                console.print(
                    f"[yellow]Embed model unavailable.[/yellow] Pull it: "
                    f"[cyan]ollama pull {self._embed_model}[/cyan] "
                    f"(Ollama must run)."
                )
                return
            self._ensure_indexed()

        res = rag.answer(
            self.vec, self.llm, question,
            k=self._rag_k,
            max_distance=self._rag_max_distance,
            llm_ready=self._llm_ok,
        )
        self._render_grounded(question, res)
        self._log("ask", f"ask: {question}", f"mode={res.mode} "
                                             f"sources={len(res.used)}")

    def _render_grounded(self, question: str, res) -> None:
        """Answer first, then the provenance table. Every claim the model makes
        is citable back to a row the operator can see."""
        if res.mode in (rag.MODE_UNAVAILABLE, rag.MODE_RETRIEVAL_FAILED):
            console.print(f"[yellow]{escape(res.message)}[/yellow]")
            return

        if res.mode == rag.MODE_NO_FINDINGS:
            console.print(Panel(escape(res.text), border_style="yellow",
                                title="No grounded answer"))
            return

        if res.mode == rag.MODE_SEARCH:
            console.print(f"[yellow]{escape(res.message)}[/yellow]")
            self._render_sources(question, res.used)
            return

        border = "yellow" if res.refused else "blue"
        title = "Not covered by findings" if res.refused else "Grounded answer"
        console.print(Panel(escape(res.text or "(empty response)"),
                            border_style=border, title=title))
        self._render_sources(question, res.used, res.dropped)

    def _render_sources(self, question: str, hits: list[dict],
                        dropped: int = 0) -> None:
        if not hits:
            return
        if dropped:
            console.print(f"[dim]{dropped} further finding(s) omitted to keep "
                          f"the model's context within limits.[/dim]")
        t = Table(title=f"Sources - {escape(question)}")
        t.add_column("#", style="cyan", justify="right")
        t.add_column("Finding", style="green")
        t.add_column("Where", style="dim")
        t.add_column("Dist", style="dim", justify="right")
        for i, h in enumerate(hits, 1):
            meta = h.get("metadata", {})
            where = meta.get("host", "") or ""
            if meta.get("port"):
                where += f":{meta['port']}"
            dist = h.get("distance")
            t.add_row(str(i),
                      escape(meta.get("title")
                             or (h.get("document") or "")[:70]),
                      escape(where),
                      "-" if dist is None else f"{dist:.2f}")
        console.print(t)

    def _recall_summary(self, question: str, hits: list[dict]) -> None:
        """Grounded summary of the rows recall just retrieved.

        Routed through rag.summarize rather than an inline prompt: the finding
        text here comes from the scanned host exactly as it does for `ask`, so
        it gets the same untrusted-data fencing, the same restated rules, and
        the same output guard.
        """
        res = rag.summarize(self.llm, question, hits)
        if res.mode == rag.MODE_BLOCKED:
            console.print(f"[red]{escape(res.message)}[/red]")
            return
        if res.mode != rag.MODE_ANSWER:
            if res.message:
                console.print(f"[dim]{escape(res.message)}[/dim]")
            return
        console.print(Panel(escape(res.text),
                            border_style="yellow" if res.refused else "blue",
                            title="Recall summary"))

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
            "  scan <target>         nmap scan (IP/host; URLs route to web tools)\n"
            "  gobuster <url>        brute-force web directories\n"
            "  nikto <url>           web server vulnerability scan (noisy)\n"
            "  searchsploit <terms>  search ExploitDB for exploits\n"
            "  sqlmap <url>          test a URL for SQL injection\n"
            "  hydra <tgt> <svc> <user> <passlist>   brute-force a login\n"
            "  payloads [category]   browse the payload catalog\n"
            "  revshell <name> <lhost> <lport> [enc] reverse shell\n"
            "  webshell <name> [param]               web shell\n"
            "  listener <name> <lport>               attacker-side listener\n"
            "  tty / privesc <name>  post-exploitation helpers\n"
            "  checklist [service]   per-service enumeration methodology\n"
            "  attack / mitre        ATT&CK techniques exercised so far\n"
            "  recall <question>     semantic search of past findings (RAG)\n"
            "  ask <question>        grounded answer from those findings\n"
            "  what do we know       full engagement summary\n"
            "  next                  numbered menu of next steps (pick by number)\n"
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


def start_engagement(target: str, model: str | None = None,
                     stealth: bool = False) -> None:
    cfg = load_config()
    eid = _new_id()
    # Normalize so the scope guard works on a bare host/IP even if the operator
    # engaged with a full URL; keep the URL as a web target for the web tools.
    t = normalize(target)
    e = Engagement(
        id=eid, name=target, scope=[t.host or target], phase=Phase.RECON,
        created_at=_now(), stealth=stealth,
        model=model or cfg.get("llm.model", "dolphin-mistral"),
    )
    if t.is_web and t.url:
        e.add_web_target(t.url)
    store = _store_for(cfg, eid)
    store.save(e)
    Orchestrator(cfg, e, store).run()


def start_shell(model: str | None = None) -> None:
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
