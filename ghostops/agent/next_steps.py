"""Registry-driven next-step actions for the interactive menu.

The menu the operator sees is built ONLY from real registered tools and
concrete targets already in engagement memory - never from model free text - so
a tool GhostOps cannot run can never appear (build_actions asserts every
action's tool is in the registry). The model may reorder these candidates
(see the orchestrator's _rank_menu), but it can neither add nor rename them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from ghostops.models import Engagement

QUIT = "quit"

# nmap service name -> hydra service token (must be in HydraTool._SERVICES)
_HYDRA_BY_NAME = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet", "mysql": "mysql",
    "postgresql": "postgres", "postgres": "postgres", "rdp": "rdp",
    "ms-wbt-server": "rdp", "smb": "smb", "microsoft-ds": "smb",
    "netbios-ssn": "smb", "vnc": "vnc", "smtp": "smtp", "pop3": "pop3",
    "imap": "imap",
}
_HYDRA_BY_PORT = {
    22: "ssh", 21: "ftp", 23: "telnet", 3306: "mysql", 5432: "postgres",
    3389: "rdp", 445: "smb", 139: "smb", 5900: "vnc", 25: "smtp",
    110: "pop3", 143: "imap",
}
_WEB_NAMES = {"http", "https", "http-alt", "http-proxy", "ssl/http", "https-alt"}
_WEB_PORTS = {80, 443, 8080, 8000, 8888, 8443, 8081}


@dataclass
class Action:
    label: str                 # menu line shown to the operator (no number)
    tool: str                  # a REAL registered tool name
    args: dict                 # concrete args (target/url/service from memory)
    intrusive: bool = False    # noisy tools (hydra, sqlmap) - flagged in the UI
    # inputs to ask for AFTER selection, BEFORE the confirm gate:
    # list of (arg_name, question). Cancellable (blank/'q').
    prompts: list = field(default_factory=list)


def _is_web(name: str, port: int) -> bool:
    return (name or "").lower() in _WEB_NAMES or port in _WEB_PORTS


def build_actions(engagement: Engagement, registry: dict) -> list[Action]:
    """Every runnable next step = discovered services x applicable registered
    tools. Only tools present in `registry` are emitted, and each action targets
    a host/port/url already in memory. Non-intrusive actions are ordered first.
    """
    actions: list[Action] = []
    seen: set = set()

    def add(a: Action) -> None:
        if a.tool not in registry:          # structural: no invented tools, ever
            return
        key = (a.tool, tuple(sorted(a.args.items())))
        if key in seen:
            return
        seen.add(key)
        actions.append(a)

    for h in engagement.hosts:
        for s in sorted(h.services, key=lambda x: x.port):
            host, port, name = h.ip, s.port, (s.name or "")
            banner = s.banner.strip()

            # web -> gobuster (enum) + nikto (vuln scan, intrusive)
            if _is_web(name, port):
                scheme = ("https" if port in (443, 8443) or "https" in name
                          or "ssl" in name else "http")
                url = f"{scheme}://{host}:{port}"
                add(Action(
                    label=f"Enumerate web content on {host}:{port} (gobuster)",
                    tool="gobuster", args={"url": url}))
                add(Action(
                    label=f"Scan web service on {host}:{port} for vulns (nikto)",
                    tool="nikto", args={"url": url}, intrusive=True))

            # login service -> hydra (brute-force; intrusive; needs credentials)
            svc = _HYDRA_BY_NAME.get(name.lower()) or _HYDRA_BY_PORT.get(port)
            if svc:
                add(Action(
                    label=f"Brute-force {svc.upper()} login on {host}:{port} (hydra)",
                    tool="hydra", args={"target": host, "service": svc},
                    intrusive=True,
                    prompts=[("username", "username to try"),
                             ("passlist", "path to a password list")]))

            # any versioned service -> searchsploit (find known exploits)
            if banner:
                add(Action(
                    label=f"Search exploits for '{banner}' on {host}:{port} (searchsploit)",
                    tool="searchsploit", args={"query": banner}))

    # user-provided web targets (from `scan <url>` / `engage <url>`), persisted
    # so the web tools stay offered even when nmap found no services on the host.
    for url in getattr(engagement, "web_targets", []) or []:
        add(Action(label=f"Enumerate web content on {url} (gobuster)",
                   tool="gobuster", args={"url": url}))
        add(Action(label=f"Scan {url} for web vulnerabilities (nikto)",
                   tool="nikto", args={"url": url}, intrusive=True))

    # sqlmap: only when a PARAMETERISED URL already exists in memory (a finding
    # whose text carries http(s)://...?x=y). sqlmap needs a param to run, so we
    # never offer it for a bare service.
    for f in engagement.findings:
        tokens = (f.description or "").split() + [f.title or ""]
        for tok in tokens:
            tok = tok.strip().rstrip(").,")
            if tok.startswith(("http://", "https://")) and "?" in tok and "=" in tok:
                if urlparse(tok).hostname:
                    add(Action(
                        label=f"Test {tok} for SQL injection (sqlmap)",
                        tool="sqlmap", args={"url": tok}, intrusive=True))

    actions.sort(key=lambda a: a.intrusive)   # stable: non-intrusive first
    return actions


def resolve_choice(menu: list[Action], text: str):
    """Map raw input to a choice.

    Returns an Action for a valid 1-based number, the QUIT sentinel for 'q',
    or None for anything invalid (the caller re-shows the menu - there is never
    a silent default to another tool).
    """
    t = (text or "").strip().lower()
    if t in ("q", "quit"):
        return QUIT
    if not t.isdigit():
        return None
    idx = int(t)
    if 1 <= idx <= len(menu):
        return menu[idx - 1]
    return None
