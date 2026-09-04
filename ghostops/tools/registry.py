"""Registry of available tools. Add new BaseTool subclasses here."""
from __future__ import annotations

from ghostops.config import Config
from ghostops.tools.base_tool import BaseTool
from ghostops.tools.gobuster_tool import GobusterTool
from ghostops.tools.hydra_tool import HydraTool
from ghostops.tools.nikto_tool import NiktoTool
from ghostops.tools.nmap_tool import NmapTool
from ghostops.tools.searchsploit_tool import SearchsploitTool
from ghostops.tools.sqlmap_tool import SqlmapTool


def build_registry(cfg: Config) -> dict[str, BaseTool]:
    """Instantiate all tools with their config-driven defaults."""
    reg: dict[str, BaseTool] = {}

    reg["nmap"] = NmapTool(
        timeout=cfg.get("tools.nmap.timeout", 600),
        default_args=cfg.get("tools.nmap.default_args", ""),
    )
    reg["gobuster"] = GobusterTool(
        timeout=cfg.get("tools.gobuster.timeout", 600),
        wordlist=cfg.get("tools.gobuster.wordlist", ""),
    )
    reg["searchsploit"] = SearchsploitTool(
        timeout=cfg.get("tools.searchsploit.timeout", 120),
    )
    reg["sqlmap"] = SqlmapTool(
        timeout=cfg.get("tools.sqlmap.timeout", 900),
    )
    reg["hydra"] = HydraTool(
        timeout=cfg.get("tools.hydra.timeout", 900),
    )
    reg["nikto"] = NiktoTool(
        timeout=cfg.get("tools.nikto.timeout", 900),
    )

    return reg


def tool_catalog(reg: dict[str, BaseTool]) -> str:
    """A compact text catalog of tools + args, for the LLM system prompt."""
    lines = []
    for name, tool in reg.items():
        avail = "available" if tool.is_available() else "NOT INSTALLED"
        props = tool.args_schema.get("properties", {})
        arglist = ", ".join(props.keys())
        lines.append(f"- {name} ({avail}): {tool.description} [args: {arglist}]")
    return "\n".join(lines)
