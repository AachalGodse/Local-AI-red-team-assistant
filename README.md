# GhostOps — Local AI Red Team Assistant

A fully local, agentic pentest co-pilot: it **executes** security tools (starting
with nmap), **remembers** everything discovered in an engagement, follows the
**pentest kill chain**, and generates a **report** — all on your machine, no cloud.

> **Authorized use only.** GhostOps is for penetration testing, CTFs, and lab
> environments where you have **explicit written authorization** for every target
> in scope. The built-in scope guard hard-blocks any target you haven't declared.

---

## Current status — MVP vertical slice (working)

This is the reliable core the rest builds on. Implemented and tested:

- ✅ **CLI** (`ghostops engage/shell/resume/report/engagements/setup/version`)
- ✅ **Agent loop** with a strict JSON tool-call contract for the LLM router
- ✅ **nmap tool** — execute → parse XML → structured hosts/services/findings
- ✅ **Scope guard** — hard block on out-of-scope IPs/CIDRs/hostnames
- ✅ **Confirmation gate** before any tool executes
- ✅ **Engagement memory** — SQLite, persists hosts/ports/findings/creds across sessions
- ✅ **"What do we know?"** summary + deterministic next-step suggestions
- ✅ **Kill-chain phase** tracking with auto-advance
- ✅ **Markdown report** generator
- ✅ **Offline mode** — works with commands even when Ollama isn't running

Not yet built (roadmap): more tools (gobuster, searchsploit, sqlmap, hydra),
payload generator, RAG memory, packaging. See `GhostOps_Plan.md`.

---

## Architecture

```
CLI (typer)  →  Orchestrator (agent loop)
                   ├── LLM router (Ollama, strict JSON) ── offline fallback
                   ├── Scope guard  →  Confirm gate  →  Tool layer (nmap, …)
                   ├── Engagement memory (SQLite, structured)
                   └── Report generator (Markdown)
```

Everything renders from one structured schema (`ghostops/models.py`) — the memory
store, the summary, and the report are all just views over it.

---

## Setup

GhostOps is written in Python and runs on Windows for development, but the
security tools it drives (nmap, etc.) are Linux-native. **Recommended: run it
inside WSL2 + Kali** so the tools are available.

### 1. Python deps

```bash
pip install -r requirements.txt
```

### 2. Security tools (Kali / Debian / WSL2)

```bash
wsl --install -d kali-linux          # Windows: one-time WSL2 + Kali install
sudo apt update
sudo apt install nmap gobuster ffuf sqlmap hydra nikto exploitdb john
```

### 3. Ollama + uncensored model (optional for dev, required for AI mode)

```bash
# install Ollama (https://ollama.com), then:
ollama pull dolphin-mistral      # 7B, ~4GB — the default
ollama pull nomic-embed-text     # for future RAG memory
# No GPU? Try:  ollama pull phi3:mini
```

Run `ghostops setup` any time to check what's installed.

---

## Usage

```bash
ghostops setup                       # verify tools / model / config
ghostops engage 10.10.10.100         # start an engagement (scope = that target)
ghostops engage 10.10.10.0/24        # a CIDR range
ghostops shell                       # free chat (scope = *)
ghostops resume last                 # resume the most recent engagement
ghostops engagements                 # list all saved engagements
ghostops report last -o report.md    # generate a pentest report
```

Inside an engagement (REPL):

```
scan <target>          run an nmap scan (in-scope only)
what do we know        full engagement summary
next                   suggested next steps from discovered services
scope / scope add X    view or extend the authorized scope
tools                  list tools + whether they're installed
help / exit
```

With Ollama running you can also speak naturally
("do a full port sweep of the target") and the LLM router picks the tool.

---

## Configuration

Copy `config.example.yaml` to `./config.yaml` or `~/.ghostops/config.yaml` and
edit the model, tool timeouts, and safety toggles. Safety defaults:
`confirm_before_run: true` and `enforce_scope: true`.

---

## Development

```bash
python -m pytest tests/ -q          # runs without Ollama or security tools
python -m compileall ghostops       # syntax check
python -m ghostops <command>        # run without installing
```
