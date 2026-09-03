# GhostOps — Local AI Red Team Assistant

A fully local, agentic pentest co-pilot. It **runs** the security tools
(nmap, gobuster, searchsploit, sqlmap, hydra), **remembers** everything
discovered — structurally in SQLite and semantically via embeddings — follows
the **pentest kill chain**, maps every action to **MITRE ATT&CK**, serves
curated payloads and per-service checklists, and generates a **Markdown
report**. Everything runs on your machine through [Ollama](https://ollama.com) —
**no cloud, no API keys, no data leaving the box**.

> ⚠️ **Authorized use only.** GhostOps is for penetration testing, CTFs, and lab
> environments where you have **explicit written authorization** for every target
> in scope. The built-in scope guard hard-blocks any target you haven't declared.
> You are responsible for staying within your authorization and the law.

**Why local?** Cloud pentest assistants send your target IPs and vulnerability
data to a third party — an OPSEC failure. GhostOps keeps the whole engagement on
your machine. **Why curated payloads?** Local models hallucinate exploit syntax,
so payloads come from a reviewed catalog, never the model.

---

## Features

Everything below is implemented and covered by the test suite (42 tests):

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
- ✅ **Tools:** nmap, gobuster, searchsploit, sqlmap, hydra
- ✅ **Payload generator** — curated reverse/bind/web shells, listeners, TTY
  upgrades and privesc enum, with per-payload OPSEC notes and `--encode`
- ✅ **Service checklists** — curated per-service enumeration methodology
  (16 services) that also drives the `next` suggestions
- ✅ **MITRE ATT&CK mapping** — actions (tools, payloads) map to ATT&CK
  techniques; the report gains an ATT&CK section
- ✅ **Semantic memory (RAG)** — optional ChromaDB + `nomic-embed-text`
  embeddings; `recall <question>` finds past findings by meaning. Augments the
  SQLite memory, never replaces it; fully optional (degrades cleanly if absent)

The roadmap in `GhostOps_Plan.md` is now fully implemented.

> **Payloads are curated, not model-generated.** GhostOps ships a reviewed
> catalog (`ghostops/knowledge/payloads.yaml`) rather than asking the LLM to
> write shells — the plan's whole point is that local models fabricate wrong
> exploit syntax. Note: host antivirus (Windows Defender) quarantines the
> plaintext catalog on sight; see **Antivirus** below.

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

ghostops generate                              # browse the payload catalog
ghostops generate revshell python3 -l 10.10.14.5 -p 4444
ghostops generate revshell bash -l 10.10.14.5 -p 4444 --encode
ghostops generate webshell php --param cmd
ghostops generate listener nc -p 4444

ghostops checklist                             # list services with checklists
ghostops checklist smb                         # enumeration steps for SMB
ghostops attack                                # action -> MITRE ATT&CK map
ghostops model                                 # which LLM is active (AI/offline)
ghostops recall "what web servers did we find" # semantic search (RAG)
```

Inside an engagement (REPL):

```
scan <target>          run an nmap scan (in-scope only)
gobuster <url>         brute-force web directories
searchsploit <terms>  search ExploitDB
sqlmap <url>          test a URL for SQL injection
hydra <t> <svc> <u> <passlist>   brute-force a login
payloads [category]    browse the payload catalog
revshell <name> <lhost> <lport> [enc]   generate a reverse shell
webshell <name> [param]                 generate a web shell
listener <name> <lport>                 attacker-side listener
tty / privesc <name>   post-exploitation helpers
checklist [service]    per-service enumeration methodology
attack / mitre         ATT&CK techniques exercised so far
recall <question>      semantic search of past findings (RAG)
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
`confirm_before_run: true` and `enforce_scope: true`. Two models are configured
under `llm`: `model` (the **router/reasoning** model — never generates payloads)
and `embed_model` (embeddings for RAG). Run `ghostops model` to see which is
active and whether you're in AI or offline mode.

---

## Semantic memory / RAG (optional)

On top of the structured SQLite memory, GhostOps can index findings into a
vector store so you can ask questions by **meaning**:

```bash
recall what did we find on the web servers      # inside the REPL
ghostops recall "weak credentials" last          # from the shell
```

It's fully optional — install only if you want it:

```bash
pip install -e '.[rag]'          # ChromaDB
ollama pull nomic-embed-text     # the embedding model
```

Without either, GhostOps runs exactly as before and `recall` tells you what's
missing. RAG **augments** the SQLite memory (still the source of truth) — it
never replaces it, and the model only *reasons over* retrieved findings, never
invents them.

---

## Antivirus (Windows dev only)

The payload catalog contains real offensive one-liners, so **Windows Defender
quarantines `ghostops/knowledge/payloads.yaml` the moment it hits disk** — and
`ghostops generate` then reports "catalog not found". This does not affect
Kali/WSL2, where the tool is meant to run and no such AV is present. If you
develop on Windows, either:

- work inside **WSL2/Kali** (recommended — the security tools are there too), or
- ship the base64 form **`payloads.b64`** (carries no plaintext signatures; the
  loader prefers it automatically), or
- exclude the project directory from Defender (elevated PowerShell, one time):

  ```powershell
  Add-MpPreference -ExclusionPath "C:\path\to\GhostOps"
  ```

  An exclusion is worth it regardless: Defender also flags searchsploit hits,
  sqlmap, and hydra output during normal use.

---

## Development

```bash
python -m pytest tests/ -q          # runs without Ollama or security tools
python -m compileall ghostops       # syntax check
python -m ghostops <command>        # run without installing
```

The design is deliberately simple: one structured schema (`ghostops/models.py`)
is the source of truth, and the memory store, the `what do we know` summary, and
the report are all just views over it. Curated knowledge (payloads, checklists,
ATT&CK mappings) lives as reviewed YAML under `ghostops/knowledge/`, never
generated by the model.

---

## Disclaimer & License

GhostOps is provided for **authorized security testing, education, and research
only**. Using it against systems you do not own or lack explicit written
permission to test is illegal. The authors accept no liability for misuse or for
any damage caused by this software. Use responsibly and stay in scope.

Licensed under the **MIT License** — see [`LICENSE`](LICENSE).
