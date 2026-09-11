# GhostOps

**A local, offline AI red-team copilot.** GhostOps is a penetration-testing assistant that *runs* the security tools itself, remembers everything it finds, follows standard offensive methodology, and writes the final report — all on your own machine, with no cloud and no API keys.

It is built on three principles that set it apart from chat-style pentest assistants:

- **It executes, not just suggests.** You give it an authorized target in plain English; it selects and runs the right tool, parses the results into structured memory, and offers you the next steps as a menu.
- **It's fully local and private.** Reasoning runs through a local model via [Ollama](https://ollama.com). Nothing about your target leaves the machine.
- **It doesn't invent findings.** Tools, payloads, and reported vulnerabilities come from real tool output and a curated, reviewed dataset — never from the model's imagination. Its grounded question-answering (`ask`) is hardened so that even text served by a hostile target cannot turn into fabricated results.

---

## ⚠️ Authorized use only

GhostOps is for testing systems you **own** or have **explicit written permission** to test. Several of its tools (hydra, sqlmap, nikto) are actively intrusive and noisy, and scanning or attacking systems without authorization is illegal in most jurisdictions. The built-in scope guard blocks out-of-scope targets and every intrusive action requires confirmation — but these are safety rails, not a substitute for authorization. **You are responsible for staying within a lawful, authorized scope.**

For safe practice, point it at a lab target you control: [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), Metasploitable, or a HackTheBox / TryHackMe box.

---

## How it works

```
you type  →  scope guard (blocks out-of-scope targets)  →  confirm
   →  run tool  →  parse results into structured memory (SQLite)
   →  suggest next steps as a menu + map to MITRE ATT&CK  →  generate report
```

The reasoning model turns plain English into a tool choice and ranks the next steps — but the menu you pick from is always built from the six real, registered tools, so it can never suggest something it can't actually run. If no model is available, GhostOps drops cleanly into a deterministic offline mode and keeps working.

---

## Features

- **AI router with offline fallback** — a local model picks the right tool via a strict contract; with no model, a deterministic router still handles scanning and core commands.
- **Menu-driven next steps** — numbered, built from the tool registry against what's actually in memory. Non-intrusive actions first; intrusive ones flagged and sorted last.
- **Six integrated tools** — nmap, gobuster, searchsploit, sqlmap, hydra, nikto — run directly, with output parsed into structured findings.
- **Structured memory (SQLite)** — one database per engagement: hosts, services, findings, credentials, web targets, and an activity log.
- **Kill-chain phases** — reconnaissance → scanning → enumeration → exploitation → post-exploitation → reporting, auto-advancing as you progress.
- **Grounded RAG (`ask`)** — ask questions about an engagement in plain English and get an answer drawn *only* from retrieved findings, with a Sources table. Hardened against prompt injection from scanner-controlled text.
- **Semantic recall** — search an engagement's findings by meaning, not just exact match.
- **Curated payload generator** — reverse / bind / web shells, listeners, TTY upgrades, with OPSEC notes. Payloads come from a reviewed dataset, never the model.
- **Service enumeration checklists** — curated methodology for common services.
- **MITRE ATT&CK mapping** — every action maps to a real technique ID.
- **Markdown report generation** — a clean pentest report built from what the tools actually found.
- **Safety layer** — scope guard, confirmation gate on intrusive actions, and no-shell-injection command construction (list-argv, never `shell=True`).

---

## The six tools

| Tool | Purpose | Intrusive |
|------|---------|-----------|
| **nmap** | Port and service discovery | No |
| **gobuster** | Web content / directory discovery | No |
| **searchsploit** | Local ExploitDB lookup (offline, no network) | No |
| **sqlmap** | SQL injection testing | Yes — noisy |
| **hydra** | Credential brute-forcing | Yes — very noisy |
| **nikto** | Web-server vulnerability scanning | Yes — noisy |

Intrusiveness is a real flag in code, not just documentation: intrusive tools are sorted last in the menu, rendered with a red tag, and always pass through the confirmation gate before running.

---

## Installation

**Requirements:** Python ≥ 3.11, Linux. Developed and tested on Kali (including WSL2); the installer also has a Fedora/`dnf` path, which is supported but not yet tested.

```bash
git clone https://github.com/AachalGodse/Local-AI-red-team-assistant
cd Local-AI-red-team-assistant
bash install.sh                 # core + system tools + Ollama
```

> **Note:** the repository is currently **private**, so an unauthenticated
> `git clone` will fail. Until it is made public you need repository access
> (or a local copy of the source) for this step.

The installer is idempotent and runs in four stages: system tools (auto-detects `apt` or `dnf`), pipx, Ollama (installs it, starts the server, pulls `dolphin-mistral`), then GhostOps itself.

Options:

```bash
bash install.sh --rag           # also install the ChromaDB extra (for recall/ask)
bash install.sh --no-ollama     # skip Ollama install and model pull
```

> **Fedora note:** `gobuster` and `searchsploit` aren't in the default dnf repos — the installer will flag them for manual install.

### Manual install

```bash
pipx install .
pipx inject ghostops 'chromadb>=0.5'    # optional — enables recall / ask
ollama pull nomic-embed-text            # optional — embed model for recall / ask
```

Or from source, with the RAG extra:

```bash
pip install -e '.[rag]'
```

### External dependencies (not bundled)

- **Security tools:** nmap, gobuster, sqlmap, hydra, nikto, searchsploit — installed as system packages.
- **Ollama** with **dolphin-mistral** — the reasoning/router model. Optional: without it, GhostOps runs in deterministic offline mode.
- **nomic-embed-text** — embedding model, required for `recall` and `ask`.
- **ChromaDB** — optional `[rag]` extra, required for semantic memory.

Run `ghostops setup` any time to check what's installed and what's missing.

---

## Quickstart

```bash
# See what's active and whether you're in AI or offline mode
ghostops model

# Start an engagement against an authorized target
ghostops engage http://localhost:3000     # e.g. a local Juice Shop instance
```

Inside the engagement REPL:

```
ghostops> scan localhost           # run nmap, findings land in memory
ghostops> next                     # numbered menu of next steps
ghostops> what do we know          # everything stored so far
ghostops> ask what did we find on the web service?
ghostops> exit
```

Then generate the report:

```bash
ghostops report -o engagement.md
```

---

## Command reference

**CLI**

| Command | Purpose |
|---------|---------|
| `engage <target>` | Start a new engagement against a target |
| `shell` | Free-form chat with the red-team AI (scope = `*`) |
| `resume [id]` | Resume a previous engagement (defaults to the last) |
| `report [id] -o <file>` | Generate a markdown pentest report |
| `engagements` | List all saved engagements |
| `generate [category] [name] -l <lhost> -p <lport>` | Render a curated offensive payload. With only a category it *lists* that category's catalog instead |
| `checklist <service>` | Show the enumeration checklist for a service |
| `attack` | Show the action → MITRE ATT&CK mapping |
| `recall <question> [id]` | Semantic search over an engagement's findings |
| `ask <question> [id]` | Answer a question using *only* that engagement's findings |
| `model` | Show the active model and AI/offline mode |
| `setup` | Check tools, models, and configuration |
| `help` | Welcome screen and command reference |
| `version` | Show the GhostOps version |

Run bare `ghostops` for the welcome screen; `--no-intro` skips the first-run walkthrough.

**In-engagement REPL:** `scan`, `gobuster`, `nikto`, `searchsploit`, `sqlmap`, `hydra`, `payloads`, `revshell`, `webshell`, `listener`, `tty`, `privesc`, `checklist`, `attack`, `recall`, `ask`, `what do we know`, `next`, `scope` / `scope add`, `tools`, `phase`, `help`, `exit`.

---

## Design principles

GhostOps holds three lines throughout:

1. **The model reasons; it never invents.** Tool choices are constrained to the real registry, payloads come from a curated dataset, and reported findings come from actual tool output. The grounded `ask` path answers only from retrieved findings and refuses when they don't cover the question.
2. **Safety guards are non-bypassable.** The scope guard, confirmation gate, and shell-injection-safe command building sit in front of every tool and cannot be routed around.
3. **It works offline.** With no model, no network, or no ChromaDB, GhostOps keeps running: tools still execute, the deterministic router takes over, and the semantic features report what is missing instead of crashing. The one exception is the `ghostops ask` / `ghostops recall` *subcommands*, which exit non-zero when ChromaDB is absent; the same commands inside an engagement print the install hint and carry on.

---

## Known limitations

- **Planted text still reaches the screen, just not the answer.** The grounded `ask` path is defended in depth against text planted by a hostile scanned host: retrieved findings are fenced as untrusted data, citation-shaped text is defused, and an independent output guard withholds any answer containing a command shape or a citation to a finding that does not exist. Two residuals are accepted rather than hardened further. First, the **Sources** table printed under every answer shows each finding's raw text on purpose, so you can audit what the model was given — which means planted content is visible there even when it is kept out of the answer. Treat Sources rows as untrusted scanner output, not as GhostOps' own conclusions. Second, a hostile host can influence the *wording* of a refusal, though not the dangerous content inside it.

---

## Testing

```bash
pytest
```

135 tests currently pass. Some are skipped automatically when an optional dependency (ChromaDB, an installed catalog, etc.) isn't present on the machine.

---

## License

MIT — see the [`LICENSE`](LICENSE) file at the repository root.
