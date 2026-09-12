# Known issues

Items 1-13 came from auditing the README against the tree at `5b24137` —
each was verified against the source, and several were demonstrated by
running the code; their line references are to that commit. Items 14-15
were found in lab runs; their references are to `bd98bde`.

Anything since fixed is marked **Fixed** and kept for the record rather
than deleted. **14 of the 15 are still open.**

Severity is about impact on a user, not effort:

| | |
|---|---|
| **medium** | wrong behaviour, or a documented guarantee that does not hold |
| **low** | correct behaviour, inaccurate or incomplete documentation |
| **nit** | cosmetic |

---

## Safety guarantees that are narrower than documented

### 1. The scope guard has two documented bypasses — medium
`README.md:15` says the scope guard blocks out-of-scope targets. Two shipped
paths remove it entirely: `ghostops shell` builds a full tool-capable
orchestrator with `scope=["*"]` (`ghostops/agent/orchestrator.py:958`), and
`scope add *` does the same to a live engagement
(`ghostops/agent/orchestrator.py:786`). `ScopeGuard` treats `*` as allow-all by
design, so both are opt-outs rather than bugs — but the README states the
guarantee without the exceptions. Either name them, or require an explicit
flag for a wildcard scope.

### 2. `ask` "refuses when findings don't cover the question" is only partly enforced — medium
`README.md:174`. The deterministic part is real: when retrieval returns nothing
within `max_distance`, the model is never called and GhostOps answers
`NO RELEVANT FINDINGS` itself (`ghostops/agent/rag.py:433`). Once a hit is
inside the threshold, refusal depends on the model honouring rule 4 of
`GROUNDED_ANSWER_SYSTEM` — a prompt instruction, not an enforced property. The
output guard catches command shapes and bogus citations, not a confidently
irrelevant answer. Reword to distinguish the enforced case from the prompted
one.

### 3. Confirmation-gate wording is now out of date — low
`README.md:46` describes a "confirmation gate on intrusive actions". Since
`5b24137` the gate fires for **every** tool when `safety.confirm_before_run` is
true, and **unconditionally** for intrusive tools regardless of that setting
(`ghostops/agent/orchestrator.py:349`). The current text understates it.

---

## Correctness

### 4. The next-steps menu offers tools that are not installed — medium
`README.md:29` claims the menu "can never suggest something it can't actually
run". `build_registry` (`ghostops/tools/registry.py:14`) instantiates all six
tools with no availability check, and `build_actions`
(`ghostops/agent/next_steps.py:50`) filters only on registry membership. On a
box without, say, nikto, the step is still offered; picking it prints the
command as a dry run rather than failing hard. Filter on `is_available()`, or
mark unavailable steps in the menu.

### 5. gobuster's default wordlist is never installed — medium
The built-in default is `/usr/share/wordlists/dirb/common.txt`
(`ghostops/config.py:30`), but `install.sh:46` installs neither `dirb` nor
`wordlists`, and the README's dependency list does not mention needing one. On
a fresh Kali the first gobuster run fails for a reason that is not obvious.
Add `wordlists` to the installer and to `README.md:106`.

### 6. `ghostops setup` does not check the RAG dependencies — medium
`README.md:111` offers `setup` as the way to see "what's installed and what's
missing", directly under a dependency list whose last two entries are
ChromaDB and `nomic-embed-text`. `setup` checks nine binaries plus Ollama
reachability and the **router** model (`ghostops/setup_wizard.py:14`); it never
checks ChromaDB and never checks the embed model. Extend `setup`, or point at
`ghostops model` for the embed side.

### 7. `report` only finds engagements from the directory you started in — medium
`engagements.dir` defaults to the cwd-relative `./engagements`
(`ghostops/config.py:24-25`), no config file exists after a fresh install, and
`setup` never writes one. So the Quickstart's `ghostops report -o
engagement.md` (`README.md:138`) silently finds nothing if you have changed
directory since `engage`. Default to an absolute `~/.ghostops/engagements`, or
say so in the Quickstart.

---

## Documentation

### 8. nmap can never appear as a next step — low
`README.md:29` says the menu is built from "the six real, registered tools".
`build_actions` has no nmap branch, so the menu emits at most five: gobuster,
nikto, searchsploit, hydra, sqlmap. nmap is how a scan starts, not a follow-up
— but the count is wrong as written.

### 9. `ask` and `recall` are inert after the documented default install — low
Both feature bullets (`README.md:40-41`) read as available out of the box. They
need the optional `[rag]` extra *and* `nomic-embed-text`; without ChromaDB,
`ask` returns `MODE_UNAVAILABLE` (`ghostops/agent/rag.py:401`). `bash
install.sh` without `--rag` does not install either. Mark both bullets as
requiring the extra.

### 10. `pip install -e '.[rag]'` fails on the platform the README targets — low
**Fixed** — the README now shows the virtualenv form. Kept for the record.

`README.md:101`. Kali and Debian ship an externally-managed Python (PEP 668), so
a bare `pip install -e` outside a virtualenv is refused. Show the venv form, or
`--break-system-packages`.

### 11. `bindshell` is missing from the REPL verb list — low
`README.md:166`. It is a real payload category and a bare REPL verb exactly
like `revshell` and `webshell`
(`ghostops/agent/orchestrator.py:40`, dispatch at `:843`). Same omission class
as the nikto one fixed in `3152509`.

### 12. The payload category list is one short — nit
`README.md:42` lists reverse/bind/web shells, listeners and TTY upgrades. The
catalog has six categories; `privesc` (Linux and Windows enumeration blocks,
`ghostops/knowledge/payloads.yaml:328`) is missing. The OPSEC-notes and
curated-dataset claims in that bullet are correct — every one of the 29 entries
carries an `opsec` field.

### 13. `checklist <service>` should be `[service]` — nit
`README.md:155`. The argument is optional (`ghostops/cli.py:174`); bare
`checklist` lists every service. The README's own notation elsewhere
(`resume [id]`, `report [id]`) would write it with brackets.

---

## Output and presentation

### 14. Nikto findings are not printed inline — low
A nikto run shows only its one-line summary. `_render_result`
(`ghostops/agent/orchestrator.py:463`) prints that summary plus a per-host
port table gated on `if result.hosts:`, and never reads `result.findings`.
Nikto populates `result.findings` (`ghostops/tools/nikto_tool.py:87`) and
returns no hosts, so its items are stored correctly but invisible at the
moment you run it — they surface only via `what do we know`, `recall`, `ask`,
or the report. Render `result.findings` in `_render_result`.

### 15. A briefing can blend hosts — low
`_brief` (`ghostops/agent/orchestrator.py:479`) scopes its user payload to
the current result, but builds its system message as `SUMMARIZE_SYSTEM` plus
`self._context_blob()`, and `_context_blob`
(`ghostops/agent/orchestrator.py:994`) emits engagement-wide state including
up to ten hosts and their ports. In a multi-host engagement the model can
therefore attribute one host's services to another in the free-text
briefing. The stored per-host data is unaffected and stays correct. Scope
the briefing's context to the host just scanned.
