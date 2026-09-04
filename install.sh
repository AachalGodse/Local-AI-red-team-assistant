#!/usr/bin/env bash
# GhostOps installer — installs the `ghostops` command via pipx, so it lands on
# your PATH and runs from anywhere with NO venv to activate. Works on
# Kali/Debian (apt) and Fedora (dnf). Re-running is safe (idempotent).
#
#   bash install.sh              # ghostops (core) + system tools + Ollama
#   bash install.sh --rag        # also add the RAG extra (ChromaDB)
#   bash install.sh --no-ollama  # skip the Ollama install / model pull
set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
say(){ echo -e "$@"; }
say "${RED}GhostOps installer (pipx)${NC}"
say "=================================================="
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WANT_RAG=0; WANT_OLLAMA=1
for a in "$@"; do
  case "$a" in
    --rag) WANT_RAG=1 ;;
    --no-ollama) WANT_OLLAMA=0 ;;
  esac
done

# --- detect package manager --------------------------------------------------
PM=""
if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf >/dev/null 2>&1; then PM=dnf
fi
pm_install(){  # best-effort: never abort the whole install if a pkg is missing
  [ -z "$PM" ] && return 0
  if [ "$PM" = apt ]; then
    sudo apt-get update -qq || true
    sudo apt-get install -y -qq "$@" || true
  else
    sudo dnf install -y -q "$@" || true
  fi
}

# --- 1. system security tools (system-provided, never bundled) ---------------
say "\n${YELLOW}[1/4] System security tools${NC}"
if [ -z "$PM" ]; then
  say "  ${YELLOW}No apt or dnf found. Install nmap, gobuster, sqlmap, hydra,"
  say "  searchsploit (exploitdb) yourself, then re-run.${NC}"
elif [ "$PM" = apt ]; then
  pm_install nmap gobuster ffuf sqlmap hydra nikto exploitdb john curl \
             python3 python3-pip pipx
else
  # Fedora: gobuster / exploitdb aren't in the default repos - note it.
  pm_install nmap sqlmap hydra nikto john curl python3 python3-pip pipx
  say "  ${YELLOW}note: gobuster and searchsploit may need a manual install on Fedora.${NC}"
fi

# --- 2. pipx -----------------------------------------------------------------
say "\n${YELLOW}[2/4] pipx${NC}"
if ! command -v pipx >/dev/null 2>&1; then
  python3 -m pip install --user -q pipx 2>/dev/null \
    || python3 -m pip install --user --break-system-packages -q pipx || true
fi
(python3 -m pipx ensurepath >/dev/null 2>&1) \
  || (pipx ensurepath >/dev/null 2>&1) || true
if ! command -v pipx >/dev/null 2>&1; then
  say "  ${RED}pipx not available. Install it via your package manager, then re-run.${NC}"
  exit 1
fi
say "  ${GREEN}pipx ready${NC}"

# --- 3. Ollama (optional local LLM) ------------------------------------------
if [ "$WANT_OLLAMA" = 1 ]; then
  say "\n${YELLOW}[3/4] Ollama (optional - local LLM)${NC}"
  if ! command -v ollama >/dev/null 2>&1; then
    curl -fsSL https://ollama.com/install.sh | sh \
      || say "  ${YELLOW}Ollama install skipped/failed - GhostOps still runs offline.${NC}"
  else
    say "  ${GREEN}already installed${NC}"
  fi
  if command -v ollama >/dev/null 2>&1; then
    curl -s http://localhost:11434/api/tags >/dev/null 2>&1 \
      || { (nohup ollama serve >/tmp/ollama.log 2>&1 &) || true; sleep 2; }
    ollama pull dolphin-mistral \
      || say "  ${YELLOW}model pull skipped - later: ollama pull dolphin-mistral${NC}"
  fi
else
  say "\n${YELLOW}[3/4] Ollama - skipped (--no-ollama)${NC}"
fi

# --- 4. GhostOps via pipx (idempotent) ---------------------------------------
say "\n${YELLOW}[4/4] Installing GhostOps (pipx)${NC}"
pipx install --force "$REPO"
if [ "$WANT_RAG" = 1 ]; then
  say "  adding RAG extra (ChromaDB) ..."
  pipx inject ghostops "chromadb>=0.5" || true
fi

say ""
say "${GREEN}==================================================${NC}"
say "${GREEN}  GhostOps installed. Open a NEW shell, then:${NC}"
say "${GREEN}==================================================${NC}"
say "  ghostops help                 # what it is + commands"
say "  ghostops setup                # check tools / model"
say "  ghostops engage <target>      # start (authorized targets only)"
say "  RAG later:  pipx inject ghostops 'chromadb>=0.5'  &&  ollama pull nomic-embed-text"
say "  If 'ghostops' isn't found: run 'pipx ensurepath' and reopen the shell."
