#!/usr/bin/env bash
# GhostOps installer — CPU/no-GPU Kali/Debian/WSL2. Uses a venv so it does NOT
# depend on the system pip (Kali/WSL often ship an ancient python2 pip that
# breaks editable installs and --break-system-packages).
#
#   bash install.sh              # tools + Ollama + CPU model + GhostOps (venv)
#   bash install.sh --fast-model # also pull dolphin-phi (2.7B) for speed
set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
echo -e "${RED}GhostOps installer (CPU / no-GPU profile)${NC}"
echo "=================================================="
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v apt >/dev/null 2>&1; then
  echo -e "${RED}apt not found. Run this inside Kali/Debian/Ubuntu (VM or WSL2).${NC}"
  exit 1
fi

# 1. Security tools + python venv support -------------------------------------
echo -e "\n${YELLOW}[1/4] Security tools + Python venv${NC}"
TOOLS=(nmap gobuster ffuf sqlmap hydra nikto exploitdb john curl whois dnsutils
       python3 python3-venv python3-full)
MISSING=()
for t in "${TOOLS[@]}"; do
  dpkg -s "$t" >/dev/null 2>&1 || MISSING+=("$t")
done
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "  installing: ${MISSING[*]}"
  sudo apt-get update -qq && sudo apt-get install -y -qq "${MISSING[@]}"
else
  echo -e "  ${GREEN}all present${NC}"
fi

# 2. Ollama -------------------------------------------------------------------
echo -e "\n${YELLOW}[2/4] Ollama (local LLM runtime)${NC}"
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
else
  echo -e "  ${GREEN}already installed${NC}"
fi
# WSL has no systemd by default — start the server in the background if needed.
if ! curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "  starting 'ollama serve' in the background ..."
  (nohup ollama serve >/tmp/ollama.log 2>&1 &) || true
  sleep 3
fi

# 3. Model (CPU-friendly, uncensored) ----------------------------------------
echo -e "\n${YELLOW}[3/4] Pulling model (no-GPU profile)${NC}"
echo "  dolphin-mistral (7B, ~4GB) — best quality on a 16GB/8-core CPU box"
ollama pull dolphin-mistral
if [ "$1" == "--fast-model" ]; then
  echo "  dolphin-phi (2.7B) — faster fallback"
  ollama pull dolphin-phi
fi

# 4. GhostOps in a venv (avoids the system python2 pip entirely) --------------
echo -e "\n${YELLOW}[4/4] Installing GhostOps (isolated venv)${NC}"
VENV="$SCRIPT_DIR/.venv"
python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade pip -q
"$VENV/bin/python" -m pip install -e "$SCRIPT_DIR"
# expose a global 'ghostops' command via ~/.local/bin
mkdir -p "$HOME/.local/bin"
ln -sf "$VENV/bin/ghostops" "$HOME/.local/bin/ghostops"

echo ""
echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}  GhostOps installed (venv: $VENV)${NC}"
echo -e "${GREEN}==================================================${NC}"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) : ;;
  *) echo -e "${YELLOW}  Add ~/.local/bin to PATH (once):${NC}"
     echo "    echo 'export PATH=\$HOME/.local/bin:\$PATH' >> ~/.bashrc && source ~/.bashrc" ;;
esac
echo "  ghostops setup                 # verify everything"
echo "  ghostops engage <target>       # start (authorized targets only)"
echo "  Slow replies? edit config.yaml -> llm.model: dolphin-phi"
