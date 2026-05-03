#!/usr/bin/env bash
# =============================================================================
# OffSec Runbook — Linux / macOS Setup Script
# https://github.com/MetalGuvSolid/OffSec-Runbook
#
# Usage: ./setup.sh
# Checks and installs all required dependencies, then launches the app.
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BOLD}"
echo "  ╔═══════════════════════════════════════╗"
echo "  ║       OffSec Runbook  — Setup         ║"
echo "  ║          Linux / macOS                ║"
echo "  ╚═══════════════════════════════════════╝"
echo -e "${NC}"

# ── Verify repo root ──────────────────────────────────────────────────────────
if [[ ! -f "$SCRIPT_DIR/package.json" ]]; then
  error "package.json not found. Run this script from the OffSec-Runbook root directory."
fi

# ── Node.js ───────────────────────────────────────────────────────────────────
info "Checking for Node.js..."
if ! command -v node &>/dev/null; then
  warn "Node.js not found. Attempting to install via NodeSource (requires sudo)..."
  if command -v apt-get &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    sudo apt-get install -y nodejs
  elif command -v brew &>/dev/null; then
    brew install node@18
  else
    error "Cannot auto-install Node.js. Install v18+ manually from https://nodejs.org and re-run."
  fi
fi

NODE_VERSION=$(node -v | sed 's/v//')
NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  error "Node.js v${NODE_VERSION} found but v18+ is required. Upgrade from https://nodejs.org"
fi
success "Node.js v${NODE_VERSION} found."

# ── npm ───────────────────────────────────────────────────────────────────────
if ! command -v npm &>/dev/null; then
  error "npm not found. Reinstall Node.js from https://nodejs.org (npm is bundled with it)."
fi
success "npm $(npm -v) found."

# ── Git ───────────────────────────────────────────────────────────────────────
info "Checking for Git..."
if ! command -v git &>/dev/null; then
  warn "Git not found. Attempting to install..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get install -y git
  elif command -v brew &>/dev/null; then
    brew install git
  else
    error "Cannot auto-install Git. Install it manually and re-run."
  fi
fi
success "Git $(git --version | awk '{print $3}') found."

# ── npm dependencies ──────────────────────────────────────────────────────────
info "Installing npm dependencies..."
cd "$SCRIPT_DIR"
npm install
success "Dependencies installed."

# ── Verify Vite ───────────────────────────────────────────────────────────────
info "Verifying Vite..."
if ! npx vite --version &>/dev/null; then
  error "Vite not found after npm install. Check the output above for errors."
fi
success "Vite $(npx vite --version) ready."

# ── Launch ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  All dependencies satisfied. Starting OffSec Runbook...${NC}"
echo -e "  Open ${CYAN}http://localhost:5173${NC} in your browser once Vite is ready."
echo -e "  Press ${YELLOW}Ctrl+C${NC} to stop the server."
echo ""

npm run dev
