# =============================================================================
# OffSec Runbook — Windows Setup Script (PowerShell)
# https://github.com/MetalGuvSolid/OffSec-Runbook
#
# Usage: .\setup.ps1
# Checks and installs all required dependencies, then launches the app.
#
# If you see an execution policy error, run this first:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# =============================================================================

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Info    { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn    { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err     { param($msg) Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║       OffSec Runbook  — Setup         ║" -ForegroundColor Magenta
Write-Host "  ║             Windows                   ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# ── Verify repo root ──────────────────────────────────────────────────────────
if (-not (Test-Path (Join-Path $ScriptDir "package.json"))) {
    Write-Err "package.json not found. Run this script from the OffSec-Runbook root directory."
}

# ── Node.js ───────────────────────────────────────────────────────────────────
Write-Info "Checking for Node.js..."
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue

if (-not $nodeCmd) {
    Write-Warn "Node.js not found. Attempting to install via winget..."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install OpenJS.NodeJS.LTS --accept-source-agreements --accept-package-agreements
        # Refresh PATH for this session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    }
    if (-not $nodeCmd) {
        Write-Err "Node.js could not be installed automatically.`nInstall v18+ manually from https://nodejs.org then re-run this script."
    }
}

$nodeVersion = (node -v).TrimStart('v')
$nodeMajor   = [int]($nodeVersion.Split('.')[0])
if ($nodeMajor -lt 18) {
    Write-Err "Node.js v$nodeVersion found but v18+ is required. Upgrade from https://nodejs.org"
}
Write-Success "Node.js v$nodeVersion found."

# ── npm ───────────────────────────────────────────────────────────────────────
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Err "npm not found. Reinstall Node.js from https://nodejs.org (npm is bundled with it)."
}
Write-Success "npm $(npm -v) found."

# ── Git ───────────────────────────────────────────────────────────────────────
Write-Info "Checking for Git..."
$gitCmd = Get-Command git -ErrorAction SilentlyContinue

if (-not $gitCmd) {
    Write-Warn "Git not found. Attempting to install via winget..."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install Git.Git --accept-source-agreements --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    }
    if (-not $gitCmd) {
        Write-Err "Git could not be installed automatically.`nInstall it manually from https://git-scm.com/download/win then re-run this script."
    }
}
Write-Success "$(git --version) found."

# ── npm dependencies ──────────────────────────────────────────────────────────
Write-Info "Installing npm dependencies..."
Set-Location $ScriptDir
npm install
if ($LASTEXITCODE -ne 0) { Write-Err "npm install failed. See errors above." }
Write-Success "Dependencies installed."

# ── Verify Vite ───────────────────────────────────────────────────────────────
Write-Info "Verifying Vite..."
$viteVersion = npx vite --version 2>&1
if ($LASTEXITCODE -ne 0) { Write-Err "Vite not found after npm install. Check the output above for errors." }
Write-Success "Vite $viteVersion ready."

# ── Launch ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  All dependencies satisfied. Starting OffSec Runbook..." -ForegroundColor Green
Write-Host "  Open " -NoNewline; Write-Host "http://localhost:5173" -ForegroundColor Cyan -NoNewline; Write-Host " in your browser once Vite is ready."
Write-Host "  Press Ctrl+C to stop the server."
Write-Host ""

npm run dev
