# OffSec Runbook

A specialized, high-performance React dashboard designed for penetration testers and security researchers. This tool serves as a supporting dashboard for offensive security engagements, CTFs, and labs — parsing scan data and maintaining a structured methodology throughout an audit.

![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-latest-646CFF?logo=vite&logoColor=white)
![Node](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js&logoColor=white)
![License](https://img.shields.io/badge/Use-Authorised%20Auditing%20Only-red)

---

## 🚀 Access the App

**The easiest way to use OffSec Runbook is directly in your browser — no installation required:**

### 👉 [https://metalguvsolid.github.io/OffSec-Runbook/](https://metalguvsolid.github.io/OffSec-Runbook/)

The app runs entirely in your browser. No data leaves your machine. Just open the link and go.

> If you prefer to run the app locally (e.g. for offline use or development), see the [Local Setup](#quick-setup-local) section below.

---

## Privacy and Security

This application is designed with **OffSec best practices** in mind:

- **Local-First:** The app runs entirely in your local browser environment.
- **Data Sovereignty:** No engagement data, IP addresses, or findings are ever transmitted to an external server.
- **Persistence:** All session data is stored in your browser's `localStorage`.

---

## Quick Setup (Local)

The fastest way to run the app locally is to use the provided setup script for your OS. Each script checks for prerequisites, installs any missing dependencies, and launches the app.

### Linux / macOS

```bash
git clone https://github.com/MetalGuvSolid/OffSec-Runbook.git
cd OffSec-Runbook
chmod +x OffSec_Runbook_Linux.sh
./OffSec_Runbook_Linux.sh
```

### Windows (PowerShell)

```powershell
git clone https://github.com/MetalGuvSolid/OffSec-Runbook.git
cd OffSec-Runbook
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\OffSec_Runbook_Win.ps1
```

> See the [Manual Installation](#manual-installation) section below if you prefer to set things up step by step.

---

## Manual Installation

### Step 1 — Prerequisites

You must have **Node.js v18.0 or higher** and **Git** installed.

#### Linux (Debian / Kali)

```bash
# Update package lists
sudo apt update

# Install Node.js v18+ via NodeSource (recommended over apt default)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs

# Install npm separately if not bundled
sudo apt install -y npm

# Install Git if not already present
sudo apt install -y git

# Verify
node -v   # Should print v18.x.x or higher
npm -v
git --version
```

> **Kali users:** The above NodeSource method is recommended. The version in the default Kali repos may be outdated.

#### Windows

1. Download the **Node.js LTS** installer from [nodejs.org](https://nodejs.org) and run it. This also installs `npm` — if for any reason npm is missing afterwards, re-run the Node.js installer or install it separately via `winget install OpenJS.NodeJS.LTS` in PowerShell.
2. Download **Git for Windows** from [git-scm.com](https://git-scm.com/download/win) and run the installer. During setup, select *"Git from the command line and also from 3rd-party software"* when prompted.
3. Verify by opening **PowerShell** or **Command Prompt** and running:

```powershell
node -v    # Should print v18.x.x or higher
npm -v
git --version
```

---

### Step 2 — Clone the Repository

#### Linux / macOS

```bash
git clone https://github.com/MetalGuvSolid/OffSec-Runbook.git
cd OffSec-Runbook
```

#### Windows (PowerShell or Command Prompt)

```powershell
git clone https://github.com/MetalGuvSolid/OffSec-Runbook.git
cd OffSec-Runbook
```

---

### Step 3 — Install Dependencies

This installs React, Vite, Lucide-React, and all other required packages defined in `package.json`.

#### Linux / macOS

```bash
npm install
```

#### Windows

```powershell
npm install
```

> If you see permission errors on Windows, run PowerShell **as Administrator** and retry.

---

## Running the App

### Linux / macOS

```bash
npm run dev
```

### Windows

```powershell
npm run dev
```

Once started, Vite will output:

```
  VITE vX.X.X  ready in Xms

  ➜  Local:   http://localhost:5173/
```

Open **http://localhost:5173** in your browser. The dashboard will load immediately.

> **Note:** The dev server must remain running in your terminal for the app to be accessible. To stop it, press `Ctrl + C`.

---

## Feature Breakdown

### Reconnaissance and Nmap Parsing

Import your Nmap XML files directly. The app parses the data to identify open ports, services, and versions, automatically populating your target list.

### Phase-Based Workflows

The dashboard is divided into logical penetration testing phases:

- **Enumeration:** Dedicated modules for SMB, SNMP, and DNS.
- **Active Directory:** Tracking for Kerberoasting, BloodHound results, and Domain Admin paths.
- **Web Exploitation:** Structured checklists for OWASP Top 10 and common CMS vulnerabilities.

### Command Generator

Contains a library of copy-paste ready commands for industry-standard tools like `ffuf`, `nmap`, `crackmapexec`, and `gobuster`, dynamically updated based on your target's IP.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Build Tool | Vite |
| Frontend | React 18 |
| Icons | Lucide-React |
| Styling | CSS / Tailwind |
| Runtime | Node.js 18+ |

---

## Troubleshooting

**`npm install` fails with EACCES errors (Linux)**
```bash
# Fix npm global permissions — do NOT use sudo with npm install
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
export PATH=~/.npm-global/bin:$PATH  # Add this to your ~/.bashrc or ~/.zshrc
```

**Port 5173 already in use**
```bash
# Linux: find and kill the process using the port
lsof -ti:5173 | xargs kill

# Windows PowerShell
Get-Process -Id (Get-NetTCPConnection -LocalPort 5173).OwningProcess | Stop-Process
```

**`node: command not found` after install (Linux)**
```bash
# Source your shell profile to pick up the new PATH
source ~/.bashrc   # or source ~/.zshrc
```

**PowerShell execution policy error (Windows)**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

**Script still blocked after setting execution policy (Windows)**

If the script was downloaded via a browser or file transfer, Windows may have tagged it with a security zone marker that blocks execution even after setting the policy. Unblock it with:
```powershell
Unblock-File -Path ".\OffSec_Runbook_Win.ps1"
```
Then run the script again normally.

---

## Legal Disclaimer

This tool is for **authorised security auditing purposes only**. The developer assumes no liability for misuse or damage caused by this application. Always ensure you have **explicit, written consent** before performing any security testing.
