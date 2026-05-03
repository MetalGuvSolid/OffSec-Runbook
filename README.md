# OffSec Runbook

A specialized, high-performance React dashboard designed for penetration testers and security researchers. This tool serves as a supporting dashboard for offensive security engagements/CTFs/Labs, parsing scan data, and maintaining a structured methodology throughout an audit.

## Privacy and Security
This application is designed with **OffSec best practices** in mind:
*   **Local-First:** The app runs entirely in your local browser environment[cite: 1].
*   **Data Sovereignty:** No engagement data, IP addresses, or findings are ever transmitted to an external server.
*   **Persistence:** All session data is stored in your browser's `localStorage`.

---

## Getting Started (Installation)

To run the OffSec Runbook, you need to set up the Vite development environment on your local machine.

### 1. Prerequisites
You must have Node.js installed (version 18.0 or higher).
*   **Windows/macOS**: Download the installer from nodejs.org.
*   **Linux (Debian/Kali)**: Run `sudo apt install nodejs npm`.

### 2. Download the Project
Clone the repository from GitHub to your local workspace:
```bash
git clone https://github.com/MetalGuvSolid/OffSec-Runbook.git
cd OffSec-Runbook
```

### 3. Install the Environment
Vite requires several libraries (React, Lucide-React, etc.) to function. Install them by running:
```bash
npm install
```

---

## Running the App

Once the installation is complete, follow these steps to open the app in your browser:

1.  **Launch the Development Server**:
    In your terminal, within the project folder, run:
    ```bash
    npm run dev
    ```

2.  **Open the Localhost Link**:
    Vite will start a local web server. Look for the following output in your terminal:
    `➜ Local: http://localhost:5173/`

3.  **Access in Browser**:
    Open your preferred web browser and navigate to **http://localhost:5173**. The dashboard will load immediately.

---

## Feature Breakdown

### Reconnaissance and Nmap Parsing
Import your Nmap XML files directly. The app parses the data to identify open ports, services, and versions, automatically populating your target list.

### Phase-Based Workflows
The dashboard is divided into logical penetration testing phases:
*   **Enumeration**: Dedicated modules for SMB, SNMP, and DNS.
*   **Active Directory**: Tracking for Kerberoasting, BloodHound results, and Domain Admin paths.
*   **Web Exploitation**: Structured checklists for OWASP Top 10 and common CMS vulnerabilities.

### Command Generator
Contains a library of copy-paste ready commands for industry-standard tools like ffuf, nmap, crackmapexec, and gobuster, dynamically updated based on your target's IP.

---

## Tech Stack and Dependencies
*   **Engine**: Vite (Next-generation frontend tooling)
*   **Frontend**: React 18
*   **Icons**: Lucide-React
*   **Styling**: Standard CSS / Tailwind (as configured)

---

### Legal Disclaimer
This tool is for authorised security auditing purposes only. The developer assumes no liability for misuse or damage caused by this application. Always ensure you have explicit, written consent before performing any security testing.
```
