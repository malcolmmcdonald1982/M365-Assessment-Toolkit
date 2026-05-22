# M365 Assessment Toolkit

A free, open-source Microsoft 365 security assessment tool for IT consultants and administrators. Runs locally on Windows — no data leaves your machine.

This tool is not intended to replace enterprise security platforms. It fills a gap for IT professionals who need practical assessments without enterprise licensing costs.

## What it does

- Runs a security assessment against any M365 tenant across 6 workloads
- Evaluates 23 findings covering identity, conditional access, Exchange, Teams, SharePoint and Intune
- Scores the tenant based on real attack paths — not just Microsoft Secure Score
- Remediates findings with one click, with full rollback capability
- Produces professional Word reports (Assessment Report, Remediation Report, Comparison Report)
- Simulates attack chains to show which findings enable which attacks
- Compares two assessments to track improvement over time

## What it looks like

### Assessment Dashboard
The dashboard shows a live risk score, colour-coded findings by severity, and module run status.

![Dashboard](docs/screenshots/dashboard.png)

### Findings with Investigation Scripts
Each finding card includes an inline PowerShell investigation script you can run directly to dig into the detail behind the finding.

![Findings panel with investigation script](docs/screenshots/findings-investigate.png)

### Generated Reports
One click produces a professionally formatted Word document ready to hand to a client.

![Word report sample](docs/screenshots/report-sample.png)

### Attack Simulation
Maps your open findings to real attack chains — showing exactly which combination of misconfigurations an attacker would exploit, in sequence.

![Attack simulation](docs/screenshots/attack-simulation.png)

## Prerequisites

The installer handles all of these automatically:

| Prerequisite | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Backend server |
| Flask | Latest | Web framework |
| Node.js | 18+ | Report generator |
| docx (npm) | Latest | Word document creation |
| Microsoft.Graph | 2.0+ | Identity, Security, Intune |
| ExchangeOnlineManagement | 3.0+ | Exchange Online |
| MicrosoftTeams | 5.0+ | Microsoft Teams |
| Microsoft.Online.SharePoint.PowerShell | 16.0+ | SharePoint Online |

## Installation

### Option 1 — One-line install (quickest)

Open PowerShell as Administrator and run:

```powershell
irm https://raw.githubusercontent.com/malcolmmcdonald1982/M365-Assessment-Toolkit/main/install.ps1 | iex
```

The installer downloads all files from GitHub, installs all prerequisites, and creates a desktop shortcut. Nothing else needed.

### Option 2 — Download and run

1. Click the green **Code** button on this page and select **Download ZIP**
2. Extract the ZIP — you should have a folder containing `install.ps1`, `backend.py`, `index.html` etc.
3. Open PowerShell as Administrator
4. Run:

```powershell
cd "C:\path\to\extracted-folder"
.\install.ps1
```

### Option 3 — Clone the repo

If you have Git installed:

```powershell
git clone https://github.com/malcolmmcdonald1982/M365-Assessment-Toolkit.git C:\AssetTool
cd C:\AssetTool
.\install.ps1
```

All three options install to `C:\M365 Assessment Toolkit` and create a desktop shortcut.

## After installation

Double-click the **M365 Assessment Toolkit** shortcut on your desktop. The tool opens automatically in your browser at `http://localhost:5000`. Keep the black PowerShell window open while using the tool — closing it stops the backend.

## Authentication

**Interactive Login** — No setup required. The tool prompts for credentials when each module runs. Suitable for one-off assessments.

**App Registration** — Requires setup in Entra ID. Silent authentication for Graph-based modules. Recommended for repeat assessments.

### Setting up App Registration

1. Go to [Entra ID > App registrations](https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps)
2. Click **New registration** — name it `M365 Assessment Toolkit`
3. Copy the **Application (client) ID** and **Directory (tenant) ID**
4. Go to **Certificates & secrets** > **New client secret** — copy the **Value**
5. Go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**
6. Add these permissions:

```
User.Read.All
Directory.Read.All
RoleManagement.Read.Directory
UserAuthenticationMethod.Read.All
Reports.Read.All
Policy.Read.All
SecurityEvents.Read.All
Organization.Read.All
Application.Read.All
DeviceManagementManagedDevices.Read.All
DeviceManagementConfiguration.Read.All
AuditLog.Read.All
IdentityRiskyUser.Read.All
```

7. Click **Grant admin consent**

> Exchange, Teams and SharePoint always use interactive login — these PowerShell modules do not support app-only authentication.

## Understanding the Score

The tool's score is **not the same as Microsoft Secure Score**.

| | This Tool | Microsoft Secure Score |
|---|---|---|
| Measures | Real attack path exposure | Configuration compliance |
| A high score means | Low attack surface | Settings follow Microsoft recommendations |
| A low score means | Specific attack paths are open | Some recommended settings are off |

The tool scores 0–100 based on severity-weighted findings:
- **Critical** findings: -8 points each (capped at -32)
- **High** findings: -5 points each (capped at -20)
- **Medium** findings: -3 points each (capped at -12)
- **Low** findings: -1 point each (capped at -4)
- **Floor:** 10 (never shows zero)

A tenant can have a high Microsoft Secure Score and still score poorly here — because Secure Score rewards enabling features, not blocking attack paths.

## Updating

```powershell
irm https://raw.githubusercontent.com/malcolmmcdonald1982/M365-Assessment-Toolkit/main/update.ps1 | iex
```

The updater downloads the latest files from GitHub and applies them. Your saved sessions, reports and output files are never touched.

## Uninstalling

```powershell
irm https://raw.githubusercontent.com/malcolmmcdonald1982/M365-Assessment-Toolkit/main/uninstall.ps1 | iex
```

The uninstaller offers to back up your saved sessions and reports before removing.

## Data and Privacy

- All data stays on your local machine — nothing is sent to external servers
- Assessment results are saved to `C:\M365 Assessment Toolkit\output\`
- The tool reads tenant data but never writes to it during assessment
- Remediation scripts write to the tenant only when you explicitly click Apply Fix
- Each remediation change is snapshotted before it is made
- There is no backend server, no cloud component, no third party in the data flow — just you, your machine and Microsoft's APIs

For client engagements, ensure you have a Data Processing Agreement in place before running assessments against a client tenant.

## Data Flow

When you run an assessment:

1. PowerShell scripts run locally on your machine
2. They connect directly to Microsoft's APIs using your credentials or app registration — the same as any Microsoft PowerShell module
3. Results are returned as JSON and saved locally to `C:\M365 Assessment Toolkit\output\`
4. The local Flask backend processes the results and displays them in your browser
5. Nothing is transmitted to any external server at any point

## AI Disclosure

This tool was developed with AI assistance. The security logic, findings, scoring model, attack path mapping and architecture were designed by the author based on real-world M365 assessment experience. AI was used as a development aid to help bring it to life. All code is fully open source and publicly auditable on GitHub.

## Folder Structure

```
C:\M365 Assessment Toolkit\
├── backend.py              # Flask backend
├── index.html              # Frontend (served at localhost:5000)
├── generate-report.js      # Word report generator
├── package.json            # npm dependencies
├── scripts\                # Assessment PowerShell scripts
├── remediation\            # Remediation + rollback scripts
├── output\                 # Sessions, CSVs, remediation logs
└── reports\                # Generated Word documents
```

## Modules

| Module | Tag | Auth | Findings |
|---|---|---|---|
| Identity & MFA | ENTRA | App Reg or Interactive | 5 |
| Security & CA | SEC | App Reg or Interactive | 7 |
| Exchange Online | EXO | Interactive only | 3 |
| Teams | TEAMS | Interactive only | 2 |
| SharePoint | SPO | Interactive only | 2 |
| Intune / Devices | MDM | App Reg or Interactive | 4 |

## Licence

MIT — free to use, modify and distribute. See [LICENSE](LICENSE).

## Disclaimer

This tool is provided as-is for educational and professional use. Always obtain written approval before remediating any tenant. The authors accept no liability for changes made to live environments.
