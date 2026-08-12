# M365 Assessment Toolkit — Product Story
## From Inception to Platform

---

## The Problem It Solves

Security consultants and MSPs assessing Microsoft 365 tenants faced a gap in the market.
Enterprise tools like CoreView, Varonis and Adaptive Shield exist — but cost $10,000–$100,000
per year and are built for in-house security teams, not consultants walking into a client site.

Free tools like ScubaGear and Maester exist — but produce raw PowerShell output and JSON.
No GUI, no client reports, no remediation, no attack simulation. Built for engineers, not
consultants.

The market had two extremes and nothing in the middle.

The M365 Assessment Toolkit was built to fill that gap — a professional-grade Microsoft 365
security assessment platform that any consultant can run in 20 minutes, get a scored report,
simulate the risk, fix the issues, and hand over a branded deliverable. Free. Open source.
No cloud dependency.

---

## The Journey

### v1.0.0 — 5 May 2026 — Foundation
*"Prove the concept"*

The initial release established the core architecture that everything since has been built on:

**Assessment Engine**
- 23 findings across 6 modules: Identity, Security/CA, Exchange, Teams, SharePoint, Intune
- Dual authentication: Interactive Login and App Registration
- Severity-weighted scoring (Critical / High / Medium / Low)
- Session auto-save and reload without re-running scripts

**Remediation**
- 9 Tier 1 auto-fix findings with paired rollback scripts
- Pre-remediation safety checks (dependency scan before changes)
- Snapshot saved before every change — full rollback capability
- Approval gate with customisable fields (approver, change reference, date)
- Manual PowerShell commands displayed on each remediation card
- Remediation log saved per engagement

**Reports**
- Assessment Report: findings, score, recommendations, metrics appendix
- Remediation Report: before/after score, changes made, approval details
- Comparison Report: two assessments side-by-side
- Consultant branding fields (name, role, email)
- Word (.docx) and print-to-PDF output

**Simulator**
- 7 attack chain models: BEC, Account Takeover, Privilege Escalation, OAuth Abuse,
  Data Exfiltration, Ransomware, Invisible Persistence
- Toggle findings to simulate fixes — live score and chain status update
- Risk narrative updates in real time
- Export What-If report

**Packaging**
- One-line installer with prerequisite detection
- Update script (preserves all data)
- Uninstall script (optional data backup)

---

### v1.1.0 — 22 May 2026 — Trust and Transparency

**Bug Fix**
- Consultant details (name, role, email) not appearing in Word reports — fixed

**Transparency**
- Minimum role documentation added to Interactive Login section
- Read-only banner added above Run Assessment button — makes clear no tenant
  changes occur during scanning
- AI development disclosure added to footer across full UI
- Version bumped and visible in status endpoint

---

### v1.2.0 — 23 May 2026 — Authentication and Coverage

**Certificate-Based Authentication**
- Third auth option alongside Interactive and App Registration
- User provides Tenant ID, Client ID, Certificate Thumbprint
- Certificate loaded from Windows certificate store — no client secret stored in UI
- Applies to Graph-based modules (Identity, Security, Intune)

**Environment Selector**
- Commercial / GCC dropdown added
- GCCH and DoD listed as Coming Soon

**7 New Findings (23 → 30)**
- ID-006 — Risky Users Not Reviewed (High)
- ID-007 — No Emergency Access Account Detected (High)
- SEC-006 — No Microsoft Sentinel Connected (Medium)
- EXO-004 — DMARC Not Configured (High)
- EXO-005 — SPF or DKIM Not Configured (High)
- MDM-003 — No Windows Update Ring Configured (Medium)
- MDM-004 — BitLocker Not Enforced (High)

**Full Investigation Script Coverage**
- All 30 findings now have ready-to-run PowerShell investigation scripts
- 14 findings previously had no investigation script — all gaps filled

---

### v1.2.1 — 24 May 2026 — Update Infrastructure

**Auto Update Checker**
- Tool checks GitHub for newer version on every startup
- Banner appears when update is available
- Update Now button applies update directly from within the tool
- What's New links to GitHub releases page
- Dismiss closes banner for the session

---

### v1.3.0 — 25 May 2026 — Workflow and Permissions

**Read/Write Permission Separation**
- Assessment and remediation credentials configurable independently
- Separate mode supports dedicated write account with minimum required permissions
- Supports Interactive, App Registration and Certificate for both read and write
- Fails safely if write permissions insufficient — nothing changes in tenant

**UX Improvements**
- Metric cards sorted by status: red → amber → green
- Issues surface immediately without scrolling
- Sidebar reordered to natural consultant workflow
- Authentication section renamed for clarity
- Comprehensive README updates — permission tables, troubleshooting

---

### v1.4.0 — 5 June 2026 — Depth and Intelligence
*Current release*

**18 New Findings (30 → 48 across 6 modules)**

*Entra ID — Application Security (10 new findings)*
- ENTRA-001 — High-Privilege App Registrations (Critical)
- ENTRA-002 — Expired App Registration Credentials (High)
- ENTRA-003 — App Credentials Expiring ≤30 Days (High)
- ENTRA-004 — App Credentials Expiring 31–90 Days (Medium)
- ENTRA-005 — Never-Expiring App Credentials (Medium)
- ENTRA-006 — Unowned App Registrations (Medium)
- ENTRA-007 — Multi-Tenant App Registrations (Medium)
- ENTRA-008 — Implicit Grant Flow Enabled (Medium)
- ENTRA-009 — Privileged Service Principals (Critical)
- ENTRA-010 — Privileged Managed Identities (High)

*Cross-module (8 new findings)*
- CA-003 — No CA Policy Enforcing MFA for All Users (Critical)
- EXO-006 — Zero-Hour Auto Purge Not Fully Enabled (High)
- TEAMS-003 — Anonymous Users Can Join Meetings (Medium)
- TEAMS-004 — Third-Party Teams Apps Unrestricted (Medium)
- SPO-003 — OneDrive External Sharing Unrestricted (High)
- SPO-004 — Guest Access Expiry Not Configured (Medium)
- MDM-005 — No Mobile Device Compliance Policy (High)
- MDM-006 — Defender for Endpoint Not Integrated with Intune (Medium)

**MS Secure Score Integration in Simulator**
- Simulator shows Secure Baseline (actual MS Secure Score), Projected and Uplift
- Each finding carries a secure_score_impact value
- Toggling findings updates projected score in real time
- 2 new attack chains: APP-TAKEOVER, SP-PERSIST

**UI Polish**
- Font changed from Syne to Inter — wider legibility, more professional feel
- Richer darker colour palette — removes AI-tool aesthetic
- Card depth with box-shadows, accent stripe on header
- CSS dividers replacing pipe characters in simulator banner
- Tighter typography hierarchy throughout
- Simulator labels: Attack Path Score / Simulated Path Score
- MS Secure Score / MS Projected / MS Uplift

**Performance**
- Get-IdentityMetrics.ps1: bulk role lookup, run time reduced from >300s to ~48s

---

## Where We Are Now

At v1.4 the tool is:
- **48 findings** across 6 modules (Identity, Security/CA, Exchange, Teams, SharePoint, Intune)
- **Full investigation scripts** on every finding
- **Auto-remediation** with rollback on Tier 1 findings
- **Attack simulator** with MS Secure Score integration
- **Professional Word reports** with consultant branding
- **Three authentication methods** — Interactive, App Registration, Certificate
- **Read/write permission separation** for enterprise environments
- **Auto update checker** built in
- **Zero cloud dependency** — runs entirely on the consultant's machine

**Market position:** The most capable free M365 security assessment tool available.
No other free tool combines this level of technical depth with a consultant-ready workflow.

---

## The Road Ahead

### v1.5.0 — 19 June 2026 — Compliance Intelligence
*Research complete, ready to build*

**8-Framework Compliance Mapping across all 48 findings:**

| Framework | Region |
|---|---|
| CIS M365 Foundations v7.0.0 | Global |
| NIST CSF 2.0 | US / Global |
| ISO 27001:2022 Annex A | Global |
| Cyber Essentials v3.3 | 🇬🇧 UK |
| NCSC CAF v4.0 | 🇬🇧 UK Public Sector / CNI |
| SOC 2 CC6/CC7 | 🇺🇸 US / Global SaaS |
| Australian Essential Eight | 🇦🇺 Australia |
| EU NIS2 Article 21 | 🇪🇺 EU |

**Framework Selector**
- Consultant selects which frameworks apply to the client engagement
- All reports, cards, simulator and comparison respect the selection
- UK CE-only client sees only CE content — no irrelevant framework noise
- Consultant internal view always shows all frameworks

**Enhanced Simulator What-If Export**
- Gap count before/after per selected framework
- Per-pillar coverage for CE and Essential Eight
- Findings simulated as fixed — which compliance obligations each one closes
- Findings still open — which gaps remain and why
- Auto-generated: "Fix these N findings to achieve full [Framework] compliance"
- Becomes the client's remediation project brief

**Impact**
- Tool classification upgrades from security scanner to
  multi-framework compliance assessment platform
- UK, US, EU, Australia all covered in one scan
- Every finding now has measurable compliance value, not just security value

---

### v1.6.0 — 17 July 2026 — Defender Workloads

New module covering Microsoft Defender configuration depth:
- Defender for Office 365 configuration
- Defender Antivirus settings (aligned to CIS Intune for Defender AV v1.0.0)
- Defender for Identity signals
- Defender for Endpoint policy coverage
- Attack Surface Reduction rules
- New investigation + remediation scripts for all Defender findings

---

### v1.7.0 — 14 August 2026 — Power Platform

New module covering Power Platform governance:
- Power Apps external sharing controls
- Power Automate connector policies
- Power Platform DLP policies
- Environment security settings
- Guest access to Power Platform

---

### v1.8.0 — 11 September 2026 — Purview / DLP
*End of the open source free tier feature roadmap*

New module covering data governance:
- DLP policies enabled (CIS M365 v7.0.0 — 3.2.1 / 3.2.2 / 3.2.3)
- DLP policies covering Microsoft Teams
- DLP policies for Copilot users
- Sensitivity label policies published (CIS 3.3.1)
- Information Protection configuration
- Insider Risk Management baseline

**At v1.8 the tool covers:**
- 8 assessment modules
- 60+ findings
- 8 compliance frameworks
- 4 global regions (UK, US, EU, Australia)
- Full remediation with approval workflow and rollback
- Professional Word reports with multi-framework gap analysis
- Attack simulation with compliance impact
- Zero cost — free and open source

---

### v2.0.0 — January 2027 — Local Pro
*First monetisation milestone*

**Architecture shift:** Flat session files → SQLite database

**New capabilities:**
- Multi-client portfolio dashboard — manage all client assessments in one place
- Trend tracking — security score and compliance gap count over time per client
- Scheduled assessments via Windows Service / Task Scheduler
- Drift alerts — notify when a previously passing check starts failing
- Azure posture assessment module (CIS Azure Foundations v6.0.0)
- White-label branding per client engagement
- Endpoint hardening module prep (CIS Intune Win10/11, Edge, Office, Defender AV)

**Commercial model:** Free open source + optional one-time Pro licence

**Target audience:** Solo consultants and small MSPs on their own infrastructure

---

### v2.5.0 — June 2027 — SaaS Beta (Invite Only)
*Cloud deployment, first subscribers*

**Architecture shift:** SQLite → PostgreSQL hosted on Azure App Service

**New capabilities:**
- Azure AD authentication — multi-user, team collaboration
- Client self-service portal — clients can view their own reports
- API integrations with PSA/RMM tools (ConnectWise, Autotask, Datto)
- Email/Teams drift alerts without a machine being on
- Always-on scheduled assessments
- Invite-only beta for select MSPs

**Commercial model:** Monthly subscription per MSP (tiered by client count)

---

### v3.0.0 — Q4 2027 — SaaS GA (Full MSP Platform)
*Commercial launch*

**Full MSP platform:**
- Tiered subscription pricing (Starter / Pro / Enterprise)
- White-label reseller programme — MSPs brand it as their own
- Full PSA/RMM API ecosystem
- Combined M365 + Azure posture dashboard
- Endpoint hardening assessments (Windows, Edge, Office, Defender)
- Multi-tenant management — MSPs running 50+ client assessments
- Continuous compliance monitoring — not just point-in-time
- Executive dashboards for client boards
- Managed service enabler — the backbone of an MSP's security offering

**Market classification at v3.0:**
A Cloud Security Posture Management (CSPM) and GRC platform for Microsoft cloud
environments — M365 and Azure — with MSP multi-tenant capability.

Comparable products at this stage: Cynomi, Guardz, Huntress — but with deeper
technical assessment, richer compliance framework coverage, and a proven
open-source user base built over 18 months.

---

## The Numbers at a Glance

| Version | Findings | Modules | Frameworks | Deployment | Model |
|---|---|---|---|---|---|
| v1.0 | 23 | 6 | 0 | Local | Free |
| v1.2 | 30 | 6 | 0 | Local | Free |
| v1.4 | 48 | 6 | 0 | Local | Free |
| v1.5 | 48 | 6 | 8 | Local | Free |
| v1.8 | 60+ | 8 | 8 | Local | Free |
| v2.0 | 60+ | 9 | 8 | Local | Free + Pro |
| v2.5 | 70+ | 10 | 8 | Cloud | Subscription |
| v3.0 | 80+ | 11 | 8 | Cloud | MSP Platform |

---

## Why This Wins

No other tool — free or paid — delivers the full consultant workflow:

1. **Assess** — run against a tenant in 20 minutes, no PS knowledge required
2. **Score** — severity-weighted posture score with MS Secure Score context
3. **Map** — every finding mapped to 8 global compliance frameworks
4. **Simulate** — show the client what attackers can do today and what compliance
   looks like if they fix it
5. **Remediate** — auto-fix with rollback, approval gates, full audit trail
6. **Report** — branded Word report tailored to the client's compliance framework
7. **Compare** — prove improvement at the next engagement
8. **Plan** — What-If export is the client's remediation project brief

All of that. One portable tool. Free.

---

*Document maintained alongside C:\AssetTool — update after each release.*
*Last updated: May 2026*
