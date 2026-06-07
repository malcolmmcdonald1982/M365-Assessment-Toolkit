# Changelog

All notable changes to the M365 Assessment Toolkit are documented here.

## [1.7.0] - 2026-06-07

### New Findings (6 new — 48 → 54 total)

**On-Premises AD Sync**
- SYNC-001 — Entra Connect Sync Stale (last sync >3h) — High
- SYNC-002 — Federated Authentication Detected (ADFS/PTA attack surface) — Medium

**Guest & B2B Security**
- GUEST-001 — Guest Users Can Invite Other Guests — Medium
- GUEST-002 — Guest Users Have Member-Level Directory Permissions — High
- GUEST-003 — No Guest Access Reviews Configured — Medium
- GUEST-004 — No Cross-Tenant Access Restrictions Configured — Medium

All 6 new findings include: severity justification, effort estimates, full framework mappings (CIS, NIST, ISO, CE, CAF, SOC2, E8, NIS2), and PowerShell investigation scripts.

### New Features

**Potential Breach Cost Estimates**
- Every triggered finding now shows a financial exposure range (e.g. £500K – £5M for Critical)
- Based on IBM Cost of a Data Breach Report 2024 UK averages, by severity band
- Displayed on finding cards in the UI (amber callout)
- Shown as a dedicated "Potential exposure" row in Word finding cards across all report types
- Gives CEOs and boards a financial language anchor for each finding

**Industry Benchmark Comparison**
- Score display now shows how the tenant compares to the industry average (62/100)
- Colour-coded delta: green if above, amber if within ±5, red if below
- Industry benchmark line shown on the Score Trend chart
- Included in the Word assessment report score section
- Source: Microsoft Security Intelligence Report 2024 / IBM Cost of a Data Breach 2024

**GRC Export (CSV)**
- New "GRC Export (CSV)" button in the Findings tab alongside the Compliance Annex export
- Exports all triggered findings as a structured spreadsheet: Finding ID, Title, Severity, Module, Status, Effort, Hours, Breach Cost (low/high), Observed Value, Framework list, Reason/Notes
- BOM-prefixed for Excel compatibility
- Ready to drop into ServiceNow, Archer, Jira, or any GRC platform

**Score Trend Chart**
- New "Score Trend" section in the Compare tab
- Load 2–6 saved session JSON files to plot score over time
- SVG line chart with colour-coded score dots, band zone shading, and industry benchmark line
- Legend shows each session's score, org name, and date
- Fully client-side — no additional backend calls required

**Data Residency Notice**
- "🔒 Fully local — no data leaves your machine" notice in the footer
- Tooltip explains the tool operates entirely locally against your own tenant via Microsoft Graph API
- Addresses the question auditors and compliance officers always ask

### Report Improvements

- Score section now includes a two-column benchmark comparison table (Your score vs Industry average)
- Score bands unified to 5 levels across all report types (Excellent/Good/Fair/Poor/Critical Risk)
- Breach cost added to every finding card in all three Word report types
- Page numbers (Page X of Y) added to footer of all reports (v1.6.0 improvement)
- Consultant email used in footer instead of hardcoded placeholder (v1.6.0 improvement)

### Bug Fixes / Improvements
- `COLOURS.orange` added to report colour palette (was referenced but undefined — caused report generation errors for "Poor" band scores)
- New metrics added to METRIC_DISPLAY for all 7 new identity data points

## [1.6.0] - 2026-06-07

### New Features

**Severity Justification Per Finding**
- Every finding now includes a `severity_reason` field — one clear sentence explaining exactly why that severity level was assigned (e.g. "Critical because legacy protocols bypass MFA entirely…")
- Displayed as an italic callout under the description on each finding card in the UI
- Included in the Word assessment report as a dedicated "Why this severity" row per finding card
- Answers the question consultants and clients always ask: "Why Critical and not High?"

**Remediation Effort Estimates**
- Every finding now carries `effort` (Low / Medium / High) and `effort_hours` (estimated hours) fields
- Displayed as a colour-coded effort badge in each finding card header (green = Low, amber = Medium, red = High)
- Shown in the recommendations table in all Word reports with estimated hours (e.g. "Low (~1h)")
- Allows clients and project managers to plan remediation sprints with realistic time budgets

**Scheduled / Automated Scans**
- New "Scheduled Scans" sidebar panel for configuring unattended recurring assessments
- Uses App Registration credentials (Tenant ID, Client ID, Client Secret) — no interactive login required
- Creates a Windows Task Scheduler task (`M365Scan_<ClientName>`) running weekly, daily, or monthly at 06:00
- Auto-generates `run_scheduled_scan.py` headless runner — calls the scan engine and saves JSON output to the output folder
- `/schedule` and `/schedule/list` API endpoints for task creation and management

### Bug Fixes / Improvements
- Recommendations table effort column now uses live `effort`/`effort_hours` from finding data instead of a hardcoded lookup map
- All 48 findings have been reviewed and updated with accurate severity justifications and effort estimates

---

## [1.5.0] - 2026-06-06

### Bug Fixes (UAT)

- Fixed version comparison logic — update banner no longer shows when running a version ahead of the GitHub latest release
- Fixed compare endpoint — now includes `activeFrameworks` and framework-enriched `findings` in both session objects, enabling the framework compliance delta section
- Fixed framework totals — `fwTotals` now computed dynamically from `FRAMEWORK_MAPPING` at report time instead of hardcoded constants; auto-updates when new workloads are added in future versions
- Fixed simulator framework grid — `minmax(190px)` reduced to `minmax(140px)` so all 8 frameworks fit on one row without NIS2 wrapping to a third line

### New Features

**Multi-Framework Compliance Mapping — all 48 findings mapped to 8 frameworks**

Every finding now carries compliance references across:
- CIS Microsoft 365 Foundations Benchmark v7.0.0 (E3 L1 / E3 L2 / E5 L1 / E5 L2)
- NIST Cybersecurity Framework 2.0
- ISO 27001:2022 Annex A
- Cyber Essentials v3.3 (UK)
- NCSC Cyber Assessment Framework v4.0 (UK)
- SOC 2 Trust Services Criteria CC6/CC7 (US / Global SaaS)
- Australian Essential Eight (ASD 2024)
- EU NIS2 Article 21

**Framework Selector**
- Choose which frameworks are in scope per client engagement
- Set in Assessment Details — controls all badges, simulator gap counters and reports
- UK CE-only clients see only CE content — no irrelevant framework noise
- All/None quick-select buttons
- Selection saved in session file

**Framework Badges on Finding Cards**
- Each triggered finding shows compact framework chips
- Badges respect active framework selection
- Hover tooltip shows full control ID and title
- E5-required controls highlighted in amber

**Scan Progress Bar**
- Live progress bar appears during assessment
- Shows current module name and step count (e.g. Running Security... 2 of 6)
- Disappears automatically on completion

**Hidden Backend Window**
- Python backend now runs silently — no black console window
- Browser opens automatically on launch
- Tool closes cleanly via Stop Tool button

**Stop Tool Button**
- New button in sidebar shuts down backend cleanly
- No need to find and kill Python in Task Manager

### Improvements

- Heartbeat keeps backend alive while browser is open — auto-shuts down 90s after browser closes
- Session files now include `activeFrameworks` and correct `toolVersion`
- Per-module timeouts: Security and Identity extended to 600s (was 300s for all)
- Version now read dynamically from VERSION file — no more hardcoded version strings
- First-scan timing notice added above Run Assessment button and in scan log

## [1.4.0] - 2026-06-05

### New Features

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

*Across all modules (8 new findings)*
- CA-003 — No CA Policy Enforcing MFA for All Users (Critical)
- EXO-006 — Zero-Hour Auto Purge (ZAP) Not Fully Enabled (High)
- TEAMS-003 — Anonymous Users Can Join Meetings (Medium)
- TEAMS-004 — Third-Party Teams Apps Unrestricted (Medium)
- SPO-003 — OneDrive External Sharing Unrestricted (High)
- SPO-004 — Guest Access Expiry Not Configured (Medium)
- MDM-005 — No Mobile Device Compliance Policy (High)
- MDM-006 — Defender for Endpoint Not Integrated with Intune (Medium)

**Simulated Microsoft Secure Score in Attack Simulator**
- Simulator now shows Secure Baseline (your actual MS Secure Score), Secure Projected, and Secure Uplift
- Each finding carries a secure_score_impact value — toggling findings updates the projected score in real time
- Shows the concrete MS Secure Score improvement achievable by fixing open findings
- Requires Security module to have run to populate the baseline

**Full Investigation Script Coverage for all 18 new findings**
- Every new finding includes a ready-to-run PowerShell investigation script
- Scripts surface per-policy detail, credential expiry lists, ZAP status, app permission breakdowns

### Improvements

- Get-IdentityMetrics.ps1 performance optimised — bulk role lookup, capped owner checks, inverted SP/MI enumeration. Run time reduced from >300s to ~48s on large tenants
- ZAP check covers malware, phishing and spam policies separately with fallback for older EXO module versions
- Two new attack chains added to the simulator: APP-TAKEOVER and SP-PERSIST

## [1.3.0] - 2026-05-25

### New Features

**Read/Write Permission Separation**
- Assessment and remediation credentials can now be configured independently
- Default behaviour unchanged — Same as Assessment requires no action from existing users
- Separate mode allows a dedicated write account with minimum required permissions
- Supports Interactive, App Registration and Certificate for both read and write
- Fails safely if write permissions are insufficient — nothing changes in the tenant

**Metric Cards sorted by status**
- Overview metrics now display red → amber → green
- Issues surface immediately without scrolling

### Improvements

- Sidebar reordered to natural consultant workflow — client details, auth, modules, run
- Authentication section renamed to Assessment Authentication for clarity
- Comprehensive README updates — read/write separation guide, minimum permissions tables, troubleshooting section
- Certificate auth NEW badge removed — feature is now established

## [1.2.1] - 2026-05-24

### New Features

**Auto Update Checker**
- Tool silently checks GitHub for a newer version on every startup
- Banner appears at the top of the UI when an update is available
- Update Now button applies the update directly from within the tool — no need to visit GitHub manually
- What's New links to the GitHub releases page so users can see what changed
- Dismiss closes the banner for the session

## [1.2.0] - 2026-05-23

### New Features

**Certificate-Based Authentication**
- Third authentication option added alongside Interactive and App Registration
- User provides Tenant ID, Client ID, and Certificate Thumbprint
- Certificate must be installed in the local Windows certificate store (Current User\My or Local Machine\My)
- Applies to Graph-based modules (Identity, Security, Intune) — Exchange, Teams and SharePoint continue to use interactive login
- No client secret stored in the UI — cleaner for repeat assessments where security policy prohibits stored credentials

**Environment Selector**
- Environment dropdown added to the UI
- Commercial / GCC — single option covering all global commercial tenants and US GCC (both use identical endpoints)
- GCCH and DoD listed as Coming Soon — endpoint switching is built in but not yet validated without access to a government high tenant

**7 New Findings (23 → 30)**
- ID-006 — Risky Users Not Reviewed (High)
- ID-007 — No Emergency Access Account Detected (High)
- SEC-006 — No Microsoft Sentinel Connected (Medium)
- EXO-004 — DMARC Not Configured (High)
- EXO-005 — SPF or DKIM Not Configured (High)
- MDM-003 — No Windows Update Ring Configured (Medium)
- MDM-004 — BitLocker Not Enforced (High)

**Full Investigation Script Coverage**
- All 30 findings now have an Investigate button with a ready-to-run PowerShell script
- Previously 14 findings had no investigation script — all gaps filled
- New scripts cover: SEC-001–005, CA-001–002, EXO-002–003, TEAMS-001–002, SPO-001–002, MDM-002, and all 7 new findings

---

## [1.1.0] - 2026-05-22

### Bug Fixes

**Consultant details not appearing in Word reports**
- generateReport() was sending the raw scan result to the backend without the consultant name, role and email fields entered in the UI
- Fixed by reading those three fields from the DOM at report generation time and merging them into the request payload
- Consultant details now populate correctly in all generated Word reports

### Transparency & Trust

**Minimum role documentation**
- Interactive login section now shows minimum roles required (Global Reader for most modules, Exchange Administrator for Exchange)
- Removes ambiguity for users without Global Admin access

**Read-only banner**
- Green notice added directly above Run Assessment button confirming assessment is read-only
- Makes clear that no tenant changes occur during scanning — only explicit remediation actions write to the tenant

**AI disclosure**
- Footer added across the full UI showing version, MIT licence, GitHub link and AI development disclosure
- Addresses community questions about development transparency

**Version bump**
- Tool version updated to 1.1.0 in status endpoint and saved session files

---

## [1.0.0] - 2026-05-05

### Initial Release

**Assessment Engine**
- 23 findings across 6 modules: Identity, Security/CA, Exchange, Teams, SharePoint, Intune
- Dual authentication: Interactive Login and App Registration
- Severity-weighted scoring model (Critical/High/Medium/Low)
- Session auto-save and reload without re-running scripts

**Remediation**
- 9 Tier 1 auto-fix findings with paired rollback scripts
- Pre-remediation safety checks (dependency scan before changes)
- Snapshot saved before every change for full rollback capability
- Approval gate with customisable fields (approver, change reference, date)
- Session-level and individual approval recording
- Manual PowerShell commands displayed on each remediation card
- Remediation log saved per engagement

**Reports**
- Assessment Report: findings, score, recommendations, metrics appendix
- Remediation Report: before/after score, changes made, approval details, open findings
- Comparison Report: two-assessment side-by-side with resolved/new/still open
- Consultant branding fields (name, role, email)
- Word (.docx) and print-to-PDF output

**Simulator**
- 7 attack chain models: BEC, Account Takeover, Privilege Escalation, OAuth Abuse,
  Data Exfiltration, Ransomware, Invisible Persistence
- Toggle findings to simulate fixes — live score and chain status update
- Risk narrative updates in real time
- Export What-If report

**Comparison**
- Load two saved sessions and compare score, findings, metrics
- Resolved / New / Still Open / Improved categorisation
- Downloadable comparison Word report

**Packaging**
- One-line installer with prerequisite detection and auto-install
- Update script (preserves all data)
- Uninstall script (optional data backup)
