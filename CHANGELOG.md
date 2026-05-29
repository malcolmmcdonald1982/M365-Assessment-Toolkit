# Changelog

All notable changes to the M365 Assessment Toolkit are documented here.

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
