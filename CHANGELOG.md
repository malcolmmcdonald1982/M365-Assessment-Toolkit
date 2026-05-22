# Changelog

All notable changes to the M365 Assessment Toolkit are documented here.

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
