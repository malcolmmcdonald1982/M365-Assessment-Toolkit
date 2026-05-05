# Changelog

All notable changes to the M365 Assessment Toolkit are documented here.

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
