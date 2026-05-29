<!--
SYNC IMPACT REPORT
==================
Version change: [template] → 1.0.0
Bump rationale: Initial ratification — all placeholder tokens replaced with concrete project
  content for the first time. Treating as a 1.0.0 release (no prior versioned baseline).

Modified principles:
  [PRINCIPLE_1_NAME] → I. Local Execution & Data Sovereignty
  [PRINCIPLE_2_NAME] → II. Read-Only Assessment
  [PRINCIPLE_3_NAME] → III. Explicit Change Control
  [PRINCIPLE_4_NAME] → IV. Least Privilege
  [PRINCIPLE_5_NAME] → V. Transparency & Auditability

Added sections:
  "Security & Privacy Standards" (Section 2)
  "Development & Release Standards" (Section 3)

Removed sections: none

Templates checked:
  ✅ .specify/templates/plan-template.md — Constitution Check placeholder is generic
     and compatible with these principles; no update required.
  ✅ .specify/templates/spec-template.md — Scope/requirements structure is
     compatible; no update required.
  ✅ .specify/templates/tasks-template.md — Task phases and categories are
     compatible; no update required.
  ✅ .specify/templates/commands/ — No command template files present; skipped.
  ✅ README.md — Source of truth for all principles defined here; no update required.

Deferred TODOs: none — all placeholders resolved.
-->

# M365 Assessment Toolkit Constitution

## Core Principles

### I. Local Execution & Data Sovereignty

All assessment data MUST remain on the local machine. The tool MUST NOT transmit tenant
data, credentials, scan results, assessment sessions, or any user content to external
servers at any point during assessment or remediation.

The tool has no cloud component, no backend server, and no third-party data flow — only
the local machine and Microsoft's APIs. The sole permitted outbound network calls are:

- Direct connections to Microsoft's published APIs (Graph, Exchange, Teams, SharePoint)
- A read-only version check against the project's public GitHub raw VERSION file
  (no tenant data, no credentials, no analytics transmitted)

Any future feature that requires outbound network calls beyond these two categories MUST
be explicitly approved as a constitutional amendment before implementation.

### II. Read-Only Assessment

The assessment phase MUST be strictly read-only. The tool MUST NOT write to, modify, or
delete any configuration or data in the M365 tenant during assessment execution.

Write operations to the tenant are ONLY permitted during explicitly user-initiated
remediation. Remediation MUST NOT begin automatically as a side effect of assessment.

### III. Explicit Change Control

Every remediation action MUST require explicit user approval before execution. No change
may be applied to a live tenant silently or automatically.

Before every write operation, a snapshot of the current tenant configuration MUST be
captured. Rollback MUST be available for every applied change via a corresponding rollback
script. A remediation script without a rollback script is not considered complete.

### IV. Least Privilege

Authentication and authorization MUST follow the principle of least privilege at all
times.

- The minimum role or permission set that covers the required operation MUST be used.
- Assessment (read) and remediation (write) credentials are logically separate and MUST
  be independently configurable via the Remediation Authentication sidebar option.
- The documented minimum permission sets in README.md define the ceiling for what the
  tool will request — permissions MUST NOT be expanded without a constitutional amendment.

### V. Transparency & Auditability

All code is open source and publicly auditable. Security findings MUST map to real,
demonstrated attack paths — not to configuration compliance alone or Microsoft Secure
Score equivalence.

The tool MUST include zero telemetry, analytics, or usage tracking of any kind. No
information about usage patterns, tenant identifiers, user identity, or assessment results
may be collected, aggregated, or transmitted.

## Security & Privacy Standards

- Credentials entered into the tool MUST NOT be written to disk by the tool itself.
  Interactive login credentials are handled entirely by the underlying PowerShell modules
  (Microsoft.Graph, ExchangeOnlineManagement, MicrosoftTeams, SharePoint). App
  Registration client secrets and certificate thumbprints are held in memory for the
  session only.
- Assessment results are saved locally to `C:\M365 Assessment Toolkit\output\` only.
  No results leave the local machine except by explicit user action outside the tool.
- For client engagements, a Data Processing Agreement MUST be in place before running
  assessments against a client tenant. The tool does not enforce this — it is an
  operational responsibility of the user.
- Certificate-based authentication is the RECOMMENDED method for recurring assessments
  where security policy prohibits stored client secrets.

## Development & Release Standards

- All remediation PowerShell scripts MUST have a corresponding rollback script in
  `remediation/`. A pull request that adds a `Remediate-*.ps1` without a matching
  `Rollback-*.ps1` MUST NOT be merged.
- Versioning follows semantic versioning (MAJOR.MINOR.PATCH) recorded in the `VERSION`
  file. The auto-update banner reads this file; the format MUST NOT change.
- The auto-update mechanism MUST remain read-only and require explicit user approval.
  Silent or automatic updates are prohibited.
- PowerShell scripts MUST be idempotent where technically feasible. Running a script twice
  MUST NOT produce a worse outcome than running it once.
- The one-line installer (`install.ps1`) MUST install all prerequisites and create the
  desktop shortcut without requiring manual steps beyond running it as Administrator.

## Governance

This constitution supersedes all other development practices, conventions, and informal
agreements within this project.

**Amendment procedure**: Any amendment requires (1) a documented description of the
proposed change, (2) an explicit rationale, (3) an impact assessment against existing
features and scripts, and (4) a version bump to `CONSTITUTION_VERSION` per the versioning
policy below. Amendments are recorded via a Sync Impact Report HTML comment prepended to
this file.

**Versioning policy**:
- MAJOR: Backward-incompatible governance changes — principle removal, redefinition, or
  permission model changes that invalidate existing scripts.
- MINOR: New principle, new mandatory section, or materially expanded guidance that adds
  new obligations.
- PATCH: Clarifications, wording improvements, typo fixes, or non-semantic refinements
  that do not change obligations.

**Compliance review**: All pull requests and code reviews MUST verify compliance with
the five Core Principles. Any complexity that appears to violate a principle MUST be
explicitly justified in the PR description. Unjustified violations are grounds for
blocking a merge.

**Runtime guidance**: See `CLAUDE.md` for runtime development guidance and `README.md`
for the authoritative permissions reference.

**Version**: 1.0.0 | **Ratified**: 2026-05-29 | **Last Amended**: 2026-05-29
