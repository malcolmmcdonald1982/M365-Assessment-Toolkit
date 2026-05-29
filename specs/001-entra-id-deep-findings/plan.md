# Implementation Plan: Entra ID Deep Findings

**Branch**: `001-entra-id-deep-findings` | **Date**: 2026-05-29 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-entra-id-deep-findings/spec.md`

## Summary

Extend the Identity & MFA module to surface deep Entra ID workload identity findings
covering app registrations (privileges, expiring credentials, ownership), service
principals (high-privilege directory roles), and managed identities (high-privilege
directory roles). Ten new findings are added to the existing findings library, scoring
model, investigation scripts, and attack chain simulation. Changes are confined to three
existing files: the PowerShell assessment script, the Python backend, and the frontend
investigation ID set.

## Technical Context

**Language/Version**: Python 3.11+ (`backend.py`), PowerShell 5.1+/7.x (`scripts/`),
JavaScript ES2020+ (`index.html`)

**Primary Dependencies**: Microsoft.Graph PowerShell module v7.x (already installed);
Flask + flask-cors (already installed); no new dependencies required

**Storage**: Metrics collected by PowerShell script → JSON stdout → Flask in-memory dict
→ browser session (existing pipeline, unchanged)

**Testing**: Manual integration testing against a real tenant with known-configuration
app registrations and service principal role assignments; no automated test framework
exists in this project

**Target Platform**: Windows 10/11 (PowerShell + Python 3.11+ already installed as
prerequisites)

**Project Type**: Local desktop security assessment tool — Flask backend serving a
single-page HTML frontend via `http://localhost:5000`

**Performance Goals**: The Identity & MFA module (including all new queries) MUST
complete within 3 minutes for tenants with up to 500 app registrations

**Constraints**:
- 300-second subprocess timeout enforced by `run_script()` in `backend.py` — the
  extended PowerShell script MUST complete within this limit
- All new Graph queries MUST reuse the Graph SDK session established during
  authentication at the top of `Get-IdentityMetrics.ps1` — no second login prompt
- No new Graph API application permissions are required: `Application.Read.All`,
  `Directory.Read.All`, and `RoleManagement.Read.Directory` already cover all needed
  endpoints (confirmed in research.md)

**Scale/Scope**: Single-tenant per assessment run; the `-All` flag in Graph PowerShell
cmdlets handles transparent pagination for tenants with more than 100 objects

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Local Execution & Data Sovereignty | ✅ PASS | All new Graph queries run locally. No new outbound network calls beyond existing Microsoft Graph endpoint. |
| II. Read-Only Assessment | ✅ PASS | All new queries are GET operations. No writes to the tenant are introduced. |
| III. Explicit Change Control | ✅ PASS | No remediation scripts in this feature per spec assumption. No tenant writes introduced. |
| IV. Least Privilege | ✅ PASS | No new permissions required. Existing `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory` cover all needed queries. |
| V. Transparency & Auditability | ✅ PASS | All findings map to documented real attack paths. No telemetry introduced. |

**Gate result: All five principles satisfied. No violations. Proceed to Phase 0.**

*Post-design re-check*: No design decisions in Phase 1 introduced any conflicts.
Constitution check remains fully passed.

## Project Structure

### Documentation (this feature)

```text
specs/001-entra-id-deep-findings/
├── plan.md                        # This file
├── research.md                    # Phase 0 output
├── data-model.md                  # Phase 1 output
├── quickstart.md                  # Phase 1 output
└── contracts/
    └── finding-contracts.md       # Phase 1 output
```

### Source Code (repository root)

```text
# No new files — three existing files are extended in place

scripts/
└── Get-IdentityMetrics.ps1       # Extended: app reg, SP, MI queries appended;
                                  # new metric keys added to JSON output object

backend.py                        # Extended: 10 entries in FINDINGS_LIBRARY,
                                  # 10 entries in METRIC_DISPLAY,
                                  # 10 entries in INVESTIGATION_SCRIPTS,
                                  # 2 entries in ATTACK_CHAINS

index.html                        # 1-line change: INVESTIGATE_IDS set updated
                                  # to include all 10 new ENTRA-xxx IDs
```

**Structure Decision**: Minimal in-place extension of three existing files. No new source
files, no new module entry in `MODULE_SCRIPTS`, no new module item in the frontend module
list. New findings appear under the existing ENTRA / Identity & MFA module, consistent
with the spec assumption to keep the module count at six.
