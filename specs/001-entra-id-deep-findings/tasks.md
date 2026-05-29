---
description: "Task list for Entra ID Deep Findings"
---

# Tasks: Entra ID Deep Findings

**Input**: Design documents from `specs/001-entra-id-deep-findings/`

**Prerequisites**: plan.md ✅ spec.md ✅ research.md ✅ data-model.md ✅ contracts/finding-contracts.md ✅

**Tests**: No automated test tasks — manual integration testing via quickstart.md.

**Organization**: Tasks are grouped by user story to enable independent implementation
and testing. All three user stories extend the same three files; the Foundation phase
establishes shared code that all stories depend on.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Exact file paths included in all implementation tasks

---

## Phase 1: Setup

**Purpose**: Confirm integration points before any changes are made

- [x] T001 [P] Read scripts/Get-IdentityMetrics.ps1 and identify: (a) the end of the authentication block (after `Connect-MgGraph`), (b) the `$result = @{...}` output object at the bottom, and (c) any existing permission-related variables to reuse
- [x] T002 [P] Read backend.py lines 37–234 and identify insertion points for: (a) FINDINGS_LIBRARY list end, (b) METRIC_DISPLAY dict end, (c) `count_good_zero` set inside `format_metric()`, (d) INVESTIGATION_SCRIPTS dict end, (e) ATTACK_CHAINS list end

---

## Phase 2: Foundational (Blocking Prerequisites for All User Stories)

**Purpose**: Add shared lookup tables and metric key scaffolding to the PowerShell script.
All three user stories depend on these completing first.

**⚠️ CRITICAL**: No user story implementation can begin until T003–T005 are complete.

- [x] T003 Add `$HighPrivPermissions` hashtable to scripts/Get-IdentityMetrics.ps1, inserted after the auth block. The hashtable maps permission name (string) → risk level ("Critical" or "High"). Include all 22 permissions from research.md §2. Add a comment `# Entra ID Deep Findings — shared lookup tables`.

- [x] T004 Add `$PrivSPIds` role membership lookup block to scripts/Get-IdentityMetrics.ps1, inserted after the `$HighPrivPermissions` definition. Query all 10 high-privilege directory roles from research.md §6, collect all member ObjectIds into `$PrivSPIds` hashtable (ObjectId → RoleName). Wrap in `try { } catch { }` so a missing role does not abort the script.

- [x] T005 Add all 10 new metric keys with default value `0` to the `$result = @{...}` output object at the bottom of scripts/Get-IdentityMetrics.ps1 (before `ConvertTo-Json`). Keys from data-model.md: `high_priv_app_reg_count`, `expiring_cred_30d_count`, `expiring_cred_90d_count`, `expired_cred_count`, `never_expire_cred_count`, `unowned_app_reg_count`, `multitenant_app_reg_count`, `implicit_grant_app_count`, `priv_service_principal_count`, `priv_managed_identity_count`.

**Checkpoint**: Foundation complete — all three user story blocks can now be added to the script, and backend changes can proceed in parallel.

---

## Phase 3: User Story 1 — App Registration Risk Review (Priority: P1) 🎯 MVP

**Goal**: Surface 8 findings covering app registration permissions, credential health,
ownership, multi-tenant exposure, and implicit grant flow.

**Independent Test**: Run Identity & MFA module against a tenant with at least one
app registration. Verify ENTRA-001 through ENTRA-008 findings appear in the dashboard
when conditions are met, and show as not-triggered when conditions are not met.
See quickstart.md for tenant setup steps.

### Implementation for User Story 1

- [x] T006 [US1] Add app registration query block to scripts/Get-IdentityMetrics.ps1, inserted before the `$result` output object. Block must:
  - Call `Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials,Web,SignInAudience -ErrorAction SilentlyContinue`
  - For each app: check `PasswordCredentials` and `KeyCredentials` for expired, expiring (≤30d), expiring (31–90d), and never-expire credentials (endDateTime is null)
  - Check `Web.ImplicitGrantSettings.EnableIdTokenIssuance` and `EnableAccessTokenIssuance` for implicit grant
  - Check `SignInAudience` for multi-tenant (`AzureADMultipleOrgs` or `AzureADandPersonalMicrosoftAccount`)
  - For high-priv check: get the Microsoft Graph service principal once (`appId eq '00000003-0000-0000-c000-000000000000'`), build an AppRoleId→Permission name map, then for each app call `Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue` and check its app role assignments against `$HighPrivPermissions`
  - Populate: `$high_priv_app_reg_count`, `$expiring_cred_30d_count`, `$expiring_cred_90d_count`, `$expired_cred_count`, `$never_expire_cred_count`, `$implicit_grant_app_count`, `$multitenant_app_reg_count`
  - Track high-risk app IDs in `$RiskyAppIds` list (for the owner check in T007)
  - Wrap entire block in `try { } catch { }` — on failure, all counts remain at 0

- [x] T007 [US1] Add owner check block to scripts/Get-IdentityMetrics.ps1, inserted immediately after the T006 app registration block. Block must:
  - If `$RiskyAppIds.Count -le 200`: check all app registrations for missing owners
  - If `$RiskyAppIds.Count -gt 200`: check only apps in `$RiskyAppIds` (performance cap per research.md §7)
  - For each app ID: call `Get-MgApplicationOwner -ApplicationId $id -ErrorAction SilentlyContinue`; increment `$unowned_app_reg_count` if owner count is 0
  - Update `$result` output key `unowned_app_reg_count`
  - Wrap in `try { } catch { }`

- [x] T008 [P] [US1] Add 8 new entries (ENTRA-001 through ENTRA-008) to `FINDINGS_LIBRARY` in backend.py, inserted after the last existing finding in the list. Use the finding catalogue from data-model.md for IDs, metrics, severities. Write full `description` and `recommendation` text for each finding, consistent in length and style with existing entries. Use `lambda v: isinstance(v, (int, float)) and v > 0` as the threshold for all 8.

- [x] T009 [P] [US1] Add 8 new entries to `METRIC_DISPLAY` in backend.py (one per metric key from data-model.md Table "METRIC_DISPLAY Entries"). Format is `"{}"`  for all 8. Add all 8 new count keys to the `count_good_zero` set inside `format_metric()` (same section as `"high_privilege_app_count"`).

- [x] T010 [P] [US1] Add ENTRA-001 through ENTRA-008 investigation scripts to `INVESTIGATION_SCRIPTS` dict in backend.py. Each entry requires `title`, `description`, and `script` (a multiline PowerShell string using `r"""`). Scripts must: connect with `Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome`, query the relevant entity, display results in `Format-Table -AutoSize`, export to a timestamped CSV, and call `Disconnect-MgGraph`. Use existing scripts (ID-001..ID-007) as style reference.

- [x] T011 [US1] Add `APP-TAKEOVER` entry to `ATTACK_CHAINS` list in backend.py. Use the contract from contracts/finding-contracts.md: `requires: ["ENTRA-001", "ENTRA-002"]`, severity `critical`. Write 5 concrete attack steps and an impact statement consistent with existing chain entries.

**Checkpoint**: User Story 1 independently testable — run Identity module, verify 8 ENTRA app reg finding cards appear with correct severity and Investigate buttons.

---

## Phase 4: User Story 2 — Service Principal Privilege Review (Priority: P2)

**Goal**: Surface ENTRA-009, identifying service principals assigned to high-privilege
directory roles and linking them to the SP-PERSIST attack chain.

**Independent Test**: Run Identity module against a tenant where at least one service
principal holds the Application Administrator role. Verify ENTRA-009 appears as a
Critical finding with a working investigation script.

### Implementation for User Story 2

- [x] T012 [US2] Add service principal role check block to scripts/Get-IdentityMetrics.ps1, inserted after the T007 owner check block. Block must:
  - Call `Get-MgServicePrincipal -Filter "servicePrincipalType eq 'Application'" -All -Property Id,DisplayName,ServicePrincipalType -ErrorAction SilentlyContinue`
  - For each SP: check if `$PrivSPIds.ContainsKey($sp.Id)` (uses lookup table from T004)
  - Count matching SPs into `$priv_service_principal_count`
  - Wrap in `try { } catch { }`

- [x] T013 [P] [US2] Add ENTRA-009 entry to `FINDINGS_LIBRARY` in backend.py. Severity: critical. Metric: `priv_service_principal_count`. Description and recommendation must explain the service-principal-as-backdoor attack path.

- [x] T014 [P] [US2] Add `priv_service_principal_count` to `METRIC_DISPLAY` in backend.py and to the `count_good_zero` set in `format_metric()`.

- [x] T015 [P] [US2] Add ENTRA-009 investigation script to `INVESTIGATION_SCRIPTS` in backend.py. Script must query all directory roles, retrieve members, filter for service principal members (not users), and output a table showing role name, SP display name, and SP type. Export to CSV.

- [x] T016 [US2] Add `SP-PERSIST` entry to `ATTACK_CHAINS` in backend.py. Use the contract from contracts/finding-contracts.md: `requires: ["ENTRA-009"]`, severity `high`. Write 5 attack steps.

**Checkpoint**: User Stories 1 AND 2 independently testable — ENTRA-009 finding and SP-PERSIST attack chain active when conditions met.

---

## Phase 5: User Story 3 — Managed Identity Privilege Review (Priority: P3)

**Goal**: Surface ENTRA-010, identifying managed identities assigned to high-privilege
directory roles.

**Independent Test**: Run Identity module against a tenant where at least one managed
identity holds a privileged directory role. Verify ENTRA-010 appears as a High finding
with a working investigation script.

### Implementation for User Story 3

- [x] T017 [US3] Add managed identity role check block to scripts/Get-IdentityMetrics.ps1, inserted after the T012 service principal block. Block must:
  - Call `Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'" -All -Property Id,DisplayName,ServicePrincipalType -ErrorAction SilentlyContinue`
  - For each MI: check `$PrivSPIds.ContainsKey($mi.Id)`
  - Count into `$priv_managed_identity_count`
  - Wrap in `try { } catch { }`

- [x] T018 [P] [US3] Add ENTRA-010 entry to `FINDINGS_LIBRARY` in backend.py. Severity: high. Metric: `priv_managed_identity_count`. Description must explain managed identity privilege escalation risk.

- [x] T019 [P] [US3] Add `priv_managed_identity_count` to `METRIC_DISPLAY` in backend.py and to the `count_good_zero` set in `format_metric()`.

- [x] T020 [P] [US3] Add ENTRA-010 investigation script to `INVESTIGATION_SCRIPTS` in backend.py. Script must: query managed identity service principals, cross-reference against directory roles, output table with MI name, type (SystemAssigned/UserAssigned), and role name. Export to CSV.

**Checkpoint**: All three user stories independently testable.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final wiring and validation across all three stories.

- [x] T021 Update `INVESTIGATE_IDS` constant in `index.html` at line ~1305. Add all 10 new IDs: `'ENTRA-001','ENTRA-002','ENTRA-003','ENTRA-004','ENTRA-005','ENTRA-006','ENTRA-007','ENTRA-008','ENTRA-009','ENTRA-010'` to the existing `new Set([...])` call. This enables the Investigate button on all 10 new finding cards.

- [ ] T022 End-to-end manual validation per quickstart.md: run Identity & MFA module, verify all 10 ENTRA-xxx findings appear when conditions are met, verify no false positives on a clean tenant, verify Investigate buttons work for all 10, verify attack simulation shows APP-TAKEOVER and SP-PERSIST chains.

- [ ] T023 Verify the generated Assessment Report (Word document via generate-report.js) includes ENTRA-xxx findings. Download a report from a session containing ENTRA findings and confirm the findings section is populated correctly.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — read-only review tasks, start immediately
- **Foundational (Phase 2)**: Depends on Setup — T003/T004/T005 are sequential within this phase
- **User Stories (Phase 3–5)**: All depend on Foundational completion
  - US1 (Phase 3): Start after T005 complete
  - US2 (Phase 4): Start after T005 complete; T004 lookup table required
  - US3 (Phase 5): Start after T005 complete; T004 lookup table required
  - US2 and US3 can proceed in parallel after Foundation
- **Polish (Phase 6)**: Depends on all user stories complete

### Within Each User Story

- Script changes (T006, T012, T017) MUST complete before end-to-end testing
- Backend changes (T008–T011, T013–T016, T018–T020) can run in parallel with script changes
- Each user story MUST be independently validated before starting the next

### Parallel Opportunities

Within Phase 3 (US1), after T006 completes:
- T007 depends on T006 (uses `$RiskyAppIds`)
- T008, T009, T010, T011 all touch backend.py — run sequentially, but independent of T006/T007 (different file)

Within Phase 4 (US2):
- T012 (script) can run in parallel with T013, T014, T015, T016 (backend) since different files

Within Phase 5 (US3):
- T017 (script) can run in parallel with T018, T019, T020 (backend) since different files

---

## Parallel Example: User Story 2

```text
# After Foundation complete, start these simultaneously:

Task A (script): "Add SP role check block in scripts/Get-IdentityMetrics.ps1" (T012)

Task B (backend): "Add ENTRA-009 to FINDINGS_LIBRARY, METRIC_DISPLAY, count_good_zero in backend.py" (T013, T014)
Task C (backend): "Add ENTRA-009 investigation script to INVESTIGATION_SCRIPTS in backend.py" (T015)
Task D (backend): "Add SP-PERSIST attack chain to ATTACK_CHAINS in backend.py" (T016)

# B, C, D can all start before A completes (different file)
# All four must complete before US2 checkpoint validation
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001, T002)
2. Complete Phase 2: Foundation (T003–T005) — CRITICAL, blocks all stories
3. Complete Phase 3: User Story 1 (T006–T011)
4. Complete T021 (INVESTIGATE_IDS update for ENTRA-001..008)
5. **STOP and VALIDATE**: Run Identity module, verify 8 findings + APP-TAKEOVER chain
6. Demo or deploy if validated

### Incremental Delivery

1. Foundation → US1 → Validate (8 findings, 1 attack chain) → Ship
2. Add US2 → Validate (ENTRA-009, SP-PERSIST) → Ship
3. Add US3 → Validate (ENTRA-010) → Final polish → Ship

---

## Notes

- [P] tasks = different files or different non-dependent sections
- [Story] label maps to spec.md user stories US1/US2/US3
- All script changes go to one file: `scripts/Get-IdentityMetrics.ps1`
- All backend changes go to one file: `backend.py`
- Frontend change is one line in `index.html`
- Wrap ALL new PowerShell blocks in `try { } catch { }` — errors MUST default to 0, not abort the script
- Investigation scripts use `Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory" -NoWelcome`
- Performance target: Identity module ≤3 minutes for 500 app registrations (see research.md §8)
