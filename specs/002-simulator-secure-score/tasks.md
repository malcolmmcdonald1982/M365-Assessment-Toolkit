---
description: "Task list for Simulator Secure Score"
---

# Tasks: Simulator Secure Score

**Input**: Design documents from `specs/002-simulator-secure-score/`

**Prerequisites**: plan.md ✅ spec.md ✅ research.md ✅ data-model.md ✅ contracts/simulator-ui-contract.md ✅

**Tests**: No automated tests — manual validation per quickstart.md.

**Organization**: 10 tasks across 4 phases. This is a small 2-file change:
`backend.py` (impact values + evaluate_findings) and `index.html` (HTML + CSS + JS).
US1 and US2 share the same implementation — US2 is the "actual baseline" variant of
the same `hasActual` logic introduced in US1.

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1 or US2 (maps to spec.md user stories)

---

## Phase 1: Setup

**Purpose**: Locate exact insertion points before making any edits.

- [X] T001 [P] Read `backend.py` lines 37–200 and identify: (a) the last finding entry in `FINDINGS_LIBRARY` (just before the closing `]`), (b) the `triggered.append({...})` call inside `evaluate_findings()`, and (c) confirm `secure_score_impact` does not already exist on any finding.

- [X] T002 [P] Read `index.html` lines 789–814 (`.sim-score-banner`) and lines 1867–1885 (`renderSimResults()`) and 1791–1804 (`initSimulator()`) to confirm DOM element IDs and confirm `simSSBaseline`, `simSSProjected`, `simSSDelta` do not already exist.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add `secure_score_impact` to backend.py so the field flows into session data.
Both user stories depend on this.

**⚠️ CRITICAL**: T008 (frontend calculation) cannot be validated until T004 is complete
and a fresh assessment is run.

- [X] T003 Add `"secure_score_impact": N` field to every finding entry in `FINDINGS_LIBRARY` in `backend.py`. Use the exact values from `research.md` §3. All 40 findings must be updated. Findings without a Secure Score mapping use value `0`. Example for existing field: `{"id":"CA-001",...,"secure_score_impact": 15}`.

- [X] T004 Add `"secure_score_impact": f.get("secure_score_impact", 0)` to the `triggered.append({...})` dict inside `evaluate_findings()` in `backend.py`, immediately after the `"observed_value": value` line. This ensures the field is included in session JSON and the `/run` response.

**Checkpoint**: Restart the backend and run a fresh assessment — the `findings` array in the response should now include `secure_score_impact` on each triggered finding.

---

## Phase 3: User Story 1 — Dual Score Display (Priority: P1) 🎯 MVP

**Goal**: Show estimated Secure Score alongside risk score in the simulator, updating
as findings are toggled. Includes US2 (baseline vs projected comparison) since both
modes are controlled by the same `hasActual` flag.

**Independent Test**: Run any assessment, open the Simulator tab. Verify 3 new score
blocks appear (Secure Baseline, Secure Projected, Secure Uplift). Toggle a finding and
verify Secure Projected increases and Secure Uplift updates. See quickstart.md.

### Implementation for User Story 1 (and US2)

- [X] T005 [P] [US1] Add `.sim-score-separator` div and 3 new `.sim-score-block` divs to `.sim-score-banner` in `index.html`, inserted after the existing `simBrokenChains` block (line ~812). Follow the exact HTML from `contracts/simulator-ui-contract.md §1`:
  - A separator `<div class="sim-score-separator">|</div>`
  - Block with label "Secure Baseline" and `id="simSSBaseline"`
  - Block with label "Secure Projected", `id="simSSProjected"`, and a child `<div class="sim-score-sub" id="simSSEstLabel" style="display:none;">Estimated</div>`
  - Block with label "Secure Uplift" and `id="simSSDelta"`

- [X] T006 [US1] Add two new CSS rules to the stylesheet section in `index.html`. Add `.sim-score-sub` and `.sim-score-separator` exactly as specified in `contracts/simulator-ui-contract.md §1`. Place them adjacent to the existing `.sim-score-block`, `.sim-score-label`, `.sim-score-val` rules.

- [X] T007 [US1] Add Secure Score baseline initialisation block to `initSimulator()` in `index.html`, inserted after the existing line that sets `simScoreCurrent` (line ~1800). Code from `contracts/simulator-ui-contract.md §3`:
  - Read `assessmentData?.allMetrics?.secure_score_percentage`, set `simSSBaseline` text
  - Show or hide `simSSEstLabel` based on whether the value is null

- [X] T008 [US1] Add Secure Score calculation and display block to `renderSimResults()` in `index.html`, inserted after the existing block that updates `simScoreDiff` (line ~1879). Code from `contracts/simulator-ui-contract.md §2`:
  - Compute `baseline` from `assessmentData?.allMetrics?.secure_score_percentage ?? 0`
  - Compute `uplift` = sum of `secure_score_impact || 0` for all findings where `simState[f.id] === false`
  - Compute `projected = Math.min(100, baseline + uplift)` and `delta = projected - baseline`
  - Update `simSSBaseline`, `simSSProjected` (with colour coding), `simSSDelta`, `simSSEstLabel`

**Checkpoint**: US1 and US2 independently testable — open simulator, verify 3 new blocks,
toggle findings, verify scores update. Test estimation mode (Security module not run) and
baseline mode (Security module run). No existing score blocks should be affected.

---

## Phase 4: Polish & Cross-Cutting Concerns

- [X] T009 Manual regression check per `quickstart.md`: (a) full test with Security module, (b) estimation-only test without Security module, (c) old-session backward compatibility test — load a pre-feature session and verify no console errors and `+0 pts` uplift appears gracefully.

- [X] T010 Verify the "Export What-If Report" (`exportSimReport`) still generates correctly and the new Secure Score values appear in the exported HTML report. No code change expected — the new DOM elements should render automatically.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately, both tasks parallel
- **Foundational (Phase 2)**: T003 → T004 (sequential; T004 references field added in T003)
- **US1/US2 (Phase 3)**: T005/T006 depend on T002 (setup review); T007 depends on T005;
  T008 depends on T006, T007, and T004 (needs backend field in session data)
- **Polish (Phase 4)**: Depends on all Phase 3 tasks complete

### Cross-File Parallel Opportunity

After Setup, two independent work streams:

```text
Stream A (backend.py): T003 → T004
Stream B (index.html): T005 → T006 → T007

Both streams feed into: T008 (requires T004 + T007)
```

Stream A and Stream B can run simultaneously since they touch different files.

---

## Parallel Example

```text
# After T001 and T002 complete, start both streams simultaneously:

Stream A: "Add secure_score_impact to FINDINGS_LIBRARY in backend.py" (T003)
          → "Add field to evaluate_findings() dict in backend.py" (T004)

Stream B: "Add 3 score blocks to .sim-score-banner in index.html" (T005)
          → "Add .sim-score-sub and .sim-score-separator CSS in index.html" (T006)
          → "Add initSimulator() baseline block in index.html" (T007)

# T008 starts only after BOTH T004 and T007 are complete
```

---

## Implementation Strategy

### MVP (Single Pass — all tasks are small)

This feature is compact enough for a single delivery:

1. T001 + T002 (setup, 5 min)
2. T003 → T004 (backend, 15 min — 40 impact values + 1 dict line)
3. T005 → T006 → T007 → T008 (frontend, 20 min)
4. T009 + T010 (validation, 10 min)

Total estimated effort: ~50 minutes.

---

## Notes

- [P] tasks = different files or truly independent (T001 and T002 review different areas)
- All 40 findings in research.md §3 need impact values in T003 — use the table exactly
- `simFindings` already has `secure_score_impact` after a fresh assessment run; old sessions default to 0 via `|| 0`
- The `simSSEstLabel` sub-label is controlled by `display:none` / `display:block` — no class toggling needed
- Projected score colour coding follows the same thresholds as `simScoreSim`: green ≥70, warning ≥50, red <50
