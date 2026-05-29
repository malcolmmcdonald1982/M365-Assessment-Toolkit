# Implementation Plan: Simulator Secure Score

**Branch**: `002-simulator-secure-score` | **Date**: 2026-05-29 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/002-simulator-secure-score/spec.md`

## Summary

Add an estimated Microsoft Secure Score display to the Attack Path Simulator, shown
alongside the existing risk score. As the consultant toggles findings on/off, both the
risk score and the estimated Secure Score update in real time. The baseline Secure Score
comes from the actual value collected during assessment (if the Security module ran);
otherwise the display shows an estimate. The calculation is entirely client-side — no
new backend API calls or endpoints are introduced.

## Technical Context

**Language/Version**: Python 3.11+ (`backend.py`), JavaScript ES2020+ (`index.html`)

**Primary Dependencies**: No new dependencies — Flask and plain JS already in place

**Storage**: `secure_score_impact` (int) added to each finding dict returned by
`evaluate_findings()` and stored in session JSON files. Old sessions without this field
default gracefully to impact = 0 (estimation still works, just without per-finding deltas).

**Testing**: Manual — run an assessment with Security & CA module included, open the
simulator, verify both score displays update correctly on toggle.

**Target Platform**: Windows 10/11, localhost browser (existing tool platform)

**Project Type**: Local web-UI security assessment tool — same architecture throughout

**Performance Goals**: Secure Score update MUST be imperceptible (<200ms) — it is a
client-side arithmetic operation with no network call.

**Constraints**:
- No new backend endpoints — calculation happens entirely in the browser
- No new Graph API calls or permissions — display-only feature
- Must degrade gracefully for sessions created before this feature (impact = 0 fallback)
- Projected Secure Score MUST be clamped to [0, 100]

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. Local Execution & Data Sovereignty | ✅ PASS | Pure client-side calculation; no new outbound network calls. |
| II. Read-Only Assessment | ✅ PASS | Display feature only; no writes to tenant. |
| III. Explicit Change Control | ✅ PASS | No remediation scripts added; no tenant writes. |
| IV. Least Privilege | ✅ PASS | No new permissions; reads only data already collected. |
| V. Transparency & Auditability | ✅ PASS | "Estimated" label shown when no actual baseline; approximate nature of values disclosed. |

**Gate result: All principles satisfied. Proceed to Phase 0.**

*Post-design re-check*: No design decisions introduced conflicts. Constitution check remains
fully passed.

## Project Structure

### Documentation (this feature)

```text
specs/002-simulator-secure-score/
├── plan.md                       # This file
├── research.md                   # Phase 0 output
├── data-model.md                 # Phase 1 output
├── quickstart.md                 # Phase 1 output
└── contracts/
    └── simulator-ui-contract.md  # Phase 1 output
```

### Source Code (repository root)

```text
# No new files — two existing files extended in place

backend.py       # Add secure_score_impact to every finding in FINDINGS_LIBRARY;
                 # include it in evaluate_findings() output dict

index.html       # Extend .sim-score-banner HTML with 3 new score blocks
                 # (Secure Baseline, Secure Projected, Secure Delta);
                 # extend renderSimResults() with client-side Secure Score calc;
                 # read baseline from assessmentData
```

**Structure Decision**: Minimal two-file extension. All changes are additive — no existing
logic is removed or restructured. Old sessions continue to work with 0-impact fallback.
