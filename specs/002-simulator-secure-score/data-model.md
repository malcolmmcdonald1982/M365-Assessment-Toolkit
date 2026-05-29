# Data Model: Simulator Secure Score

**Feature**: 002-simulator-secure-score
**Date**: 2026-05-29

## New Field: `secure_score_impact` on Finding

Added to every entry in `FINDINGS_LIBRARY` in `backend.py`:

| Field | Type | Range | Description |
|-------|------|-------|-------------|
| `secure_score_impact` | `int` | 0–25 | Approximate Microsoft Secure Score points gained by remediating this finding. 0 for findings that do not map to a Secure Score action. |

This field is included in the `evaluate_findings()` output and therefore in:
- The `/run` endpoint response (`findings` array)
- All new session JSON files (`output/Session_*.json`)
- The `/findings-library` endpoint response

Old session files do not have this field. The frontend defaults to `0` via
`f.secure_score_impact || 0`.

---

## Runtime State (frontend only — not persisted)

| Variable | Type | Source | Description |
|----------|------|--------|-------------|
| `baseline` | `int` | `assessmentData.allMetrics.secure_score_percentage` rounded, or `0` | Actual Secure Score collected during assessment. `0` if Security module not run. |
| `hasActual` | `bool` | `assessmentData.allMetrics.secure_score_percentage != null` | Whether a real baseline was measured. Controls the "Estimated" label. |
| `uplift` | `int` | Sum of `secure_score_impact` for all fixed findings in `simState` | Point improvement from currently simulated fixes. |
| `projected` | `int` | `Math.min(100, baseline + uplift)` | Clamped estimated post-remediation Secure Score. |
| `delta` | `int` | `projected - baseline` | Point delta displayed as "+N". |

---

## DOM Elements Added (index.html)

Three new `sim-score-block` divs appended to `.sim-score-banner`:

| Element ID | Label | Content | Visible when |
|-----------|-------|---------|-------------|
| `simSSBaseline` | "Secure Baseline" | `baseline/100` or `"—"` | Always |
| `simSSProjected` | "Secure Projected" | `projected/100` with optional "Estimated" sub-label | Always |
| `simSSDelta` | "Secure Uplift" | `+N pts` or `+0 pts` | Always |

The "Estimated" sub-label (small, muted text below the score value in `simSSProjected`)
is shown when `!hasActual`, signalling to the consultant that no real baseline was measured.

---

## Secure Score Impact Values (full table — stored in FINDINGS_LIBRARY)

See research.md §3 for the complete per-finding table. Values range from 0 to 16.
The maximum total uplift across all findings is ~210 pts; the projected score is capped
at 100 regardless.
