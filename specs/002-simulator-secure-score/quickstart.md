# Quickstart: Testing Simulator Secure Score

**Feature**: 002-simulator-secure-score
**Date**: 2026-05-29

---

## Testing with Security Module Run (Full Test)

1. Start the backend: run `python backend.py` from `C:\AssetTool`
2. Open `http://localhost:5000`
3. Run an assessment with **Security & CA** module included (Interactive login)
4. After completion, click the **Simulator** tab

**Expected**:
- Score banner shows 8 blocks: the original 5 plus a `|` separator and the 3 new
  Secure Score blocks (Secure Baseline, Secure Projected, Secure Uplift)
- **Secure Baseline** shows the actual collected Secure Score (e.g., `45/100`)
- **Secure Projected** shows the same value initially (no findings toggled yet)
- **Secure Uplift** shows `+0 pts`
- No "Estimated" sub-label below Secure Projected

5. Toggle one finding to "simulated as fixed" (e.g., CA-001 — No CA Policies)

**Expected**:
- **Secure Projected** increases by 15 points (CA-001 impact = 15)
- **Secure Uplift** shows `+15 pts` in green
- Secure Baseline remains unchanged

6. Toggle additional findings

**Expected**:
- Secure Projected continues to increase with each toggle
- Secure Uplift accumulates correctly
- Secure Projected never exceeds 100/100

7. Click "Fix All"

**Expected**:
- Secure Projected shows a high value (likely 80–100/100 depending on tenant)
- Secure Uplift shows the total gain

8. Click "Reset All"

**Expected**:
- All three Secure Score values return to their initial state (+0 pts)

---

## Testing Without Security Module (Estimation Mode)

1. Run an assessment with **Security & CA module UNCHECKED**
2. Open the Simulator tab

**Expected**:
- **Secure Baseline** shows `—`
- **Secure Projected** shows `0/100` initially, increasing as findings are toggled
- Small "Estimated" sub-label visible below Secure Projected
- Uplift still accumulates correctly as findings are toggled

---

## Testing Old Sessions (Backward Compatibility)

1. Click "Load Assessment"
2. Load a session JSON file created before this feature was deployed

**Expected**:
- Simulator loads normally
- Secure Score blocks display with `—` baseline if no Security data, or actual baseline if present
- Secure Uplift shows `+0 pts` for all toggles (old sessions have no `secure_score_impact` field)
- No errors in the browser console

---

## Regression Checks

After verifying the new Secure Score display, also verify these existing behaviours are
unchanged:

- [ ] Current Score and Simulated Score still update correctly on toggle
- [ ] Improvement delta still updates correctly
- [ ] Active Chains and Chains Broken counts still update
- [ ] Attack chain cards still render correctly
- [ ] "Export What-If Report" still generates a report (Secure Score values should appear
      in the report since they are in the DOM)
- [ ] "Fix All" and "Reset All" buttons still work

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| Secure Score blocks not visible | HTML not updated | Verify new `sim-score-block` divs were added to `.sim-score-banner` |
| Uplift always shows `+0 pts` | `secure_score_impact` not in session | Restart backend and run a fresh assessment |
| `+0 pts` for all findings in a fresh session | `evaluate_findings()` not updated | Verify `secure_score_impact` was added to the `triggered.append(...)` dict |
| "Estimated" label always showing | `allMetrics.secure_score_percentage` missing | Ensure Security & CA module was included in the run |
| Score exceeds 100 | Clamping not applied | Verify `Math.min(100, baseline + uplift)` is in `renderSimResults()` |
